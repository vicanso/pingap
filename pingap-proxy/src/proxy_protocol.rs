// Copyright 2024-2025 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The PROXY protocol on the listening side, versions 1 and 2.
//!
//! A load balancer that works on connections (a cloud NLB, HAProxy in
//! TCP mode) has no `X-Forwarded-For` to write: it says who the client is
//! in a header of its own, ahead of everything the client sends. Read
//! here, the address in it becomes the peer address of the connection,
//! which is what the access log, the address checks and the rate limits
//! of the proxy go by.
//!
//! The header is taken from a trusted proxy only (`basic.trusted_proxies`):
//! anyone else who could send one could be whoever they like. A
//! connection of somebody else, and one of a trusted proxy that starts
//! with something else, is left as it comes.
//!
//! On a TLS listener the header stands in front of the handshake, and
//! pingora hands the connection over there ([`PreTlsProcess`]). A listener
//! without TLS has no such place: [`ProxyProtocolApp`] stands in front of
//! the HTTP application and reads the header before the first request.

use super::LOG_TARGET;
use super::ja4::Ja4Collector;
use ahash::AHashMap;
use async_trait::async_trait;
use parking_lot::RwLock;
use pingap_core::{ProxyProtocolTlvs, parse_v2_tlvs};
use pingora::apps::ServerApp;
use pingora::listeners::PreTlsProcess;
use pingora::protocols::l4::socket::SocketAddr as PingoraSocketAddr;
use pingora::protocols::l4::stream::Stream as L4Stream;
use pingora::protocols::{GetSocketDigest, SocketDigest, Stream};
use pingora::server::ShutdownWatch;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::{Instant, timeout_at};
use tracing::debug;

const TLV_SHARDS: usize = 16;
const TLV_MIN_SWEEP_SIZE: usize = 256;

/// Pre-TLS client IP allow check callback.
pub(crate) type IpAllowCheck = Arc<dyn Fn(IpAddr) -> bool + Send + Sync>;

struct TlvEntry {
    digest: Weak<SocketDigest>,
    tlvs: Arc<ProxyProtocolTlvs>,
}

#[repr(align(128))]
#[derive(Default)]
struct TlvShard(RwLock<AHashMap<usize, TlvEntry>>);

/// Sharded store mapping live connections' [`SocketDigest`] pointers to their
/// decoded inbound PROXY protocol v2 TLVs, cleaned up lazily via [`Weak`].
#[derive(Default)]
pub(crate) struct ProxyProtocolTlvStore {
    shards: [TlvShard; TLV_SHARDS],
}

impl ProxyProtocolTlvStore {
    fn key(digest: &Arc<SocketDigest>) -> usize {
        Arc::as_ptr(digest) as usize
    }

    fn shard(&self, key: usize) -> &TlvShard {
        &self.shards[(key >> 4) % TLV_SHARDS]
    }

    pub(crate) fn insert(
        &self,
        digest: &Arc<SocketDigest>,
        tlvs: Arc<ProxyProtocolTlvs>,
    ) {
        let key = Self::key(digest);
        let mut map = self.shard(key).0.write();
        if map.len() >= TLV_MIN_SWEEP_SIZE {
            map.retain(|_, entry| entry.digest.strong_count() > 0);
        }
        map.insert(
            key,
            TlvEntry {
                digest: Arc::downgrade(digest),
                tlvs,
            },
        );
    }

    pub(crate) fn get(
        &self,
        digest: &Arc<SocketDigest>,
    ) -> Option<Arc<ProxyProtocolTlvs>> {
        let key = Self::key(digest);
        let map = self.shard(key).0.read();
        let entry = map.get(&key)?;
        let expected = entry.digest.as_ptr();
        (expected == Arc::as_ptr(digest)).then(|| entry.tlvs.clone())
    }
}

/// How long the connection of a trusted proxy may say nothing at all, and
/// how long the rest of a header may take once its start is there.
///
/// The first is long: some balancers send the header only together with
/// the first bytes of the client, and a client may open a connection well
/// before it has a request for it. Taken for a connection without a
/// header in the meantime, the header that comes later would be read as
/// a broken request. So a connection is not judged before something has
/// arrived on it, and one that stays silent is closed.
#[derive(Clone, Copy)]
pub(crate) struct Timeouts {
    first_byte: Duration,
    rest: Duration,
}

pub(crate) const TIMEOUTS: Timeouts = Timeouts {
    first_byte: Duration::from_secs(60),
    rest: Duration::from_secs(5),
};
/// The longest version 1 header there is, `\r\n` included.
const V1_MAX_LEN: usize = 107;
const V1_PREFIX: &[u8] = b"PROXY ";
const V2_SIGNATURE: &[u8] = b"\r\n\r\n\0\r\nQUIT\n";
/// The signature, the version and command, the family, the length.
const V2_FIXED_LEN: usize = 16;

/// What a header says of the connection.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Header {
    /// A client's connection, passed on: where it comes from.
    Proxied(SocketAddr),
    /// The proxy's own (a health check), or of a kind that has no
    /// address to take: the connection keeps the address it has.
    Local,
}

#[derive(Debug, PartialEq, Eq)]
enum Parsed {
    /// It may still become a header.
    Incomplete,
    /// It is something else: a request, a ClientHello.
    Absent,
    /// A header of `len` bytes, with optional decoded PROXY v2 TLVs.
    Header {
        header: Header,
        len: usize,
        tlvs: Option<Arc<ProxyProtocolTlvs>>,
    },
    /// It starts as a header and is none.
    Invalid,
    /// Nothing arrived in the time a connection is given.
    Silent,
}

/// Reads `buf` as the start of a connection.
fn parse(buf: &[u8]) -> Parsed {
    let starts = |signature: &[u8]| {
        let len = buf.len().min(signature.len());
        buf[..len] == signature[..len]
    };
    if starts(V2_SIGNATURE) {
        if buf.len() < V2_SIGNATURE.len() {
            return Parsed::Incomplete;
        }
        return parse_v2(buf);
    }
    if starts(V1_PREFIX) {
        if buf.len() < V1_PREFIX.len() {
            return Parsed::Incomplete;
        }
        return parse_v1(buf);
    }
    Parsed::Absent
}

/// `PROXY TCP4 192.0.2.1 198.51.100.1 56324 443\r\n`
fn parse_v1(buf: &[u8]) -> Parsed {
    let window = &buf[..buf.len().min(V1_MAX_LEN)];
    let Some(end) = window.windows(2).position(|pair| pair == b"\r\n") else {
        return if buf.len() >= V1_MAX_LEN {
            Parsed::Invalid
        } else {
            Parsed::Incomplete
        };
    };
    let len = end + 2;
    let Ok(line) = std::str::from_utf8(&buf[V1_PREFIX.len()..end]) else {
        return Parsed::Invalid;
    };
    let mut parts = line.split(' ');
    let family = parts.next().unwrap_or_default();
    // Whatever follows is to be ignored, the specification says.
    if family == "UNKNOWN" {
        return Parsed::Header {
            header: Header::Local,
            len,
            tlvs: None,
        };
    }
    // A decimal number without a sign or zeros in front, as it is
    // specified: `parse` alone takes `+443` and `0443`.
    let port = |text: &str| {
        let plain = text.bytes().all(|byte| byte.is_ascii_digit())
            && (text.len() == 1 || !text.starts_with('0'));
        plain.then(|| text.parse::<u16>().ok()).flatten()
    };
    let source = parts.next().and_then(|ip| ip.parse::<IpAddr>().ok());
    let destination = parts.next().and_then(|ip| ip.parse::<IpAddr>().ok());
    let source_port = parts.next().and_then(port);
    let destination_port = parts.next().and_then(port);
    let (Some(source), Some(destination), Some(port), Some(_), None) = (
        source,
        destination,
        source_port,
        destination_port,
        parts.next(),
    ) else {
        return Parsed::Invalid;
    };
    let matches_family = match family {
        "TCP4" => source.is_ipv4() && destination.is_ipv4(),
        "TCP6" => source.is_ipv6() && destination.is_ipv6(),
        _ => false,
    };
    if !matches_family {
        return Parsed::Invalid;
    }
    Parsed::Header {
        header: Header::Proxied(SocketAddr::new(source, port)),
        len,
        tlvs: None,
    }
}

fn opt_tlvs(tlv_bytes: &[u8]) -> Option<Option<Arc<ProxyProtocolTlvs>>> {
    let parsed = parse_v2_tlvs(tlv_bytes)?;
    Some((!parsed.is_empty()).then(|| Arc::new(parsed)))
}

fn parse_v2_tcp4(
    addresses: &[u8],
) -> Option<(Header, Option<Arc<ProxyProtocolTlvs>>)> {
    let block = addresses.get(..12)?;
    let ip = Ipv4Addr::new(block[0], block[1], block[2], block[3]);
    let port = u16::from_be_bytes([block[8], block[9]]);
    let tlvs = opt_tlvs(&addresses[12..])?;
    Some((Header::Proxied(SocketAddr::new(IpAddr::V4(ip), port)), tlvs))
}

fn parse_v2_tcp6(
    addresses: &[u8],
) -> Option<(Header, Option<Arc<ProxyProtocolTlvs>>)> {
    let block = addresses.get(..36)?;
    let mut ip = [0u8; 16];
    ip.copy_from_slice(&block[..16]);
    let port = u16::from_be_bytes([block[32], block[33]]);
    let tlvs = opt_tlvs(&addresses[36..])?;
    Some((
        Header::Proxied(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port)),
        tlvs,
    ))
}

fn parse_v2_unix(
    addresses: &[u8],
) -> Option<(Header, Option<Arc<ProxyProtocolTlvs>>)> {
    let tlvs = if let Some(tlv_bytes) = addresses.get(216..) {
        opt_tlvs(tlv_bytes)?
    } else if addresses.is_empty() {
        None
    } else {
        return None;
    };
    Some((Header::Local, tlvs))
}

fn parse_v2_local(
    family: u8,
    addresses: &[u8],
) -> Option<(Header, Option<Arc<ProxyProtocolTlvs>>)> {
    if addresses.is_empty() {
        return Some((Header::Local, None));
    }
    let addr_len = match family {
        1 => 12,
        2 => 36,
        3 => 216,
        _ => 0,
    };
    let tlv_bytes = addresses.get(addr_len..)?;
    Some((Header::Local, opt_tlvs(tlv_bytes)?))
}

fn parse_v2_payload(
    command: u8,
    family: u8,
    addresses: &[u8],
) -> Option<(Header, Option<Arc<ProxyProtocolTlvs>>)> {
    match (command, family) {
        // LOCAL: the proxy speaks for itself; skip any dummy address block
        // corresponding to `family` before reading optional trailing TLVs.
        (0, family) => parse_v2_local(family, addresses),
        // AF_INET: two addresses of four bytes, two ports.
        (1, 1) => parse_v2_tcp4(addresses),
        // AF_INET6: two addresses of sixteen bytes, two ports.
        (1, 2) => parse_v2_tcp6(addresses),
        // AF_UNSPEC: no address block; only TLVs may be present.
        (1, 0) => Some((Header::Local, opt_tlvs(addresses)?)),
        // AF_UNIX: optional 216-byte address block followed by TLVs.
        (1, 3) => parse_v2_unix(addresses),
        _ => None,
    }
}

/// The binary form: the signature, a byte of version and command, a byte
/// of address family and transport, the length of what follows, the
/// addresses, and whatever else the proxy has to say (TLVs).
fn parse_v2(buf: &[u8]) -> Parsed {
    if buf.len() < V2_FIXED_LEN {
        return Parsed::Incomplete;
    }
    let version = buf[12] >> 4;
    let command = buf[12] & 0x0f;
    let family = buf[13] >> 4;
    let len = V2_FIXED_LEN + u16::from_be_bytes([buf[14], buf[15]]) as usize;
    if version != 2 || command > 1 {
        return Parsed::Invalid;
    }
    if buf.len() < len {
        return Parsed::Incomplete;
    }
    let addresses = &buf[V2_FIXED_LEN..len];
    let Some((header, tlvs)) = parse_v2_payload(command, family, addresses)
    else {
        return Parsed::Invalid;
    };
    Parsed::Header { header, len, tlvs }
}

/// Reads from the start of a connection until it is known whether a
/// header stands there. Returns every byte read and what was found:
/// `Silent` for a connection on which nothing arrived in time, and
/// `Incomplete` for one that was closed, or went quiet in the middle of
/// what may have become a header.
async fn read_header<R: AsyncRead + Unpin>(
    reader: &mut R,
    timeouts: Timeouts,
) -> (Vec<u8>, Parsed) {
    let mut buf = Vec::with_capacity(256);
    let mut chunk = [0u8; 2048];
    let mut deadline = Instant::now() + timeouts.first_byte;
    loop {
        match parse(&buf) {
            Parsed::Incomplete => {},
            parsed => return (buf, parsed),
        }
        match timeout_at(deadline, reader.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => {
                if buf.is_empty() {
                    deadline = Instant::now() + timeouts.rest;
                }
                buf.extend_from_slice(&chunk[..n]);
            },
            Err(_) if buf.is_empty() => return (buf, Parsed::Silent),
            _ => return (buf, Parsed::Incomplete),
        }
    }
}

fn digest_peer_ip(digest: Option<&Arc<SocketDigest>>) -> Option<IpAddr> {
    digest.and_then(|digest| {
        digest
            .peer_addr()
            .and_then(|addr| addr.as_inet())
            .map(|addr| addr.ip().to_canonical())
    })
}

/// The address the connection was made from, as the socket has it.
pub(crate) fn peer_ip(stream: &L4Stream) -> Option<IpAddr> {
    digest_peer_ip(stream.get_socket_digest().as_ref())
}

/// A digest of the socket of `stream` that has `source` for the address
/// of the peer. Everything else is asked of the socket as before.
fn digest_with_peer(stream: &L4Stream, source: SocketAddr) -> SocketDigest {
    #[cfg(unix)]
    let digest = {
        use std::os::unix::io::AsRawFd;
        SocketDigest::from_raw_fd(stream.as_raw_fd())
    };
    #[cfg(windows)]
    let digest = {
        use std::os::windows::io::AsRawSocket;
        SocketDigest::from_raw_socket(stream.as_raw_socket())
    };
    let _ = digest.peer_addr.set(Some(PingoraSocketAddr::Inet(source)));
    digest
}

/// Takes the PROXY protocol header off the start of `stream`, where a
/// proxy that `is_trusted` has put one, updates the socket digest with
/// the proxied peer address when present, and returns any decoded PROXY v2
/// TLVs.
pub(crate) async fn accept_with_tlvs(
    stream: &mut L4Stream,
    timeouts: Timeouts,
    is_trusted: impl Fn(IpAddr) -> bool,
) -> pingora::Result<Option<Arc<ProxyProtocolTlvs>>> {
    let Some(peer) = peer_ip(stream) else {
        return Ok(None);
    };
    if !is_trusted(peer) {
        return Ok(None);
    }
    let (read, parsed) = read_header(stream, timeouts).await;
    match parsed {
        Parsed::Header { header, len, tlvs } => {
            // What came with the header belongs to the client. Once, and
            // all of it: pingora replays put-back chunks last in, first
            // out.
            stream.rewind(&read[len..]);
            if let Header::Proxied(source) = header {
                debug!(
                    target: LOG_TARGET,
                    proxy = peer.to_string(),
                    client = source.to_string(),
                    "proxy protocol header"
                );
                let digest = digest_with_peer(stream, source);
                stream.set_socket_digest(digest);
            }
            Ok(tlvs)
        },
        Parsed::Invalid => Err(pingora::Error::explain(
            pingora::ErrorType::InvalidHTTPHeader,
            format!("invalid proxy protocol header from {peer}"),
        )),
        Parsed::Silent => Err(pingora::Error::explain(
            pingora::ErrorType::ReadTimedout,
            format!("nothing on the connection of proxy {peer}"),
        )),
        Parsed::Absent | Parsed::Incomplete => {
            stream.rewind(&read);
            Ok(None)
        },
    }
}

/// Takes the PROXY protocol header off the start of `stream` without
/// returning decoded TLVs.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) async fn accept(
    stream: &mut L4Stream,
    timeouts: Timeouts,
    is_trusted: impl Fn(IpAddr) -> bool,
) -> pingora::Result<()> {
    accept_with_tlvs(stream, timeouts, is_trusted)
        .await
        .map(|_| ())
}

/// What a TLS listener does with a connection before the handshake: the
/// PROXY protocol header first, where the server reads one, then any
/// configured IP allow/deny check against the resolved client address, and
/// finally the ClientHello for the JA4 fingerprint, where it takes one.
/// pingora has one such hook per listener, and the order matters: IP
/// enforcement and the fingerprint see the connection as the header leaves it.
pub(crate) struct PreTls {
    pub proxy_protocol: bool,
    pub tlvs: Option<Arc<ProxyProtocolTlvStore>>,
    pub ip_checker: Option<IpAllowCheck>,
    pub ja4: Option<Ja4Collector>,
}

impl PreTls {
    async fn process_with(
        &self,
        stream: &mut L4Stream,
        is_trusted: impl Fn(IpAddr) -> bool,
    ) -> pingora::Result<()> {
        if self.proxy_protocol {
            let tlvs = accept_with_tlvs(stream, TIMEOUTS, is_trusted).await?;
            if let (Some(tlvs), Some(store), Some(digest)) =
                (tlvs, &self.tlvs, stream.get_socket_digest())
            {
                store.insert(&digest, tlvs);
            }
        }
        if let Some(check_ip) = &self.ip_checker
            && let Some(ip) = peer_ip(stream)
            && !check_ip(ip)
        {
            return Err(pingora::Error::explain(
                pingora::ErrorType::ConnectRefused,
                format!("client ip {ip} denied before tls handshake"),
            ));
        }
        if let Some(ja4) = &self.ja4 {
            ja4.process(stream).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl PreTlsProcess for PreTls {
    async fn process(&self, stream: &mut L4Stream) -> pingora::Result<()> {
        self.process_with(stream, pingap_core::is_trusted_proxy)
            .await
    }
}

/// The application of a listener without TLS that reads the PROXY
/// protocol: the header, then the HTTP application as it is.
///
/// pingora calls an application once per connection and again each time
/// the application hands the connection back for another request. The
/// header stands at the start of the connection and nowhere else - read
/// on a later round, a client could put one in front of its second
/// request and be whoever it names. So the rounds are made here, and the
/// connection is never handed back to pingora.
pub struct ProxyProtocolApp<A> {
    inner: Arc<A>,
    timeouts: Timeouts,
    is_trusted: fn(IpAddr) -> bool,
    proxy_protocol: bool,
    tlvs: Option<Arc<ProxyProtocolTlvStore>>,
    ip_checker: Option<IpAllowCheck>,
}

impl<A> ProxyProtocolApp<A> {
    pub fn new(inner: A) -> Self {
        Self {
            inner: Arc::new(inner),
            timeouts: TIMEOUTS,
            is_trusted: pingap_core::is_trusted_proxy,
            proxy_protocol: true,
            tlvs: None,
            ip_checker: None,
        }
    }

    #[must_use]
    pub(crate) fn with_tlvs(
        mut self,
        tlvs: Option<Arc<ProxyProtocolTlvStore>>,
    ) -> Self {
        self.tlvs = tlvs;
        self
    }

    #[must_use]
    pub(crate) fn with_ip_checker(
        mut self,
        ip_checker: Option<IpAllowCheck>,
    ) -> Self {
        self.ip_checker = ip_checker;
        self
    }

    async fn accept_and_filter(&self, stream: Stream) -> Option<Stream> {
        // Anything but the plain connection of a listener is not for
        // this to read from.
        // Of the stream itself: asked of the box, `as_any` is the box.
        let stream: Stream = if self.proxy_protocol
            && (*stream).as_any().is::<L4Stream>()
        {
            let mut l4 = stream.into_any().downcast::<L4Stream>().ok()?;
            match accept_with_tlvs(&mut l4, self.timeouts, self.is_trusted)
                .await
            {
                Ok(tlvs) => {
                    if let (Some(tlvs), Some(store), Some(digest)) =
                        (tlvs, &self.tlvs, l4.get_socket_digest())
                    {
                        store.insert(&digest, tlvs);
                    }
                },
                Err(e) => {
                    debug!(target: LOG_TARGET, error = %e, "connection is dropped");
                    return None;
                },
            }
            l4
        } else {
            stream
        };
        if let Some(check_ip) = &self.ip_checker
            && let Some(ip) =
                digest_peer_ip(stream.get_socket_digest().as_ref())
            && !check_ip(ip)
        {
            debug!(target: LOG_TARGET, ip = %ip, "client ip denied");
            return None;
        }
        Some(stream)
    }
}

#[async_trait]
impl<A> ServerApp for ProxyProtocolApp<A>
where
    A: ServerApp + Send + Sync + 'static,
{
    async fn process_new(
        self: &Arc<Self>,
        stream: Stream,
        shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        let stream = self.accept_and_filter(stream).await?;
        let mut reusable = self.inner.process_new(stream, shutdown).await;
        while let Some(stream) = reusable {
            reusable = self.inner.process_new(stream, shutdown).await;
        }
        None
    }

    async fn cleanup(&self) {
        self.inner.cleanup().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};

    fn v2(command: u8, family: u8, addresses: &[u8]) -> Vec<u8> {
        let mut header = V2_SIGNATURE.to_vec();
        header.push(0x20 | command);
        header.push(family);
        header.extend_from_slice(&(addresses.len() as u16).to_be_bytes());
        header.extend_from_slice(addresses);
        header
    }

    fn v2_tcp4() -> Vec<u8> {
        let mut addresses = vec![192, 0, 2, 1, 198, 51, 100, 1];
        addresses.extend_from_slice(&56324u16.to_be_bytes());
        addresses.extend_from_slice(&443u16.to_be_bytes());
        // a TLV behind the addresses
        addresses.extend_from_slice(&[0x04, 0x00, 0x02, 0xaa, 0xbb]);
        v2(1, 0x11, &addresses)
    }

    fn proxied(addr: &str) -> Header {
        Header::Proxied(addr.parse().unwrap())
    }

    #[test]
    fn test_parse_v1() {
        let header = b"PROXY TCP4 192.0.2.1 198.51.100.1 56324 443\r\n";
        let mut buf = header.to_vec();
        buf.extend_from_slice(b"GET / HTTP/1.1\r\n\r\n");
        assert_eq!(
            Parsed::Header {
                header: proxied("192.0.2.1:56324"),
                len: header.len(),
                tlvs: None,
            },
            parse(&buf)
        );
        let header = b"PROXY TCP6 2001:db8::1 2001:db8::2 4000 443\r\n";
        let mut buf = header.to_vec();
        buf.extend_from_slice(b"rest");
        assert_eq!(
            Parsed::Header {
                header: proxied("[2001:db8::1]:4000"),
                len: header.len(),
                tlvs: None,
            },
            parse(&buf)
        );
        let header = b"PROXY TCP4 192.0.2.1 198.51.100.1 56324 443\r\n";
        // the proxy's own connection, with or without what may follow
        for line in
            ["PROXY UNKNOWN\r\n", "PROXY UNKNOWN ffff::1 ffff::2 1 2\r\n"]
        {
            assert_eq!(
                Parsed::Header {
                    header: Header::Local,
                    len: line.len(),
                    tlvs: None,
                },
                parse(line.as_bytes())
            );
        }

        // every start of a header may become one
        for len in 0..header.len() {
            assert_eq!(Parsed::Incomplete, parse(&header[..len]), "{len}");
        }
        // and something else is something else from its first byte on
        for other in [
            &b"GET / HTTP/1.1\r\n"[..],
            b"PROXIED / HTTP/1.1\r\n",
            b"P0",
            b"\x16\x03\x01\x02\x00",
            b"\r\n\r\nGET",
        ] {
            assert_eq!(Parsed::Absent, parse(other), "{other:?}");
        }

        for broken in [
            "PROXY TCP4 192.0.2.1 198.51.100.1 56324\r\n",
            "PROXY TCP4 192.0.2.1 198.51.100.1 56324 443 1\r\n",
            "PROXY TCP4 192.0.2.1 198.51.100.1 99999 443\r\n",
            "PROXY TCP4 2001:db8::1 2001:db8::2 4000 443\r\n",
            "PROXY TCP6 192.0.2.1 198.51.100.1 56324 443\r\n",
            "PROXY UDP4 192.0.2.1 198.51.100.1 56324 443\r\n",
            "PROXY TCP4 host 198.51.100.1 56324 443\r\n",
            "PROXY  TCP4 192.0.2.1 198.51.100.1 56324 443\r\n",
            // a port is a plain number
            "PROXY TCP4 192.0.2.1 198.51.100.1 +56324 443\r\n",
            "PROXY TCP4 192.0.2.1 198.51.100.1 056324 443\r\n",
            "PROXY TCP4 192.0.2.1 198.51.100.1 56324 \r\n",
        ] {
            assert_eq!(Parsed::Invalid, parse(broken.as_bytes()), "{broken}");
        }
        // no end of the line within the length a header may have
        let endless = format!("PROXY TCP4 {}", "1".repeat(200));
        assert_eq!(Parsed::Invalid, parse(endless.as_bytes()));
    }

    #[test]
    fn test_parse_v2() {
        let header = v2_tcp4();
        let mut buf = header.clone();
        buf.extend_from_slice(b"\x16\x03\x01");
        assert_eq!(
            Parsed::Header {
                header: proxied("192.0.2.1:56324"),
                len: header.len(),
                tlvs: None,
            },
            parse(&buf)
        );
        for len in 0..header.len() {
            assert_eq!(Parsed::Incomplete, parse(&header[..len]), "{len}");
        }

        let mut addresses = vec![0u8; 36];
        addresses[..16].copy_from_slice(
            &"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets(),
        );
        addresses[32..34].copy_from_slice(&4000u16.to_be_bytes());
        assert_eq!(
            Parsed::Header {
                header: proxied("[2001:db8::1]:4000"),
                len: 52,
                tlvs: None,
            },
            parse(&v2(1, 0x21, &addresses))
        );

        // LOCAL, and the families that have no address to take
        for (command, family, addresses) in
            [(0, 0x00, 0), (0, 0x11, 12), (1, 0x00, 0), (1, 0x31, 216)]
        {
            let header = v2(command, family, &vec![0u8; addresses]);
            assert_eq!(
                Parsed::Header {
                    header: Header::Local,
                    len: header.len(),
                    tlvs: None,
                },
                parse(&header),
                "{command} {family}"
            );
        }

        // a version that is not 2, a command there is none of, a family
        // there is none of, addresses that are too short
        let mut wrong_version = v2_tcp4();
        wrong_version[12] = 0x11;
        assert_eq!(Parsed::Invalid, parse(&wrong_version));
        assert_eq!(Parsed::Invalid, parse(&v2(2, 0x11, &[0u8; 12])));
        assert_eq!(Parsed::Invalid, parse(&v2(1, 0x41, &[0u8; 12])));
        assert_eq!(Parsed::Invalid, parse(&v2(1, 0x11, &[0u8; 11])));
        assert_eq!(Parsed::Invalid, parse(&v2(1, 0x21, &[0u8; 35])));
        assert_eq!(Parsed::Invalid, parse(&v2(1, 0x31, &[0u8; 10])));
    }

    /// What the connecting side writes (`send_proxy_protocol` of an
    /// upstream) is what this side reads: one pingap behind another is
    /// told of the client.
    #[test]
    fn test_parse_what_an_upstream_sends() {
        use pingap_core::{ProxyProtocolVersion, new_proxy_protocol_header};
        for version in [ProxyProtocolVersion::V1, ProxyProtocolVersion::V2] {
            for (source, destination, expected) in [
                ("192.0.2.1:56324", "198.51.100.1:443", "192.0.2.1:56324"),
                (
                    "[2001:db8::1]:4000",
                    "[2001:db8::2]:443",
                    "[2001:db8::1]:4000",
                ),
                // the IPv4 client of a dual-stack listener
                (
                    "[::ffff:192.0.2.1]:56324",
                    "[::ffff:198.51.100.1]:443",
                    "192.0.2.1:56324",
                ),
                // one end of each family
                (
                    "192.0.2.1:56324",
                    "[2001:db8::2]:443",
                    "[::ffff:192.0.2.1]:56324",
                ),
            ] {
                let header = new_proxy_protocol_header(
                    version,
                    Some((
                        source.parse().unwrap(),
                        destination.parse().unwrap(),
                    )),
                );
                let mut buf = header.to_vec();
                buf.extend_from_slice(b"GET / HTTP/1.1\r\n\r\n");
                assert_eq!(
                    Parsed::Header {
                        header: proxied(expected),
                        len: header.len(),
                        tlvs: None,
                    },
                    parse(&buf),
                    "{version:?} {source} {destination}"
                );
            }
            // a connection of the proxy's own
            let header = new_proxy_protocol_header(version, None);
            assert_eq!(
                Parsed::Header {
                    header: Header::Local,
                    len: header.len(),
                    tlvs: None,
                },
                parse(&header),
                "{version:?}"
            );
        }
    }

    /// A connected pingora stream, and the client end of it.
    async fn connected_stream() -> (L4Stream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let mut stream = L4Stream::from(server);
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = stream.as_raw_fd();
            stream.set_socket_digest(SocketDigest::from_raw_fd(fd));
        }
        (stream, client)
    }

    fn peer_of(stream: &L4Stream) -> String {
        stream
            .get_socket_digest()
            .and_then(|digest| digest.peer_addr().map(|addr| addr.to_string()))
            .unwrap_or_default()
    }

    /// The header gives the connection its address and is gone from what
    /// is read next; without the trust of the peer nothing is read.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_accept() {
        let trusted = |ip: IpAddr| ip.is_loopback();
        let nobody = |_: IpAddr| false;
        let v1 = b"PROXY TCP4 192.0.2.1 198.51.100.1 56324 443\r\n".to_vec();
        let request = b"GET / HTTP/1.1\r\n\r\n".to_vec();
        let read_back = async |stream: &mut L4Stream, len: usize| {
            let mut read = vec![0u8; len];
            stream.read_exact(&mut read).await.unwrap();
            read
        };

        // Nobody is trusted: the header is the client's to explain.
        let (mut stream, mut client) = connected_stream().await;
        let mut sent = v1.clone();
        sent.extend_from_slice(&request);
        client.write_all(&sent).await.unwrap();
        accept(&mut stream, TIMEOUTS, nobody).await.unwrap();
        assert_eq!(true, peer_of(&stream).starts_with("127.0.0.1:"));
        assert_eq!(sent, read_back(&mut stream, sent.len()).await);

        for header in [v1, v2_tcp4()] {
            let (mut stream, mut client) = connected_stream().await;
            // in pieces, as a slow proxy would send it
            let writer = {
                let mut sent = header.clone();
                sent.extend_from_slice(&request);
                tokio::spawn(async move {
                    for piece in sent.chunks(7) {
                        client.write_all(piece).await.unwrap();
                        client.flush().await.unwrap();
                        tokio::task::yield_now().await;
                    }
                    client
                })
            };
            accept(&mut stream, TIMEOUTS, trusted).await.unwrap();
            let _client = writer.await.unwrap();
            assert_eq!("192.0.2.1:56324", peer_of(&stream));
            assert_eq!(request, read_back(&mut stream, request.len()).await);
        }

        // A trusted proxy that sends none: its own address, and all of
        // what it sent.
        let (mut stream, mut client) = connected_stream().await;
        client.write_all(&request).await.unwrap();
        accept(&mut stream, TIMEOUTS, trusted).await.unwrap();
        assert_eq!(true, peer_of(&stream).starts_with("127.0.0.1:"));
        assert_eq!(request, read_back(&mut stream, request.len()).await);

        // Regression: a balancer that sends the header with the first
        // bytes of the client, on a connection the client opened ahead
        // of its request. Judged after five seconds of silence, it was a
        // connection without a header, and the header a broken request.
        let patient = Timeouts {
            first_byte: Duration::from_secs(30),
            rest: Duration::from_millis(200),
        };
        let (mut stream, mut client) = connected_stream().await;
        let writer = {
            let mut sent = v2_tcp4();
            sent.extend_from_slice(&request);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(400)).await;
                client.write_all(&sent).await.unwrap();
                client
            })
        };
        accept(&mut stream, patient, trusted).await.unwrap();
        let _client = writer.await.unwrap();
        assert_eq!("192.0.2.1:56324", peer_of(&stream));
        assert_eq!(request, read_back(&mut stream, request.len()).await);

        // One that says nothing at all in the time it is given is closed,
        // not handed on as a connection without a header.
        let impatient = Timeouts {
            first_byte: Duration::from_millis(50),
            rest: Duration::from_millis(50),
        };
        let (mut stream, _client) = connected_stream().await;
        assert_eq!(
            true,
            accept(&mut stream, impatient, trusted).await.is_err()
        );
        // The start of a header and then nothing: as it came, for the
        // request it is not to be refused as.
        let (mut stream, mut client) = connected_stream().await;
        client.write_all(b"PROXY TCP4 192").await.unwrap();
        accept(&mut stream, impatient, trusted).await.unwrap();
        assert_eq!(true, peer_of(&stream).starts_with("127.0.0.1:"));
        assert_eq!(
            b"PROXY TCP4 192".to_vec(),
            read_back(&mut stream, 14).await
        );

        // The proxy's own connection keeps its address.
        let (mut stream, mut client) = connected_stream().await;
        client.write_all(b"PROXY UNKNOWN\r\nGET").await.unwrap();
        accept(&mut stream, TIMEOUTS, trusted).await.unwrap();
        assert_eq!(true, peer_of(&stream).starts_with("127.0.0.1:"));
        assert_eq!(b"GET".to_vec(), read_back(&mut stream, 3).await);

        // A header that is none ends the connection.
        let (mut stream, mut client) = connected_stream().await;
        client
            .write_all(b"PROXY TCP4 not an address\r\n")
            .await
            .unwrap();
        assert_eq!(true, accept(&mut stream, TIMEOUTS, trusted).await.is_err());
    }

    /// An application that takes four bytes of each round it is given
    /// and hands the connection back once.
    #[derive(Default)]
    struct FourBytes {
        rounds: std::sync::Mutex<Vec<(String, Vec<u8>)>>,
    }

    #[async_trait]
    impl ServerApp for FourBytes {
        async fn process_new(
            self: &Arc<Self>,
            mut stream: Stream,
            _shutdown: &ShutdownWatch,
        ) -> Option<Stream> {
            let mut read = vec![0u8; 4];
            stream.read_exact(&mut read).await.ok()?;
            let peer = stream
                .get_socket_digest()
                .and_then(|digest| {
                    digest.peer_addr().map(|addr| addr.to_string())
                })
                .unwrap_or_default();
            let mut rounds = self.rounds.lock().unwrap();
            rounds.push((peer, read));
            (rounds.len() < 2).then_some(stream)
        }
    }

    /// Regression of a design that was not built: the header is read at
    /// the start of a connection and never again. pingora calls the
    /// application once more for each request of a connection that is
    /// kept; read there, a client put a header in front of its second
    /// request and was whoever it named.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_app_reads_the_header_once() {
        let (stream, mut client) = connected_stream().await;
        client
            .write_all(
                b"PROXY TCP4 192.0.2.1 198.51.100.1 56324 443\r\nAAAAPROXY TCP4 10.0.0.1 10.0.0.2 1 2\r\n",
            )
            .await
            .unwrap();
        let mut app = ProxyProtocolApp::new(FourBytes::default());
        app.is_trusted = |ip| ip.is_loopback();
        let inner = app.inner.clone();
        let (_tx, shutdown) = tokio::sync::watch::channel(false);
        // Both rounds are made in here: nothing is handed back.
        let handed_back =
            Arc::new(app).process_new(Box::new(stream), &shutdown).await;
        assert_eq!(true, handed_back.is_none());
        assert_eq!(
            vec![
                ("192.0.2.1:56324".to_string(), b"AAAA".to_vec()),
                ("192.0.2.1:56324".to_string(), b"PROX".to_vec()),
            ],
            *inner.rounds.lock().unwrap()
        );
    }

    fn tlv_entry(tlv_type: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![tlv_type];
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(value);
        out
    }

    fn sample_v2_tlvs() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&tlv_entry(pingap_core::PP2_TYPE_ALPN, b"h2"));
        out.extend_from_slice(&tlv_entry(
            pingap_core::PP2_TYPE_AUTHORITY,
            b"api.example.com",
        ));
        out.extend_from_slice(&tlv_entry(
            pingap_core::PP2_TYPE_UNIQUE_ID,
            b"req-xyz",
        ));
        let mut aws_val = vec![pingap_core::PP2_SUBTYPE_AWS_VPCE_ID];
        aws_val.extend_from_slice(b"vpce-999");
        out.extend_from_slice(&tlv_entry(pingap_core::PP2_TYPE_AWS, &aws_val));
        out
    }

    fn v2_tcp4_with_tlvs(tlv_bytes: &[u8]) -> Vec<u8> {
        let mut addresses = vec![192, 0, 2, 10, 198, 51, 100, 1];
        addresses.extend_from_slice(&44444u16.to_be_bytes());
        addresses.extend_from_slice(&443u16.to_be_bytes());
        addresses.extend_from_slice(tlv_bytes);
        v2(1, 0x11, &addresses)
    }

    #[test]
    fn test_parse_v2_tlvs_across_families() {
        let tlvs = sample_v2_tlvs();
        let expected = Arc::new(ProxyProtocolTlvs {
            alpn: Some("h2".to_string()),
            authority: Some("api.example.com".to_string()),
            unique_id: Some("req-xyz".to_string()),
            aws_vpce_id: Some("vpce-999".to_string()),
            ..Default::default()
        });

        let tcp4 = v2_tcp4_with_tlvs(&tlvs);
        assert_eq!(
            Parsed::Header {
                header: proxied("192.0.2.10:44444"),
                len: tcp4.len(),
                tlvs: Some(expected.clone()),
            },
            parse(&tcp4)
        );

        let mut tcp6_payload = vec![0u8; 36];
        tcp6_payload[..16].copy_from_slice(
            &"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets(),
        );
        tcp6_payload[32..34].copy_from_slice(&5000u16.to_be_bytes());
        tcp6_payload.extend_from_slice(&tlv_entry(
            pingap_core::PP2_TYPE_NETNS,
            b"netns-a",
        ));
        let tcp6 = v2(1, 0x21, &tcp6_payload);
        assert_eq!(
            Parsed::Header {
                header: proxied("[2001:db8::2]:5000"),
                len: tcp6.len(),
                tlvs: Some(Arc::new(ProxyProtocolTlvs {
                    netns: Some("netns-a".to_string()),
                    ..Default::default()
                })),
            },
            parse(&tcp6)
        );

        for (command, family, prefix_len) in
            [(0, 0x00, 0), (1, 0x00, 0), (1, 0x31, 216)]
        {
            let mut body = vec![0u8; prefix_len];
            body.extend_from_slice(&tlvs);
            let hdr = v2(command, family, &body);
            assert_eq!(
                Parsed::Header {
                    header: Header::Local,
                    len: hdr.len(),
                    tlvs: Some(expected.clone()),
                },
                parse(&hdr)
            );
        }

        // Malformed truncated TLV turns header invalid.
        let bad = v2_tcp4_with_tlvs(&[
            pingap_core::PP2_TYPE_AUTHORITY,
            0x00,
            0x05,
            b'a',
        ]);
        assert_eq!(Parsed::Invalid, parse(&bad));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_tlv_store_insert_get_and_sweep() {
        let store = ProxyProtocolTlvStore::default();
        let tlvs = Arc::new(ProxyProtocolTlvs {
            authority: Some("stored.example.com".to_string()),
            ..Default::default()
        });
        let (stream, _client) = connected_stream().await;
        let digest = stream.get_socket_digest().unwrap();
        store.insert(&digest, tlvs.clone());
        assert_eq!(Some(tlvs.clone()), store.get(&digest));

        // Stale entries past TLV_MIN_SWEEP_SIZE are swept once dropped.
        let mut stale_streams = Vec::new();
        for _ in 0..TLV_MIN_SWEEP_SIZE {
            let (s, c) = connected_stream().await;
            let d = s.get_socket_digest().unwrap();
            store.insert(&d, tlvs.clone());
            stale_streams.push((s, c));
        }
        drop(stale_streams);
        let (fresh, _c) = connected_stream().await;
        let fresh_digest = fresh.get_socket_digest().unwrap();
        store.insert(&fresh_digest, tlvs.clone());
        assert_eq!(Some(tlvs), store.get(&fresh_digest));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_pre_tls_tlvs_and_ip_checker() {
        let tlvs = sample_v2_tlvs();
        let header = v2_tcp4_with_tlvs(&tlvs);

        // PreTls resolves PROXY v2 peer + TLVs, then denies matching client IP.
        let store = Arc::new(ProxyProtocolTlvStore::default());
        let pre_tls_deny = PreTls {
            proxy_protocol: true,
            tlvs: Some(store.clone()),
            ip_checker: Some(Arc::new(|ip| {
                ip != "192.0.2.10".parse::<IpAddr>().unwrap()
            })),
            ja4: None,
        };
        let (mut stream, mut client) = connected_stream().await;
        client.write_all(&header).await.unwrap();
        client.write_all(b"\x16\x03\x01").await.unwrap();
        let err = pre_tls_deny
            .process_with(&mut stream, |ip| ip.is_loopback())
            .await
            .unwrap_err();
        assert_eq!(pingora::ErrorType::ConnectRefused, *err.etype());
        let digest = stream.get_socket_digest().unwrap();
        assert_eq!(
            Some("api.example.com"),
            store
                .get(&digest)
                .as_deref()
                .and_then(|t| t.authority.as_deref())
        );

        // Allowed client IP passes with TLVs stored and ClientHello untouched.
        let pre_tls_allow = PreTls {
            proxy_protocol: true,
            tlvs: Some(store.clone()),
            ip_checker: Some(Arc::new(|ip| {
                ip == "192.0.2.10".parse::<IpAddr>().unwrap()
            })),
            ja4: None,
        };
        let (mut stream, mut client) = connected_stream().await;
        client.write_all(&header).await.unwrap();
        client.write_all(b"\x16\x03\x01").await.unwrap();
        pre_tls_allow
            .process_with(&mut stream, |ip| ip.is_loopback())
            .await
            .unwrap();
        let digest = stream.get_socket_digest().unwrap();
        assert_eq!(
            Some("vpce-999"),
            store
                .get(&digest)
                .as_deref()
                .and_then(|t| t.aws_vpce_id.as_deref())
        );
        let mut buf = [0u8; 3];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(b"\x16\x03\x01", &buf);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_proxy_protocol_app_tlvs_and_ip_checker() {
        let tlvs = sample_v2_tlvs();
        let header = v2_tcp4_with_tlvs(&tlvs);
        let (_tx, shutdown) = tokio::sync::watch::channel(false);

        // Denied after PROXY v2 peer override -> dropped before inner.
        let store = Arc::new(ProxyProtocolTlvStore::default());
        let (stream, mut client) = connected_stream().await;
        client.write_all(&header).await.unwrap();
        client.write_all(b"AAAA").await.unwrap();
        let mut app = ProxyProtocolApp::new(FourBytes::default())
            .with_tlvs(Some(store.clone()))
            .with_ip_checker(Some(Arc::new(|ip| {
                ip != "192.0.2.10".parse::<IpAddr>().unwrap()
            })));
        app.is_trusted = |ip| ip.is_loopback();
        let app = Arc::new(app);
        let inner = app.inner.clone();
        assert_eq!(
            true,
            app.process_new(Box::new(stream), &shutdown).await.is_none()
        );
        assert_eq!(0, inner.rounds.lock().unwrap().len());

        // Allowed client -> TLVs stored and inner runs cleanly.
        let (stream, mut client) = connected_stream().await;
        let digest = stream.get_socket_digest().unwrap();
        client.write_all(&header).await.unwrap();
        client.write_all(b"AAAABBBB").await.unwrap();
        let mut app = ProxyProtocolApp::new(FourBytes::default())
            .with_tlvs(Some(store.clone()))
            .with_ip_checker(Some(Arc::new(|ip| {
                ip == "192.0.2.10".parse::<IpAddr>().unwrap()
            })));
        app.is_trusted = |ip| ip.is_loopback();
        let app = Arc::new(app);
        let inner = app.inner.clone();
        let _ = app.process_new(Box::new(stream), &shutdown).await;
        // Original digest was replaced by digest_with_peer, so check via store count or inner rounds.
        assert_eq!(2, inner.rounds.lock().unwrap().len());
        assert_eq!("192.0.2.10:44444", inner.rounds.lock().unwrap()[0].0);
        drop(digest);
    }
}
