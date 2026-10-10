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

//! The PROXY protocol on the connecting side, versions 1 and 2.
//!
//! A backend that reads the header (`listen ... proxy_protocol` of nginx,
//! `accept-proxy` of HAProxy) is told by it which client a connection is
//! made for, at the level of the connection: there is no HTTP header to
//! trust or to forge. The header is the first thing on a connection,
//! ahead of a TLS handshake where there is one, and it is said once: the
//! connection belongs to that client from then on.
//!
//! pingora has no setting for it. It lets a peer bring its own way of
//! connecting ([`Connect`], `PeerOptions::custom_l4`), and that is what
//! [`ProxyProtocolConnector`] is: it connects as pingora does and writes
//! the header before it hands the connection over.
//!
//! The listening side, which reads such a header, is in `pingap-proxy`.

use async_trait::async_trait;
use pingora::connectors::l4::Connect;
#[cfg(unix)]
use pingora::protocols::l4::ext::connect_uds;
use pingora::protocols::l4::ext::{set_recv_buf, set_tcp_fastopen_connect};
use pingora::protocols::l4::socket::SocketAddr as PeerAddr;
use pingora::protocols::l4::stream::Stream;
use pingora::{Error, ErrorType, OrErr, Result};
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpSocket;

/// The names a configuration has for the versions, in lower case.
pub const PROXY_PROTOCOL_VERSIONS: [&str; 2] = ["v1", "v2"];

const V2_SIGNATURE: &[u8] = b"\r\n\r\n\0\r\nQUIT\n";
/// Version 2 and the command: `LOCAL` for a connection of the proxy's
/// own, `PROXY` for one that is passed on.
const V2_LOCAL: u8 = 0x20;
const V2_PROXY: u8 = 0x21;
/// The address family and the transport: TCP over IPv4, TCP over IPv6.
const V2_TCP4: u8 = 0x11;
const V2_TCP6: u8 = 0x21;

/// The form of the header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyProtocolVersion {
    /// A line of text: `PROXY TCP4 192.0.2.1 198.51.100.1 56324 443\r\n`.
    V1,
    /// The binary form.
    V2,
}

impl ProxyProtocolVersion {
    /// `v1` or `v2`, in any case. `None` for anything else.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "v1" => Some(Self::V1),
            "v2" => Some(Self::V2),
            _ => None,
        }
    }
}

/// Both ends in one family, which is all a header has room for: IPv4 where
/// both are, the IPv4-mapped addresses of a dual-stack socket included,
/// and IPv6 otherwise, with the IPv4 end mapped into it.
fn same_family(
    source: SocketAddr,
    destination: SocketAddr,
) -> (SocketAddr, SocketAddr) {
    let canonical = |addr: SocketAddr| {
        SocketAddr::new(addr.ip().to_canonical(), addr.port())
    };
    let (source, destination) = (canonical(source), canonical(destination));
    if source.is_ipv4() == destination.is_ipv4() {
        return (source, destination);
    }
    let mapped = |addr: SocketAddr| match addr.ip() {
        IpAddr::V4(ip) => {
            SocketAddr::new(IpAddr::V6(ip.to_ipv6_mapped()), addr.port())
        },
        IpAddr::V6(_) => addr,
    };
    (mapped(source), mapped(destination))
}

/// An address as version 1 writes it. An IPv6 address is groups of
/// hexadecimal digits there and nothing else: `Display` ends an
/// IPv4-mapped one in dotted decimals.
fn v1_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some() => {
            let segments = v6.segments();
            format!("::ffff:{:x}:{:x}", segments[6], segments[7])
        },
        _ => ip.to_string(),
    }
}

/// The header a connection starts with.
///
/// `addresses` are where the client comes from and what of this proxy it
/// came to. `None` is for a connection that is made for nobody, a health
/// check: the backend is told to go by the connection itself (`LOCAL` in
/// version 2; version 1 has `UNKNOWN` for it).
///
/// A client that is passed on without an address to give would be
/// `PROXY` with no family in version 2, which is not written here: every
/// listener of this proxy is a TCP one, and its clients have addresses.
pub fn new_proxy_protocol_header(
    version: ProxyProtocolVersion,
    addresses: Option<(SocketAddr, SocketAddr)>,
) -> Vec<u8> {
    let addresses =
        addresses.map(|(source, destination)| same_family(source, destination));
    match (version, addresses) {
        (ProxyProtocolVersion::V1, None) => b"PROXY UNKNOWN\r\n".to_vec(),
        (ProxyProtocolVersion::V1, Some((source, destination))) => {
            let family = if source.is_ipv4() { "TCP4" } else { "TCP6" };
            format!(
                "PROXY {family} {} {} {} {}\r\n",
                v1_ip(source.ip()),
                v1_ip(destination.ip()),
                source.port(),
                destination.port()
            )
            .into_bytes()
        },
        (ProxyProtocolVersion::V2, None) => {
            let mut header = V2_SIGNATURE.to_vec();
            // LOCAL, no family, nothing that follows
            header.extend_from_slice(&[V2_LOCAL, 0, 0, 0]);
            header
        },
        (ProxyProtocolVersion::V2, Some((source, destination))) => {
            let mut addresses = Vec::with_capacity(36);
            let family = match (source.ip(), destination.ip()) {
                (IpAddr::V4(source), IpAddr::V4(destination)) => {
                    addresses.extend_from_slice(&source.octets());
                    addresses.extend_from_slice(&destination.octets());
                    V2_TCP4
                },
                (source, destination) => {
                    // of one family by now: neither is IPv4
                    for ip in [source, destination] {
                        if let IpAddr::V6(ip) = ip {
                            addresses.extend_from_slice(&ip.octets());
                        }
                    }
                    V2_TCP6
                },
            };
            addresses.extend_from_slice(&source.port().to_be_bytes());
            addresses.extend_from_slice(&destination.port().to_be_bytes());
            let mut header = V2_SIGNATURE.to_vec();
            header.push(V2_PROXY);
            header.push(family);
            header.extend_from_slice(&(addresses.len() as u16).to_be_bytes());
            header.extend_from_slice(&addresses);
            header
        },
    }
}

/// What pingora's own connector takes from the peer for the socket it
/// opens. A connector that stands in for it is given the address and
/// nothing else, so these come with it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ProxyProtocolConnectOptions {
    /// How long connecting and sending the header may take.
    pub connection_timeout: Option<Duration>,
    pub tcp_recv_buf: Option<usize>,
    pub tcp_fast_open: bool,
}

/// Connects to a backend and writes a PROXY protocol header as the first
/// bytes of the connection.
#[derive(Debug)]
pub struct ProxyProtocolConnector {
    header: Vec<u8>,
    options: ProxyProtocolConnectOptions,
}

/// The failure of a connection attempt as pingora has it, which is what
/// says whether the request may go to another backend and what the client
/// is answered.
fn new_connect_error(e: std::io::Error, addr: &PeerAddr) -> Box<Error> {
    let etype = match e.kind() {
        ErrorKind::ConnectionRefused => ErrorType::ConnectRefused,
        ErrorKind::TimedOut => ErrorType::ConnectTimedout,
        ErrorKind::AddrNotAvailable
        | ErrorKind::PermissionDenied
        | ErrorKind::AddrInUse => ErrorType::InternalError,
        ErrorKind::NetworkUnreachable | ErrorKind::HostUnreachable => {
            ErrorType::ConnectNoRoute
        },
        _ => ErrorType::ConnectError,
    };
    Error::because(etype, format!("Fail to connect to {addr}"), e)
}

impl ProxyProtocolConnector {
    pub fn new(header: Vec<u8>, options: ProxyProtocolConnectOptions) -> Self {
        Self { header, options }
    }

    /// The header every connection of this connector starts with.
    pub fn header(&self) -> &[u8] {
        &self.header
    }

    fn set_socket(&self, socket: &TcpSocket) -> Result<()> {
        #[cfg(unix)]
        let raw = socket.as_raw_fd();
        #[cfg(windows)]
        let raw = socket.as_raw_socket();
        if self.options.tcp_fast_open {
            set_tcp_fastopen_connect(raw)?;
        }
        if let Some(size) = self.options.tcp_recv_buf {
            set_recv_buf(raw, size)?;
        }
        Ok(())
    }

    async fn connect_and_send(&self, addr: &PeerAddr) -> Result<Stream> {
        // Nothing of a request is on its way yet: a header that cannot be
        // sent is a connection that was not made.
        let not_sent = |e: std::io::Error| {
            Error::because(
                ErrorType::ConnectError,
                format!("Fail to send the PROXY protocol header to {addr}"),
                e,
            )
        };
        match addr {
            PeerAddr::Inet(inet) => {
                let socket = if inet.is_ipv4() {
                    TcpSocket::new_v4()
                } else {
                    TcpSocket::new_v6()
                }
                .or_err(ErrorType::SocketError, "failed to create socket")
                .map_err(|e| {
                    Error::because(
                        ErrorType::InternalError,
                        format!("Fail to connect to {addr}"),
                        e,
                    )
                })?;
                // An option the kernel refuses is a connection that was
                // not made, as it is for pingora's own connector.
                self.set_socket(&socket).map_err(|e| {
                    e.more_context(format!("Fail to connect to {addr}"))
                })?;
                let mut stream = socket
                    .connect(*inet)
                    .await
                    .map_err(|e| new_connect_error(e, addr))?;
                stream.write_all(&self.header).await.map_err(not_sent)?;
                Ok(stream.into())
            },
            #[cfg(unix)]
            PeerAddr::Unix(unix) => {
                let Some(path) = unix.as_pathname() else {
                    return Error::e_explain(
                        ErrorType::InternalError,
                        format!("{addr} is not the path of a socket"),
                    );
                };
                let mut stream = connect_uds(path).await?;
                stream.write_all(&self.header).await.map_err(not_sent)?;
                Ok(stream.into())
            },
        }
    }
}

/// `connecting` to `addr`, given up after `limit` where there is one.
async fn within<T>(
    limit: Option<Duration>,
    addr: &PeerAddr,
    connecting: impl Future<Output = Result<T>>,
) -> Result<T> {
    let Some(limit) = limit else {
        return connecting.await;
    };
    tokio::time::timeout(limit, connecting).await.map_err(|e| {
        Error::because(
            ErrorType::ConnectTimedout,
            format!("timeout {limit:?} connecting to server {addr}"),
            e,
        )
    })?
}

#[async_trait]
impl Connect for ProxyProtocolConnector {
    async fn connect(&self, addr: &PeerAddr) -> Result<Stream> {
        within(
            self.options.connection_timeout,
            addr,
            self.connect_and_send(addr),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    fn addr(value: &str) -> SocketAddr {
        value.parse().unwrap()
    }

    #[test]
    fn test_version() {
        assert_eq!(
            Some(ProxyProtocolVersion::V1),
            ProxyProtocolVersion::parse("v1")
        );
        assert_eq!(
            Some(ProxyProtocolVersion::V2),
            ProxyProtocolVersion::parse(" V2 ")
        );
        for other in ["", "1", "2", "v3", "true", "on"] {
            assert_eq!(None, ProxyProtocolVersion::parse(other), "{other}");
        }
        for name in PROXY_PROTOCOL_VERSIONS {
            assert_eq!(true, ProxyProtocolVersion::parse(name).is_some());
        }
    }

    #[test]
    fn test_header_v1() {
        let v1 = |source: &str, destination: &str| {
            String::from_utf8(new_proxy_protocol_header(
                ProxyProtocolVersion::V1,
                Some((addr(source), addr(destination))),
            ))
            .unwrap()
        };
        assert_eq!(
            "PROXY TCP4 192.0.2.1 198.51.100.1 56324 443\r\n",
            v1("192.0.2.1:56324", "198.51.100.1:443")
        );
        assert_eq!(
            "PROXY TCP6 2001:db8::1 2001:db8::2 4000 443\r\n",
            v1("[2001:db8::1]:4000", "[2001:db8::2]:443")
        );
        // A dual-stack listener has IPv4 clients under mapped addresses:
        // they are IPv4 clients.
        assert_eq!(
            "PROXY TCP4 192.0.2.1 198.51.100.1 56324 443\r\n",
            v1("[::ffff:192.0.2.1]:56324", "[::ffff:198.51.100.1]:443")
        );
        // One end of each family: IPv6, and the mapped address in the
        // digits the specification has for one, not in dotted decimals.
        assert_eq!(
            "PROXY TCP6 ::ffff:c000:201 2001:db8::2 56324 443\r\n",
            v1("192.0.2.1:56324", "[2001:db8::2]:443")
        );
        assert_eq!(
            "PROXY TCP6 2001:db8::1 ::ffff:c633:6401 4000 443\r\n",
            v1("[2001:db8::1]:4000", "198.51.100.1:443")
        );
        // the longest there is fits the 107 bytes a reader allows for
        let longest = v1(
            "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe]:65535",
            "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffd]:65535",
        );
        assert_eq!(true, longest.len() <= 107, "{}", longest.len());

        assert_eq!(
            b"PROXY UNKNOWN\r\n".to_vec(),
            new_proxy_protocol_header(ProxyProtocolVersion::V1, None)
        );
    }

    #[test]
    fn test_header_v2() {
        let v2 = |source: &str, destination: &str| {
            new_proxy_protocol_header(
                ProxyProtocolVersion::V2,
                Some((addr(source), addr(destination))),
            )
        };
        let mut tcp4 = V2_SIGNATURE.to_vec();
        tcp4.extend_from_slice(&[0x21, 0x11, 0, 12]);
        tcp4.extend_from_slice(&[192, 0, 2, 1, 198, 51, 100, 1]);
        tcp4.extend_from_slice(&56324u16.to_be_bytes());
        tcp4.extend_from_slice(&443u16.to_be_bytes());
        assert_eq!(28, tcp4.len());
        assert_eq!(tcp4, v2("192.0.2.1:56324", "198.51.100.1:443"));
        assert_eq!(
            tcp4,
            v2("[::ffff:192.0.2.1]:56324", "[::ffff:198.51.100.1]:443")
        );

        let mut tcp6 = V2_SIGNATURE.to_vec();
        tcp6.extend_from_slice(&[0x21, 0x21, 0, 36]);
        tcp6.extend_from_slice(
            &"2001:db8::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        tcp6.extend_from_slice(
            &"::ffff:198.51.100.1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        tcp6.extend_from_slice(&4000u16.to_be_bytes());
        tcp6.extend_from_slice(&443u16.to_be_bytes());
        assert_eq!(52, tcp6.len());
        // one end of each family
        assert_eq!(tcp6, v2("[2001:db8::1]:4000", "198.51.100.1:443"));

        let mut local = V2_SIGNATURE.to_vec();
        local.extend_from_slice(&[0x20, 0, 0, 0]);
        assert_eq!(
            local,
            new_proxy_protocol_header(ProxyProtocolVersion::V2, None)
        );
    }

    /// The header is on the connection before anything the caller writes,
    /// and all of it.
    #[tokio::test]
    async fn test_connector_sends_the_header_first() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = listener.local_addr().unwrap();
        for (version, tcp_fast_open) in [
            (ProxyProtocolVersion::V1, false),
            (ProxyProtocolVersion::V2, false),
            (ProxyProtocolVersion::V2, true),
        ] {
            let header = new_proxy_protocol_header(
                version,
                Some((addr("192.0.2.1:56324"), addr("198.51.100.1:443"))),
            );
            let connector = ProxyProtocolConnector::new(
                header.clone(),
                ProxyProtocolConnectOptions {
                    connection_timeout: Some(Duration::from_secs(5)),
                    tcp_recv_buf: Some(64 * 1024),
                    tcp_fast_open,
                },
            );
            assert_eq!(header, connector.header());
            let mut stream =
                match connector.connect(&PeerAddr::Inet(local)).await {
                    Ok(stream) => stream,
                    // A kernel that has fast open switched off for its
                    // clients refuses the option, to pingora's own
                    // connector as well: there is nothing to see here.
                    Err(e)
                        if tcp_fast_open
                            && e.to_string()
                                .contains("TCP_FASTOPEN_CONNECT") =>
                    {
                        continue;
                    },
                    Err(e) => panic!("{e}"),
                };
            stream.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
            stream.flush().await.unwrap();
            drop(stream);

            let (mut accepted, _) = listener.accept().await.unwrap();
            let mut received = Vec::new();
            accepted.read_to_end(&mut received).await.unwrap();
            let mut expected = header;
            expected.extend_from_slice(b"GET / HTTP/1.1\r\n\r\n");
            assert_eq!(expected, received);
        }
    }

    /// A backend that is not there is one that refused, as it is for
    /// pingora's own connector: the type of the error is what a retry and
    /// the answer to the client go by.
    #[tokio::test]
    async fn test_connector_errors() {
        // an address nothing listens on: bound, and given up again
        let unused = {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap()
        };
        let connector = ProxyProtocolConnector::new(
            new_proxy_protocol_header(ProxyProtocolVersion::V2, None),
            ProxyProtocolConnectOptions::default(),
        );
        let error = connector
            .connect(&PeerAddr::Inet(unused))
            .await
            .err()
            .unwrap();
        assert_eq!(ErrorType::ConnectRefused, error.etype);
        assert_eq!(
            true,
            error.to_string().contains(&unused.to_string()),
            "{error}"
        );

        // A backend that does not answer in the time it is given: one
        // that timed out, and without a limit one that is waited for.
        let silent = PeerAddr::Inet(unused);
        let error = within(
            Some(Duration::from_millis(20)),
            &silent,
            std::future::pending::<Result<()>>(),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(ErrorType::ConnectTimedout, error.etype);
        assert_eq!(true, error.to_string().contains("timeout 20ms"), "{error}");
        assert_eq!(7, within(None, &silent, async { Ok(7) }).await.unwrap());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_connector_unix_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backend.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let header = new_proxy_protocol_header(
            ProxyProtocolVersion::V1,
            Some((addr("192.0.2.1:56324"), addr("198.51.100.1:443"))),
        );
        let connector = ProxyProtocolConnector::new(
            header.clone(),
            ProxyProtocolConnectOptions::default(),
        );
        let addr: PeerAddr =
            format!("unix:{}", path.display()).parse().unwrap();
        let stream = connector.connect(&addr).await.unwrap();
        drop(stream);
        let (mut accepted, _) = listener.accept().await.unwrap();
        let mut received = Vec::new();
        accepted.read_to_end(&mut received).await.unwrap();
        assert_eq!(header, received);
    }
}
