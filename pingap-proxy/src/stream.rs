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

//! Native Layer 4 TCP & TLS SNI passthrough proxy engine (`[streams.*]`).
//!
//! Runs completely independently of Pingora's HTTP `ProxyHttp` pipeline: each
//! stream listener is its own `pingora::services::listening::Service<StreamApp>`
//! registered alongside HTTP servers on startup. When `sni_routes` is configured,
//! [`StreamApp`] peeks the TLS ClientHello before dialing an upstream, extracts
//! the SNI hostname without terminating TLS, selects the target upstream, and
//! replays all peeked ClientHello bytes verbatim after connecting.

use super::proxy_protocol;
use super::{Error, LOG_TARGET};

type Result<T, E = Error> = std::result::Result<T, E>;
use ahash::AHashMap;
use async_trait::async_trait;
use pingap_config::StreamConf;
use pingap_core::ja4::{
    ClientHelloStatus, MAX_CLIENT_HELLO_SIZE, extract_sni, read_client_hello,
};
use pingap_core::{
    UpstreamInstance, is_trusted_proxy, new_proxy_protocol_header,
    new_tcp_keepalive, now_ms, unix_socket_path,
};
use pingap_performance::{stream_connection_close, stream_connection_open};
use pingap_upstream::{TcpPeer, Upstream, UpstreamProvider};
use pingap_util::IpRules;
use pingora::apps::ServerApp;
#[cfg(unix)]
use pingora::listeners::ListenerConfig;
use pingora::listeners::TcpSocketOptions;
use pingora::protocols::l4::ext::TcpKeepalive;
use pingora::protocols::l4::socket::SocketAddr as BackendAddr;
use pingora::protocols::l4::stream::Stream as L4Stream;
use pingora::protocols::{GetSocketDigest, Stream};
use pingora::server::ShutdownWatch;
use pingora::services::ServiceWithDependents;
use pingora::services::listening::Service;
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::time::{Instant as TokioInstant, timeout, timeout_at};
use tracing::{debug, info, warn};

static STREAM_ACCESS_TARGET: &str = "pingap::stream_access";
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_SNI_READ_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONNECT_ATTEMPTS: usize = 3;
const MAX_PEEK_BYTES: usize = MAX_CLIENT_HELLO_SIZE + 2048;
const RELAY_BUF_SIZE: usize = 16 * 1024;

type WildcardSniRoutes = Vec<(String, String)>;

/// Hot-reloadable runtime configuration for a Layer 4 stream listener.
#[derive(Debug, Clone)]
pub struct StreamRuntime {
    pub name: String,
    pub default_upstream: Option<String>,
    sni_exact: AHashMap<String, String>,
    /// `(suffix_without_wildcard_dot, upstream)`, sorted descending by suffix
    /// length so the most specific wildcard (`*.api.example.com`) wins over
    /// a broader one (`*.example.com`).
    sni_wildcards: WildcardSniRoutes,
    pub proxy_protocol: bool,
    pub connect_timeout: Option<Duration>,
    pub idle_timeout: Option<Duration>,
    pub sni_read_timeout: Duration,
    pub max_connections: Option<usize>,
    allow_ips: Option<IpRules>,
    deny_ips: Option<IpRules>,
}

fn normalize_host_key(raw: &str) -> String {
    raw.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn build_sni_tables(
    routes: Option<&BTreeMap<String, String>>,
) -> (AHashMap<String, String>, WildcardSniRoutes) {
    let mut sni_exact = AHashMap::new();
    let mut sni_wildcards = Vec::new();
    for (pattern, upstream) in routes.into_iter().flatten() {
        let normalized = normalize_host_key(pattern);
        if let Some(suffix) = normalized.strip_prefix("*.") {
            if !suffix.is_empty() {
                sni_wildcards.push((suffix.to_string(), upstream.clone()));
            }
        } else if !normalized.is_empty() {
            sni_exact.insert(normalized, upstream.clone());
        }
    }
    // Longest suffix first, then lexicographical tie-breaker.
    sni_wildcards
        .sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| a.0.cmp(&b.0)));
    (sni_exact, sni_wildcards)
}

fn parse_ip_rules(
    stream_name: &str,
    label: &str,
    list: Option<&Vec<String>>,
) -> Result<Option<IpRules>> {
    let Some(list) = list.filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    IpRules::try_new(list).map(Some).map_err(|e| Error::Common {
        category: "stream".to_string(),
        message: format!("stream({stream_name}) {label}: {e}"),
    })
}

impl StreamRuntime {
    /// Builds a runtime stream policy from a [`StreamConf`].
    pub fn try_from_conf(name: &str, conf: &StreamConf) -> Result<Self> {
        let (sni_exact, sni_wildcards) =
            build_sni_tables(conf.sni_routes.as_ref());
        Ok(Self {
            name: name.to_string(),
            default_upstream: conf
                .upstream
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(str::to_string),
            sni_exact,
            sni_wildcards,
            proxy_protocol: conf.proxy_protocol.unwrap_or(false),
            connect_timeout: conf.connect_timeout,
            idle_timeout: conf.idle_timeout,
            sni_read_timeout: conf
                .sni_read_timeout
                .unwrap_or(DEFAULT_SNI_READ_TIMEOUT),
            max_connections: conf.max_connections,
            allow_ips: parse_ip_rules(
                name,
                "allow_ips",
                conf.allow_ips.as_ref(),
            )?,
            deny_ips: parse_ip_rules(name, "deny_ips", conf.deny_ips.as_ref())?,
        })
    }

    /// Whether TLS SNI inspection is required for incoming connections.
    #[inline]
    pub fn has_sni_routes(&self) -> bool {
        !self.sni_exact.is_empty() || !self.sni_wildcards.is_empty()
    }

    /// Selects the upstream name for `sni`: exact match > longest wildcard
    /// subdomain (`*.domain`) > `default_upstream`.
    pub fn resolve_upstream(&self, sni: Option<&str>) -> Option<&str> {
        if let Some(raw) = sni {
            let host = normalize_host_key(raw);
            if let Some(upstream) = self.sni_exact.get(&host) {
                return Some(upstream.as_str());
            }
            for (suffix, upstream) in &self.sni_wildcards {
                if matches_wildcard_suffix(&host, suffix) {
                    return Some(upstream.as_str());
                }
            }
        }
        self.default_upstream.as_deref()
    }

    /// Checks client access against `deny_ips` (first) and `allow_ips`.
    pub fn is_ip_allowed(&self, ip: IpAddr) -> bool {
        if self
            .deny_ips
            .as_ref()
            .is_some_and(|rules| rules.is_match_addr(&ip))
        {
            return false;
        }
        self.allow_ips
            .as_ref()
            .is_none_or(|rules| rules.is_match_addr(&ip))
    }
}

#[inline]
fn matches_wildcard_suffix(host: &str, suffix: &str) -> bool {
    let Some(dot) = host.len().checked_sub(suffix.len() + 1) else {
        return false;
    };
    let bytes = host.as_bytes();
    dot > 0
        && bytes[dot] == b'.'
        && bytes[dot + 1..].eq_ignore_ascii_case(suffix.as_bytes())
}

/// Lookup provider for hot-reloaded [`StreamRuntime`] definitions.
pub trait StreamProvider: Send + Sync {
    /// Returns the runtime configuration for `name`, if configured.
    fn get(&self, name: &str) -> Option<Arc<StreamRuntime>>;
}

/// Decrements `counter` automatically on drop so every early exit releases its
/// slot cleanly.
struct ActiveConnectionGuard {
    counter: Arc<AtomicUsize>,
}

impl Drop for ActiveConnectionGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

fn try_acquire_connection(
    counter: &Arc<AtomicUsize>,
    max: Option<usize>,
) -> Option<ActiveConnectionGuard> {
    loop {
        let current = counter.load(Ordering::Acquire);
        if max.is_some_and(|limit| current >= limit) {
            return None;
        }
        if counter
            .compare_exchange(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            return Some(ActiveConnectionGuard {
                counter: counter.clone(),
            });
        }
    }
}

/// Ensures `upstream.completed()` runs once when a dial attempt incremented
/// `Upstream::processing`.
struct UpstreamProcessingGuard {
    upstream: Option<Arc<Upstream>>,
}

impl UpstreamProcessingGuard {
    fn arm(&mut self, upstream: Arc<Upstream>) {
        if self.upstream.is_none() {
            self.upstream = Some(upstream);
        }
    }
}

impl Drop for UpstreamProcessingGuard {
    fn drop(&mut self) {
        if let Some(upstream) = self.upstream.take() {
            upstream.completed();
        }
    }
}

#[derive(Default)]
struct StreamPeek {
    sni: Option<String>,
    buf: Vec<u8>,
    client_eof: bool,
    timed_out_empty: bool,
}

/// Peeks a ClientHello without consuming irreversible state from `reader`,
/// returning all raw bytes read so callers can forward them verbatim to the
/// chosen upstream.
async fn peek_client_hello<R: AsyncRead + Unpin>(
    reader: &mut R,
    read_timeout: Duration,
) -> StreamPeek {
    let deadline = TokioInstant::now() + read_timeout;
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    loop {
        match read_client_hello(&buf) {
            ClientHelloStatus::Complete(body) => {
                return StreamPeek {
                    sni: extract_sni(&body),
                    buf,
                    ..Default::default()
                };
            },
            ClientHelloStatus::Invalid => {
                return StreamPeek {
                    buf,
                    ..Default::default()
                };
            },
            ClientHelloStatus::Incomplete if buf.len() >= MAX_PEEK_BYTES => {
                return StreamPeek {
                    buf,
                    ..Default::default()
                };
            },
            ClientHelloStatus::Incomplete => {},
        }
        match timeout_at(deadline, reader.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => buf.extend_from_slice(&chunk[..n]),
            Ok(_) => {
                return StreamPeek {
                    client_eof: true,
                    buf,
                    ..Default::default()
                };
            },
            Err(_) => {
                return StreamPeek {
                    timed_out_empty: buf.is_empty(),
                    buf,
                    ..Default::default()
                };
            },
        }
    }
}

enum ConnectedUpstream {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(UnixStream),
}

impl ConnectedUpstream {
    async fn connect(
        addr: &BackendAddr,
        dur: Duration,
    ) -> std::io::Result<Self> {
        match addr {
            BackendAddr::Inet(socket_addr) => {
                let tcp = timeout(dur, TcpStream::connect(socket_addr))
                    .await
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "upstream tcp connect timeout",
                        )
                    })??;
                let _ = tcp.set_nodelay(true);
                Ok(Self::Tcp(tcp))
            },
            #[cfg(unix)]
            BackendAddr::Unix(unix_addr) => {
                let path = unix_addr.as_pathname().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "unnamed unix socket",
                    )
                })?;
                let unix = timeout(dur, UnixStream::connect(path))
                    .await
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "upstream unix connect timeout",
                        )
                    })??;
                Ok(Self::Unix(unix))
            },
        }
    }

    async fn write_all_timed(
        &mut self,
        data: &[u8],
        dur: Duration,
    ) -> std::io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let fut = async {
            match self {
                Self::Tcp(s) => s.write_all(data).await,
                #[cfg(unix)]
                Self::Unix(s) => s.write_all(data).await,
            }
        };
        timeout(dur, fut).await.map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "upstream initial write timeout",
            )
        })?
    }
}

fn stream_addrs(stream: &L4Stream) -> (Option<SocketAddr>, Option<SocketAddr>) {
    let Some(digest) = stream.get_socket_digest() else {
        return (None, None);
    };
    let peer = digest.peer_addr().and_then(|addr| addr.as_inet()).copied();
    let local = digest.local_addr().and_then(|addr| addr.as_inet()).copied();
    (peer, local)
}

enum DialStep {
    Connected(ConnectedUpstream),
    RetryBackend,
    Abort(&'static str),
}

async fn connect_and_prepare_peer(
    upstream: &Arc<Upstream>,
    runtime: &StreamRuntime,
    peer: &TcpPeer,
    client_addr: Option<SocketAddr>,
    local_addr: Option<SocketAddr>,
    peeked_bytes: &[u8],
) -> DialStep {
    let dur = runtime
        .connect_timeout
        .or(peer.connection_timeout)
        .unwrap_or(DEFAULT_CONNECT_TIMEOUT);

    let mut conn = match ConnectedUpstream::connect(&peer.addr, dur).await {
        Ok(conn) => {
            upstream.record_tcp_connect_result(&peer.addr_str, true);
            conn
        },
        Err(err) => {
            debug!(
                target: LOG_TARGET,
                stream = runtime.name,
                backend = %peer.addr_str,
                error = %err,
                "l4 upstream connect failed"
            );
            upstream.record_tcp_connect_result(&peer.addr_str, false);
            return DialStep::RetryBackend;
        },
    };

    if let Some(ver) = peer.send_proxy_protocol {
        let header =
            new_proxy_protocol_header(ver, client_addr.zip(local_addr));
        if let Err(err) = conn.write_all_timed(header.as_slice(), dur).await {
            debug!(
                target: LOG_TARGET,
                stream = runtime.name,
                backend = %peer.addr_str,
                error = %err,
                "send outbound proxy protocol fail"
            );
            upstream.record_tcp_connect_result(&peer.addr_str, false);
            return DialStep::RetryBackend;
        }
    }

    if let Err(err) = conn.write_all_timed(peeked_bytes, dur).await {
        debug!(
            target: LOG_TARGET,
            stream = runtime.name,
            backend = %peer.addr_str,
            error = %err,
            "replay peeked client bytes fail"
        );
        return DialStep::Abort("upstream_write_failed");
    }
    DialStep::Connected(conn)
}

struct DialSuccess {
    stream: ConnectedUpstream,
    peer: TcpPeer,
    _processing: UpstreamProcessingGuard,
}

async fn dial_upstream(
    upstream: &Arc<Upstream>,
    runtime: &StreamRuntime,
    client_addr: Option<SocketAddr>,
    local_addr: Option<SocketAddr>,
    peeked_bytes: &[u8],
    shutdown: &ShutdownWatch,
) -> std::result::Result<DialSuccess, &'static str> {
    let client_ip = client_addr.map(|addr| addr.ip().to_string());
    let attempts = upstream.backend_count().clamp(1, MAX_CONNECT_ATTEMPTS);
    let mut failed = Vec::with_capacity(attempts);
    let mut processing = UpstreamProcessingGuard { upstream: None };

    for attempt in 0..attempts {
        if *shutdown.borrow() {
            return Err("shutdown");
        }
        let bump = processing.upstream.is_none() && attempt == 0;
        let Some(peer) =
            upstream.select_tcp_peer(client_ip.as_deref(), &failed, bump)
        else {
            return Err(if failed.is_empty() {
                "no_healthy_backend"
            } else {
                "connect_failed"
            });
        };
        if bump {
            processing.arm(upstream.clone());
        }
        match connect_and_prepare_peer(
            upstream,
            runtime,
            &peer,
            client_addr,
            local_addr,
            peeked_bytes,
        )
        .await
        {
            DialStep::Connected(conn) => {
                return Ok(DialSuccess {
                    stream: conn,
                    peer,
                    _processing: processing,
                });
            },
            DialStep::RetryBackend => failed.push(peer.addr_str.to_string()),
            DialStep::Abort(reason) => return Err(reason),
        }
    }
    Err("connect_failed")
}

async fn read_with_shared_idle<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
    idle_limit_ms: Option<u64>,
    last_active_ms: &AtomicU64,
) -> std::io::Result<usize> {
    let Some(limit_ms) = idle_limit_ms else {
        return reader.read(buf).await;
    };
    loop {
        let elapsed =
            now_ms().saturating_sub(last_active_ms.load(Ordering::Relaxed));
        if elapsed >= limit_ms {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "stream idle timeout",
            ));
        }
        let deadline =
            TokioInstant::now() + Duration::from_millis(limit_ms - elapsed);
        tokio::select! {
            res = reader.read(buf) => return res,
            _ = tokio::time::sleep_until(deadline) => {},
        }
    }
}

async fn copy_one_way<R, W>(
    reader: &mut R,
    writer: &mut W,
    idle_limit_ms: Option<u64>,
    last_active_ms: &AtomicU64,
    byte_counter: &AtomicU64,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; RELAY_BUF_SIZE];
    loop {
        let n = read_with_shared_idle(
            reader,
            &mut buf,
            idle_limit_ms,
            last_active_ms,
        )
        .await?;
        if n == 0 {
            let _ = writer.shutdown().await;
            return Ok(());
        }
        last_active_ms.store(now_ms(), Ordering::Relaxed);
        writer.write_all(&buf[..n]).await?;
        byte_counter.fetch_add(n as u64, Ordering::Relaxed);
    }
}

fn classify_relay_result(res: std::io::Result<()>) -> &'static str {
    match res {
        Ok(()) => "ok",
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => "idle_timeout",
        Err(_) => "relay_error",
    }
}

async fn relay_split_streams<UR, UW>(
    down: L4Stream,
    mut up_r: UR,
    mut up_w: UW,
    client_eof: bool,
    idle_timeout: Option<Duration>,
    tx_counter: &AtomicU64,
    rx_counter: &AtomicU64,
) -> &'static str
where
    UR: AsyncRead + Unpin,
    UW: AsyncWrite + Unpin,
{
    let (mut down_r, mut down_w) = tokio::io::split(down);
    let idle_limit_ms = idle_timeout
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX).max(1));
    let last_active_ms = AtomicU64::new(now_ms());

    if client_eof {
        let _ = up_w.shutdown().await;
        return classify_relay_result(
            copy_one_way(
                &mut up_r,
                &mut down_w,
                idle_limit_ms,
                &last_active_ms,
                rx_counter,
            )
            .await,
        );
    }

    let c2u = copy_one_way(
        &mut down_r,
        &mut up_w,
        idle_limit_ms,
        &last_active_ms,
        tx_counter,
    );
    let u2c = copy_one_way(
        &mut up_r,
        &mut down_w,
        idle_limit_ms,
        &last_active_ms,
        rx_counter,
    );
    classify_relay_result(tokio::try_join!(c2u, u2c).map(|_| ()))
}

struct StreamSessionLog<'a> {
    stream: &'a str,
    started: Instant,
    client_addr: Option<SocketAddr>,
    sni: Option<&'a str>,
    upstream: &'a str,
    backend: &'a str,
    tx_bytes: u64,
    rx_bytes: u64,
    result: &'a str,
}

fn finish_stream_session(entry: StreamSessionLog<'_>) {
    stream_connection_close(
        entry.stream,
        entry.upstream,
        entry.result,
        entry.tx_bytes,
        entry.rx_bytes,
    );
    info!(
        target: STREAM_ACCESS_TARGET,
        stream = entry.stream,
        client_addr = entry
            .client_addr
            .map_or_else(|| "-".to_string(), |a| a.to_string()),
        sni = entry.sni.unwrap_or("-"),
        upstream = if entry.upstream.is_empty() {
            "-"
        } else {
            entry.upstream
        },
        backend = if entry.backend.is_empty() {
            "-"
        } else {
            entry.backend
        },
        bytes_tx = entry.tx_bytes,
        bytes_rx = entry.rx_bytes,
        duration_ms = entry.started.elapsed().as_millis() as u64,
        result = entry.result,
        "stream connection closed"
    );
}

/// Pingora [`ServerApp`] serving a Layer 4 TCP / TLS SNI passthrough listener.
pub struct StreamApp {
    name: String,
    stream_provider: Arc<dyn StreamProvider>,
    upstream_provider: Arc<dyn UpstreamProvider>,
    active_connections: Arc<AtomicUsize>,
    is_trusted_proxy: fn(IpAddr) -> bool,
}

impl StreamApp {
    /// Builds a new Layer 4 stream application named `name`.
    pub fn new(
        name: String,
        stream_provider: Arc<dyn StreamProvider>,
        upstream_provider: Arc<dyn UpstreamProvider>,
    ) -> Self {
        Self {
            name,
            stream_provider,
            upstream_provider,
            active_connections: Arc::new(AtomicUsize::new(0)),
            is_trusted_proxy,
        }
    }

    async fn read_inbound_preamble(
        &self,
        down: &mut L4Stream,
        runtime: &StreamRuntime,
        client_addr: &mut Option<SocketAddr>,
    ) -> std::result::Result<StreamPeek, &'static str> {
        let _ = down.set_nodelay();
        if runtime.proxy_protocol {
            if let Err(err) = proxy_protocol::accept(
                down,
                proxy_protocol::TIMEOUTS,
                self.is_trusted_proxy,
            )
            .await
            {
                debug!(
                    target: LOG_TARGET,
                    stream = self.name,
                    error = %err,
                    "inbound proxy protocol header rejected"
                );
                return Err("proxy_protocol_error");
            }
            (*client_addr, _) = stream_addrs(down);
        }
        if let Some(peer) = *client_addr
            && !runtime.is_ip_allowed(peer.ip())
        {
            return Err("ip_denied");
        }
        if !runtime.has_sni_routes() {
            return Ok(StreamPeek::default());
        }
        let peek = peek_client_hello(down, runtime.sni_read_timeout).await;
        if peek.client_eof && peek.buf.is_empty() {
            return Err("client_eof");
        }
        if peek.timed_out_empty && runtime.default_upstream.is_none() {
            return Err("sni_timeout");
        }
        Ok(peek)
    }

    async fn relay_stream(
        &self,
        mut down: L4Stream,
        runtime: &StreamRuntime,
        shutdown: &ShutdownWatch,
        client_addr: &mut Option<SocketAddr>,
        local_addr: Option<SocketAddr>,
        state: &mut StreamRunState,
    ) -> &'static str {
        let peek = match self
            .read_inbound_preamble(&mut down, runtime, client_addr)
            .await
        {
            Ok(peek) => peek,
            Err(reason) => return reason,
        };
        state.sni.clone_from(&peek.sni);

        let Some(target) = runtime.resolve_upstream(state.sni.as_deref())
        else {
            return "no_route";
        };
        target.clone_into(&mut state.upstream);

        let Some(upstream) = self.upstream_provider.get(target) else {
            return "upstream_not_found";
        };
        let dial = match dial_upstream(
            &upstream,
            runtime,
            *client_addr,
            local_addr,
            &peek.buf,
            shutdown,
        )
        .await
        {
            Ok(dial) => dial,
            Err(reason) => return reason,
        };
        state
            .tx_bytes
            .fetch_add(peek.buf.len() as u64, Ordering::Relaxed);
        state.backend.push_str(&dial.peer.addr_str);

        let DialSuccess {
            stream: conn,
            peer: _peer,
            _processing,
        } = dial;
        match conn {
            ConnectedUpstream::Tcp(up) => {
                let (up_r, up_w) = up.into_split();
                relay_split_streams(
                    down,
                    up_r,
                    up_w,
                    peek.client_eof,
                    runtime.idle_timeout,
                    &state.tx_bytes,
                    &state.rx_bytes,
                )
                .await
            },
            #[cfg(unix)]
            ConnectedUpstream::Unix(up) => {
                let (up_r, up_w) = up.into_split();
                relay_split_streams(
                    down,
                    up_r,
                    up_w,
                    peek.client_eof,
                    runtime.idle_timeout,
                    &state.tx_bytes,
                    &state.rx_bytes,
                )
                .await
            },
        }
    }

    async fn handle_connection(
        &self,
        stream: L4Stream,
        shutdown: &ShutdownWatch,
    ) {
        let started = Instant::now();
        let Some(runtime) = self.stream_provider.get(&self.name) else {
            warn!(
                target: LOG_TARGET,
                stream = self.name,
                "stream runtime config missing"
            );
            return;
        };
        let (mut client_addr, local_addr) = stream_addrs(&stream);
        let Some(_active_guard) = try_acquire_connection(
            &self.active_connections,
            runtime.max_connections,
        ) else {
            finish_stream_session(StreamSessionLog {
                stream: &self.name,
                started,
                client_addr,
                sni: None,
                upstream: "",
                backend: "",
                tx_bytes: 0,
                rx_bytes: 0,
                result: "max_connections",
            });
            return;
        };
        stream_connection_open(&self.name);

        let mut state = StreamRunState::default();
        let result = self
            .relay_stream(
                stream,
                &runtime,
                shutdown,
                &mut client_addr,
                local_addr,
                &mut state,
            )
            .await;

        finish_stream_session(StreamSessionLog {
            stream: &self.name,
            started,
            client_addr,
            sni: state.sni.as_deref(),
            upstream: &state.upstream,
            backend: &state.backend,
            tx_bytes: state.tx_bytes.load(Ordering::Relaxed),
            rx_bytes: state.rx_bytes.load(Ordering::Relaxed),
            result,
        });
    }
}

#[derive(Default)]
struct StreamRunState {
    sni: Option<String>,
    upstream: String,
    backend: String,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
}

#[async_trait]
impl ServerApp for StreamApp {
    async fn process_new(
        self: &Arc<Self>,
        stream: Stream,
        shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        let Ok(l4) = stream.into_any().downcast::<L4Stream>() else {
            return None;
        };
        self.handle_connection(*l4, shutdown).await;
        None
    }
}

fn stream_tcp_keepalive(conf: &StreamConf) -> Option<TcpKeepalive> {
    new_tcp_keepalive(
        conf.tcp_idle,
        conf.tcp_interval,
        conf.tcp_probe_count,
        conf.tcp_user_timeout,
    )
}

fn stream_socket_options(conf: &StreamConf) -> Option<TcpSocketOptions> {
    let tcp_keepalive = stream_tcp_keepalive(conf);
    if conf.tcp_fastopen.is_none()
        && tcp_keepalive.is_none()
        && conf.reuse_port.is_none()
    {
        return None;
    }
    let mut opts = TcpSocketOptions::default();
    opts.tcp_fastopen = conf.tcp_fastopen;
    opts.tcp_keepalive = tcp_keepalive;
    opts.so_reuseport = conf.reuse_port;
    Some(opts)
}

#[cfg(unix)]
fn add_stream_unix_endpoint(
    service: &mut Service<StreamApp>,
    path: &str,
) -> Result<()> {
    service.add_listener(ListenerConfig::uds(path));
    Ok(())
}

#[cfg(not(unix))]
fn add_stream_unix_endpoint(
    _service: &mut Service<StreamApp>,
    _path: &str,
) -> Result<()> {
    Err(Error::Common {
        category: "listen".to_string(),
        message: "unix sockets are not available on this build".to_string(),
    })
}

fn add_stream_endpoint(
    service: &mut Service<StreamApp>,
    addr: &str,
    opts: Option<&TcpSocketOptions>,
) -> Result<()> {
    match unix_socket_path(addr) {
        Ok(Some(path)) => add_stream_unix_endpoint(service, path),
        Ok(None) => {
            if let Some(opt) = opts {
                service.add_tcp_with_settings(addr, opt.clone());
            } else {
                service.add_tcp(addr);
            }
            Ok(())
        },
        Err(message) => Err(Error::Common {
            category: "listen".to_string(),
            message,
        }),
    }
}

/// Builder that turns a `[streams.<name>]` entry into a Pingora listening
/// service isolated from HTTP `ProxyHttp` servers.
pub struct StreamServer {
    name: String,
    conf: StreamConf,
    app: StreamApp,
}

impl StreamServer {
    /// Creates a new stream server from `conf` and validates its runtime
    /// parameters and listen addresses.
    pub fn new(
        name: String,
        conf: StreamConf,
        stream_provider: Arc<dyn StreamProvider>,
        upstream_provider: Arc<dyn UpstreamProvider>,
    ) -> Result<Self> {
        let _ = StreamRuntime::try_from_conf(&name, &conf)?;
        let app =
            StreamApp::new(name.clone(), stream_provider, upstream_provider);
        Ok(Self { name, conf, app })
    }

    /// Validates listener configuration without binding or starting sockets.
    pub fn check(self) -> Result<()> {
        self.build_internal(false).map(|_| ())
    }

    /// Builds the Pingora listening [`Service`] ready to register on the server.
    pub fn build_service(self) -> Result<Box<dyn ServiceWithDependents>> {
        self.build_internal(true)
            .map(|service| Box::new(service) as Box<dyn ServiceWithDependents>)
    }

    fn build_internal(self, announce: bool) -> Result<Service<StreamApp>> {
        let addrs: Vec<&str> = self
            .conf
            .addr
            .split(',')
            .map(str::trim)
            .filter(|a| !a.is_empty())
            .collect();
        if addrs.is_empty() {
            return Err(Error::Common {
                category: "stream".to_string(),
                message: format!("stream({}) addr is empty", self.name),
            });
        }
        let threads = self
            .conf
            .threads
            .map(|value| if value == 0 { num_cpus::get() } else { value });
        let socket_opts = stream_socket_options(&self.conf);
        if announce {
            info!(
                target: LOG_TARGET,
                name = self.name,
                addr = self.conf.addr,
                threads,
                has_sni_routes = self
                    .conf
                    .sni_routes
                    .as_ref()
                    .is_some_and(|routes| !routes.is_empty()),
                "stream server is listening"
            );
        }
        let mut service =
            Service::new(format!("Pingap Stream {}", self.name), self.app);
        service.threads = threads;
        for addr in addrs {
            add_stream_endpoint(&mut service, addr, socket_opts.as_ref())?;
        }
        Ok(service)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::RwLock;
    use pingap_config::UpstreamConf;
    use pingap_core::ja4::testing::{
        client_hello_body, client_hello_records, sni as sni_ext,
    };
    use pingora::protocols::SocketDigest;
    use pretty_assertions::assert_eq;
    use tokio::net::TcpListener;

    struct StaticStreams(RwLock<AHashMap<String, Arc<StreamRuntime>>>);
    impl StaticStreams {
        fn new(name: &str, conf: &StreamConf) -> Arc<Self> {
            let mut map = AHashMap::new();
            map.insert(
                name.to_string(),
                Arc::new(StreamRuntime::try_from_conf(name, conf).unwrap()),
            );
            Arc::new(Self(RwLock::new(map)))
        }
        fn swap(&self, name: &str, conf: &StreamConf) {
            let mut map = AHashMap::new();
            map.insert(
                name.to_string(),
                Arc::new(StreamRuntime::try_from_conf(name, conf).unwrap()),
            );
            *self.0.write() = map;
        }
    }
    impl StreamProvider for StaticStreams {
        fn get(&self, name: &str) -> Option<Arc<StreamRuntime>> {
            self.0.read().get(name).cloned()
        }
    }

    struct StaticUpstreams(AHashMap<String, Arc<Upstream>>);
    impl UpstreamProvider for StaticUpstreams {
        fn get(&self, name: &str) -> Option<Arc<Upstream>> {
            self.0.get(name).cloned()
        }
        fn list(&self) -> Vec<(String, Arc<Upstream>)> {
            self.0.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
        }
    }

    fn make_upstream(
        name: &str,
        addrs: &[String],
        send_pp: Option<&str>,
    ) -> Arc<Upstream> {
        Arc::new(
            Upstream::new(
                name,
                &UpstreamConf {
                    addrs: addrs.to_vec(),
                    send_proxy_protocol: send_pp.map(str::to_string),
                    ..Default::default()
                },
                None,
            )
            .unwrap(),
        )
    }

    async fn spawn_tagged_tcp_echo(
        tag: &'static [u8],
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    loop {
                        match sock.read(&mut chunk).await {
                            Ok(0) => break,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                            Err(_) => return,
                        }
                    }
                    let mut reply = tag.to_vec();
                    reply.extend_from_slice(&buf);
                    let _ = sock.write_all(&reply).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        (addr, handle)
    }

    #[cfg(unix)]
    async fn accept_as_l4_stream(listener: &TcpListener) -> L4Stream {
        use std::os::unix::io::AsRawFd;
        let (server, _) = listener.accept().await.unwrap();
        let mut l4 = L4Stream::from(server);
        let fd = l4.as_raw_fd();
        l4.set_socket_digest(SocketDigest::from_raw_fd(fd));
        l4
    }

    #[cfg(unix)]
    fn spawn_stream_proxy(
        app: Arc<StreamApp>,
    ) -> (SocketAddr, tokio::sync::watch::Sender<bool>) {
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        std_listener.set_nonblocking(true).unwrap();
        let addr = std_listener.local_addr().unwrap();
        let listener = TcpListener::from_std(std_listener).unwrap();
        let (tx, shutdown) = tokio::sync::watch::channel(false);
        let mut rx_stop = shutdown.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = rx_stop.changed() => break,
                    res = listener.accept() => {
                        let Ok((sock, _)) = res else { break; };
                        let mut l4 = L4Stream::from(sock);
                        {
                            use std::os::unix::io::AsRawFd;
                            let fd = l4.as_raw_fd();
                            l4.set_socket_digest(SocketDigest::from_raw_fd(fd));
                        }
                        let app = app.clone();
                        let shutdown = shutdown.clone();
                        tokio::spawn(async move {
                            let _ = app.process_new(Box::new(l4), &shutdown).await;
                        });
                    }
                }
            }
        });
        (addr, tx)
    }

    #[test]
    fn test_sni_routing_precedence_and_ip_acl() {
        let mut sni_routes = BTreeMap::new();
        sni_routes
            .insert("api.example.com".to_string(), "exact_up".to_string());
        sni_routes.insert("*.example.com".to_string(), "broad_up".to_string());
        sni_routes
            .insert("*.dev.example.com".to_string(), "dev_up".to_string());

        let conf = StreamConf {
            addr: "127.0.0.1:9443".to_string(),
            upstream: Some("fallback_up".to_string()),
            sni_routes: Some(sni_routes),
            allow_ips: Some(vec!["10.0.0.0/8".to_string()]),
            deny_ips: Some(vec!["10.0.0.5".to_string()]),
            ..Default::default()
        };
        let rt = StreamRuntime::try_from_conf("tls", &conf).unwrap();
        assert_eq!(
            Some("exact_up"),
            rt.resolve_upstream(Some("API.EXAMPLE.COM."))
        );
        assert_eq!(
            Some("dev_up"),
            rt.resolve_upstream(Some("svc.dev.example.com"))
        );
        assert_eq!(
            Some("broad_up"),
            rt.resolve_upstream(Some("other.example.com"))
        );
        // Apex domain must NOT match `*.example.com`.
        assert_eq!(
            Some("fallback_up"),
            rt.resolve_upstream(Some("example.com"))
        );
        assert_eq!(Some("fallback_up"), rt.resolve_upstream(None));

        assert_eq!(true, rt.is_ip_allowed("10.1.2.3".parse().unwrap()));
        assert_eq!(false, rt.is_ip_allowed("10.0.0.5".parse().unwrap()));
        assert_eq!(false, rt.is_ip_allowed("192.168.1.1".parse().unwrap()));

        // Service construction smoke test.
        let srv = StreamServer::new(
            "tls".to_string(),
            conf,
            StaticStreams::new("tls", &StreamConf::default()),
            Arc::new(StaticUpstreams(AHashMap::new())),
        )
        .unwrap();
        assert_eq!(true, srv.build_service().is_ok());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_tcp_passthrough_half_close_and_failover() {
        let (up_addr, up_task) = spawn_tagged_tcp_echo(b"OK:").await;
        // Include a dead closed port before the live backend to verify connect failover.
        let dead_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead_listener.local_addr().unwrap();
        drop(dead_listener);

        let mut ups = AHashMap::new();
        ups.insert(
            "tcp_up".to_string(),
            make_upstream(
                "tcp_up",
                &[dead_addr.to_string(), up_addr.to_string()],
                None,
            ),
        );
        let conf = StreamConf {
            addr: "127.0.0.1:0".to_string(),
            upstream: Some("tcp_up".to_string()),
            connect_timeout: Some(Duration::from_secs(2)),
            ..Default::default()
        };
        let app = Arc::new(StreamApp::new(
            "tcp".to_string(),
            StaticStreams::new("tcp", &conf),
            Arc::new(StaticUpstreams(ups)),
        ));
        let (proxy_addr, _stop) = spawn_stream_proxy(app);

        // Two attempts cover round-robin landing on dead_addr first or second.
        let payload = vec![b'x'; 32 * 1024];
        for _ in 0..2 {
            let mut client = TcpStream::connect(proxy_addr).await.unwrap();
            client.write_all(&payload).await.unwrap();
            // Half-close write side: backend keeps reading until FIN, then sends response.
            client.shutdown().await.unwrap();
            let mut received = Vec::new();
            client.read_to_end(&mut received).await.unwrap();
            assert_eq!(3 + payload.len(), received.len());
            assert_eq!(&b"OK:"[..], &received[..3]);
            assert_eq!(&payload[..], &received[3..]);
        }
        up_task.abort();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_sni_passthrough_fragmented_wildcard_and_fallback() {
        let (addr_exact, t1) = spawn_tagged_tcp_echo(b"EXACT:").await;
        let (addr_wild, t2) = spawn_tagged_tcp_echo(b"WILD:").await;
        let (addr_fb, t3) = spawn_tagged_tcp_echo(b"FB:").await;

        let mut ups = AHashMap::new();
        ups.insert(
            "u_exact".to_string(),
            make_upstream("u_exact", &[addr_exact.to_string()], None),
        );
        ups.insert(
            "u_wild".to_string(),
            make_upstream("u_wild", &[addr_wild.to_string()], None),
        );
        ups.insert(
            "u_fb".to_string(),
            make_upstream("u_fb", &[addr_fb.to_string()], None),
        );
        let providers = Arc::new(StaticUpstreams(ups));

        let mut sni_routes = BTreeMap::new();
        sni_routes.insert("api.example.com".to_string(), "u_exact".to_string());
        sni_routes
            .insert("*.app.example.com".to_string(), "u_wild".to_string());

        let conf = StreamConf {
            addr: "127.0.0.1:0".to_string(),
            upstream: Some("u_fb".to_string()),
            sni_routes: Some(sni_routes.clone()),
            sni_read_timeout: Some(Duration::from_secs(2)),
            ..Default::default()
        };
        let app = Arc::new(StreamApp::new(
            "sni".to_string(),
            StaticStreams::new("sni", &conf),
            providers.clone(),
        ));
        let (proxy_addr, _stop1) = spawn_stream_proxy(app);

        // 1. Fragmented ClientHello for exact SNI replays every byte verbatim to u_exact.
        let hello_exact = client_hello_records(
            &client_hello_body(
                0x0303,
                &[0x1301],
                Some(&[(0x0000, sni_ext("API.example.com"))]),
            ),
            24,
        );
        let mut c1 = TcpStream::connect(proxy_addr).await.unwrap();
        for piece in hello_exact.chunks(17) {
            c1.write_all(piece).await.unwrap();
            tokio::task::yield_now().await;
        }
        c1.write_all(b"TAIL").await.unwrap();
        c1.shutdown().await.unwrap();
        let mut r1 = Vec::new();
        c1.read_to_end(&mut r1).await.unwrap();
        assert_eq!(true, r1.starts_with(b"EXACT:"));
        assert_eq!(&hello_exact[..], &r1[6..6 + hello_exact.len()]);
        assert_eq!(&b"TAIL"[..], &r1[6 + hello_exact.len()..]);

        // 2. Wildcard SNI goes to u_wild.
        let hello_wild = client_hello_records(
            &client_hello_body(
                0x0303,
                &[0x1301],
                Some(&[(0x0000, sni_ext("v1.app.example.com"))]),
            ),
            16 * 1024,
        );
        let mut c2 = TcpStream::connect(proxy_addr).await.unwrap();
        c2.write_all(&hello_wild).await.unwrap();
        c2.shutdown().await.unwrap();
        let mut r2 = Vec::new();
        c2.read_to_end(&mut r2).await.unwrap();
        assert_eq!(true, r2.starts_with(b"WILD:"));
        assert_eq!(&hello_wild[..], &r2[5..]);

        // 3. Plain non-TLS traffic falls back to default upstream with exact replay.
        let mut c3 = TcpStream::connect(proxy_addr).await.unwrap();
        c3.write_all(b"PLAIN_HELLO\n").await.unwrap();
        c3.shutdown().await.unwrap();
        let mut r3 = Vec::new();
        c3.read_to_end(&mut r3).await.unwrap();
        assert_eq!(b"FB:PLAIN_HELLO\n", &r3[..]);

        // 4. Without fallback `upstream`, plain traffic & unmatched SNI disconnect cleanly.
        let strict_conf = StreamConf {
            addr: "127.0.0.1:0".to_string(),
            upstream: None,
            sni_routes: Some(sni_routes),
            sni_read_timeout: Some(Duration::from_millis(80)),
            ..Default::default()
        };
        let strict_app = Arc::new(StreamApp::new(
            "strict".to_string(),
            StaticStreams::new("strict", &strict_conf),
            providers,
        ));
        let (strict_addr, _stop2) = spawn_stream_proxy(strict_app);

        let mut c_plain = TcpStream::connect(strict_addr).await.unwrap();
        c_plain.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        let mut eof_buf = Vec::new();
        match c_plain.read_to_end(&mut eof_buf).await {
            Ok(_) => {},
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::BrokenPipe
                ) => {},
            Err(e) => panic!("unexpected read error: {e}"),
        }
        assert_eq!(true, eof_buf.is_empty());

        let mut c_silent = TcpStream::connect(strict_addr).await.unwrap();
        let mut silent_buf = Vec::new();
        let _ = c_silent.read_to_end(&mut silent_buf).await.unwrap();
        assert_eq!(true, silent_buf.is_empty());

        t1.abort();
        t2.abort();
        t3.abort();
    }

    #[cfg(all(unix, feature = "openssl"))]
    #[tokio::test]
    async fn test_tls_sni_end_to_end_without_proxy_holding_certs() {
        use pingora::tls::pkey::PKey;
        use pingora::tls::ssl::{
            Ssl, SslAcceptor, SslConnector, SslMethod, SslVerifyMode,
        };
        use pingora::tls::x509::X509;

        fn self_signed(cn: &str) -> (X509, PKey<pingora::tls::pkey::Private>) {
            let mut params =
                pingap_certificate::rcgen::CertificateParams::new(vec![
                    cn.to_string(),
                ])
                .unwrap();
            params
                .distinguished_name
                .push(pingap_certificate::rcgen::DnType::CommonName, cn);
            let kp = pingap_certificate::rcgen::KeyPair::generate().unwrap();
            let cert_key = params.self_signed(&kp).unwrap();
            let cert = X509::from_pem(cert_key.pem().as_bytes()).unwrap();
            let key = PKey::private_key_from_pem(kp.serialize_pem().as_bytes())
                .unwrap();
            (cert, key)
        }

        fn spawn_tls_backend(
            cn: &'static str,
            reply: &'static [u8],
        ) -> SocketAddr {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let (cert, key) = self_signed(cn);
            let mut acc =
                SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
            acc.set_private_key(&key).unwrap();
            acc.set_certificate(&cert).unwrap();
            let acc = acc.build();
            std::thread::spawn(move || {
                use std::io::{Read, Write};
                let (sock, _) = listener.accept().unwrap();
                let mut tls =
                    Ssl::new(acc.context()).unwrap().accept(sock).unwrap();
                let mut req = [0u8; 64];
                let _ = tls.read(&mut req);
                tls.write_all(reply).unwrap();
                tls.shutdown().unwrap();
            });
            addr
        }

        let addr_a = spawn_tls_backend("alpha.tls.test", b"FROM_ALPHA");
        let addr_b = spawn_tls_backend("beta.tls.test", b"FROM_BETA");

        let mut ups = AHashMap::new();
        ups.insert(
            "up_a".to_string(),
            make_upstream("up_a", &[addr_a.to_string()], None),
        );
        ups.insert(
            "up_b".to_string(),
            make_upstream("up_b", &[addr_b.to_string()], None),
        );

        let mut sni_routes = BTreeMap::new();
        sni_routes.insert("alpha.tls.test".to_string(), "up_a".to_string());
        sni_routes.insert("*.beta.tls.test".to_string(), "up_b".to_string());

        let conf = StreamConf {
            addr: "127.0.0.1:0".to_string(),
            sni_routes: Some(sni_routes),
            ..Default::default()
        };
        let app = Arc::new(StreamApp::new(
            "tls_e2e".to_string(),
            StaticStreams::new("tls_e2e", &conf),
            Arc::new(StaticUpstreams(ups)),
        ));
        let (proxy_addr, _stop) = spawn_stream_proxy(app);

        let call_tls = move |sni_host: &str| {
            use std::io::{Read, Write};
            let mut connector =
                SslConnector::builder(SslMethod::tls()).unwrap();
            connector.set_verify(SslVerifyMode::NONE);
            let ssl = connector
                .build()
                .configure()
                .unwrap()
                .into_ssl(sni_host)
                .unwrap();
            let tcp = std::net::TcpStream::connect(proxy_addr).unwrap();
            let mut stream = ssl.connect(tcp).unwrap();
            let cn = stream
                .ssl()
                .peer_certificate()
                .unwrap()
                .subject_name()
                .entries()
                .next()
                .unwrap()
                .data()
                .to_string()
                .unwrap();
            stream.write_all(b"hi").unwrap();
            let mut body = Vec::new();
            let _ = stream.read_to_end(&mut body);
            (cn, body)
        };

        let (cn_a, body_a) =
            tokio::task::spawn_blocking(move || call_tls("alpha.tls.test"))
                .await
                .unwrap();
        assert_eq!("alpha.tls.test", cn_a);
        assert_eq!(b"FROM_ALPHA", &body_a[..]);

        let (cn_b, body_b) =
            tokio::task::spawn_blocking(move || call_tls("svc.beta.tls.test"))
                .await
                .unwrap();
        assert_eq!("beta.tls.test", cn_b);
        assert_eq!(b"FROM_BETA", &body_b[..]);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_proxy_protocol_inbound_outbound_acl_and_sni_pipeline() {
        let (backend_addr, backend_task) =
            spawn_tagged_tcp_echo(b"RECV:").await;
        let mut ups = AHashMap::new();
        ups.insert(
            "tls_pp".to_string(),
            make_upstream("tls_pp", &[backend_addr.to_string()], Some("v1")),
        );
        let mut sni_routes = BTreeMap::new();
        sni_routes.insert("edge.example.com".to_string(), "tls_pp".to_string());

        let conf = StreamConf {
            addr: "127.0.0.1:0".to_string(),
            sni_routes: Some(sni_routes),
            proxy_protocol: Some(true),
            allow_ips: Some(vec!["198.51.100.0/24".to_string()]),
            ..Default::default()
        };
        let streams = StaticStreams::new("pp_sni", &conf);
        let upstream_provider = Arc::new(StaticUpstreams(ups));

        // 1. Trusted peer: inbound PP sets real client IP 198.51.100.42 (passes allow_ips),
        //    SNI routes to tls_pp, outbound PP v1 forwards 198.51.100.42, then ClientHello arrives.
        let trusted_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let trusted_addr = trusted_listener.local_addr().unwrap();
        let mut trusted_app = StreamApp::new(
            "pp_sni".to_string(),
            streams.clone(),
            upstream_provider.clone(),
        );
        trusted_app.is_trusted_proxy = |ip| ip.is_loopback();
        let trusted_app = Arc::new(trusted_app);
        let (_stop_tx, stop_rx) = tokio::sync::watch::channel(false);

        let server_fut = tokio::spawn({
            let trusted_app = trusted_app.clone();
            let stop_rx = stop_rx.clone();
            async move {
                let l4 = accept_as_l4_stream(&trusted_listener).await;
                let _ = trusted_app.process_new(Box::new(l4), &stop_rx).await;
                // Second connection: denied spoofed/unlisted IP 203.0.113.9 in inbound PP.
                let l4_denied = accept_as_l4_stream(&trusted_listener).await;
                let _ = trusted_app
                    .process_new(Box::new(l4_denied), &stop_rx)
                    .await;
            }
        });

        let hello = client_hello_records(
            &client_hello_body(
                0x0303,
                &[0x1301],
                Some(&[(0x0000, sni_ext("edge.example.com"))]),
            ),
            16 * 1024,
        );
        let mut wire =
            b"PROXY TCP4 198.51.100.42 10.0.0.1 55555 443\r\n".to_vec();
        wire.extend_from_slice(&hello);

        let mut client = TcpStream::connect(trusted_addr).await.unwrap();
        client.write_all(&wire).await.unwrap();
        client.shutdown().await.unwrap();
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        let out_str = String::from_utf8_lossy(&out);
        assert_eq!(true, out_str.starts_with("RECV:PROXY TCP4 198.51.100.42 "));
        assert_eq!(
            true,
            out.windows(hello.len()).any(|w| w == hello.as_slice())
        );

        let mut denied_client = TcpStream::connect(trusted_addr).await.unwrap();
        let mut blocked =
            b"PROXY TCP4 203.0.113.9 10.0.0.1 44444 443\r\n".to_vec();
        blocked.extend_from_slice(&hello);
        denied_client.write_all(&blocked).await.unwrap();
        let mut denied_out = Vec::new();
        match denied_client.read_to_end(&mut denied_out).await {
            Ok(_) => {},
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::BrokenPipe
                ) => {},
            Err(e) => panic!("unexpected denied read error: {e}"),
        }
        assert_eq!(true, denied_out.is_empty());
        server_fut.await.unwrap();

        // 2. Untrusted peer attempting to spoof allowlisted IP in PP header must NOT bypass ACL.
        let untrusted_listener =
            TcpListener::bind("127.0.0.1:0").await.unwrap();
        let untrusted_addr = untrusted_listener.local_addr().unwrap();
        let mut untrusted_app =
            StreamApp::new("pp_sni".to_string(), streams, upstream_provider);
        untrusted_app.is_trusted_proxy = |_| false;
        let untrusted_app = Arc::new(untrusted_app);
        let srv = tokio::spawn(async move {
            let l4 = accept_as_l4_stream(&untrusted_listener).await;
            let _ = untrusted_app.process_new(Box::new(l4), &stop_rx).await;
        });
        let mut spoof = TcpStream::connect(untrusted_addr).await.unwrap();
        let _ = spoof.write_all(&wire).await;
        let mut spoof_out = Vec::new();
        match spoof.read_to_end(&mut spoof_out).await {
            Ok(_) => {},
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::BrokenPipe
                ) => {},
            Err(e) => panic!("unexpected spoof read error: {e}"),
        }
        assert_eq!(true, spoof_out.is_empty());
        srv.await.unwrap();

        backend_task.abort();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_limits_timeouts_active_upload_and_hot_reload() {
        // Streaming echo backend that echoes each chunk immediately and sends a
        // leading `+` banner once connected so tests can synchronize without sleep.
        let spawn_live_echo = |tag: &'static [u8]| async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let task = tokio::spawn(async move {
                loop {
                    let Ok((mut sock, _)) = listener.accept().await else {
                        break;
                    };
                    tokio::spawn(async move {
                        if sock.write_all(tag).await.is_err() {
                            return;
                        }
                        let mut buf = [0u8; 1024];
                        loop {
                            match sock.read(&mut buf).await {
                                Ok(0) => {
                                    let _ = sock.shutdown().await;
                                    break;
                                },
                                Ok(n) => {
                                    if sock.write_all(&buf[..n]).await.is_err()
                                    {
                                        break;
                                    }
                                },
                                Err(_) => break,
                            }
                        }
                    });
                }
            });
            (addr, task)
        };

        let (addr_1, t1) = spawn_live_echo(b"U1:").await;
        let (addr_2, t2) = spawn_live_echo(b"U2:").await;
        let mut ups = AHashMap::new();
        ups.insert(
            "u1".to_string(),
            make_upstream("u1", &[addr_1.to_string()], None),
        );
        ups.insert(
            "u2".to_string(),
            make_upstream("u2", &[addr_2.to_string()], None),
        );
        let providers = Arc::new(StaticUpstreams(ups));

        let conf = StreamConf {
            addr: "127.0.0.1:0".to_string(),
            upstream: Some("u1".to_string()),
            max_connections: Some(1),
            idle_timeout: Some(Duration::from_millis(120)),
            ..Default::default()
        };
        let streams = StaticStreams::new("limits", &conf);
        let app = Arc::new(StreamApp::new(
            "limits".to_string(),
            streams.clone(),
            providers,
        ));
        let (proxy_addr, _stop) = spawn_stream_proxy(app);

        // Wait for `U1:` banner so c1 is deterministically inside active relay.
        let mut c1 = TcpStream::connect(proxy_addr).await.unwrap();
        let mut banner = [0u8; 3];
        c1.read_exact(&mut banner).await.unwrap();
        assert_eq!(b"U1:", &banner);

        // 2nd connection is deterministically rejected while c1 holds slot 1/1.
        let mut c2 = TcpStream::connect(proxy_addr).await.unwrap();
        let mut c2_buf = Vec::new();
        c2.read_to_end(&mut c2_buf).await.unwrap();
        assert_eq!(true, c2_buf.is_empty());

        // Hot-reload upstream target from u1 -> u2 while c1 stays open on u1.
        let next_conf = StreamConf {
            addr: "127.0.0.1:0".to_string(),
            upstream: Some("u2".to_string()),
            max_connections: Some(4),
            idle_timeout: Some(Duration::from_millis(120)),
            ..Default::default()
        };
        streams.swap("limits", &next_conf);

        // Existing c1 finishes cleanly against u1.
        c1.write_all(b"keep-open").await.unwrap();
        c1.shutdown().await.unwrap();
        let mut r1 = Vec::new();
        c1.read_to_end(&mut r1).await.unwrap();
        assert_eq!(b"keep-open", &r1[..]);

        // New connection immediately sees hot-reloaded u2.
        let mut c3 = TcpStream::connect(proxy_addr).await.unwrap();
        c3.write_all(b"fresh").await.unwrap();
        c3.shutdown().await.unwrap();
        let mut r3 = Vec::new();
        c3.read_to_end(&mut r3).await.unwrap();
        assert_eq!(b"U2:fresh", &r3[..]);

        // Shared idle timeout: active periodic writes past 120ms stay open and
        // receive echoes, then silence triggers timeout close.
        let mut c_idle = TcpStream::connect(proxy_addr).await.unwrap();
        let mut b2 = [0u8; 3];
        c_idle.read_exact(&mut b2).await.unwrap();
        assert_eq!(b"U2:", &b2);
        for _ in 0..4 {
            tokio::time::sleep(Duration::from_millis(45)).await;
            c_idle.write_all(b"a").await.unwrap();
            let mut one = [0u8; 1];
            c_idle.read_exact(&mut one).await.unwrap();
            assert_eq!(b"a", &one);
        }
        let mut idle_buf = Vec::new();
        c_idle.read_to_end(&mut idle_buf).await.unwrap();
        assert_eq!(true, idle_buf.is_empty());

        t1.abort();
        t2.abort();
    }
}
