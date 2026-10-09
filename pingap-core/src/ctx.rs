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

use crate::{Ja4Fingerprint, Plugin, get_request_host, now_ms};
use ahash::AHashMap;
use bytes::BytesMut;
use http::StatusCode;
use http::{HeaderName, HeaderValue};
#[cfg(feature = "tracing")]
use opentelemetry::{
    Context,
    global::{BoxedSpan, BoxedTracer, ObjectSafeSpan},
    trace::{SpanKind, TraceContextExt, Tracer},
};
use pingora::cache::CacheKey;
use pingora::http::RequestHeader;
use pingora::protocols::Digest;
use pingora::protocols::TimingDigest;
use pingora::proxy::Session;
use pingora_limits::inflight::Guard;
use std::borrow::Cow;
use std::fmt::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime};
use strum::EnumString;

// Constants for time conversions in milliseconds.
const SECOND: u64 = 1_000;
const MINUTE: u64 = 60 * SECOND;
const HOUR: u64 = 60 * MINUTE;

#[inline]
/// Format the duration in human readable format, checking smaller units first.
/// e.g., ms, s, m, h.
pub fn format_duration(buf: &mut BytesMut, ms: u64) {
    if ms < SECOND {
        // Format as milliseconds if less than a second.
        buf.extend_from_slice(itoa::Buffer::new().format(ms).as_bytes());
        buf.extend_from_slice(b"ms");
    } else if ms < MINUTE {
        // Format as seconds with one decimal place if less than a minute.
        buf.extend_from_slice(
            itoa::Buffer::new().format(ms / SECOND).as_bytes(),
        );
        let value = (ms % SECOND) / 100;
        if value != 0 {
            buf.extend_from_slice(b".");
            buf.extend_from_slice(itoa::Buffer::new().format(value).as_bytes());
        }
        buf.extend_from_slice(b"s");
    } else if ms < HOUR {
        // Format as minutes with one decimal place if less than an hour.
        buf.extend_from_slice(
            itoa::Buffer::new().format(ms / MINUTE).as_bytes(),
        );
        let value = ms % MINUTE * 10 / MINUTE;
        if value != 0 {
            buf.extend_from_slice(b".");
            buf.extend_from_slice(itoa::Buffer::new().format(value).as_bytes());
        }
        buf.extend_from_slice(b"m");
    } else {
        // Format as hours with one decimal place.
        buf.extend_from_slice(itoa::Buffer::new().format(ms / HOUR).as_bytes());
        let value = ms % HOUR * 10 / HOUR;
        if value != 0 {
            buf.extend_from_slice(b".");
            buf.extend_from_slice(itoa::Buffer::new().format(value).as_bytes());
        }
        buf.extend_from_slice(b"h");
    }
}

#[derive(PartialEq)]
pub enum ModifiedMode {
    Upstream,
    Response,
}

impl From<&str> for ModifiedMode {
    fn from(value: &str) -> Self {
        match value {
            "upstream" => ModifiedMode::Upstream,
            _ => ModifiedMode::Response,
        }
    }
}

/// Trait for modifying the response body.
pub trait ModifyResponseBody: Sync + Send {
    /// Handles the modification of response body data.
    fn handle(
        &mut self,
        session: &Session,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
    ) -> pingora::Result<()>;
    /// Returns the name of the modifier.
    fn name(&self) -> &str {
        "unknown"
    }
}

/// Information about a single client connection.
#[derive(Default)]
pub struct ConnectionInfo {
    /// A unique identifier for the connection.
    pub id: usize,
    /// The IP address of the client.
    pub client_ip: Option<String>,
    /// The remote address of the client connection.
    pub remote_addr: Option<String>,
    /// The remote port of the client connection.
    pub remote_port: Option<u16>,
    /// The server address the client connected to.
    pub server_addr: Option<String>,
    /// The server port the client connected to.
    pub server_port: Option<u16>,
    /// The TLS version used for the connection, if any.
    ///
    /// Stored as `Cow<'static, str>` so values borrowed from pingora's
    /// `SslDigest` (usually `&'static str`) do not allocate per request.
    pub tls_version: Option<Cow<'static, str>>,
    /// The TLS cipher used for the connection, if any.
    pub tls_cipher: Option<Cow<'static, str>>,
    /// The JA4 fingerprint of the client's ClientHello, when the server
    /// collects it. Shared by every request on the connection.
    pub ja4: Option<Arc<Ja4Fingerprint>>,
    /// The certificate the client presented in the TLS handshake, on a
    /// server that asks for one (`tls_client_ca`). It was verified
    /// against that CA: a certificate that does not verify ends the
    /// handshake. Shared by every request on the connection.
    pub tls_client_cert: Option<Arc<TlsClientCert>>,
    /// Indicates whether the connection was reused (e.g., HTTP keep-alive).
    pub reused: bool,
}

/// What is told about the certificate of a client: enough to say who it
/// is to an upstream, a plugin or the access log.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsClientCert {
    /// The subject, its parts in the order the certificate has them:
    /// `O=Example, CN=device-42`.
    pub subject: String,
    /// The SHA-256 of the certificate, in lower case hex.
    pub fingerprint: String,
    /// The serial number, in lower case hex.
    pub serial: String,
}

/// All timing-related metrics for the request lifecycle.
// #[derive(Default)]
pub struct Timing {
    /// Timestamp in milliseconds when the request was created.
    pub created_at: Instant,
    /// The total duration of the client connection in milliseconds.
    /// May be large for reused connections.
    pub connection_duration: u64,
    /// The duration of the TLS handshake with the client in milliseconds.
    pub tls_handshake: Option<i32>,
    /// The total duration to connect to the upstream server in milliseconds.
    pub upstream_connect: Option<i32>,
    /// The duration of the TCP connection to the upstream server in milliseconds.
    pub upstream_tcp_connect: Option<i32>,
    /// The duration of the TLS handshake with the upstream server in milliseconds.
    pub upstream_tls_handshake: Option<i32>,
    /// How long the upstream connect waited for an offload thread before it
    /// began, in milliseconds. Only present when
    /// `basic.upstream_connect_offload_*` is on; it separates scheduling
    /// delay in the offload pool from network latency.
    pub upstream_connect_offload_wait: Option<i32>,
    /// The duration the upstream server took to process the request in milliseconds.
    pub upstream_processing: Option<i32>,
    /// The duration from sending the request to receiving the upstream response in milliseconds.
    pub upstream_response: Option<i32>,
    /// The total duration of the upstream connection in milliseconds.
    pub upstream_connection_duration: Option<u64>,
    /// The duration of the cache lookup in milliseconds.
    pub cache_lookup: Option<i32>,
    /// The duration spent waiting for a cache lock in milliseconds.
    pub cache_lock: Option<i32>,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            created_at: Instant::now(),
            connection_duration: 0,
            tls_handshake: None,
            upstream_connect: None,
            upstream_tcp_connect: None,
            upstream_tls_handshake: None,
            upstream_connect_offload_wait: None,
            upstream_processing: None,
            upstream_response: None,
            upstream_connection_duration: None,
            cache_lookup: None,
            cache_lock: None,
        }
    }
}

/// Trait for upstream instance, used to handle the upstream instance lifecycle.
pub trait UpstreamInstance: Send + Sync {
    fn on_transport_failure(&self, address: &str);
    fn on_response(&self, address: &str, status: StatusCode);
    /// Marks the request as finished on this upstream.
    ///
    /// Returns the number of in-flight requests still being processed *after*
    /// releasing this one (so a zero means the upstream is idle).
    fn completed(&self) -> i32;
}

/// Trait for location instance
pub trait LocationInstance: Send + Sync {
    /// Get location's name
    fn name(&self) -> &str;
    /// Get the upstream of location
    fn upstream(&self) -> &str;
    /// Whether the location has a rewrite rule at all, so that the uri of
    /// a request is only kept (`Features::original_uri`) where it may be
    /// replaced.
    fn has_rewrite(&self) -> bool {
        false
    }
    /// Rewrites the request url. Returns whether the path changed; named
    /// captures of the rewrite pattern are added to `variables`. An error
    /// when the rule gives something that is no path: the request is then
    /// refused and not sent on with the path it came with.
    fn rewrite(
        &self,
        header: &mut RequestHeader,
        variables: &mut Option<AHashMap<String, String>>,
    ) -> pingora::Result<bool>;
    /// Returns the proxy header to upstream
    fn headers(&self) -> Option<&Vec<(HeaderName, HeaderValue, bool)>>;
    /// Returns the client body size limit
    fn client_body_size_limit(&self) -> usize;
    /// Called when the request is received from the client
    /// Returns
    /// `Result<(u64, i32)>` - A tuple containing:
    ///   - The new total number of accepted requests (u64)
    ///   - The new number of currently processing requests (i32)
    fn on_request(&self) -> pingora::Result<(u64, i32)>;
    /// Called when the response is received from the upstream
    fn on_response(&self);
    /// Puts the timeouts of the location in place of the upstream's, on the
    /// peer of one of its requests. A location that sets none leaves the
    /// peer as it is.
    fn apply_timeouts(
        &self,
        _options: &mut pingora::upstreams::peer::PeerOptions,
    ) {
    }
}

/// Information about the upstream (backend) server.
#[derive(Default)]
pub struct UpstreamInfo {
    /// Upstream instance
    pub upstream_instance: Option<Arc<dyn UpstreamInstance>>,
    /// Location instance
    pub location_instance: Option<Arc<dyn LocationInstance>>,
    /// The location (route) that directed the request to this upstream.
    pub location: Arc<str>,
    /// The name of the upstream server or group.
    pub name: Arc<str>,
    /// The address of the upstream server.
    pub address: String,
    /// Indicates if the connection to the upstream was reused.
    pub reused: bool,
    /// The number of requests currently being processed by the upstream.
    pub processing_count: Option<i32>,
    /// The current number of active connections to the upstream.
    pub connected_count: Option<i32>,
    /// The HTTP status code of upstream response.
    pub status: Option<StatusCode>,
    /// The number of retries for failed connections.
    pub retries: u8,
    /// Maximum number of retries for failed connections.
    pub max_retries: Option<u8>,
    /// The maximum total time window allowed for an operation and all of its subsequent retries.
    ///
    /// The timer starts from the beginning of the **initial attempt**. Once this time window
    /// is exceeded, no more retries will be initiated, even if the maximum number of
    /// retries (`max_retries`) has not been reached.
    ///
    /// If set to `None`, there is no time limit for the retry process.
    pub max_retry_window: Option<Duration>,
    /// The backends this request was sent to and that failed it in a way
    /// that is retried. The next attempt goes to another one, where there
    /// is one.
    pub failed_addresses: Vec<String>,
    /// The request as one in flight on its backend, for an upstream that
    /// chooses by that (`least_conn`): counted from the attempt to the
    /// next one, or to the end of the request.
    pub backend_inflight: Option<InflightGuard>,
}

/// One request in flight on a backend, for as long as this is kept: the
/// count goes up when it is made and down when it is dropped, whichever
/// way the request ends.
pub struct InflightGuard(Arc<AtomicU32>);

impl InflightGuard {
    pub fn new(count: Arc<AtomicU32>) -> Self {
        count.fetch_add(1, Ordering::Relaxed);
        Self(count)
    }
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// What a limit has left for the client of this request, as the
/// `X-RateLimit-*` response headers tell it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitQuota {
    /// What the limit allows: requests in any one interval, or at once.
    pub limit: u64,
    /// How many of them are left, this request counted.
    pub remaining: u64,
    /// In how many seconds all of them are back if nothing more is sent.
    /// `None` for a limit on concurrent requests, where that is whenever
    /// they end.
    pub reset: Option<u64>,
}

/// State related to the current request being processed.
#[derive(Default)]
pub struct RequestState {
    /// A unique identifier for the request.
    pub request_id: Option<String>,
    /// The HTTP status code of the response.
    pub status: Option<StatusCode>,
    /// The size of the request payload in bytes.
    pub payload_size: usize,
    /// The inflight limiters this request is counted in, one guard each.
    /// A limiter's count goes down again when its guard is dropped, at the
    /// end of the request.
    pub guards: Vec<Guard>,
    /// The total number of requests currently being processed by the service.
    pub processing_count: i32,
    /// The total number of requests accepted by the service.
    pub accepted_count: u64,
    /// The number of requests currently being processed for this location.
    pub location_processing_count: i32,
    /// The total number of requests accepted for this location.
    pub location_accepted_count: u64,
    /// The request passed every filter and is on its way to an upstream.
    /// A failure from here on closes the client's connection, whatever
    /// the proxy says of it: pingora asks whether it may be kept only for
    /// a request that failed in one of the filters.
    pub proxying: bool,
    /// The budget to report to the client, from the limit that has the
    /// least left of those that were asked to report theirs.
    pub rate_limit: Option<RateLimitQuota>,
}

/// Components of the cache key that stand for something this request
/// said - the coding it accepts, the image formats it takes - and that
/// another request for the same url has others in the place of.
///
/// A `PURGE` is such another request: it names the url and says nothing of
/// codings or formats. What it has to remove is the entry under every one
/// of the alternatives, not only under its own.
#[derive(Clone, Debug)]
pub struct CacheKeyVariant {
    /// Where in `keys` its components start.
    pub at: usize,
    /// How many of them there are for this request, which may be none.
    pub len: usize,
    /// Every list of components that can stand here, the empty one
    /// included.
    pub alternatives: Arc<Vec<Vec<String>>>,
}

/// Which parameters of the query a cache key is made of.
#[derive(Debug, Clone, PartialEq)]
pub enum CacheQueryRule {
    /// All but these.
    Ignore(Vec<String>),
    /// These and no other.
    Allow(Vec<String>),
}

impl CacheQueryRule {
    /// The query string a cache key is made of: the parameters the rule
    /// keeps, in the order of their names.
    ///
    /// `?b=2&a=1` and `?a=1&b=2` are the same page and were two entries,
    /// and a tracking parameter (`utm_source`, `fbclid`) made one entry
    /// per visitor. Parameters of the same name keep the order they came
    /// in, which is theirs to mean something. Names are compared as they
    /// are written, not decoded.
    pub fn key_query(&self, query: &str) -> String {
        fn name(pair: &str) -> &str {
            pair.split('=').next().unwrap_or(pair)
        }
        let mut pairs: Vec<&str> = query
            .split('&')
            .filter(|pair| !pair.is_empty())
            .filter(|pair| {
                let name = name(pair);
                match self {
                    Self::Ignore(names) => !names.iter().any(|n| n == name),
                    Self::Allow(names) => names.iter().any(|n| n == name),
                }
            })
            .collect();
        pairs.sort_by(|a, b| name(a).cmp(name(b)));
        pairs.join("&")
    }
}

/// All cache-related configuration and statistics for a request.
#[derive(Default)]
pub struct CacheInfo {
    /// The namespace for cache entries.
    pub namespace: Option<String>,
    /// The list of keys used to generate the final cache key.
    pub keys: Option<Vec<String>>,
    /// Which of `keys` are one alternative among several, see
    /// [`CacheKeyVariant`].
    pub key_variants: Option<Vec<CacheKeyVariant>>,
    /// Whether to respect Cache-Control headers.
    pub check_cache_control: bool,
    /// The maximum time-to-live for cache entries.
    pub max_ttl: Option<Duration>,
    /// Request headers the origin's `Vary` response header may turn into
    /// cache variants (lowercased); `None` honours every header it names.
    pub vary_headers: Option<Arc<Vec<String>>>,
    /// How long a response stays fresh when the origin names no lifetime,
    /// for the statuses that are kept by default, in place of one second.
    pub default_ttl: Option<Duration>,
    /// The same for single statuses, also ones that are not kept by
    /// default: `(status, lifetime)`. A lifetime of zero keeps a status
    /// out.
    pub status_ttl: Option<Arc<Vec<(u16, Duration)>>>,
    /// Which parameters of the query the cache key is made of, where
    /// the plugin has a rule for that.
    pub query_rule: Option<Arc<CacheQueryRule>>,
    /// The query the key of this request was made of by that rule, from
    /// the moment the key is made (`settle_key_query`): with the
    /// parameters the rule leaves out gone and the others in order.
    /// Empty for no query at all. The upstream is asked with it too, see
    /// `ask_with_key_query`.
    pub key_query: Option<String>,
    /// The client asked for a copy that is checked with the origin
    /// (`Cache-Control: no-cache`), and the plugin lets clients do that:
    /// what is cached is revalidated before it is served.
    pub revalidate: bool,
    /// The number of cache read operations performed.
    pub reading_count: Option<u32>,
    /// The number of cache write operations performed.
    pub writing_count: Option<u32>,
}

impl CacheInfo {
    /// Makes the query the cache key is made of, from the request as it
    /// is now. Called when the key is made, which is after the request
    /// plugins have run: one that takes a parameter out of the query
    /// (`key_auth` with `hide_credentials`) has done so by then, also
    /// when it is listed after the cache. Taken when the cache plugin
    /// ran, the key query had the credential in it, and the upstream was
    /// then asked with what was meant to be hidden from it.
    pub fn settle_key_query(&mut self, header: &RequestHeader) {
        if let Some(rule) = &self.query_rule {
            self.key_query =
                Some(rule.key_query(header.uri.query().unwrap_or_default()));
        }
    }

    /// Gives `header`, the request that goes to the upstream, the query
    /// the cache key is made of, where that is not the request's own.
    ///
    /// The key says which parameters a response depends on; with the
    /// others sent on all the same it was the upstream that decided. A
    /// parameter spelled another way than the rule has it (`p%61ge=2`
    /// for `page`, `x=1;page=2`) was left out of the key and read by the
    /// upstream, and page 2 was stored as the page without a number, for
    /// everyone. Asked with the query of the key, the upstream can not
    /// tell two requests of one key apart.
    ///
    /// Only the request to the upstream is changed, not the client's:
    /// the access log and the plugins see what was asked for. `false`
    /// when the uri can not be made, and then the request must not be
    /// sent as it is.
    pub fn ask_with_key_query(&self, header: &mut RequestHeader) -> bool {
        let made;
        let query = match (&self.key_query, &self.query_rule) {
            (Some(query), _) => query.as_str(),
            // No key was made for this request, so nothing is stored
            // either: the rule is applied all the same, for an upstream
            // that sees one kind of query on this location.
            (None, Some(rule)) => {
                made = rule.key_query(header.uri.query().unwrap_or_default());
                made.as_str()
            },
            (None, None) => return true,
        };
        // `/a?` is `/a` in the key, and is sent as that.
        if header.uri.query() == (!query.is_empty()).then_some(query) {
            return true;
        }
        let path_and_query = if query.is_empty() {
            header.uri.path().to_string()
        } else {
            format!("{}?{query}", header.uri.path())
        };
        let mut parts = header.uri.clone().into_parts();
        let Ok(path_and_query) = path_and_query.parse() else {
            return false;
        };
        parts.path_and_query = Some(path_and_query);
        let Ok(uri) = http::Uri::from_parts(parts) else {
            return false;
        };
        header.set_uri(uri);
        true
    }
}

/// Optional features like tracing, plugins, and response modifications.
#[derive(Default)]
pub struct Features {
    /// A map of custom variables for request processing.
    pub variables: Option<AHashMap<String, String>>,
    /// The uri the client asked for, when the location has rewritten it.
    /// A plugin that sends the client somewhere relative to where it is
    /// (the `directory` plugin, adding the closing slash) goes by this:
    /// the rewritten path is the upstream's, not the browser's.
    pub original_uri: Option<http::Uri>,
    /// A list of plugin names and their processing times in milliseconds.
    pub plugin_processing_times: Option<Vec<(Arc<str>, u32)>>,
    /// Statistics about response compression.
    pub compression_stat: Option<CompressionStat>,
    /// A map of plugin names and their response body handlers.
    pub modify_body_handlers:
        Option<AHashMap<String, Box<dyn ModifyResponseBody>>>,
    /// What a plugin settled at one step of a request and goes by again
    /// at a later one, under a name of its own: see
    /// [`Ctx::set_plugin_note`].
    pub plugin_notes: Option<Vec<(String, &'static str)>>,
    /// OpenTelemetry tracer for distributed tracing (available with the "tracing" feature).
    #[cfg(feature = "tracing")]
    pub otel_tracer: Option<OtelTracer>,
    /// OpenTelemetry span for the upstream request (available with the "tracing" feature).
    #[cfg(feature = "tracing")]
    pub upstream_span: Option<BoxedSpan>,
}

#[derive(Default)]
/// Statistics about response compression operations.
pub struct CompressionStat {
    /// The algorithm used for compression (e.g., "gzip", "br").
    pub algorithm: String,
    /// The size of the data before compression in bytes.
    pub in_bytes: usize,
    /// The size of the data after compression in bytes.
    pub out_bytes: usize,
    /// The time taken to perform the compression operation.
    pub duration: Duration,
}

impl CompressionStat {
    /// Calculates the compression ratio.
    pub fn ratio(&self) -> f64 {
        if self.out_bytes == 0 {
            return 0.0;
        }
        (self.in_bytes as f64) / (self.out_bytes as f64)
    }
}

/// A wrapper for OpenTelemetry tracing components.
#[cfg(feature = "tracing")]
pub struct OtelTracer {
    /// The tracer instance.
    pub tracer: BoxedTracer,
    /// The main span for the incoming HTTP request.
    pub http_request_span: BoxedSpan,
}

#[cfg(feature = "tracing")]
impl OtelTracer {
    /// Creates a new child span for an upstream request.
    #[inline]
    pub fn new_upstream_span(&self, name: &str) -> BoxedSpan {
        self.tracer
            .span_builder(name.to_string())
            .with_kind(SpanKind::Client)
            .start_with_context(
                &self.tracer,
                // Set the parent span context to link this upstream span with the main request span.
                &Context::current().with_remote_span_context(
                    self.http_request_span.span_context().clone(),
                ),
            )
    }
}

/// A plugin paired with the name it was registered under in the location config.
pub type NamedPlugin = (Arc<str>, Arc<dyn Plugin>);

/// A `Ctx` value the access log can print. The `{:name}` in a log format
/// parses into one of these once, when the format is read, so writing a
/// log line dispatches on an enum instead of comparing the name against
/// every key on every request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumString, strum::Display)]
#[strum(serialize_all = "snake_case")]
pub enum CtxLogField {
    ConnectionId,
    UpstreamReused,
    UpstreamStatus,
    UpstreamAddr,
    Processing,
    UpstreamConnected,
    UpstreamConnectTime,
    UpstreamConnectTimeHuman,
    UpstreamProcessingTime,
    UpstreamProcessingTimeHuman,
    UpstreamResponseTime,
    UpstreamResponseTimeHuman,
    UpstreamTcpConnectTime,
    UpstreamTcpConnectTimeHuman,
    UpstreamTlsHandshakeTime,
    UpstreamTlsHandshakeTimeHuman,
    UpstreamConnectOffloadWaitTime,
    UpstreamConnectOffloadWaitTimeHuman,
    UpstreamConnectionTime,
    UpstreamConnectionTimeHuman,
    ConnectionTime,
    ConnectionTimeHuman,
    Location,
    ConnectionReused,
    TlsVersion,
    TlsCipher,
    TlsClientSubject,
    TlsClientFingerprint,
    TlsClientSerial,
    TlsClientVerified,
    Ja4,
    #[strum(serialize = "ja4_r")]
    Ja4R,
    #[strum(serialize = "ja4_o")]
    Ja4O,
    #[strum(serialize = "ja4_ro")]
    Ja4Ro,
    TlsHandshakeTime,
    TlsHandshakeTimeHuman,
    CompressionTime,
    CompressionTimeHuman,
    CompressionRatio,
    CacheLookupTime,
    CacheLookupTimeHuman,
    CacheLockTime,
    CacheLockTimeHuman,
    ServiceTime,
    ServiceTimeHuman,
}

/// Represents the state of a request/response cycle, tracking various metrics and properties
/// including connection details, caching information, and upstream server interactions.
#[derive(Default)]
pub struct Ctx {
    /// Information about the client connection.
    pub conn: ConnectionInfo,
    /// Information about the upstream server.
    pub upstream: UpstreamInfo,
    /// Timing metrics for the request lifecycle.
    pub timing: Timing,
    /// State related to the current request.
    pub state: RequestState,
    /// Cache-related information. Boxed behind an `Option`: most requests
    /// never touch the cache, and a `None` costs a pointer instead of the
    /// whole struct on every `Ctx`.
    pub cache: Option<Box<CacheInfo>>,
    /// Optional features, boxed for the same reason.
    pub features: Option<Box<Features>>,
    /// Plugins for the current location, shared with the location's cache
    /// of resolved plugins so a request only bumps a reference count.
    pub plugins: Option<Arc<[NamedPlugin]>>,
    /// The same list, left here while the request plugins run when one of
    /// them asks to see the responses of the others
    /// (`handles_plugin_response`), for a plugin that writes its response
    /// itself: see [`crate::decorate_plugin_response`].
    pub response_plugins: Option<Arc<[NamedPlugin]>>,
}

/// Helper struct to store connection timing and TLS details
#[derive(Debug, Default)]
pub struct DigestDetail {
    /// A guess at reuse: the connection was established more than 100 ms
    /// before this request. It is only a guess - a slow client or a long TLS
    /// handshake trips it on a brand-new connection - so the proxy takes the
    /// exact keepalive signal pingora gives it for HTTP/1 and applies this
    /// only to HTTP/2, where streams share one connection with no signal.
    pub connection_reused: bool,
    /// Age of the connection in milliseconds, wall clock.
    pub connection_time: u64,
    /// Timestamp when TCP connection was established
    pub tcp_established: u64,
    /// Timestamp when TLS handshake completed
    pub tls_established: u64,
    /// TCP connect time in milliseconds, measured by pingora on a monotonic
    /// clock. Only a connection this side opened has one; an accepted
    /// connection reports `None`.
    pub tcp_connect: Option<u64>,
    /// TLS handshake time in milliseconds, measured by pingora on a monotonic
    /// clock around the handshake itself; `None` without TLS or when it was
    /// not measured.
    pub tls_handshake: Option<u64>,
    /// Time the connect spent queued for an offload thread, in milliseconds.
    /// `None` unless the connect was offloaded.
    pub connect_offload_wait: Option<u64>,
    /// TLS protocol version if using HTTPS
    pub tls_version: Option<Cow<'static, str>>,
    /// TLS cipher suite in use if using HTTPS
    pub tls_cipher: Option<Cow<'static, str>>,
    /// The certificate of the peer, where the listener's handshake kept
    /// one for the connection.
    pub tls_client_cert: Option<Arc<TlsClientCert>>,
}

#[inline]
pub(crate) fn timing_to_ms(timing: Option<&Option<TimingDigest>>) -> u64 {
    match timing {
        Some(Some(item)) => item
            .established_ts
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
        _ => 0,
    }
}

/// Extracts timing and TLS information from connection digest.
/// Used for metrics and logging connection details.
#[inline]
pub fn get_digest_detail(digest: &Digest) -> DigestDetail {
    let tcp_established = timing_to_ms(digest.timing_digest.first());
    let mut connection_time = 0;
    let now = now_ms();
    if tcp_established > 0 && tcp_established < now {
        connection_time = now - tcp_established;
    }
    let connection_reused = connection_time > 100;
    // The first entry is the transport layer, the last one the outermost
    // layer - the TLS session when there is one, otherwise the transport
    // layer again, which is why the handshake is only read under TLS.
    let tcp_connect = establishment_ms(digest.timing_digest.first());
    let connect_offload_wait = offload_wait_ms(digest.timing_digest.first());

    let Some(ssl_digest) = &digest.ssl_digest else {
        return DigestDetail {
            connection_reused,
            tcp_established,
            connection_time,
            tcp_connect,
            connect_offload_wait,
            ..Default::default()
        };
    };

    DigestDetail {
        connection_reused,
        tcp_established,
        connection_time,
        tcp_connect,
        connect_offload_wait,
        tls_established: timing_to_ms(digest.timing_digest.last()),
        tls_handshake: establishment_ms(digest.timing_digest.last()),
        // Clone the Cow: Borrowed(&'static str) is allocation-free.
        tls_version: Some(ssl_digest.version.clone()),
        tls_cipher: Some(ssl_digest.cipher.clone()),
        // Made once, when the handshake was done: a request takes a
        // reference to it.
        tls_client_cert: ssl_digest
            .extension
            .get::<Arc<TlsClientCert>>()
            .cloned(),
    }
}

/// The layer's own establishment time, when pingora measured it.
fn establishment_ms(timing: Option<&Option<TimingDigest>>) -> Option<u64> {
    timing
        .and_then(|item| item.as_ref())
        .and_then(|item| item.establishment_duration)
        .map(|duration| duration.as_millis() as u64)
}

/// How long the transport connect waited for an offload thread, when it was
/// offloaded at all.
fn offload_wait_ms(timing: Option<&Option<TimingDigest>>) -> Option<u64> {
    timing
        .and_then(|item| item.as_ref())
        .and_then(|item| item.offload_wait_duration)
        .map(|duration| duration.as_millis() as u64)
}

impl Ctx {
    /// Creates a new Ctx instance with the current timestamp and default values.
    ///
    /// Returns a new Ctx struct initialized with the current timestamp and all other fields
    /// set to their default values.
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    /// Adds a variable to the state's variables map with the given key and value.
    ///
    /// # Arguments
    /// * `key` - The variable name.
    /// * `value` - The value to store for this variable.
    #[inline]
    pub fn add_variable(&mut self, key: &str, value: &str) {
        // Lazily initialize features and variables map.
        let features = self.features.get_or_insert_default();
        let variables = features.variables.get_or_insert_with(AHashMap::new);
        variables.insert(key.to_string(), value.to_string());
    }

    /// Extends the variables map with the given key-value pairs.
    ///
    /// # Arguments
    /// * `values` - A HashMap containing the key-value pairs to add.
    #[inline]
    pub fn extend_variables(&mut self, values: AHashMap<String, String>) {
        let features = self.features.get_or_insert_default();
        if let Some(variables) = features.variables.as_mut() {
            variables.extend(values);
        } else {
            features.variables = Some(values);
        }
    }

    /// Returns the value of a variable by key.
    ///
    /// # Arguments
    /// * `key` - The key of the variable to retrieve.
    ///
    /// Returns: Option<&str> representing the value of the variable, or None if the variable does not exist.
    #[inline]
    pub fn get_variable(&self, key: &str) -> Option<&str> {
        self.features
            .as_ref()?
            .variables
            .as_ref()?
            .get(key)
            .map(|v| v.as_str())
    }

    /// Keeps `note` for the plugin that calls itself `name`, until the
    /// request ends.
    ///
    /// For a decision that is made once and has to hold: the request a
    /// later step sees is not the one the first step saw - a location
    /// rewrites the path, another plugin takes a parameter out of the
    /// query or changes a header - and a plugin that decided again from
    /// what is there then could come to the other answer.
    #[inline]
    pub fn set_plugin_note(&mut self, name: &str, note: &'static str) {
        let notes = self
            .features
            .get_or_insert_default()
            .plugin_notes
            .get_or_insert_default();
        match notes.iter_mut().find(|(key, _)| key == name) {
            Some(found) => found.1 = note,
            None => notes.push((name.to_string(), note)),
        }
    }

    /// What [`Ctx::set_plugin_note`] kept under `name`.
    #[inline]
    pub fn get_plugin_note(&self, name: &str) -> Option<&'static str> {
        self.features
            .as_ref()?
            .plugin_notes
            .as_ref()?
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, note)| *note)
    }

    /// Adds a modify body handler to the context.
    ///
    /// # Arguments
    /// * `name` - The name of the handler.
    /// * `handler` - The handler to add.
    #[inline]
    pub fn add_modify_body_handler(
        &mut self,
        name: &str,
        handler: Box<dyn ModifyResponseBody>,
    ) {
        let features = self.features.get_or_insert_default();
        let handlers = features
            .modify_body_handlers
            .get_or_insert_with(AHashMap::new);
        handlers.insert(name.to_string(), handler);
    }

    /// Returns the modify body handler by name.
    #[inline]
    pub fn get_modify_body_handler(
        &mut self,
        name: &str,
    ) -> Option<&mut Box<dyn ModifyResponseBody>> {
        self.features
            .as_mut()
            .and_then(|f| f.modify_body_handlers.as_mut())
            .and_then(|h| h.get_mut(name))
    }

    // A private helper function to filter out time values that are too large (over an hour),
    // which might indicate an error or uninitialized state.
    #[inline]
    fn get_time_field(&self, field: Option<i32>) -> Option<u32> {
        if let Some(value) = field
            && value >= 0
        {
            return Some(value as u32);
        }
        None
    }

    /// Returns the upstream response time if it's less than one hour, otherwise None.
    /// This helps filter out potentially invalid or stale timing data.
    ///
    /// Returns: Option<u64> representing milliseconds, or None if time exceeds 1 hour.
    #[inline]
    pub fn get_upstream_response_time(&self) -> Option<u32> {
        self.get_time_field(self.timing.upstream_response)
    }

    /// Returns the upstream connect time if it's less than one hour, otherwise None.
    /// This helps filter out potentially invalid or stale timing data.
    ///
    /// Returns: Option<u64> representing milliseconds, or None if time exceeds 1 hour.
    #[inline]
    pub fn get_upstream_connect_time(&self) -> Option<u32> {
        self.get_time_field(self.timing.upstream_connect)
    }

    /// Returns the upstream processing time if it's less than one hour, otherwise None.
    /// This helps filter out potentially invalid or stale timing data.
    ///
    /// Returns: Option<u64> representing milliseconds, or None if time exceeds 1 hour.
    #[inline]
    pub fn get_upstream_processing_time(&self) -> Option<u32> {
        self.get_time_field(self.timing.upstream_processing)
    }

    /// Adds a plugin processing time to the context.
    ///
    /// # Arguments
    /// * `name` - The name of the plugin.
    /// * `time` - The time taken by the plugin in milliseconds.
    #[inline]
    pub fn add_plugin_processing_time(&mut self, name: &Arc<str>, time: u32) {
        // Lazily initialize features and the processing times vector.
        let features = self.features.get_or_insert_default();
        let times = features
            .plugin_processing_times
            .get_or_insert_with(|| Vec::with_capacity(5));
        if let Some(item) = times.iter_mut().find(|item| &item.0 == name) {
            item.1 += time;
        } else {
            times.push((Arc::clone(name), time));
        }
    }

    /// Appends a formatted value to the provided log buffer based on the given key.
    /// Handles various metrics including connection info, timing data, and TLS details.
    ///
    /// Resolves `key` on every call; a caller that knows the key ahead of
    /// time (the access log format) should parse it into a [`CtxLogField`]
    /// once and use [`Ctx::append_log_field`].
    ///
    /// # Arguments
    /// * `buf` - The BytesMut buffer to append the value to.
    /// * `key` - The key identifying which state value to format and append.
    #[inline]
    pub fn append_log_value(&self, buf: &mut BytesMut, key: &str) {
        // Unknown keys append nothing.
        if let Ok(field) = key.parse::<CtxLogField>() {
            self.append_log_field(buf, field);
        }
    }

    /// Appends the value of `field` to the log buffer.
    pub fn append_log_field(&self, buf: &mut BytesMut, field: CtxLogField) {
        // A macro to simplify formatting and appending optional time values.
        macro_rules! append_time {
            // Append raw milliseconds.
            ($val:expr) => {
                if let Some(ms) = $val {
                    buf.extend(itoa::Buffer::new().format(ms).as_bytes());
                }
            };
            // Append human-readable formatted time.
            ($val:expr, human) => {
                if let Some(ms) = $val {
                    format_duration(buf, ms as u64);
                }
            };
        }

        match field {
            CtxLogField::ConnectionId => {
                buf.extend(itoa::Buffer::new().format(self.conn.id).as_bytes());
            },
            CtxLogField::UpstreamReused => {
                if self.upstream.reused {
                    buf.extend(b"true");
                } else {
                    buf.extend(b"false");
                }
            },
            CtxLogField::UpstreamStatus => {
                if let Some(status) = &self.upstream.status {
                    buf.extend_from_slice(status.as_str().as_bytes());
                } else {
                    buf.extend_from_slice(b"-");
                }
            },
            CtxLogField::UpstreamAddr => {
                buf.extend(self.upstream.address.as_bytes())
            },
            CtxLogField::Processing => buf.extend(
                itoa::Buffer::new()
                    .format(self.state.processing_count)
                    .as_bytes(),
            ),
            CtxLogField::UpstreamConnected => {
                if let Some(value) = self.upstream.connected_count {
                    buf.extend(itoa::Buffer::new().format(value).as_bytes());
                }
            },

            // Timing fields
            CtxLogField::UpstreamConnectTime => {
                append_time!(self.get_upstream_connect_time())
            },
            CtxLogField::UpstreamConnectTimeHuman => {
                append_time!(self.get_upstream_connect_time(), human)
            },

            CtxLogField::UpstreamProcessingTime => {
                append_time!(self.get_upstream_processing_time())
            },
            CtxLogField::UpstreamProcessingTimeHuman => {
                append_time!(self.get_upstream_processing_time(), human)
            },
            CtxLogField::UpstreamResponseTime => {
                append_time!(self.get_upstream_response_time())
            },
            CtxLogField::UpstreamResponseTimeHuman => {
                append_time!(self.get_upstream_response_time(), human)
            },
            CtxLogField::UpstreamTcpConnectTime => {
                append_time!(self.timing.upstream_tcp_connect)
            },
            CtxLogField::UpstreamTcpConnectTimeHuman => {
                append_time!(self.timing.upstream_tcp_connect, human)
            },
            CtxLogField::UpstreamTlsHandshakeTime => {
                append_time!(self.timing.upstream_tls_handshake)
            },
            CtxLogField::UpstreamTlsHandshakeTimeHuman => {
                append_time!(self.timing.upstream_tls_handshake, human)
            },
            CtxLogField::UpstreamConnectOffloadWaitTime => {
                append_time!(self.timing.upstream_connect_offload_wait)
            },
            CtxLogField::UpstreamConnectOffloadWaitTimeHuman => {
                append_time!(self.timing.upstream_connect_offload_wait, human)
            },
            CtxLogField::UpstreamConnectionTime => {
                append_time!(self.timing.upstream_connection_duration)
            },
            CtxLogField::UpstreamConnectionTimeHuman => {
                append_time!(self.timing.upstream_connection_duration, human)
            },
            CtxLogField::ConnectionTime => {
                append_time!(Some(self.timing.connection_duration))
            },
            CtxLogField::ConnectionTimeHuman => {
                append_time!(Some(self.timing.connection_duration), human)
            },

            // Other fields
            CtxLogField::Location => {
                if !self.upstream.location.is_empty() {
                    buf.extend(self.upstream.location.as_bytes())
                }
            },
            CtxLogField::ConnectionReused => {
                if self.conn.reused {
                    buf.extend(b"true");
                } else {
                    buf.extend(b"false");
                }
            },
            CtxLogField::TlsVersion => {
                if let Some(value) = &self.conn.tls_version {
                    buf.extend(value.as_bytes());
                }
            },
            CtxLogField::TlsCipher => {
                if let Some(value) = &self.conn.tls_cipher {
                    buf.extend(value.as_bytes());
                }
            },
            CtxLogField::TlsClientSubject => {
                if let Some(cert) = &self.conn.tls_client_cert {
                    buf.extend(cert.subject.as_bytes());
                }
            },
            CtxLogField::TlsClientFingerprint => {
                if let Some(cert) = &self.conn.tls_client_cert {
                    buf.extend(cert.fingerprint.as_bytes());
                }
            },
            CtxLogField::TlsClientSerial => {
                if let Some(cert) = &self.conn.tls_client_cert {
                    buf.extend(cert.serial.as_bytes());
                }
            },
            CtxLogField::TlsClientVerified => {
                if self.conn.tls_client_cert.is_some() {
                    buf.extend(b"true");
                } else {
                    buf.extend(b"false");
                }
            },
            CtxLogField::Ja4 => {
                if let Some(fingerprint) = &self.conn.ja4 {
                    buf.extend(fingerprint.ja4().as_bytes());
                }
            },
            CtxLogField::Ja4R => {
                if let Some(fingerprint) = &self.conn.ja4 {
                    buf.extend(fingerprint.ja4_r().as_bytes());
                }
            },
            CtxLogField::Ja4O => {
                if let Some(fingerprint) = &self.conn.ja4 {
                    buf.extend(fingerprint.ja4_o().as_bytes());
                }
            },
            CtxLogField::Ja4Ro => {
                if let Some(fingerprint) = &self.conn.ja4 {
                    buf.extend(fingerprint.ja4_ro().as_bytes());
                }
            },
            CtxLogField::TlsHandshakeTime => {
                append_time!(self.timing.tls_handshake)
            },
            CtxLogField::TlsHandshakeTimeHuman => {
                append_time!(self.timing.tls_handshake, human)
            },
            CtxLogField::CompressionTime => {
                if let Some(feature) = &self.features
                    && let Some(value) = &feature.compression_stat
                {
                    append_time!(Some(value.duration.as_millis() as u64))
                }
            },
            CtxLogField::CompressionTimeHuman => {
                if let Some(feature) = &self.features
                    && let Some(value) = &feature.compression_stat
                {
                    append_time!(Some(value.duration.as_millis() as u64), human)
                }
            },
            CtxLogField::CompressionRatio => {
                if let Some(feature) = &self.features
                    && let Some(value) = &feature.compression_stat
                {
                    // One decimal place without allocating via `format!`.
                    let tenths = (value.ratio() * 10.0).round() as u64;
                    buf.extend(
                        itoa::Buffer::new().format(tenths / 10).as_bytes(),
                    );
                    buf.extend_from_slice(b".");
                    buf.extend(
                        itoa::Buffer::new().format(tenths % 10).as_bytes(),
                    );
                }
            },
            CtxLogField::CacheLookupTime => {
                append_time!(self.timing.cache_lookup)
            },
            CtxLogField::CacheLookupTimeHuman => {
                append_time!(self.timing.cache_lookup, human)
            },
            CtxLogField::CacheLockTime => {
                append_time!(self.timing.cache_lock)
            },
            CtxLogField::CacheLockTimeHuman => {
                append_time!(self.timing.cache_lock, human)
            },
            CtxLogField::ServiceTime => {
                append_time!(Some(self.timing.created_at.elapsed().as_millis()))
            },
            CtxLogField::ServiceTimeHuman => {
                append_time!(
                    Some(self.timing.created_at.elapsed().as_millis()),
                    human
                )
            },
        }
    }

    /// Generates a Server-Timing header value based on the context's timing metrics.
    ///
    /// The Server-Timing header allows servers to communicate performance metrics
    /// about the request-response cycle to the client. This implementation includes
    /// various timing metrics like connection time, processing time, and cache operations.
    ///
    /// Returns a String containing the formatted Server-Timing header value.
    pub fn generate_server_timing(&self) -> String {
        let mut timing_str = String::with_capacity(200);
        // Flag to track if this is the first timing entry, to handle commas correctly.
        let mut first = true;

        // Macro to add a timing entry to the string.
        macro_rules! add_timing {
            ($name:expr, $dur:expr) => {
                if !first {
                    timing_str.push_str(", ");
                }
                // Ignore the write! result as it's unlikely to fail with a String.
                let _ = write!(&mut timing_str, "{};dur={}", $name, $dur);
                first = false;
            };
        }

        // Aggregate and add upstream timings.
        let mut upstream_time = 0;
        if let Some(time) = self.get_upstream_connect_time() {
            upstream_time += time;
            add_timing!("upstream.connect", time);
        }
        if let Some(time) = self.get_upstream_processing_time() {
            upstream_time += time;
            add_timing!("upstream.processing", time);
        }
        if upstream_time > 0 {
            add_timing!("upstream", upstream_time);
        }

        // Aggregate and add cache timings.
        let mut cache_time = 0;
        if let Some(time) = self.timing.cache_lookup {
            cache_time += time;
            add_timing!("cache.lookup", time);
        }
        if let Some(time) = self.timing.cache_lock {
            cache_time += time;
            add_timing!("cache.lock", time);
        }
        if cache_time > 0 {
            add_timing!("cache", cache_time);
        }

        // Aggregate and add plugin timings.
        if let Some(features) = &self.features
            && let Some(times) = &features.plugin_processing_times
        {
            let mut plugin_time: u32 = 0;
            for (name, time) in times {
                if *time == 0 {
                    continue;
                }
                plugin_time += time;
                // Write directly into the shared buffer — avoid a per-plugin
                // temporary `"plugin." + name` String.
                if !first {
                    timing_str.push_str(", ");
                }
                let _ = write!(&mut timing_str, "plugin.{name};dur={time}");
                first = false;
            }
            if plugin_time > 0 {
                add_timing!("plugin", plugin_time);
            }
        }

        // Add the total service time, which is always present.
        let service_time = self.timing.created_at.elapsed().as_millis();
        // Add a separator if other timings were already added.
        if !first {
            timing_str.push_str(", ");
        }
        // Write the final timing directly.
        let _ = write!(&mut timing_str, "total;dur={}", service_time);

        timing_str
    }

    /// Pushes a single cache key component to the context.
    #[inline]
    pub fn push_cache_key(&mut self, key: String) {
        let cache_info = self.cache.get_or_insert_default();
        cache_info
            .keys
            .get_or_insert_with(|| Vec::with_capacity(2))
            .push(key);
    }

    /// Extends the cache key components with a vector of keys.
    #[inline]
    pub fn extend_cache_keys(&mut self, keys: Vec<String>) {
        let cache_info = self.cache.get_or_insert_default();
        cache_info
            .keys
            .get_or_insert_with(|| Vec::with_capacity(keys.len() + 2))
            .extend(keys);
    }
    /// Adds `current` to the cache key as the one of `alternatives` this
    /// request stands for. It may be empty: the place is noted all the
    /// same, for the request that has to know what else could be there.
    #[inline]
    pub fn push_cache_key_variant(
        &mut self,
        current: Vec<String>,
        alternatives: Arc<Vec<Vec<String>>>,
    ) {
        let cache_info = self.cache.get_or_insert_default();
        let keys = cache_info
            .keys
            .get_or_insert_with(|| Vec::with_capacity(current.len() + 2));
        cache_info
            .key_variants
            .get_or_insert_default()
            .push(CacheKeyVariant {
                at: keys.len(),
                len: current.len(),
                alternatives,
            });
        keys.extend(current);
    }

    /// Every list of key components a request for this url can have: the
    /// one of this request, with each [`CacheKeyVariant`] in it replaced by
    /// each of its alternatives. The list of this request itself when it
    /// has no variants, or when there would be too many lists to go
    /// through.
    pub fn cache_key_alternatives(&self) -> Vec<Vec<String>> {
        /// More than any sensible set of plugins gives: the codings times
        /// the selections of four image formats is 64.
        const MAX_ALTERNATIVES: usize = 1024;
        let Some(cache_info) = &self.cache else {
            return vec![vec![]];
        };
        let keys = cache_info.keys.as_deref().unwrap_or_default();
        let variants = cache_info.key_variants.as_deref().unwrap_or_default();
        let count = variants.iter().try_fold(1usize, |count, variant| {
            count.checked_mul(variant.alternatives.len().max(1))
        });
        if variants.is_empty() {
            return vec![keys.to_vec()];
        }
        if count.is_none_or(|n| n > MAX_ALTERNATIVES) {
            // Said, since whoever asked goes on with less than all of them.
            tracing::warn!(
                target: "pingap::core",
                variants = variants.len(),
                "too many cache key alternatives, only the key of this request is used"
            );
            return vec![keys.to_vec()];
        }
        let mut lists = vec![Vec::with_capacity(keys.len())];
        let mut cursor = 0;
        for variant in variants {
            // What other plugins put in between is the same in all of them.
            let fixed = keys.get(cursor..variant.at).unwrap_or_default();
            lists = lists
                .into_iter()
                .flat_map(|list: Vec<String>| {
                    variant.alternatives.iter().map(move |alternative| {
                        let mut list = list.clone();
                        list.extend_from_slice(fixed);
                        list.extend_from_slice(alternative);
                        list
                    })
                })
                .collect();
            cursor = variant.at + variant.len;
        }
        let rest = keys.get(cursor..).unwrap_or_default();
        for list in lists.iter_mut() {
            list.extend_from_slice(rest);
        }
        lists
    }

    /// Updates the upstream timing from the digest.
    #[inline]
    pub fn update_upstream_timing_from_digest(
        &mut self,
        digest: &Digest,
        reused: bool,
    ) {
        let detail = get_digest_detail(digest);
        self.timing.upstream_connection_duration = Some(detail.connection_time);
        if reused {
            return;
        }

        // pingora times each layer on a monotonic clock: the TCP connect on
        // the transport entry, the handshake on the TLS entry. Prefer those.
        if let Some(tcp_connect) = detail.tcp_connect {
            self.timing.upstream_tcp_connect = Some(tcp_connect as i32);
            self.timing.upstream_tls_handshake =
                detail.tls_handshake.map(|value| value as i32);
            self.timing.upstream_connect_offload_wait =
                detail.connect_offload_wait.map(|value| value as i32);
            return;
        }

        // Fallback for a stream that carries no measurement: split pingap's
        // own end-to-end connect timer by the wall-clock gap between the
        // layers' timestamps. Coarser, and the TCP share also absorbs
        // whatever the connector did around the connect.
        let upstream_connect_time =
            self.timing.upstream_connect.unwrap_or_default();
        let mut upstream_tcp_connect = upstream_connect_time;
        if detail.tls_established > detail.tcp_established {
            let latency =
                (detail.tls_established - detail.tcp_established) as i32;
            upstream_tcp_connect -= latency;
            self.timing.upstream_tls_handshake = Some(latency);
        }
        if upstream_tcp_connect > 0 {
            self.timing.upstream_tcp_connect = Some(upstream_tcp_connect);
        }
    }
}

/// Writes the host part of a cache key.
///
/// In lower case: a host name is case-insensitive, and one spelling keeps
/// `Example.com` from caching beside `example.com`. Anything that is not a
/// host name character is written as `%XX`. A `Host` header is whatever the
/// client sent, and written as it came `a.com/static` followed by the path
/// `/app.js` made the key of `a.com` and `/static/app.js`: one request
/// could store its response under the key of another url.
fn push_key_host(key: &mut String, host: &str) {
    for byte in host.bytes() {
        match byte {
            b'a'..=b'z'
            | b'0'..=b'9'
            | b'.'
            | b'-'
            | b'_'
            | b':'
            | b'['
            | b']' => key.push(byte as char),
            b'A'..=b'Z' => key.push(byte.to_ascii_lowercase() as char),
            _ => {
                let _ = write!(key, "%{byte:02X}");
            },
        }
    }
}

/// Generates the cache key of a request.
///
/// The primary is, in this order: the namespace, the custom keys (each
/// followed by `:`), the method, `:`, the host in lower case without its
/// port, then the path and the query. `user_tag` is the namespace.
///
/// The host is part of the key whatever the protocol. It used to come from
/// the request uri alone, which carries it in HTTP/2 but not in HTTP/1.1:
/// two domains behind one cache plugin answered with each other's pages
/// over HTTP/1.1, and a `PURGE` sent over one protocol missed what the other
/// had stored. Scheme and port are left out on purpose, so a `PURGE` sent
/// to an internal plain-http listener with the right `Host` clears what the
/// public https listener cached.
///
/// # Arguments
/// * `ctx` - The Ctx context containing cache configuration.
/// * `method` - The HTTP method as a string.
/// * `header` - The request the key is for: its host, path and query.
pub fn get_cache_key(
    ctx: &Ctx,
    method: &str,
    header: &RequestHeader,
) -> CacheKey {
    let Some(cache_info) = &ctx.cache else {
        // Return an empty key if cache is not configured for this context.
        return CacheKey::new("", "");
    };
    let namespace = cache_info.namespace.as_ref().map_or("", |v| v);
    // As it was sent, see `get_request_host`.
    let host = get_request_host(header).unwrap_or_default();
    let path = header.uri.path();
    // By the rule of the plugin where it has one: the query that was
    // settled when the key of the request was made, or, for a key that is
    // made of another request (a purge), the rule applied to that one.
    let made;
    let query = match (&cache_info.key_query, &cache_info.query_rule) {
        (Some(query), _) => (!query.is_empty()).then_some(query.as_str()),
        (None, Some(rule)) => {
            made = rule.key_query(header.uri.query().unwrap_or_default());
            (!made.is_empty()).then_some(made.as_str())
        },
        (None, None) => header.uri.query(),
    };
    // pingora's CacheKey used to take the namespace as its own argument and
    // hashed `namespace ++ primary` as one unframed byte string. That argument
    // is gone, so the namespace is written straight in front of the primary
    // here. The storage layer still partitions by namespace, so it also
    // travels in `user_tag`, which is carried alongside the key but never
    // hashed.
    let keys_len = cache_info
        .keys
        .as_ref()
        .map_or(0, |keys| keys.iter().map(|s| s.len() + 1).sum::<usize>());
    let mut key_buf = String::with_capacity(
        namespace.len()
            + keys_len
            + method.len()
            + 1
            + host.len()
            + path.len()
            + query.map_or(0, |query| query.len() + 1),
    );
    key_buf.push_str(namespace);
    // Custom key components first, each followed by ':'.
    if let Some(keys) = &cache_info.keys {
        for k in keys {
            key_buf.push_str(k);
            key_buf.push(':');
        }
    }
    // Then "METHOD:host/path?query".
    key_buf.push_str(method);
    key_buf.push(':');
    push_key_host(&mut key_buf, host);
    key_buf.push_str(path);
    if let Some(query) = query {
        key_buf.push('?');
        key_buf.push_str(query);
    }

    CacheKey::new(key_buf, namespace)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use bytes::BytesMut;
    use http::Uri;
    use pingora::cache::key::CacheHashKey;
    use pingora::protocols::tls::SslDigest;
    use pingora::protocols::tls::SslDigestExtension;
    use pretty_assertions::assert_eq;
    use std::{sync::Arc, time::Duration};

    /// A `PURGE` names a url and no coding or image format: it has to
    /// find the key of every request that named one.
    #[test]
    fn test_ask_with_key_query() {
        let ask = |uri: &str, key_query: Option<&str>| {
            let mut header = RequestHeader::build("GET", b"/", None).unwrap();
            header.set_uri(uri.parse().unwrap());
            let info = CacheInfo {
                key_query: key_query.map(str::to_string),
                ..Default::default()
            };
            assert_eq!(true, info.ask_with_key_query(&mut header));
            header.uri.to_string()
        };
        // no rule for the query: the request is sent as it came
        assert_eq!("/a?b=2&a=1", ask("/a?b=2&a=1", None));
        // the query of the key, whatever else the client sent
        assert_eq!(
            "/a?a=1&b=2",
            ask("/a?b=2&utm_source=x&a=1", Some("a=1&b=2"))
        );
        // spellings the rule does not know do not reach the upstream
        assert_eq!("/list", ask("/list?p%61ge=2", Some("")));
        assert_eq!("/list", ask("/list?x=1;page=2", Some("")));
        assert_eq!(
            "/list?size=10",
            ask("/list?Page=2&size=10", Some("size=10"))
        );
        // nothing to change
        assert_eq!("/a?a=1", ask("/a?a=1", Some("a=1")));
        assert_eq!("/a", ask("/a", Some("")));
        // an empty query is no query, as in the key
        assert_eq!("/a", ask("/a?", Some("")));

        // The query is settled when the key is made, from the request as
        // it is by then; until then the rule is what is applied.
        let rule =
            Arc::new(CacheQueryRule::Ignore(vec!["utm_source".to_string()]));
        let mut info = CacheInfo {
            query_rule: Some(rule),
            ..Default::default()
        };
        let mut header = RequestHeader::build("GET", b"/", None).unwrap();
        header.set_uri("/a?b=2&utm_source=x&a=1".parse().unwrap());
        let mut upstream = header.clone();
        assert_eq!(true, info.ask_with_key_query(&mut upstream));
        assert_eq!("/a?a=1&b=2", upstream.uri.to_string());
        // a plugin after the cache took a parameter out
        header.set_uri("/a?utm_source=x&a=1".parse().unwrap());
        info.settle_key_query(&header);
        assert_eq!(Some("a=1".to_string()), info.key_query);
        let mut ctx = Ctx {
            cache: Some(Box::new(info)),
            ..Default::default()
        };
        assert_eq!(
            Some("GET:/a?a=1"),
            get_cache_key(&ctx, "GET", &header).primary_key_str()
        );
        // and a key that is made of another request goes by the rule
        if let Some(info) = ctx.cache.as_mut() {
            info.key_query = None;
        }
        header.set_uri("/a?z=9&utm_source=x&b=1".parse().unwrap());
        assert_eq!(
            Some("GET:/a?b=1&z=9"),
            get_cache_key(&ctx, "GET", &header).primary_key_str()
        );
        // the rest of the uri is kept (HTTP/2 carries the authority)
        assert_eq!(
            "https://example.com/a?a=1",
            ask("https://example.com/a?z=9&a=1", Some("a=1"))
        );
    }

    #[test]
    fn test_cache_key_alternatives() {
        let list = |items: &[&str]| {
            items
                .iter()
                .map(|item| item.to_string())
                .collect::<Vec<_>>()
        };
        let mut ctx = Ctx::default();
        assert_eq!(vec![list(&[])], ctx.cache_key_alternatives());

        ctx.push_cache_key("fixed".to_string());
        assert_eq!(vec![list(&["fixed"])], ctx.cache_key_alternatives());

        ctx.push_cache_key_variant(
            list(&["gzip"]),
            Arc::new(vec![list(&[]), list(&["gzip"]), list(&["br"])]),
        );
        ctx.push_cache_key("lang".to_string());
        // Nothing of this one in the key of this request.
        ctx.push_cache_key_variant(
            list(&[]),
            Arc::new(vec![list(&[]), list(&["avif", "webp"])]),
        );
        assert_eq!(
            Some(list(&["fixed", "gzip", "lang"])),
            ctx.cache.as_ref().unwrap().keys
        );
        assert_eq!(
            vec![
                list(&["fixed", "lang"]),
                list(&["fixed", "lang", "avif", "webp"]),
                list(&["fixed", "gzip", "lang"]),
                list(&["fixed", "gzip", "lang", "avif", "webp"]),
                list(&["fixed", "br", "lang"]),
                list(&["fixed", "br", "lang", "avif", "webp"]),
            ],
            ctx.cache_key_alternatives()
        );

        // Too many to go through: the key of the request itself.
        let many: Vec<_> =
            (0..40).map(|index| vec![index.to_string()]).collect();
        let mut ctx = Ctx::default();
        ctx.push_cache_key_variant(list(&["1"]), Arc::new(many.clone()));
        ctx.push_cache_key_variant(list(&["2"]), Arc::new(many));
        assert_eq!(vec![list(&["1", "2"])], ctx.cache_key_alternatives());
    }

    #[test]
    fn test_ctx_new() {
        let ctx = Ctx::new();
        // Check that created_at is a recent timestamp.
        // It should be within the last 100ms.
        let elapsed_ms = ctx.timing.created_at.elapsed().as_millis();
        assert!(elapsed_ms < 100, "created_at should be a recent timestamp");
        // Check that other fields are correctly defaulted.
        assert!(ctx.cache.is_none());
        assert!(ctx.features.is_none());
        assert_eq!(ctx.conn.id, 0);
    }

    /// Tests both adding and getting variables.
    /// The certificate of a client in the access log, and that there is
    /// nothing to print without one.
    #[test]
    fn test_tls_client_cert_log_fields() {
        let mut ctx = Ctx::new();
        let print = |ctx: &Ctx, key: &str| {
            let mut buf = BytesMut::new();
            ctx.append_log_value(&mut buf, key);
            String::from_utf8_lossy(&buf).to_string()
        };
        assert_eq!("", print(&ctx, "tls_client_subject"));
        assert_eq!("false", print(&ctx, "tls_client_verified"));
        ctx.conn.tls_client_cert = Some(Arc::new(TlsClientCert {
            subject: "O=Example, CN=device-42".to_string(),
            fingerprint: "b545db7a".to_string(),
            serial: "3429".to_string(),
        }));
        assert_eq!(
            "O=Example, CN=device-42",
            print(&ctx, "tls_client_subject")
        );
        assert_eq!("b545db7a", print(&ctx, "tls_client_fingerprint"));
        assert_eq!("3429", print(&ctx, "tls_client_serial"));
        assert_eq!("true", print(&ctx, "tls_client_verified"));
    }

    #[test]
    fn test_plugin_notes() {
        let mut ctx = Ctx::new();
        assert_eq!(None, ctx.get_plugin_note("a"));
        ctx.set_plugin_note("a", "gzip");
        ctx.set_plugin_note("b", "");
        assert_eq!(Some("gzip"), ctx.get_plugin_note("a"));
        assert_eq!(Some(""), ctx.get_plugin_note("b"));
        assert_eq!(None, ctx.get_plugin_note("c"));
        // The last one said is the one kept.
        ctx.set_plugin_note("a", "br");
        assert_eq!(Some("br"), ctx.get_plugin_note("a"));
        assert_eq!(
            2,
            ctx.features
                .as_ref()
                .unwrap()
                .plugin_notes
                .as_ref()
                .unwrap()
                .len()
        );
    }

    #[test]
    fn test_add_and_get_variable() {
        let mut ctx = Ctx::new();
        assert!(
            ctx.get_variable("key1").is_none(),
            "Should be None before adding"
        );

        ctx.add_variable("key1", "value1");
        ctx.add_variable("key2", "value2");

        assert_eq!(ctx.get_variable("key1"), Some("value1"));
        assert_eq!(ctx.get_variable("key2"), Some("value2"));
        assert_eq!(ctx.get_variable("nonexistent"), None);
    }

    /// Tests the helper functions for getting filtered time values.
    #[test]
    fn test_get_time_field() {
        let mut ctx = Ctx::new();

        // Test with a valid time
        ctx.timing.upstream_response = Some(100);
        assert_eq!(ctx.get_upstream_response_time(), Some(100));

        // Test with a time is negative
        ctx.timing.upstream_response = Some(-1);
        assert_eq!(
            ctx.get_upstream_response_time(),
            None,
            "Time exceeding one hour should be None"
        );

        // Test with None
        ctx.timing.upstream_response = None;
        assert_eq!(ctx.get_upstream_response_time(), None);
    }

    /// Every log field name round-trips through the enum, and the two
    /// entry points agree.
    #[test]
    fn test_ctx_log_field_names() {
        for (name, field) in [
            ("connection_id", CtxLogField::ConnectionId),
            (
                "upstream_tcp_connect_time_human",
                CtxLogField::UpstreamTcpConnectTimeHuman,
            ),
            (
                "upstream_connect_offload_wait_time",
                CtxLogField::UpstreamConnectOffloadWaitTime,
            ),
            ("tls_version", CtxLogField::TlsVersion),
            ("tls_client_subject", CtxLogField::TlsClientSubject),
            ("tls_client_fingerprint", CtxLogField::TlsClientFingerprint),
            ("tls_client_serial", CtxLogField::TlsClientSerial),
            ("tls_client_verified", CtxLogField::TlsClientVerified),
            ("ja4", CtxLogField::Ja4),
            ("ja4_r", CtxLogField::Ja4R),
            ("ja4_o", CtxLogField::Ja4O),
            ("ja4_ro", CtxLogField::Ja4Ro),
            ("compression_ratio", CtxLogField::CompressionRatio),
            ("service_time_human", CtxLogField::ServiceTimeHuman),
        ] {
            assert_eq!(Ok(field), name.parse::<CtxLogField>(), "{name}");
            assert_eq!(name, field.to_string());
        }
        assert_eq!(true, "unknown_key".parse::<CtxLogField>().is_err());

        let mut ctx = Ctx::new();
        ctx.conn.id = 7;
        let mut by_name = BytesMut::new();
        ctx.append_log_value(&mut by_name, "connection_id");
        let mut by_field = BytesMut::new();
        ctx.append_log_field(&mut by_field, CtxLogField::ConnectionId);
        assert_eq!(b"7", by_name.as_ref());
        assert_eq!(by_name, by_field);
    }

    /// The JA4 fields print the connection's fingerprint in each form,
    /// and nothing when there is none.
    #[test]
    fn test_ja4_log_fields() {
        let mut ctx = Ctx::new();
        let value = |ctx: &Ctx, key: &str| {
            let mut buf = BytesMut::new();
            ctx.append_log_value(&mut buf, key);
            String::from_utf8(buf.to_vec()).unwrap()
        };
        assert_eq!("", value(&ctx, "ja4"));
        let fingerprint = Ja4Fingerprint::from_client_hello(
            &crate::ja4::testing::spec_example_body(),
        )
        .unwrap();
        ctx.conn.ja4 = Some(Arc::new(fingerprint.clone()));
        assert_eq!("t13d1516h2_8daaf6152771_e5627efa2ab1", value(&ctx, "ja4"));
        assert_eq!(fingerprint.ja4_r(), value(&ctx, "ja4_r"));
        assert_eq!(fingerprint.ja4_o(), value(&ctx, "ja4_o"));
        assert_eq!(fingerprint.ja4_ro(), value(&ctx, "ja4_ro"));
    }

    /// Tests the `append_log_value` function with a wider range of keys and edge cases.
    #[test]
    fn test_append_log_value_coverage() {
        let mut ctx = Ctx::new();
        // Test an unknown key, should do nothing.
        let mut buf = BytesMut::new();
        ctx.append_log_value(&mut buf, "unknown_key");
        assert!(buf.is_empty(), "Unknown key should not append anything");

        // Test boolean values
        buf = BytesMut::new();
        ctx.conn.reused = true;
        ctx.append_log_value(&mut buf, "connection_reused");
        assert_eq!(&buf[..], b"true");

        // Test optional string values
        ctx.conn.tls_version = Some("TLSv1.3".into());
        buf = BytesMut::new();
        ctx.append_log_value(&mut buf, "tls_version");
        assert_eq!(&buf[..], b"TLSv1.3");

        // Test service_time calculation
        std::thread::sleep(Duration::from_millis(11));
        buf = BytesMut::new();
        ctx.append_log_value(&mut buf, "service_time");
        let service_time: u64 =
            std::str::from_utf8(&buf[..]).unwrap().parse().unwrap();
        assert!(service_time >= 10, "Service time should be at least 10ms");
    }

    /// Tests the `get_cache_key` function's logic more thoroughly.
    #[test]
    fn test_get_cache_key() {
        let method = "GET";
        // HTTP/2: the host is in the uri.
        let mut h2 = RequestHeader::build("GET", b"/", None).unwrap();
        h2.set_uri(Uri::from_static("https://example.com/path?a=1"));
        // HTTP/1.1: the uri is the path, the host is a header.
        let h1 = |host: &str, path: &str| {
            let mut header =
                RequestHeader::build("GET", path.as_bytes(), None).unwrap();
            header.insert_header("Host", host).unwrap();
            header
        };

        // Case 1: No cache info in context.
        let ctx_no_cache = Ctx::new();
        let key1 = get_cache_key(&ctx_no_cache, method, &h2);
        assert_eq!(key1.user_tag, "");
        assert_eq!(key1.primary_key_str(), Some(""));

        // Case 2: Cache info with namespace but no keys.
        let mut ctx_with_ns = Ctx::new();
        ctx_with_ns.cache = Some(Box::new(CacheInfo {
            namespace: Some("my-ns".to_string()),
            ..Default::default()
        }));
        let key2 = get_cache_key(&ctx_with_ns, method, &h2);
        assert_eq!(key2.user_tag, "my-ns");
        assert_eq!(
            key2.primary_key_str(),
            Some("my-nsGET:example.com/path?a=1")
        );
        // Changing what goes into the key makes every entry an older
        // pingap wrote to disk unreachable after the upgrade, so the hash
        // of a known key is pinned here.
        assert_eq!(key2.primary(), "8fe845e5498004cd81203be9074a8e68");

        // The same request over HTTP/1.1 is the same entry, whatever the
        // spelling of the host and whichever port it came in on.
        for host in ["example.com", "Example.COM", "example.com:8443"] {
            let key =
                get_cache_key(&ctx_with_ns, method, &h1(host, "/path?a=1"));
            assert_eq!(key2.primary(), key.primary(), "{host}");
        }
        // Regression: another host is another entry. Over HTTP/1.1 the host
        // used to be missing from the key.
        let other =
            get_cache_key(&ctx_with_ns, method, &h1("other.com", "/path?a=1"));
        assert_eq!(
            other.primary_key_str(),
            Some("my-nsGET:other.com/path?a=1")
        );
        assert_ne!(key2.primary(), other.primary());
        // Regression: the host is the client's to write, and must not be
        // able to stand in for a piece of the path. These two used to have
        // one key.
        let odd = get_cache_key(
            &ctx_with_ns,
            method,
            &h1("example.com/static", "/app.js"),
        );
        let plain = get_cache_key(
            &ctx_with_ns,
            method,
            &h1("example.com", "/static/app.js"),
        );
        assert_eq!(
            odd.primary_key_str(),
            Some("my-nsGET:example.com%2Fstatic/app.js")
        );
        assert_ne!(odd.primary(), plain.primary());
        // An escape of its own does not get it there either.
        let escaped = get_cache_key(
            &ctx_with_ns,
            method,
            &h1("example.com%2Fstatic", "/app.js"),
        );
        assert_ne!(odd.primary(), escaped.primary());

        // No host at all (HTTP/1.0).
        let bare = RequestHeader::build("GET", b"/path", None).unwrap();
        assert_eq!(
            get_cache_key(&ctx_with_ns, method, &bare).primary_key_str(),
            Some("my-nsGET:/path")
        );

        // Case 3: Cache info with namespace and multiple keys.
        let mut ctx_with_keys = Ctx::new();
        ctx_with_keys.cache = Some(Box::new(CacheInfo {
            namespace: Some("my-ns".to_string()),
            keys: Some(vec!["user-123".to_string(), "desktop".to_string()]),
            ..Default::default()
        }));
        let key3 = get_cache_key(&ctx_with_keys, method, &h2);
        assert_eq!(key3.user_tag, "my-ns");
        assert_eq!(
            key3.primary_key_str(),
            Some("my-nsuser-123:desktop:GET:example.com/path?a=1")
        );
    }

    /// The original `test_generate_server_timing` is good, but this version
    /// is slightly more robust to minor timing variations.
    #[test]
    fn test_generate_server_timing() {
        let mut ctx = Ctx::new();
        ctx.timing.upstream_connect = Some(1);
        ctx.timing.upstream_processing = Some(2);
        ctx.timing.cache_lookup = Some(6);
        ctx.timing.cache_lock = Some(7);
        ctx.add_plugin_processing_time(&Arc::from("plugin1"), 100);

        let timing_header = ctx.generate_server_timing();

        // Check for the presence of each expected component.
        assert!(timing_header.contains("upstream.connect;dur=1"));
        assert!(timing_header.contains("upstream.processing;dur=2"));
        assert!(timing_header.contains("upstream;dur=3"));
        assert!(timing_header.contains("cache.lookup;dur=6"));
        assert!(timing_header.contains("cache.lock;dur=7"));
        assert!(timing_header.contains("cache;dur=13"));
        assert!(timing_header.contains("plugin.plugin1;dur=100"));
        assert!(timing_header.contains("plugin;dur=100"));
        assert!(timing_header.contains("total;dur="));
    }

    #[test]
    fn test_format_duration() {
        let mut buf = BytesMut::new();
        format_duration(&mut buf, (3600 + 3500) * 1000);
        assert_eq!(b"1.9h", buf.as_ref());

        buf = BytesMut::new();
        format_duration(&mut buf, (3600 + 1800) * 1000);
        assert_eq!(b"1.5h", buf.as_ref());

        buf = BytesMut::new();
        format_duration(&mut buf, (3600 + 100) * 1000);
        assert_eq!(b"1h", buf.as_ref());

        buf = BytesMut::new();
        format_duration(&mut buf, (60 + 50) * 1000);
        assert_eq!(b"1.8m", buf.as_ref());

        buf = BytesMut::new();
        format_duration(&mut buf, (60 + 2) * 1000);
        assert_eq!(b"1m", buf.as_ref());

        buf = BytesMut::new();
        format_duration(&mut buf, 1000);
        assert_eq!(b"1s", buf.as_ref());

        buf = BytesMut::new();
        format_duration(&mut buf, 512);
        assert_eq!(b"512ms", buf.as_ref());

        buf = BytesMut::new();
        format_duration(&mut buf, 1112);
        assert_eq!(b"1.1s", buf.as_ref());
    }

    #[test]
    fn test_add_variable() {
        let mut ctx = Ctx::new();
        ctx.add_variable("key1", "value1");
        ctx.add_variable("key2", "value2");
        ctx.extend_variables(AHashMap::from([
            ("key3".to_string(), "value3".to_string()),
            ("key4".to_string(), "value4".to_string()),
        ]));
        let variables =
            ctx.features.as_ref().unwrap().variables.as_ref().unwrap();
        // NOTE: The current implementation in the main code doesn't add the '$' prefix automatically.
        // The test should reflect the actual implementation.
        assert_eq!(variables.get("key1"), Some(&"value1".to_string()));
        assert_eq!(variables.get("key2"), Some(&"value2".to_string()));
        assert_eq!(variables.get("key3"), Some(&"value3".to_string()));
        assert_eq!(variables.get("key4"), Some(&"value4".to_string()));
    }

    #[test]
    fn test_cache_key() {
        let mut ctx = Ctx::new();
        ctx.push_cache_key("key1".to_string());
        ctx.extend_cache_keys(vec!["key2".to_string(), "key3".to_string()]);
        assert_eq!(
            vec!["key1".to_string(), "key2".to_string(), "key3".to_string()],
            ctx.cache.unwrap().keys.unwrap()
        );

        let mut ctx = Ctx::new();
        ctx.cache.get_or_insert_default();
        let mut header = RequestHeader::build("GET", b"/", None).unwrap();
        header.set_uri(Uri::from_static("https://example.com/path"));
        let key = get_cache_key(&ctx, "GET", &header);
        assert_eq!(key.user_tag, "");
        assert_eq!(key.primary_key_str(), Some("GET:example.com/path"));
    }

    #[test]
    fn test_state() {
        let mut ctx = Ctx::new();

        let mut buf = BytesMut::new();
        ctx.conn.id = 10;
        ctx.append_log_value(&mut buf, "connection_id");
        assert_eq!(b"10", buf.as_ref());

        buf = BytesMut::new();
        ctx.append_log_value(&mut buf, "upstream_reused");
        assert_eq!(b"false", buf.as_ref());

        buf = BytesMut::new();
        ctx.upstream.reused = true;
        ctx.append_log_value(&mut buf, "upstream_reused");
        assert_eq!(b"true", buf.as_ref());

        buf = BytesMut::new();
        ctx.upstream.address = "192.168.1.1:80".to_string();
        ctx.append_log_value(&mut buf, "upstream_addr");
        assert_eq!(b"192.168.1.1:80", buf.as_ref());

        buf = BytesMut::new();
        ctx.upstream.status = Some(StatusCode::CREATED);
        ctx.append_log_value(&mut buf, "upstream_status");
        assert_eq!(b"201", buf.as_ref());

        buf = BytesMut::new();
        ctx.state.processing_count = 10;
        ctx.append_log_value(&mut buf, "processing");
        assert_eq!(b"10", buf.as_ref());

        buf = BytesMut::new();
        ctx.timing.upstream_connect = Some(1);
        ctx.append_log_value(&mut buf, "upstream_connect_time");
        assert_eq!(b"1", buf.as_ref());

        buf = BytesMut::new();
        ctx.append_log_value(&mut buf, "upstream_connect_time_human");
        assert_eq!(b"1ms", buf.as_ref());

        buf = BytesMut::new();
        ctx.upstream.connected_count = Some(30);
        ctx.append_log_value(&mut buf, "upstream_connected");
        assert_eq!(b"30", buf.as_ref());

        buf = BytesMut::new();
        ctx.timing.upstream_processing = Some(2);
        ctx.append_log_value(&mut buf, "upstream_processing_time");
        assert_eq!(b"2", buf.as_ref());

        buf = BytesMut::new();
        ctx.append_log_value(&mut buf, "upstream_processing_time_human");
        assert_eq!(b"2ms", buf.as_ref());

        buf = BytesMut::new();
        ctx.timing.upstream_response = Some(3);
        ctx.append_log_value(&mut buf, "upstream_response_time");
        assert_eq!(b"3", buf.as_ref());

        buf = BytesMut::new();
        ctx.append_log_value(&mut buf, "upstream_response_time_human");
        assert_eq!(b"3ms", buf.as_ref());

        buf = BytesMut::new();
        ctx.timing.upstream_tcp_connect = Some(100);
        ctx.append_log_value(&mut buf, "upstream_tcp_connect_time");
        assert_eq!(b"100", buf.as_ref());

        buf = BytesMut::new();
        ctx.append_log_value(&mut buf, "upstream_tcp_connect_time_human");
        assert_eq!(b"100ms", buf.as_ref());

        buf = BytesMut::new();
        ctx.timing.upstream_tls_handshake = Some(110);
        ctx.append_log_value(&mut buf, "upstream_tls_handshake_time");
        assert_eq!(b"110", buf.as_ref());

        buf = BytesMut::new();
        ctx.timing.upstream_connect_offload_wait = Some(3);
        ctx.append_log_value(&mut buf, "upstream_connect_offload_wait_time");
        assert_eq!(b"3", buf.as_ref());
        buf = BytesMut::new();
        ctx.append_log_value(
            &mut buf,
            "upstream_connect_offload_wait_time_human",
        );
        assert_eq!(b"3ms", buf.as_ref());

        buf = BytesMut::new();
        ctx.append_log_value(&mut buf, "upstream_tls_handshake_time_human");
        assert_eq!(b"110ms", buf.as_ref());

        buf = BytesMut::new();
        ctx.timing.upstream_connection_duration = Some(120);
        ctx.append_log_value(&mut buf, "upstream_connection_time");
        assert_eq!(b"120", buf.as_ref());

        buf = BytesMut::new();
        ctx.append_log_value(&mut buf, "upstream_connection_time_human");
        assert_eq!(b"120ms", buf.as_ref());

        buf = BytesMut::new();
        ctx.upstream.location = "pingap".to_string().into();
        ctx.append_log_value(&mut buf, "location");
        assert_eq!(b"pingap", buf.as_ref());

        buf = BytesMut::new();
        ctx.timing.connection_duration = 4;
        ctx.append_log_value(&mut buf, "connection_time");
        assert_eq!(b"4", buf.as_ref());

        buf = BytesMut::new();
        ctx.append_log_value(&mut buf, "connection_time_human");
        assert_eq!(b"4ms", buf.as_ref());

        buf = BytesMut::new();
        ctx.conn.reused = false;
        ctx.append_log_value(&mut buf, "connection_reused");
        assert_eq!(b"false", buf.as_ref());

        buf = BytesMut::new();
        ctx.conn.reused = true;
        ctx.append_log_value(&mut buf, "connection_reused");
        assert_eq!(b"true", buf.as_ref());

        buf = BytesMut::new();
        ctx.conn.tls_version = Some("TLSv1.3".into());
        ctx.append_log_value(&mut buf, "tls_version");
        assert_eq!(b"TLSv1.3", buf.as_ref());

        buf = BytesMut::new();
        ctx.conn.tls_cipher =
            Some("ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".into());
        ctx.append_log_value(&mut buf, "tls_cipher");
        assert_eq!(b"ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", buf.as_ref());

        buf = BytesMut::new();
        ctx.timing.tls_handshake = Some(101);
        ctx.append_log_value(&mut buf, "tls_handshake_time");
        assert_eq!(b"101", buf.as_ref());

        buf = BytesMut::new();
        ctx.append_log_value(&mut buf, "tls_handshake_time_human");
        assert_eq!(b"101ms", buf.as_ref());

        {
            let features = ctx.features.get_or_insert_default();
            features.compression_stat = Some(CompressionStat {
                in_bytes: 1024,
                out_bytes: 500,
                duration: Duration::from_millis(5),
                ..Default::default()
            })
        }

        buf = BytesMut::new();
        ctx.append_log_value(&mut buf, "compression_time");
        assert_eq!(b"5", buf.as_ref());

        buf = BytesMut::new();
        ctx.append_log_value(&mut buf, "compression_time_human");
        assert_eq!(b"5ms", buf.as_ref());

        buf = BytesMut::new();
        ctx.append_log_value(&mut buf, "compression_ratio");
        assert_eq!(b"2.0", buf.as_ref());

        buf = BytesMut::new();
        ctx.timing.cache_lookup = Some(6);
        ctx.append_log_value(&mut buf, "cache_lookup_time");
        assert_eq!(b"6", buf.as_ref());

        buf = BytesMut::new();
        ctx.append_log_value(&mut buf, "cache_lookup_time_human");
        assert_eq!(b"6ms", buf.as_ref());

        buf = BytesMut::new();
        ctx.timing.cache_lock = Some(7);
        ctx.append_log_value(&mut buf, "cache_lock_time");
        assert_eq!(b"7", buf.as_ref());

        buf = BytesMut::new();
        ctx.append_log_value(&mut buf, "cache_lock_time_human");
        assert_eq!(b"7ms", buf.as_ref());
    }

    #[test]
    fn test_add_plugin_processing_time() {
        let mut ctx = Ctx::new();
        ctx.add_plugin_processing_time(&Arc::from("plugin1"), 100);
        ctx.add_plugin_processing_time(&Arc::from("plugin2"), 200);
        assert_eq!(
            ctx.features.unwrap().plugin_processing_times,
            Some(vec![
                (Arc::from("plugin1"), 100),
                (Arc::from("plugin2"), 200)
            ])
        );
    }

    #[test]
    fn test_get_digest_detail() {
        let mut digest = Digest::default();
        let detail = get_digest_detail(&digest);
        assert_eq!(detail.connection_reused, false);
        assert_eq!(detail.connection_time, 0);
        assert_eq!(detail.tcp_established, 0);
        assert_eq!(detail.tls_established, 0);
        assert_eq!(detail.tls_version, None);
        assert_eq!(detail.tls_cipher, None);

        digest.timing_digest.push(Some(TimingDigest {
            established_ts: SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_secs(5))
                .unwrap(),
            ..Default::default()
        }));
        digest.timing_digest.push(Some(TimingDigest {
            established_ts: SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_secs(3))
                .unwrap(),
            ..Default::default()
        }));
        digest.ssl_digest = Some(Arc::new(SslDigest {
            version: "1.3".into(),
            cipher: "123".into(),
            organization: Some("cloudflare".to_string()),
            serial_number: Some(
                "0x00000000000000000000000000000abc".to_string(),
            ),
            cert_digest: vec![],
            extension: SslDigestExtension::default(),
        }));
        let detail = get_digest_detail(&digest);
        assert_eq!(detail.connection_reused, true);
        assert_eq!(detail.tcp_established, 5000);
        assert_eq!(detail.tls_established, 3000);
        assert_eq!(detail.tls_version.as_deref(), Some("1.3"));
        assert_eq!(detail.tls_cipher.as_deref(), Some("123"));
        // Nothing measured on these entries.
        assert_eq!(detail.tcp_connect, None);
        assert_eq!(detail.tls_handshake, None);

        // pingora's per-layer measurements come through as such.
        digest.timing_digest = vec![
            Some(TimingDigest {
                establishment_duration: Some(Duration::from_millis(12)),
                ..Default::default()
            }),
            Some(TimingDigest {
                establishment_duration: Some(Duration::from_millis(34)),
                ..Default::default()
            }),
        ];
        let detail = get_digest_detail(&digest);
        assert_eq!(detail.tcp_connect, Some(12));
        assert_eq!(detail.tls_handshake, Some(34));
        // Not offloaded: no queueing time to report.
        assert_eq!(detail.connect_offload_wait, None);

        // An offloaded connect also carries the time it waited for a thread.
        digest.timing_digest[0] = Some(TimingDigest {
            establishment_duration: Some(Duration::from_millis(12)),
            offload_wait_duration: Some(Duration::from_millis(2)),
            ..Default::default()
        });
        let detail = get_digest_detail(&digest);
        assert_eq!(detail.connect_offload_wait, Some(2));

        // Without TLS the last entry is the transport again: no handshake.
        digest.ssl_digest = None;
        digest.timing_digest.truncate(1);
        let detail = get_digest_detail(&digest);
        assert_eq!(detail.tcp_connect, Some(12));
        assert_eq!(detail.tls_handshake, None);
    }

    #[test]
    fn test_update_upstream_timing_from_digest() {
        let measured = |tcp: u64, tls: u64| Digest {
            timing_digest: vec![
                Some(TimingDigest {
                    establishment_duration: Some(Duration::from_millis(tcp)),
                    ..Default::default()
                }),
                Some(TimingDigest {
                    establishment_duration: Some(Duration::from_millis(tls)),
                    ..Default::default()
                }),
            ],
            ssl_digest: Some(Arc::new(SslDigest {
                version: "1.3".into(),
                cipher: "123".into(),
                organization: None,
                serial_number: None,
                cert_digest: vec![],
                extension: SslDigestExtension::default(),
            })),
            ..Default::default()
        };

        // Measured layers are taken as they are, independent of pingap's
        // own end-to-end timer.
        let mut ctx = Ctx::new();
        ctx.timing.upstream_connect = Some(100);
        ctx.update_upstream_timing_from_digest(&measured(12, 34), false);
        assert_eq!(Some(12), ctx.timing.upstream_tcp_connect);
        assert_eq!(Some(34), ctx.timing.upstream_tls_handshake);
        assert_eq!(None, ctx.timing.upstream_connect_offload_wait);

        // The offload queueing time rides along when the connect was
        // offloaded.
        let mut ctx = Ctx::new();
        let mut offloaded = measured(12, 34);
        offloaded.timing_digest[0] = Some(TimingDigest {
            establishment_duration: Some(Duration::from_millis(12)),
            offload_wait_duration: Some(Duration::from_millis(2)),
            ..Default::default()
        });
        ctx.update_upstream_timing_from_digest(&offloaded, false);
        assert_eq!(Some(2), ctx.timing.upstream_connect_offload_wait);

        // A reused connection carries no connect cost for this request.
        let mut ctx = Ctx::new();
        ctx.timing.upstream_connect = Some(100);
        ctx.update_upstream_timing_from_digest(&measured(12, 34), true);
        assert_eq!(None, ctx.timing.upstream_tcp_connect);
        assert_eq!(None, ctx.timing.upstream_tls_handshake);

        // No measurement: fall back to splitting the end-to-end timer by
        // the layers' wall-clock timestamps.
        let mut ctx = Ctx::new();
        ctx.timing.upstream_connect = Some(100);
        let mut unmeasured = measured(0, 0);
        unmeasured.timing_digest = vec![
            Some(TimingDigest {
                established_ts: SystemTime::UNIX_EPOCH
                    .checked_add(Duration::from_millis(1_000))
                    .unwrap(),
                ..Default::default()
            }),
            Some(TimingDigest {
                established_ts: SystemTime::UNIX_EPOCH
                    .checked_add(Duration::from_millis(1_030))
                    .unwrap(),
                ..Default::default()
            }),
        ];
        ctx.update_upstream_timing_from_digest(&unmeasured, false);
        assert_eq!(Some(70), ctx.timing.upstream_tcp_connect);
        assert_eq!(Some(30), ctx.timing.upstream_tls_handshake);
    }

    #[test]
    fn test_modify_body_handler() {
        let mut ctx = Ctx::default();

        struct TestHandler {}
        impl ModifyResponseBody for TestHandler {
            fn handle(
                &mut self,
                _session: &Session,
                body: &mut Option<bytes::Bytes>,
                _end_of_stream: bool,
            ) -> pingora::Result<()> {
                *body = Some(Bytes::from("test"));
                Ok(())
            }
        }

        ctx.add_modify_body_handler("test", Box::new(TestHandler {}));
        assert_eq!(true, ctx.get_modify_body_handler("test").is_some());
    }
}
