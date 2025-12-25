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

use crate::{real_now_ms, Plugin};
use ahash::AHashMap;
use bytes::BytesMut;
use http::StatusCode;
use http::Uri;
use http::{HeaderName, HeaderValue};
#[cfg(feature = "tracing")]
use opentelemetry::{
    global::{BoxedSpan, BoxedTracer, ObjectSafeSpan},
    trace::{SpanKind, TraceContextExt, Tracer},
    Context,
};
use pingora::cache::CacheKey;
use pingora::http::RequestHeader;
use pingora::protocols::Digest;
use pingora::protocols::TimingDigest;
use pingora::proxy::Session;
use pingora_limits::inflight::Guard;
use std::fmt::Write;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

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
    fn name(&self) -> String {
        "unknown".to_string()
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
    pub tls_version: Option<String>,
    /// The TLS cipher used for the connection, if any.
    pub tls_cipher: Option<String>,
    /// Indicates whether the connection was reused (e.g., HTTP keep-alive).
    pub reused: bool,
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
    fn completed(&self) -> i32;
}

/// Trait for location instance
pub trait LocationInstance: Send + Sync {
    /// Get location's name
    fn name(&self) -> &str;
    /// Get the upstream of location
    fn upstream(&self) -> &str;
    /// Rewrite the request url
    fn rewrite(
        &self,
        header: &mut RequestHeader,
        variables: Option<&AHashMap<String, String>>,
    ) -> (bool, Option<AHashMap<String, String>>);
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
    /// A guard for rate limiting, if applicable.
    pub guard: Option<Guard>,
    /// The total number of requests currently being processed by the service.
    pub processing_count: i32,
    /// The total number of requests accepted by the service.
    pub accepted_count: u64,
    /// The number of requests currently being processed for this location.
    pub location_processing_count: i32,
    /// The total number of requests accepted for this location.
    pub location_accepted_count: u64,
}

/// All cache-related configuration and statistics for a request.
#[derive(Default)]
pub struct CacheInfo {
    /// The namespace for cache entries.
    pub namespace: Option<String>,
    /// The list of keys used to generate the final cache key.
    pub keys: Option<Vec<String>>,
    /// Whether to respect Cache-Control headers.
    pub check_cache_control: bool,
    /// The maximum time-to-live for cache entries.
    pub max_ttl: Option<Duration>,
    /// The number of cache read operations performed.
    pub reading_count: Option<u32>,
    /// The number of cache write operations performed.
    pub writing_count: Option<u32>,
}

/// Optional features like tracing, plugins, and response modifications.
#[derive(Default)]
pub struct Features {
    /// A map of custom variables for request processing.
    pub variables: Option<AHashMap<String, String>>,
    /// A list of plugin names and their processing times in milliseconds.
    pub plugin_processing_times: Option<Vec<(String, u32)>>,
    /// Statistics about response compression.
    pub compression_stat: Option<CompressionStat>,
    /// A map of plugin names and their response body handlers.
    pub modify_body_handlers:
        Option<AHashMap<String, Box<dyn ModifyResponseBody>>>,
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
    /// Cache-related information. Wrapped in Option to save memory when not in use.
    pub cache: Option<CacheInfo>,
    /// Optional features. Wrapped in Option to save memory when not in use.
    pub features: Option<Features>,
    /// Plugins for the current location
    pub plugins: Option<Vec<(String, Arc<dyn Plugin>)>>,
}

/// Helper struct to store connection timing and TLS details
#[derive(Debug, Default)]
pub struct DigestDetail {
    /// Whether the connection was reused from pool
    pub connection_reused: bool,
    /// Total connection time in milliseconds
    pub connection_time: u64,
    /// Timestamp when TCP connection was established
    pub tcp_established: u64,
    /// Timestamp when TLS handshake completed
    pub tls_established: u64,
    /// TLS protocol version if using HTTPS
    pub tls_version: Option<String>,
    /// TLS cipher suite in use if using HTTPS
    pub tls_cipher: Option<String>,
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
    let now = real_now_ms();
    if tcp_established > 0 && tcp_established < now {
        connection_time = now - tcp_established;
    }
    let connection_reused = connection_time > 100;

    let Some(ssl_digest) = &digest.ssl_digest else {
        return DigestDetail {
            connection_reused,
            tcp_established,
            connection_time,
            ..Default::default()
        };
    };

    DigestDetail {
        connection_reused,
        tcp_established,
        connection_time,
        tls_established: timing_to_ms(digest.timing_digest.last()),
        tls_version: Some(ssl_digest.version.to_string()),
        tls_cipher: Some(ssl_digest.cipher.to_string()),
    }
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
        let variables = features.variables.get_or_insert_with(AHashMap::new);
        variables.extend(values);
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
        if let Some(value) = field {
            if value >= 0 {
                return Some(value as u32);
            }
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
    pub fn add_plugin_processing_time(&mut self, name: &str, time: u32) {
        // Lazily initialize features and the processing times vector.
        let features = self.features.get_or_insert_default();
        let times = features
            .plugin_processing_times
            .get_or_insert_with(|| Vec::with_capacity(5));
        if let Some(item) = times.iter_mut().find(|item| item.0 == name) {
            item.1 += time;
        } else {
            times.push((name.to_string(), time));
        }
    }

    /// Appends a formatted value to the provided log buffer based on the given key.
    /// Handles various metrics including connection info, timing data, and TLS details.
    ///
    /// # Arguments
    /// * `buf` - The BytesMut buffer to append the value to.
    /// * `key` - The key identifying which state value to format and append.
    ///
    /// Returns: The modified BytesMut buffer.
    #[inline]
    pub fn append_log_value(&self, buf: &mut BytesMut, key: &str) {
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

        match key {
            "connection_id" => {
                buf.extend(itoa::Buffer::new().format(self.conn.id).as_bytes());
            },
            "upstream_reused" => {
                if self.upstream.reused {
                    buf.extend(b"true");
                } else {
                    buf.extend(b"false");
                }
            },
            "upstream_status" => {
                if let Some(status) = &self.upstream.status {
                    buf.extend_from_slice(status.as_str().as_bytes());
                } else {
                    buf.extend_from_slice(b"-");
                }
            },
            "upstream_addr" => buf.extend(self.upstream.address.as_bytes()),
            "processing" => buf.extend(
                itoa::Buffer::new()
                    .format(self.state.processing_count)
                    .as_bytes(),
            ),
            "upstream_connected" => {
                if let Some(value) = self.upstream.connected_count {
                    buf.extend(itoa::Buffer::new().format(value).as_bytes());
                }
            },

            // Timing fields
            "upstream_connect_time" => {
                append_time!(self.get_upstream_connect_time())
            },
            "upstream_connect_time_human" => {
                append_time!(self.get_upstream_connect_time(), human)
            },

            "upstream_processing_time" => {
                append_time!(self.get_upstream_processing_time())
            },
            "upstream_processing_time_human" => {
                append_time!(self.get_upstream_processing_time(), human)
            },
            "upstream_response_time" => {
                append_time!(self.get_upstream_response_time())
            },
            "upstream_response_time_human" => {
                append_time!(self.get_upstream_response_time(), human)
            },
            "upstream_tcp_connect_time" => {
                append_time!(self.timing.upstream_tcp_connect)
            },
            "upstream_tcp_connect_time_human" => {
                append_time!(self.timing.upstream_tcp_connect, human)
            },
            "upstream_tls_handshake_time" => {
                append_time!(self.timing.upstream_tls_handshake)
            },
            "upstream_tls_handshake_time_human" => {
                append_time!(self.timing.upstream_tls_handshake, human)
            },
            "upstream_connection_time" => {
                append_time!(self.timing.upstream_connection_duration)
            },
            "upstream_connection_time_human" => {
                append_time!(self.timing.upstream_connection_duration, human)
            },
            "connection_time" => {
                append_time!(Some(self.timing.connection_duration))
            },
            "connection_time_human" => {
                append_time!(Some(self.timing.connection_duration), human)
            },

            // Other fields
            "location" => {
                if !self.upstream.location.is_empty() {
                    buf.extend(self.upstream.location.as_bytes())
                }
            },
            "connection_reused" => {
                if self.conn.reused {
                    buf.extend(b"true");
                } else {
                    buf.extend(b"false");
                }
            },
            "tls_version" => {
                if let Some(value) = &self.conn.tls_version {
                    buf.extend(value.as_bytes());
                }
            },
            "tls_cipher" => {
                if let Some(value) = &self.conn.tls_cipher {
                    buf.extend(value.as_bytes());
                }
            },
            "tls_handshake_time" => append_time!(self.timing.tls_handshake),
            "tls_handshake_time_human" => {
                append_time!(self.timing.tls_handshake, human)
            },
            "compression_time" => {
                if let Some(feature) = &self.features {
                    if let Some(value) = &feature.compression_stat {
                        append_time!(Some(value.duration.as_millis() as u64))
                    }
                }
            },
            "compression_time_human" => {
                if let Some(feature) = &self.features {
                    if let Some(value) = &feature.compression_stat {
                        append_time!(
                            Some(value.duration.as_millis() as u64),
                            human
                        )
                    }
                }
            },
            "compression_ratio" => {
                if let Some(feature) = &self.features {
                    if let Some(value) = &feature.compression_stat {
                        buf.extend(format!("{:.1}", value.ratio()).as_bytes());
                    }
                }
            },
            "cache_lookup_time" => {
                append_time!(self.timing.cache_lookup)
            },
            "cache_lookup_time_human" => {
                append_time!(self.timing.cache_lookup, human)
            },
            "cache_lock_time" => {
                append_time!(self.timing.cache_lock)
            },
            "cache_lock_time_human" => {
                append_time!(self.timing.cache_lock, human)
            },
            "service_time" => {
                append_time!(Some(self.timing.created_at.elapsed().as_millis()))
            },
            "service_time_human" => {
                append_time!(
                    Some(self.timing.created_at.elapsed().as_millis()),
                    human
                )
            },
            // Ignore unknown keys.
            _ => {},
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
        if let Some(features) = &self.features {
            if let Some(times) = &features.plugin_processing_times {
                let mut plugin_time: u32 = 0;
                for (name, time) in times {
                    if *time == 0 {
                        continue;
                    }
                    plugin_time += time;
                    let mut plugin_name = String::with_capacity(7 + name.len());
                    plugin_name.push_str("plugin.");
                    plugin_name.push_str(name);
                    add_timing!(&plugin_name, time);
                }
                if plugin_time > 0 {
                    add_timing!("plugin", plugin_time);
                }
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

        let upstream_connect_time =
            self.timing.upstream_connect.unwrap_or_default();
        // upstream tcp, tls(if https) connect time
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

/// Generates a cache key from the request method, URI and state context.
/// The key includes an optional namespace and other key components if configured in the context.
///
/// # Arguments
/// * `ctx` - The Ctx context containing cache configuration.
/// * `method` - The HTTP method as a string.
/// * `uri` - The request URI.
///
/// Returns: A CacheKey combining the namespace, custom keys (if any), method and URI.
pub fn get_cache_key(ctx: &Ctx, method: &str, uri: &Uri) -> CacheKey {
    let Some(cache_info) = &ctx.cache else {
        // Return an empty key if cache is not configured for this context.
        return CacheKey::new("", "", "");
    };
    let namespace = cache_info.namespace.as_ref().map_or("", |v| v);
    let key = if let Some(keys) = &cache_info.keys {
        // Pre-allocate string capacity to avoid reallocations.
        let mut key_buf = String::with_capacity(
            keys.iter().map(|s| s.len() + 1).sum::<usize>()
                + method.len()
                + 1
                + uri.to_string().len(),
        );

        // Join custom key components with ':'.
        for (i, k) in keys.iter().enumerate() {
            if i > 0 {
                key_buf.push(':');
            }
            key_buf.push_str(k);
        }
        // Use write! macro to efficiently concatenate the method and URI.
        let _ = write!(&mut key_buf, ":{method}:{uri}");
        key_buf
    } else {
        // If no custom keys, use "METHOD:URI" as the key.
        format!("{method}:{uri}")
    };

    CacheKey::new(namespace, key, "")
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use bytes::BytesMut;
    use pingora::protocols::tls::SslDigest;
    use pingora::protocols::tls::SslDigestExtension;
    use pretty_assertions::assert_eq;
    use std::{sync::Arc, time::Duration};

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
        ctx.conn.tls_version = Some("TLSv1.3".to_string());
        buf = BytesMut::new();
        ctx.append_log_value(&mut buf, "tls_version");
        assert_eq!(&buf[..], b"TLSv1.3");

        // Test service_time calculation
        coarsetime::Clock::update();
        std::thread::sleep(Duration::from_millis(11));
        buf = BytesMut::new();
        ctx.append_log_value(&mut buf, "service_time");
        coarsetime::Clock::update();
        let service_time: u64 =
            std::str::from_utf8(&buf[..]).unwrap().parse().unwrap();
        assert!(service_time >= 10, "Service time should be at least 10ms");
    }

    /// Tests the `get_cache_key` function's logic more thoroughly.
    #[test]
    fn test_get_cache_key() {
        let method = "GET";
        let uri = Uri::from_static("https://example.com/path");

        // Case 1: No cache info in context.
        let ctx_no_cache = Ctx::new();
        let key1 = get_cache_key(&ctx_no_cache, method, &uri);
        assert_eq!(key1.namespace_str(), Some(""));
        assert_eq!(key1.primary_key_str(), Some(""));

        // Case 2: Cache info with namespace but no keys.
        let mut ctx_with_ns = Ctx::new();
        ctx_with_ns.cache = Some(CacheInfo {
            namespace: Some("my-ns".to_string()),
            ..Default::default()
        });
        let key2 = get_cache_key(&ctx_with_ns, method, &uri);
        assert_eq!(key2.namespace_str(), Some("my-ns"));
        assert_eq!(
            key2.primary_key_str(),
            Some("GET:https://example.com/path")
        );

        // Case 3: Cache info with namespace and multiple keys.
        let mut ctx_with_keys = Ctx::new();
        ctx_with_keys.cache = Some(CacheInfo {
            namespace: Some("my-ns".to_string()),
            keys: Some(vec!["user-123".to_string(), "desktop".to_string()]),
            ..Default::default()
        });
        let key3 = get_cache_key(&ctx_with_keys, method, &uri);
        assert_eq!(key3.namespace_str(), Some("my-ns"));
        assert_eq!(
            key3.primary_key_str(),
            Some("user-123:desktop:GET:https://example.com/path")
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
        ctx.add_plugin_processing_time("plugin1", 100);

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
        let key = get_cache_key(
            &ctx,
            "GET",
            &Uri::from_static("https://example.com/path"),
        );
        assert_eq!(key.namespace_str(), Some(""));
        assert_eq!(key.primary_key_str(), Some("GET:https://example.com/path"));
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
        ctx.conn.tls_version = Some("TLSv1.3".to_string());
        ctx.append_log_value(&mut buf, "tls_version");
        assert_eq!(b"TLSv1.3", buf.as_ref());

        buf = BytesMut::new();
        ctx.conn.tls_cipher =
            Some("ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".to_string());
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
        ctx.add_plugin_processing_time("plugin1", 100);
        ctx.add_plugin_processing_time("plugin2", 200);
        assert_eq!(
            ctx.features.unwrap().plugin_processing_times,
            Some(vec![
                ("plugin1".to_string(), 100),
                ("plugin2".to_string(), 200)
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
        }));
        digest.timing_digest.push(Some(TimingDigest {
            established_ts: SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_secs(3))
                .unwrap(),
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
        assert_eq!(detail.tls_version, Some("1.3".to_string()));
        assert_eq!(detail.tls_cipher, Some("123".to_string()));
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
