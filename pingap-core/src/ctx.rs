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

use super::now_ms;
use ahash::AHashMap;
use bytes::{Bytes, BytesMut};
use http::StatusCode;
use http::Uri;
#[cfg(feature = "full")]
use opentelemetry::{
    global::{BoxedSpan, BoxedTracer, ObjectSafeSpan},
    trace::{SpanKind, TraceContextExt, Tracer},
    Context,
};
use pingora::cache::CacheKey;
use pingora_limits::inflight::Guard;
use std::time::Duration;

const SECOND: u64 = 1_000;
const MINUTE: u64 = 60 * SECOND;
const HOUR: u64 = 60 * MINUTE;

#[inline]
fn format_duration(mut buf: BytesMut, ms: u64) -> BytesMut {
    if ms >= HOUR {
        buf.extend(itoa::Buffer::new().format(ms / HOUR).as_bytes());
        let value = ms % HOUR * 10 / HOUR;
        if value != 0 {
            buf.extend(b".");
            buf.extend(itoa::Buffer::new().format(value).as_bytes());
        }
        buf.extend(b"h");
    } else if ms >= MINUTE {
        buf.extend(itoa::Buffer::new().format(ms / MINUTE).as_bytes());
        let value = ms % MINUTE * 10 / MINUTE;
        if value != 0 {
            buf.extend(b".");
            buf.extend(itoa::Buffer::new().format(value).as_bytes());
        }
        buf.extend(b"m");
    } else if ms >= SECOND {
        buf.extend(itoa::Buffer::new().format(ms / SECOND).as_bytes());
        let value = (ms % SECOND) / 100;
        if value != 0 {
            buf.extend(b".");
            buf.extend(itoa::Buffer::new().format(value).as_bytes());
        }
        buf.extend(b"s");
    } else {
        buf.extend(itoa::Buffer::new().format(ms).as_bytes());
        buf.extend(b"ms");
    }
    buf
}

pub trait ModifyResponseBody: Sync + Send {
    fn handle(&self, data: Bytes) -> Bytes;
}

/// Statistics about response compression operations
pub struct CompressionStat {
    /// Size of the data before compression in bytes
    pub in_bytes: usize,
    /// Size of the data after compression in bytes
    pub out_bytes: usize,
    /// Time taken to perform the compression operation
    pub duration: Duration,
}

impl CompressionStat {
    pub fn ratio(&self) -> f64 {
        (self.in_bytes as f64) / (self.out_bytes as f64)
    }
}

#[cfg(feature = "full")]
pub struct OtelTracer {
    pub tracer: BoxedTracer,
    pub http_request_span: BoxedSpan,
}

#[cfg(feature = "full")]
impl OtelTracer {
    #[inline]
    pub fn new_upstream_span(&self, name: &str) -> BoxedSpan {
        self.tracer
            .span_builder(name.to_string())
            .with_kind(SpanKind::Client)
            .start_with_context(
                &self.tracer,
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
    /// Unique identifier for the connection
    pub connection_id: usize,
    /// Number of requests currently processing
    pub processing: i32,
    /// Total number of requests accepted
    pub accepted: u64,
    /// Number of requests currently processing for the current location
    pub location_processing: i32,
    /// Total number of requests accepted for the current location
    pub location_accepted: u64,
    /// Timestamp when this context was created (in milliseconds)
    pub created_at: u64,
    /// TLS version used by the client connection (e.g., "TLSv1.3")
    pub tls_version: Option<String>,
    /// TLS cipher suite used by the client connection
    pub tls_cipher: Option<String>,
    /// Time taken for TLS handshake with client (in milliseconds)
    pub tls_handshake_time: Option<u64>,
    /// HTTP status code of the response
    pub status: Option<StatusCode>,
    /// Total time the connection has been alive (in milliseconds)
    /// May be large for reused connections
    pub connection_time: u64,
    /// Indicates if this connection is reused
    pub connection_reused: bool,
    /// The location handling request
    pub location: String,
    /// Address of the upstream server
    pub upstream_address: String,
    /// Client's IP address
    pub client_ip: Option<String>,
    /// Remote connection port
    pub remote_port: Option<u16>,
    /// Remote connection address
    pub remote_addr: Option<String>,
    /// Server's listening port
    pub server_port: Option<u16>,
    /// Server's address
    pub server_addr: Option<String>,
    /// Rate limiting guard
    pub guard: Option<Guard>,
    /// Unique identifier for the request
    pub request_id: Option<String>,
    /// Namespace for cache entries
    pub cache_namespace: Option<String>,
    /// Prefix for cache keys
    pub cache_prefix: Option<String>,
    /// Whether to check cache control headers
    pub check_cache_control: bool,
    /// Time spent looking up cache entries (in milliseconds)
    pub cache_lookup_time: Option<u64>,
    /// Time spent acquiring cache locks (in milliseconds)
    pub cache_lock_time: Option<u64>,
    /// Maximum time-to-live for cache entries
    pub cache_max_ttl: Option<Duration>,
    /// The upstream server
    pub upstream: String,
    /// Indicates if the upstream connection is reused
    pub upstream_reused: bool,
    /// Number of requests processing by upstream
    pub upstream_processing: Option<i32>,
    /// Time taken to establish/reuse upstream connection (in milliseconds)
    pub upstream_connect_time: Option<u64>,
    /// Current number of active upstream connections
    pub upstream_connected: Option<i32>,
    /// Time taken for TCP connection to upstream (in milliseconds)
    pub upstream_tcp_connect_time: Option<u64>,
    /// Time taken for TLS handshake with upstream (in milliseconds)
    pub upstream_tls_handshake_time: Option<u64>,
    /// Time taken by upstream server to process request (in milliseconds)
    pub upstream_processing_time: Option<u64>,
    /// Total time taken by upstream server (in milliseconds)
    pub upstream_response_time: Option<u64>,
    /// Total time the upstream connection has been alive (in milliseconds)
    /// May be large for reused connections
    pub upstream_connection_time: Option<u64>,
    /// Size of the request payload in bytes
    pub payload_size: usize,
    /// Statistics about response compression
    pub compression_stat: Option<CompressionStat>,
    /// Handler for modifying response body
    pub modify_response_body: Option<Box<dyn ModifyResponseBody>>,
    /// Response body buffer
    pub response_body: Option<BytesMut>,
    /// Number of cache reading operations
    pub cache_reading: Option<u32>,
    /// Number of cache writing operations
    pub cache_writing: Option<u32>,
    /// OpenTelemetry tracer (only with "full" feature)
    #[cfg(feature = "full")]
    pub otel_tracer: Option<OtelTracer>,
    /// OpenTelemetry span for upstream requests (only with "full" feature)
    #[cfg(feature = "full")]
    pub upstream_span: Option<BoxedSpan>,
    /// Custom variables map for request processing
    pub variables: Option<AHashMap<String, String>>,
    /// Plugin processing times
    pub plugin_processing_times: Option<Vec<(String, u32)>>,
}

const ONE_HOUR_MS: u64 = 60 * 60 * 1000;

impl Ctx {
    /// Creates a new Ctx instance with the current timestamp and default values.
    ///
    /// Returns a new Ctx struct initialized with the current timestamp and all other fields
    /// set to their default values.
    pub fn new() -> Self {
        Self {
            created_at: now_ms(),
            ..Default::default()
        }
    }

    /// Adds a variable to the state's variables map with the given key and value.
    /// The key will be automatically prefixed with '$' before being stored.
    ///
    /// # Arguments
    /// * `key` - The variable name (will be prefixed with '$')
    /// * `value` - The value to store for this variable
    #[inline]
    pub fn add_variable(&mut self, key: &str, value: &str) {
        let key = format!("${key}");
        if let Some(variables) = self.variables.as_mut() {
            variables.insert(key, value.to_string());
        } else {
            let mut variables = AHashMap::new();
            variables.insert(key, value.to_string());
            self.variables = Some(variables);
        }
    }

    /// Returns the upstream response time if it's less than one hour, otherwise None.
    /// This helps filter out potentially invalid or stale timing data.
    ///
    /// Returns: Option<u64> representing milliseconds, or None if time exceeds 1 hour
    #[inline]
    pub fn get_upstream_response_time(&self) -> Option<u64> {
        if let Some(value) = self.upstream_response_time {
            if value < ONE_HOUR_MS {
                return Some(value);
            }
        }
        None
    }

    /// Returns the upstream connect time if it's less than one hour, otherwise None.
    /// This helps filter out potentially invalid or stale timing data.
    ///
    /// Returns: Option<u64> representing milliseconds, or None if time exceeds 1 hour
    #[inline]
    pub fn get_upstream_connect_time(&self) -> Option<u64> {
        if let Some(value) = self.upstream_connect_time {
            if value < ONE_HOUR_MS {
                return Some(value);
            }
        }
        None
    }

    /// Returns the upstream processing time if it's less than one hour, otherwise None.
    /// This helps filter out potentially invalid or stale timing data.
    ///
    /// Returns: Option<u64> representing milliseconds, or None if time exceeds 1 hour
    #[inline]
    pub fn get_upstream_processing_time(&self) -> Option<u64> {
        if let Some(value) = self.upstream_processing_time {
            if value < ONE_HOUR_MS {
                return Some(value);
            }
        }
        None
    }

    /// Adds a plugin processing time to the context
    ///
    /// # Arguments
    /// * `name` - The name of the plugin
    /// * `time` - The time taken by the plugin in milliseconds
    #[inline]
    pub fn add_plugin_processing_time(&mut self, name: &str, time: u32) {
        if let Some(times) = self.plugin_processing_times.as_mut() {
            times.push((name.to_string(), time));
        } else {
            let mut times = Vec::with_capacity(5);
            times.push((name.to_string(), time));
            self.plugin_processing_times = Some(times);
        }
    }

    /// Appends a formatted value to the provided buffer based on the given key.
    /// Handles various metrics including connection info, timing data, and TLS details.
    ///
    /// # Arguments
    /// * `buf` - The BytesMut buffer to append the value to
    /// * `key` - The key identifying which state value to format and append
    ///
    /// Returns: The modified BytesMut buffer
    #[inline]
    pub fn append_value(&self, mut buf: BytesMut, key: &str) -> BytesMut {
        match key {
            "connection_id" => {
                buf.extend(
                    itoa::Buffer::new().format(self.connection_id).as_bytes(),
                );
            },
            "upstream_reused" => {
                if self.upstream_reused {
                    buf.extend(b"true");
                } else {
                    buf.extend(b"false");
                }
            },
            "upstream_addr" => buf.extend(self.upstream_address.as_bytes()),
            "processing" => buf
                .extend(itoa::Buffer::new().format(self.processing).as_bytes()),
            "upstream_connect_time" => {
                if let Some(ms) = self.get_upstream_connect_time() {
                    buf.extend(itoa::Buffer::new().format(ms).as_bytes());
                }
            },
            "upstream_connect_time_human" => {
                if let Some(ms) = self.get_upstream_connect_time() {
                    buf = format_duration(buf, ms);
                }
            },
            "upstream_connected" => {
                if let Some(value) = self.upstream_connected {
                    buf.extend(itoa::Buffer::new().format(value).as_bytes());
                }
            },
            "upstream_processing_time" => {
                if let Some(ms) = self.get_upstream_processing_time() {
                    buf.extend(itoa::Buffer::new().format(ms).as_bytes());
                }
            },
            "upstream_processing_time_human" => {
                if let Some(ms) = self.get_upstream_processing_time() {
                    buf = format_duration(buf, ms);
                }
            },
            "upstream_response_time" => {
                if let Some(ms) = self.get_upstream_response_time() {
                    buf.extend(itoa::Buffer::new().format(ms).as_bytes());
                }
            },
            "upstream_response_time_human" => {
                if let Some(ms) = self.get_upstream_response_time() {
                    buf = format_duration(buf, ms);
                }
            },
            "upstream_tcp_connect_time" => {
                if let Some(ms) = self.upstream_tcp_connect_time {
                    buf.extend(itoa::Buffer::new().format(ms).as_bytes());
                }
            },
            "upstream_tcp_connect_time_human" => {
                if let Some(ms) = self.upstream_tcp_connect_time {
                    buf = format_duration(buf, ms);
                }
            },
            "upstream_tls_handshake_time" => {
                if let Some(ms) = self.upstream_tls_handshake_time {
                    buf.extend(itoa::Buffer::new().format(ms).as_bytes());
                }
            },
            "upstream_tls_handshake_time_human" => {
                if let Some(ms) = self.upstream_tls_handshake_time {
                    buf = format_duration(buf, ms);
                }
            },
            "upstream_connection_time" => {
                if let Some(ms) = self.upstream_connection_time {
                    buf.extend(itoa::Buffer::new().format(ms).as_bytes());
                }
            },
            "upstream_connection_time_human" => {
                if let Some(ms) = self.upstream_connection_time {
                    buf = format_duration(buf, ms);
                }
            },
            "location" => {
                if !self.location.is_empty() {
                    buf.extend(self.location.as_bytes())
                }
            },
            "connection_time" => {
                buf.extend(
                    itoa::Buffer::new().format(self.connection_time).as_bytes(),
                );
            },
            "connection_time_human" => {
                buf = format_duration(buf, self.connection_time)
            },
            "connection_reused" => {
                if self.connection_reused {
                    buf.extend(b"true");
                } else {
                    buf.extend(b"false");
                }
            },
            "tls_version" => {
                if let Some(value) = &self.tls_version {
                    buf.extend(value.as_bytes());
                }
            },
            "tls_cipher" => {
                if let Some(value) = &self.tls_cipher {
                    buf.extend(value.as_bytes());
                }
            },
            "tls_handshake_time" => {
                if let Some(ms) = self.tls_handshake_time {
                    buf.extend(itoa::Buffer::new().format(ms).as_bytes());
                }
            },
            "tls_handshake_time_human" => {
                if let Some(value) = self.tls_handshake_time {
                    buf = format_duration(buf, value);
                }
            },
            "compression_time" => {
                if let Some(value) = &self.compression_stat {
                    buf.extend(
                        itoa::Buffer::new()
                            .format(value.duration.as_millis() as u64)
                            .as_bytes(),
                    );
                }
            },
            "compression_time_human" => {
                if let Some(value) = &self.compression_stat {
                    buf =
                        format_duration(buf, value.duration.as_millis() as u64);
                }
            },
            "compression_ratio" => {
                if let Some(value) = &self.compression_stat {
                    buf.extend(format!("{:.1}", value.ratio()).as_bytes());
                }
            },
            "cache_lookup_time" => {
                if let Some(ms) = self.cache_lookup_time {
                    buf.extend(itoa::Buffer::new().format(ms).as_bytes());
                }
            },
            "cache_lookup_time_human" => {
                if let Some(ms) = self.cache_lookup_time {
                    buf = format_duration(buf, ms);
                }
            },
            "cache_lock_time" => {
                if let Some(ms) = self.cache_lock_time {
                    buf.extend(itoa::Buffer::new().format(ms).as_bytes());
                }
            },
            "cache_lock_time_human" => {
                if let Some(ms) = self.cache_lock_time {
                    buf = format_duration(buf, ms);
                }
            },
            "service_time" => {
                buf.extend(
                    itoa::Buffer::new()
                        .format(now_ms() - self.created_at)
                        .as_bytes(),
                );
            },
            "service_time_human" => {
                buf = format_duration(buf, now_ms() - self.created_at)
            },
            _ => {},
        }
        buf
    }

    /// Generates a Server-Timing header value based on the context's timing metrics.
    ///
    /// The Server-Timing header allows servers to communicate performance metrics
    /// about the request-response cycle to the client. This implementation includes
    /// various timing metrics like connection time, processing time, and cache operations.
    ///
    /// Returns a String containing the formatted Server-Timing header value.
    pub fn generate_server_timing(&self) -> String {
        // the response header should be set before get body from upstream,
        // so upstream response time, compression time, etc. are not included

        let mut timings = Vec::new();

        let mut upstream_time = 0;
        let mut upstream_time_set = false;

        // Add upstream metrics
        if let Some(time) = self.get_upstream_connect_time() {
            upstream_time += time;
            upstream_time_set = true;
            timings.push(format!("upstream.connect;dur={}", time));
        }

        if let Some(time) = self.get_upstream_processing_time() {
            upstream_time += time;
            upstream_time_set = true;
            timings.push(format!("upstream.processing;dur={}", time));
        }

        if upstream_time_set {
            timings.push(format!("upstream;dur={}", upstream_time));
        }

        let mut cache_time = 0;
        let mut cache_time_set = false;
        // Add cache metrics
        if let Some(time) = self.cache_lookup_time {
            cache_time += time;
            cache_time_set = true;
            timings.push(format!("cache.lookup;dur={}", time));
        }

        if let Some(time) = self.cache_lock_time {
            cache_time += time;
            cache_time_set = true;
            timings.push(format!("cache.lock;dur={}", time));
        }
        if cache_time_set {
            timings.push(format!("cache;dur={}", cache_time));
        }

        if let Some(times) = self.plugin_processing_times.as_ref() {
            let mut plugin_time = 0;
            for (name, time) in times {
                plugin_time += time;
                timings.push(format!("plugin.{name};dur={}", time));
            }
            timings.push(format!("plugin;dur={}", plugin_time));
        }

        // Add total service time
        let service_time = now_ms() - self.created_at;
        timings.push(format!("total;dur={}", service_time));

        timings.join(", ")
    }
}

/// Generates a cache key from the request method, URI and state context.
/// The key includes an optional namespace and prefix if configured in the state.
///
/// # Arguments
/// * `ctx` - The Ctx context containing cache configuration
/// * `method` - The HTTP method as a string
/// * `uri` - The request URI
///
/// Returns: A CacheKey combining the namespace, prefix (if any), method and URI
pub fn get_cache_key(ctx: &Ctx, method: &str, uri: &Uri) -> CacheKey {
    let namespace = ctx.cache_namespace.as_ref().map_or("", |v| v);
    let key = if let Some(prefix) = &ctx.cache_prefix {
        format!("{prefix}{method}:{uri}")
    } else {
        format!("{method}:{uri}")
    };

    CacheKey::new(namespace, key, "")
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use pretty_assertions::assert_eq;
    use std::time::Duration;

    #[test]
    fn test_format_duration() {
        let mut buf = BytesMut::new();
        buf = format_duration(buf, (3600 + 3500) * 1000);
        assert_eq!(b"1.9h", buf.as_ref());

        buf = BytesMut::new();
        buf = format_duration(buf, (3600 + 1800) * 1000);
        assert_eq!(b"1.5h", buf.as_ref());

        buf = BytesMut::new();
        buf = format_duration(buf, (3600 + 100) * 1000);
        assert_eq!(b"1h", buf.as_ref());

        buf = BytesMut::new();
        buf = format_duration(buf, (60 + 50) * 1000);
        assert_eq!(b"1.8m", buf.as_ref());

        buf = BytesMut::new();
        buf = format_duration(buf, (60 + 2) * 1000);
        assert_eq!(b"1m", buf.as_ref());

        buf = BytesMut::new();
        buf = format_duration(buf, 1000);
        assert_eq!(b"1s", buf.as_ref());

        buf = BytesMut::new();
        buf = format_duration(buf, 512);
        assert_eq!(b"512ms", buf.as_ref());

        buf = BytesMut::new();
        buf = format_duration(buf, 1112);
        assert_eq!(b"1.1s", buf.as_ref());
    }

    #[test]
    fn test_add_variable() {
        let mut ctx = Ctx::new();
        ctx.add_variable("key1", "value1");
        ctx.add_variable("key2", "value2");
        assert_eq!(
            ctx.variables.clone().unwrap().get("$key1"),
            Some(&"value1".to_string())
        );
        assert_eq!(
            ctx.variables.clone().unwrap().get("$key2"),
            Some(&"value2".to_string())
        );
    }

    #[test]
    fn test_now_ms() {
        let now = now_ms();
        assert!(now > 0);
    }

    #[test]
    fn test_get_cache_key() {
        let mut ctx = Ctx::new();
        ctx.cache_namespace = Some("test".to_string());
        let method = "GET";
        let uri = Uri::from_static("http://example.com/");
        let key = get_cache_key(&ctx, method, &uri);
        assert_eq!(
            format!("{key:?}"),
            r#"CacheKey { namespace: "test", primary: "GET:http://example.com/", primary_bin_override: None, variance: None, user_tag: "", extensions: Extensions }"#
        );

        ctx.cache_prefix = Some("prefix_".to_string());
        let key = get_cache_key(&ctx, method, &uri);
        assert_eq!(
            format!("{key:?}"),
            r#"CacheKey { namespace: "test", primary: "prefix_GET:http://example.com/", primary_bin_override: None, variance: None, user_tag: "", extensions: Extensions }"#
        );
    }

    #[test]
    fn test_state() {
        let mut ctx = Ctx::new();

        ctx.connection_id = 10;
        assert_eq!(
            b"10",
            ctx.append_value(BytesMut::new(), "connection_id").as_ref()
        );

        assert_eq!(
            b"false",
            ctx.append_value(BytesMut::new(), "upstream_reused")
                .as_ref()
        );

        ctx.upstream_reused = true;
        assert_eq!(
            b"true",
            ctx.append_value(BytesMut::new(), "upstream_reused")
                .as_ref()
        );

        ctx.upstream_address = "192.168.1.1:80".to_string();
        assert_eq!(
            b"192.168.1.1:80",
            ctx.append_value(BytesMut::new(), "upstream_addr").as_ref()
        );

        ctx.processing = 10;
        assert_eq!(
            b"10",
            ctx.append_value(BytesMut::new(), "processing").as_ref()
        );

        ctx.upstream_connect_time = Some(1);
        assert_eq!(
            b"1",
            ctx.append_value(BytesMut::new(), "upstream_connect_time")
                .as_ref()
        );
        assert_eq!(
            b"1ms",
            ctx.append_value(BytesMut::new(), "upstream_connect_time_human")
                .as_ref()
        );

        ctx.upstream_connected = Some(30);
        assert_eq!(
            b"30",
            ctx.append_value(BytesMut::new(), "upstream_connected")
                .as_ref()
        );

        ctx.upstream_processing_time = Some(2);
        assert_eq!(
            b"2",
            ctx.append_value(BytesMut::new(), "upstream_processing_time")
                .as_ref()
        );
        assert_eq!(
            b"2ms",
            ctx.append_value(BytesMut::new(), "upstream_processing_time_human")
                .as_ref()
        );

        ctx.upstream_response_time = Some(3);
        assert_eq!(
            b"3",
            ctx.append_value(BytesMut::new(), "upstream_response_time")
                .as_ref()
        );
        assert_eq!(
            b"3ms",
            ctx.append_value(BytesMut::new(), "upstream_response_time_human")
                .as_ref()
        );

        ctx.upstream_tcp_connect_time = Some(100);
        assert_eq!(
            b"100",
            ctx.append_value(BytesMut::new(), "upstream_tcp_connect_time")
                .as_ref()
        );
        assert_eq!(
            b"100ms",
            ctx.append_value(
                BytesMut::new(),
                "upstream_tcp_connect_time_human"
            )
            .as_ref()
        );

        ctx.upstream_tls_handshake_time = Some(110);
        assert_eq!(
            b"110",
            ctx.append_value(BytesMut::new(), "upstream_tls_handshake_time")
                .as_ref()
        );
        assert_eq!(
            b"110ms",
            ctx.append_value(
                BytesMut::new(),
                "upstream_tls_handshake_time_human"
            )
            .as_ref()
        );

        ctx.upstream_connection_time = Some(120);
        assert_eq!(
            b"120",
            ctx.append_value(BytesMut::new(), "upstream_connection_time")
                .as_ref()
        );
        assert_eq!(
            b"120ms",
            ctx.append_value(BytesMut::new(), "upstream_connection_time_human")
                .as_ref()
        );

        ctx.location = "pingap".to_string();
        assert_eq!(
            b"pingap",
            ctx.append_value(BytesMut::new(), "location").as_ref()
        );

        ctx.connection_time = 4;
        assert_eq!(
            b"4",
            ctx.append_value(BytesMut::new(), "connection_time")
                .as_ref()
        );
        assert_eq!(
            b"4ms",
            ctx.append_value(BytesMut::new(), "connection_time_human")
                .as_ref()
        );

        assert_eq!(
            b"false",
            ctx.append_value(BytesMut::new(), "connection_reused")
                .as_ref()
        );
        ctx.connection_reused = true;
        assert_eq!(
            b"true",
            ctx.append_value(BytesMut::new(), "connection_reused")
                .as_ref()
        );

        ctx.tls_version = Some("TLSv1.3".to_string());
        assert_eq!(
            b"TLSv1.3",
            ctx.append_value(BytesMut::new(), "tls_version").as_ref()
        );

        ctx.tls_cipher =
            Some("ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".to_string());
        assert_eq!(
            b"ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            ctx.append_value(BytesMut::new(), "tls_cipher").as_ref()
        );

        ctx.tls_handshake_time = Some(101);
        assert_eq!(
            b"101",
            ctx.append_value(BytesMut::new(), "tls_handshake_time")
                .as_ref()
        );
        assert_eq!(
            b"101ms",
            ctx.append_value(BytesMut::new(), "tls_handshake_time_human")
                .as_ref()
        );

        ctx.compression_stat = Some(CompressionStat {
            in_bytes: 1024,
            out_bytes: 500,
            duration: Duration::from_millis(5),
        });
        assert_eq!(
            b"5",
            ctx.append_value(BytesMut::new(), "compression_time")
                .as_ref()
        );
        assert_eq!(
            b"5ms",
            ctx.append_value(BytesMut::new(), "compression_time_human")
                .as_ref()
        );
        assert_eq!(
            b"2.0",
            ctx.append_value(BytesMut::new(), "compression_ratio")
                .as_ref()
        );

        ctx.cache_lookup_time = Some(6);
        assert_eq!(
            b"6",
            ctx.append_value(BytesMut::new(), "cache_lookup_time")
                .as_ref()
        );
        assert_eq!(
            b"6ms",
            ctx.append_value(BytesMut::new(), "cache_lookup_time_human")
                .as_ref()
        );

        ctx.cache_lock_time = Some(7);
        assert_eq!(
            b"7",
            ctx.append_value(BytesMut::new(), "cache_lock_time")
                .as_ref()
        );
        assert_eq!(
            b"7ms",
            ctx.append_value(BytesMut::new(), "cache_lock_time_human")
                .as_ref()
        );

        ctx.created_at = now_ms() - 1;
        assert_eq!(
            true,
            ctx.append_value(BytesMut::new(), "service_time_human")
                .ends_with(b"ms")
        );
    }

    #[test]
    fn test_add_plugin_processing_time() {
        let mut ctx = Ctx::new();
        ctx.add_plugin_processing_time("plugin1", 100);
        ctx.add_plugin_processing_time("plugin2", 200);
        assert_eq!(
            ctx.plugin_processing_times,
            Some(vec![
                ("plugin1".to_string(), 100),
                ("plugin2".to_string(), 200)
            ])
        );
    }

    #[test]
    fn test_generate_server_timing() {
        let mut ctx = Ctx::new();
        ctx.upstream_connect_time = Some(1);
        ctx.upstream_processing_time = Some(2);
        ctx.cache_lookup_time = Some(6);
        ctx.cache_lock_time = Some(7);
        ctx.created_at = now_ms() - 1;
        ctx.add_plugin_processing_time("plugin1", 100);
        ctx.add_plugin_processing_time("plugin2", 200);

        // total duration sometime changes(it may be 1 or 2), so we just check the prefix
        assert_eq!(true, ctx.generate_server_timing().starts_with("upstream.connect;dur=1, upstream.processing;dur=2, upstream;dur=3, cache.lookup;dur=6, cache.lock;dur=7, cache;dur=13, plugin.plugin1;dur=100, plugin.plugin2;dur=200, plugin;dur=300, total;dur="));
    }
}
