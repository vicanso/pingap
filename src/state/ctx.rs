// Copyright 2024 Tree xie.
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

use crate::util::format_duration;
use crate::{proxy::Location, util};
use bytes::{Bytes, BytesMut};
use http::StatusCode;
use opentelemetry::global::BoxedSpan;
use pingora_limits::inflight::Guard;
use std::{sync::Arc, time::Duration};

pub trait ModifyResponseBody: Sync + Send {
    fn handle(&self, data: Bytes) -> Bytes;
}

pub struct CompressionStat {
    pub in_bytes: usize,
    pub out_bytes: usize,
    pub duration: Duration,
}

impl CompressionStat {
    pub fn ratio(&self) -> f64 {
        (self.in_bytes as f64) / (self.out_bytes as f64)
    }
}

pub struct State {
    // current processing request
    pub processing: i32,
    // accepted request
    pub accepted: u64,
    // current location processing request
    pub location_processing: i32,
    // current location accepted request
    pub location_accepted: u64,
    // context created at
    pub created_at: u64,
    // client tls version
    pub tls_version: Option<String>,
    // client tls cipher
    pub tls_cipher: Option<String>,
    // client tls handshake time
    pub tls_handshake_time: Option<u64>,
    // http status code
    pub status: Option<StatusCode>,
    // the connection time,
    // it may be a large value if it is a reused connection
    pub connection_time: u64,
    // connection is resued
    pub connection_reused: bool,
    // the location to handle request
    pub location: Option<Arc<Location>>,
    // the upstream address
    pub upstream_address: String,
    pub client_ip: Option<String>,
    pub remote_addr: Option<String>,
    pub guard: Option<Guard>,
    pub request_id: Option<String>,
    pub cache_prefix: Option<String>,
    pub cache_lookup_time: Option<u64>,
    pub cache_lock_time: Option<u64>,
    pub cache_max_ttl: Option<Duration>,
    pub upstream_reused: bool,
    pub upstream_processing: Option<i32>,
    // upstream connect time,
    // get reused connection from pool or connect to upstream,
    // it may be a small value if it is a reused connection
    pub upstream_connect_time: Option<u64>,
    // current upstream connected connection count
    pub upstream_connected: Option<u32>,
    // upstream tcp connect time
    pub upstream_tcp_connect_time: Option<u64>,
    // upstream tls handshake time
    pub upstream_tls_handshake_time: Option<u64>,
    // upstream server processing time
    pub upstream_processing_time: Option<u64>,
    // upstream response time
    pub upstream_response_time: Option<u64>,
    // client payload size
    pub payload_size: usize,
    // compression stat, in/out bytes and compression duration
    pub compression_stat: Option<CompressionStat>,
    pub modify_response_body: Option<Box<dyn ModifyResponseBody>>,
    pub response_body: Option<BytesMut>,
    // cache reading count
    pub cache_reading: Option<u32>,
    // cache writing count
    pub cache_writing: Option<u32>,
    pub http_request_span: Option<BoxedSpan>,
}

impl Default for State {
    fn default() -> Self {
        State {
            processing: 0,
            accepted: 0,
            location_processing: 0,
            location_accepted: 0,
            tls_version: None,
            tls_cipher: None,
            tls_handshake_time: None,
            status: None,
            connection_time: 0,
            connection_reused: false,
            created_at: util::now().as_millis() as u64,
            upstream_reused: false,
            location: None,
            upstream_address: "".to_string(),
            client_ip: None,
            remote_addr: None,
            guard: None,
            request_id: None,
            cache_prefix: None,
            cache_lookup_time: None,
            cache_lock_time: None,
            cache_max_ttl: None,
            upstream_processing: None,
            upstream_connect_time: None,
            upstream_connected: None,
            upstream_tcp_connect_time: None,
            upstream_tls_handshake_time: None,
            upstream_processing_time: None,
            upstream_response_time: None,
            payload_size: 0,
            compression_stat: None,
            modify_response_body: None,
            response_body: None,
            cache_reading: None,
            cache_writing: None,
            http_request_span: None,
        }
    }
}

const ONE_HOUR_MS: u64 = 60 * 60 * 1000;

impl State {
    #[inline]
    pub fn get_upstream_response_time(&self) -> Option<u64> {
        if let Some(value) = self.upstream_response_time {
            if value < ONE_HOUR_MS {
                return Some(value);
            }
        }
        None
    }
    #[inline]
    pub fn get_upstream_connect_time(&self) -> Option<u64> {
        if let Some(value) = self.upstream_connect_time {
            if value < ONE_HOUR_MS {
                return Some(value);
            }
        }
        None
    }
    #[inline]
    pub fn get_upstream_processing_time(&self) -> Option<u64> {
        if let Some(value) = self.upstream_processing_time {
            if value < ONE_HOUR_MS {
                return Some(value);
            }
        }
        None
    }
    #[inline]
    pub fn append_value(&self, mut buf: BytesMut, key: &str) -> BytesMut {
        match key {
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
                    buf = format_duration(buf, ms);
                }
            },
            "upstream_response_time" => {
                if let Some(ms) = self.get_upstream_response_time() {
                    buf = format_duration(buf, ms);
                }
            },
            "upstream_tcp_connect_time" => {
                if let Some(ms) = self.upstream_tcp_connect_time {
                    buf = format_duration(buf, ms);
                }
            },
            "upstream_tls_handshake_time" => {
                if let Some(ms) = self.upstream_tls_handshake_time {
                    buf = format_duration(buf, ms);
                }
            },
            "location" => {
                if let Some(location) = &self.location {
                    buf.extend(location.name.as_bytes())
                }
            },
            "connection_time" => {
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
                if let Some(value) = self.tls_handshake_time {
                    buf = format_duration(buf, value);
                }
            },
            "compression_time" => {
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
                    buf = format_duration(buf, ms);
                }
            },
            "cache_lock_time" => {
                if let Some(ms) = self.cache_lock_time {
                    buf = format_duration(buf, ms);
                }
            },
            "service_time" => {
                buf = format_duration(
                    buf,
                    util::now().as_millis() as u64 - self.created_at,
                )
            },
            _ => {},
        }
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::State;
    use crate::config::LocationConf;
    use crate::proxy::Location;
    use crate::state::CompressionStat;
    use crate::util;
    use bytes::BytesMut;
    use pretty_assertions::assert_eq;
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn test_state() {
        let mut ctx = State {
            ..Default::default()
        };

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
            b"1ms",
            ctx.append_value(BytesMut::new(), "upstream_connect_time")
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
            b"2ms",
            ctx.append_value(BytesMut::new(), "upstream_processing_time")
                .as_ref()
        );

        ctx.upstream_response_time = Some(3);
        assert_eq!(
            b"3ms",
            ctx.append_value(BytesMut::new(), "upstream_response_time")
                .as_ref()
        );

        ctx.upstream_tcp_connect_time = Some(100);
        assert_eq!(
            b"100ms",
            ctx.append_value(BytesMut::new(), "upstream_tcp_connect_time")
                .as_ref()
        );
        ctx.upstream_tls_handshake_time = Some(110);
        assert_eq!(
            b"110ms",
            ctx.append_value(BytesMut::new(), "upstream_tls_handshake_time")
                .as_ref()
        );

        ctx.location = Some(Arc::new(
            Location::new(
                "pingap",
                &LocationConf {
                    ..Default::default()
                },
            )
            .unwrap(),
        ));
        assert_eq!(
            b"pingap",
            ctx.append_value(BytesMut::new(), "location").as_ref()
        );

        ctx.connection_time = 4;
        assert_eq!(
            b"4ms",
            ctx.append_value(BytesMut::new(), "connection_time")
                .as_ref()
        );

        ctx.connection_reused = true;
        assert_eq!(
            b"true",
            ctx.append_value(BytesMut::new(), "connection_reused")
                .as_ref()
        );

        ctx.tls_version = Some("tls1.3".to_string());
        assert_eq!(
            b"tls1.3",
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
            b"101ms",
            ctx.append_value(BytesMut::new(), "tls_handshake_time")
                .as_ref()
        );

        ctx.compression_stat = Some(CompressionStat {
            in_bytes: 1024,
            out_bytes: 500,
            duration: Duration::from_millis(5),
        });
        assert_eq!(
            b"5ms",
            ctx.append_value(BytesMut::new(), "compression_time")
                .as_ref()
        );
        assert_eq!(
            b"2.0",
            ctx.append_value(BytesMut::new(), "compression_ratio")
                .as_ref()
        );

        ctx.cache_lookup_time = Some(6);
        assert_eq!(
            b"6ms",
            ctx.append_value(BytesMut::new(), "cache_lookup_time")
                .as_ref()
        );

        ctx.cache_lock_time = Some(7);
        assert_eq!(
            b"7ms",
            ctx.append_value(BytesMut::new(), "cache_lock_time")
                .as_ref()
        );

        ctx.created_at = util::now().as_millis() as u64 - 1;
        assert_eq!(
            true,
            ctx.append_value(BytesMut::new(), "service_time")
                .ends_with(b"ms")
        );
    }
}
