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

use bytes::{Bytes, BytesMut};
use http::StatusCode;
use pingora_limits::inflight::Guard;
use std::time::{Duration, Instant};

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
    pub processing: i32,
    pub accepted: u64,
    pub location_processing: i32,
    pub location_accepted: u64,
    pub created_at: Instant,
    pub tls_version: Option<String>,
    pub status: Option<StatusCode>,
    pub established: u64,
    pub response_body_size: usize,
    pub reused: bool,
    pub location: String,
    pub upstream_address: String,
    pub client_ip: Option<String>,
    pub remote_addr: Option<String>,
    pub guard: Option<Guard>,
    pub request_id: Option<String>,
    pub cache_prefix: Option<String>,
    pub cache_lookup_time: Option<u64>,
    pub cache_lock_time: Option<u64>,
    pub cache_max_ttl: Option<Duration>,
    pub upstream_connect_time: Option<u64>,
    pub upstream_connected: Option<u32>,
    pub upstream_processing_time: Option<u64>,
    pub upstream_response_time: Option<u64>,
    pub payload_size: usize,
    pub compression_stat: Option<CompressionStat>,
    pub modify_response_body: Option<Box<dyn ModifyResponseBody>>,
    pub response_body: Option<BytesMut>,
}

impl Default for State {
    fn default() -> Self {
        State {
            processing: 0,
            accepted: 0,
            location_processing: 0,
            location_accepted: 0,
            tls_version: None,
            status: None,
            established: 0,
            created_at: Instant::now(),
            response_body_size: 0,
            reused: false,
            location: "".to_string(),
            upstream_address: "".to_string(),
            client_ip: None,
            remote_addr: None,
            guard: None,
            request_id: None,
            cache_prefix: None,
            cache_lookup_time: None,
            cache_lock_time: None,
            cache_max_ttl: None,
            upstream_connect_time: None,
            upstream_connected: None,
            upstream_processing_time: None,
            upstream_response_time: None,
            payload_size: 0,
            compression_stat: None,
            modify_response_body: None,
            response_body: None,
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
}
