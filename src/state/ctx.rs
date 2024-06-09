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
    pub algorithm: String,
    pub in_bytes: usize,
    pub out_bytes: usize,
    pub duration: Duration,
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
    pub location_index: Option<usize>,
    pub client_ip: Option<String>,
    pub remote_addr: Option<String>,
    pub guard: Option<Guard>,
    pub request_id: Option<String>,
    pub cache_prefix: Option<String>,
    pub cache_lock_duration: Option<Duration>,
    pub upstream_connect_time: Option<u32>,
    pub upstream_connected: Option<u32>,
    pub upstream_processing_time: Option<u32>,
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
            location_index: None,
            client_ip: None,
            remote_addr: None,
            guard: None,
            request_id: None,
            cache_prefix: None,
            cache_lock_duration: None,
            upstream_connect_time: None,
            upstream_connected: None,
            upstream_processing_time: None,
            payload_size: 0,
            compression_stat: None,
            modify_response_body: None,
            response_body: None,
        }
    }
}

impl State {
    pub fn get_upstream_connect_time(&self) -> Option<u32> {
        if self.upstream_address.is_empty() {
            return None;
        }
        self.upstream_connect_time
    }
    pub fn get_upstream_processing_time(&self) -> Option<u32> {
        self.status?;
        self.upstream_processing_time
    }
}
