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

use http::StatusCode;
use pingora_limits::inflight::Guard;
use std::time::{Duration, Instant};

pub struct State {
    pub processing: i32,
    pub accepted: u64,
    pub created_at: Instant,
    pub is_tls: bool,
    pub status: Option<StatusCode>,
    pub response_body_size: usize,
    pub reused: bool,
    pub upstream_address: String,
    pub location_index: Option<usize>,
    pub client_ip: Option<String>,
    pub guard: Option<Guard>,
    pub request_id: Option<String>,
    pub cache_prefix: Option<String>,
    pub cache_lock_duration: Option<Duration>,
}

impl Default for State {
    fn default() -> Self {
        State {
            processing: 0,
            accepted: 0,
            is_tls: false,
            status: None,
            created_at: Instant::now(),
            response_body_size: 0,
            reused: false,
            upstream_address: "".to_string(),
            location_index: None,
            client_ip: None,
            guard: None,
            request_id: None,
            cache_prefix: None,
            cache_lock_duration: None,
        }
    }
}
