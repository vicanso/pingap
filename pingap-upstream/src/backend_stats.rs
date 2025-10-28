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

use dashmap::DashMap;
use http::StatusCode;
use pingap_core::Rate;
use pingora::lb::Backends;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct WindowStats {
    pub failure_rate_percent: f64,
    pub rps: f64,
    pub total_requests: u64,
}

pub struct ConsecutiveCounters {
    /// The counter of consecutive failures
    pub failures: AtomicU32,
    /// The counter of consecutive successes
    pub successes: AtomicU32,
}
impl ConsecutiveCounters {
    pub fn new() -> Self {
        Self {
            failures: AtomicU32::new(0),
            successes: AtomicU32::new(0),
        }
    }
}

pub struct BackendStats {
    failure_status_codes: Option<HashSet<StatusCode>>,
    interval: Duration,
    rate: Rate,
    consecutive_counters: DashMap<String, ConsecutiveCounters>,
}

const FAILURE_KEY: &str = "failure";
const TOTAL_KEY: &str = "total";

// Helper to create keys efficiently, potentially avoiding allocation
// if Rate accepts different key types, but Cow<'_, str> is flexible.
#[inline]
fn make_key<'a>(prefix: &'static str, address: &'a str) -> Cow<'a, str> {
    // If Rate could take (&str, &str), we could avoid this.
    // For now, assume concatenation is needed but maybe Cow helps.
    Cow::Owned(format!("{prefix}-{address}"))
}

impl BackendStats {
    pub fn new(interval: Duration, failure_status_codes: Vec<u16>) -> Self {
        let failure_status_codes = failure_status_codes
            .iter()
            .flat_map(|code| StatusCode::from_u16(*code).ok())
            .collect::<HashSet<StatusCode>>();
        Self {
            interval,
            rate: Rate::new(interval),
            failure_status_codes: if failure_status_codes.is_empty() {
                None
            } else {
                Some(failure_status_codes)
            },
            consecutive_counters: DashMap::new(),
        }
    }
    pub fn on_transport_failure(&self, address: &str) {
        let key = make_key(FAILURE_KEY, address);
        self.rate.observe(&key, 1);
    }
    /// Returns true if the response is a success, false otherwise
    pub fn on_response(&self, address: &str, status: StatusCode) -> bool {
        let total_key = make_key(TOTAL_KEY, address);
        self.rate.observe(&total_key, 1);
        let is_request_failure =
            self.failure_status_codes.as_ref().map_or_else(
                || status.is_server_error(),
                |codes| codes.contains(&status),
            );
        // Update success / failure counters based on the determined status
        let counters = self
            .consecutive_counters
            .entry(address.to_string())
            .or_insert_with(ConsecutiveCounters::new);
        if is_request_failure {
            counters.successes.store(0, Ordering::Relaxed);
            let failure_key = make_key(FAILURE_KEY, address);
            self.rate.observe(&failure_key, 1);
            counters.failures.fetch_add(1, Ordering::Relaxed);
        } else {
            counters.successes.fetch_add(1, Ordering::Relaxed);
            counters.failures.store(0, Ordering::Relaxed);
        }
        is_request_failure
    }

    #[inline]
    pub(crate) fn get_window_stats(&self, address: &str) -> WindowStats {
        let interval = self.interval.as_secs_f64();
        let total_key = make_key(TOTAL_KEY, address);
        let failure_key = make_key(FAILURE_KEY, address);
        let rps = self.rate.rate(&total_key);
        let total = rps * interval;
        let failure = self.rate.rate(&failure_key) * interval;
        let failure_rate_percent = if total > 0.0 {
            (failure / total) * 100.0
        } else {
            0.0
        };
        WindowStats {
            total_requests: total as u64,
            failure_rate_percent,
            rps,
        }
    }
    pub fn get_consecutive_successes(&self, address: &str) -> u32 {
        self.consecutive_counters
            .get(address)
            .map(|entry| entry.successes.load(Ordering::Relaxed))
            .unwrap_or(0)
    }
    pub fn get_consecutive_failures(&self, address: &str) -> u32 {
        self.consecutive_counters
            .get(address)
            .map(|entry| entry.failures.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub fn get_all_stats(
        &self,
        backends: &Backends,
    ) -> HashMap<String, WindowStats> {
        let backends = backends
            .get_backend()
            .iter()
            .map(|backend| backend.addr.to_string())
            .collect::<HashSet<String>>();
        self.consecutive_counters
            .retain(|key, _| backends.contains(key));
        backends
            .into_iter()
            .map(|address| {
                let stats = self.get_window_stats(&address);
                (address, stats)
            })
            .collect()
    }
}
