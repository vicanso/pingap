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
use tracing::warn;

use crate::LOG_TARGET;

#[derive(Debug, Clone, Copy)]
pub struct CircuitBreakerConfig {
    /// The maximum number of consecutive failures required to trip the circuit breaker.
    /// If set to 0, circuit breaking based on consecutive failures is disabled.
    pub max_consecutive_failures: u32,

    /// The maximum failure rate (percentage, 0.0 to 100.0) required to trip the circuit breaker.
    /// If set to > 100.0, circuit breaking based on failure rate is disabled.
    pub max_failure_percent: f64,

    /// The minimum total number of requests (within the statistics window) required
    /// before the failure rate is considered significant for circuit breaking.
    /// Prevents tripping the breaker when traffic is very low.
    pub min_requests_threshold: u64,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        // Provides a reasonable set of default values
        Self {
            max_consecutive_failures: 5, // Trip after 5 consecutive failures
            max_failure_percent: 50.0,   // Trip if failure rate exceeds 50%
            min_requests_threshold: 10, // Only consider failure rate if >= 10 requests in the window
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct WindowStats {
    pub failure_rate_percent: f64,
    pub rps: f64,
    pub total_requests: u64,
}

pub struct BackendStats {
    failure_status_codes: Option<HashSet<StatusCode>>,
    interval: Duration,
    rate: Rate,
    consecutive_failures: DashMap<String, AtomicU32>,
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
            consecutive_failures: DashMap::new(),
        }
    }

    pub fn on_transport_failure(&self, address: &str) {
        let key = make_key(FAILURE_KEY, address);
        self.rate.observe(&key, 1);
    }
    pub fn on_response(&self, address: &str, status: StatusCode) {
        let total_key = make_key(TOTAL_KEY, address);
        self.rate.observe(&total_key, 1);
        let failure = self.failure_status_codes.as_ref().map_or_else(
            || status.is_server_error(),
            |codes| codes.contains(&status),
        );
        // Update failure counters based on the determined 'failure' status
        let consecutive_failure = self
            .consecutive_failures
            .entry(address.to_string())
            .or_insert_with(|| AtomicU32::new(0));
        if failure {
            let failure_key = make_key(FAILURE_KEY, address);
            self.rate.observe(&failure_key, 1);
            consecutive_failure.fetch_add(1, Ordering::Relaxed);
        } else {
            consecutive_failure.store(0, Ordering::Relaxed);
        }
    }

    #[inline]
    fn get_window_stats(&self, address: &str, interval: f64) -> WindowStats {
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

    pub fn get_all_stats(
        &self,
        backends: &Backends,
    ) -> HashMap<String, WindowStats> {
        let interval = self.interval.as_secs_f64();
        let backends = backends
            .get_backend()
            .iter()
            .map(|backend| backend.addr.to_string())
            .collect::<HashSet<String>>();
        self.consecutive_failures
            .retain(|key, _| backends.contains(key));
        backends
            .into_iter()
            .map(|address| {
                let stats = self.get_window_stats(&address, interval);
                (address, stats)
            })
            .collect()
    }
    /// Determines if the specified backend address should be circuit-broken based on
    /// current statistics and the provided configuration.
    ///
    /// # Arguments
    /// * `address` - The address of the backend to check.
    /// * `config` - The circuit breaker configuration parameters.
    ///
    /// # Returns
    /// * `true` - If the backend meets the conditions to be circuit-broken.
    /// * `false` - If the backend is currently considered healthy.
    pub fn should_circuit_break(
        &self,
        address: &str,
        config: &CircuitBreakerConfig,
    ) -> bool {
        if config.max_consecutive_failures > 0 {
            let consecutive_failures_count = self
                .consecutive_failures
                .get(address)
                .map(|entry| entry.load(Ordering::Relaxed))
                .unwrap_or(0);
            if consecutive_failures_count >= config.max_consecutive_failures {
                warn!(
                    target = LOG_TARGET,
                    address,
                    count = consecutive_failures_count,
                    threshold = config.max_consecutive_failures,
                    "circuit breaking due to consecutive failures"
                );
                return true;
            }
        }
        if config.max_failure_percent <= 100.0 {
            let stats =
                self.get_window_stats(address, self.interval.as_secs_f64());
            if stats.total_requests < config.min_requests_threshold {
                return false;
            }
            if stats.failure_rate_percent >= config.max_failure_percent {
                warn!(
                    target = LOG_TARGET,
                    address,
                    failure_rate = stats.failure_rate_percent,
                    threshold = config.max_failure_percent,
                    "circuit breaking due to consecutive failures"
                );
                return true;
            }
        }
        false
    }
}
