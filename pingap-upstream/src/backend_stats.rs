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
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

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
        self.rate.observe(&format!("{FAILURE_KEY}-{address}"), 1);
    }
    pub fn on_response(&self, address: &str, status: StatusCode) {
        self.rate.observe(&format!("{TOTAL_KEY}-{address}"), 1);
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
            self.rate.observe(&format!("{FAILURE_KEY}-{address}"), 1);
            consecutive_failure.fetch_add(1, Ordering::Relaxed);
        } else {
            consecutive_failure.store(0, Ordering::Relaxed);
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
            .map(|item| item.to_string())
            .collect::<HashSet<String>>();
        self.consecutive_failures
            .retain(|key, _| backends.contains(key));
        backends
            .into_iter()
            .map(|address| {
                let rps = self.rate.rate(&format!("{TOTAL_KEY}-{address}"));
                let total = rps * interval;
                let failure =
                    self.rate.rate(&format!("{FAILURE_KEY}-{address}"))
                        * interval;
                let failure_rate_percent =
                    if total > 0.0 { failure / total } else { 0.0 };
                let stats = WindowStats {
                    total_requests: total as u64,
                    failure_rate_percent,
                    rps,
                };
                (address, stats)
            })
            .collect()
    }
}
