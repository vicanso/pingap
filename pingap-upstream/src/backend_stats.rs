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

use crate::UpstreamProvider;
use async_trait::async_trait;
use dashmap::DashMap;
use http::StatusCode;
use pingap_core::{now_sec, BackgroundTask, Error};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Debug, Default)]
struct StatsSlot {
    // total requests count
    total_requests: AtomicU64,
    // failed requests count
    failed_requests: AtomicU64,
    // consecutive failures count
    // TODO 连续失败多少次则熔断
    consecutive_failures: AtomicU32,
}

impl StatsSlot {
    fn reset(&self) {
        self.total_requests.store(0, Ordering::Relaxed);
        self.failed_requests.store(0, Ordering::Relaxed);
    }
    fn get_counts(&self) -> (u64, u64) {
        (
            self.total_requests.load(Ordering::Relaxed),
            self.failed_requests.load(Ordering::Relaxed),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct WindowStats {
    pub failure_rate_percent: f64,
    pub rps: f64,
    pub total_requests: u64,
}

#[derive(Debug)]
struct Backend {
    red_slot: StatsSlot,
    blue_slot: StatsSlot,
    red_or_blue: AtomicBool, // true: red, false: blue
    last_reset_time: AtomicU64,
    last_interval: AtomicU64,
}

impl Backend {
    pub fn new() -> Self {
        Self {
            red_slot: StatsSlot::default(),
            blue_slot: StatsSlot::default(),
            red_or_blue: AtomicBool::new(true),
            last_reset_time: AtomicU64::new(now_sec()),
            last_interval: AtomicU64::new(0),
        }
    }
    fn get_slots(&self) -> (&StatsSlot, &StatsSlot) {
        // return the current and previous slots
        if self.red_or_blue.load(Ordering::Relaxed) {
            (&self.red_slot, &self.blue_slot)
        } else {
            (&self.blue_slot, &self.red_slot)
        }
    }
    fn toggle_and_reset_slot(&self) {
        let current_is_red =
            self.red_or_blue.fetch_xor(true, Ordering::Relaxed);
        let now = now_sec();
        let prev = self.last_reset_time.swap(now, Ordering::Relaxed);
        let value = now.saturating_sub(prev);
        self.last_interval.store(value, Ordering::Relaxed);
        if current_is_red {
            self.blue_slot.reset();
        } else {
            self.red_slot.reset();
        }
    }
    fn get_last_window_stats(&self) -> WindowStats {
        let interval = self.last_interval.load(Ordering::Relaxed);
        if interval == 0 {
            return WindowStats::default();
        }
        // get the previous slot
        let (_, previous_slot) = self.get_slots();

        let (total, failed) = previous_slot.get_counts();

        if total == 0 {
            return WindowStats::default();
        }

        let failure_rate_percent = (failed as f64 / total as f64) * 100.0;

        let rps = total as f64 / interval as f64;

        WindowStats {
            failure_rate_percent,
            rps,
            total_requests: total,
        }
    }
}

pub struct BackendStats {
    failure_status_codes: Option<HashSet<StatusCode>>,
    backends: DashMap<String, Arc<Backend>>,
}

impl BackendStats {
    pub fn new(failure_status_codes: Vec<u16>) -> Self {
        let failure_status_codes = failure_status_codes
            .iter()
            .flat_map(|code| StatusCode::from_u16(*code).ok())
            .collect::<HashSet<StatusCode>>();
        Self {
            failure_status_codes: if failure_status_codes.is_empty() {
                None
            } else {
                Some(failure_status_codes)
            },
            backends: DashMap::new(),
        }
    }
    fn get_backend(&self, address: &str) -> Arc<Backend> {
        self.backends
            .entry(address.to_string())
            .or_insert_with(|| Arc::new(Backend::new()))
            .clone()
    }
    pub fn on_transport_failure(&self, address: &str) {
        let backend = self.get_backend(address);
        let (current, _) = backend.get_slots();
        current.failed_requests.fetch_add(1, Ordering::Relaxed);
    }
    pub fn on_response(&self, address: &str, status: StatusCode) {
        let backend = self.get_backend(address);
        let (current, _) = backend.get_slots();
        current.total_requests.fetch_add(1, Ordering::Relaxed);
        let failure = self.failure_status_codes.as_ref().map_or_else(
            || status.is_server_error(),
            |codes| codes.contains(&status),
        );

        // Update failure counters based on the determined 'failure' status
        if failure {
            current.failed_requests.fetch_add(1, Ordering::Relaxed);
            current.consecutive_failures.fetch_add(1, Ordering::Relaxed);
        } else {
            current.consecutive_failures.store(0, Ordering::Relaxed);
        }
    }
    pub fn update(&self, backend_addresses: Vec<String>) {
        self.backends.retain(|backend_addr, _stats| {
            backend_addresses.contains(backend_addr)
        });
        for backend in self.backends.iter() {
            backend.toggle_and_reset_slot();
        }
    }
    pub fn get_all_stats(&self) -> HashMap<String, WindowStats> {
        self.backends
            .iter()
            .map(|pair| {
                let backend_address = pair.key().clone();
                let stats = pair.value().get_last_window_stats();
                (backend_address, stats)
            })
            .collect()
    }
}

struct BackendStatsTask {
    provider: Arc<dyn UpstreamProvider>,
}

#[async_trait]
impl BackgroundTask for BackendStatsTask {
    async fn execute(&self, _count: u32) -> Result<bool, Error> {
        for (_, upstream) in self.provider.list().iter() {
            upstream.update_backend_stats();
        }
        Ok(true)
    }
}

pub fn new_upstream_backend_stats_task(
    upstream_provider: Arc<dyn UpstreamProvider>,
) -> Box<dyn BackgroundTask> {
    Box::new(BackendStatsTask {
        provider: upstream_provider,
    })
}
