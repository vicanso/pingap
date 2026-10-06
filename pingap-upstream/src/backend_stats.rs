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

/// Consecutive outcome counters of one backend: a failure ends the run of
/// successes and vice versa.
#[derive(Default)]
struct ConsecutiveCounters {
    failures: AtomicU32,
    successes: AtomicU32,
}

impl ConsecutiveCounters {
    fn record(&self, failure: bool) {
        if failure {
            self.successes.store(0, Ordering::Relaxed);
            self.failures.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failures.store(0, Ordering::Relaxed);
            self.successes.fetch_add(1, Ordering::Relaxed);
        }
    }
}

pub struct BackendStats {
    failure_status_codes: Option<HashSet<StatusCode>>,
    interval: Duration,
    /// Requests and failures per backend over `interval`, each keyed by
    /// the address itself. One estimator keyed by `"total-<addr>"` and
    /// `"failure-<addr>"` used to format two strings per response.
    total: Rate,
    failure: Rate,
    consecutive_counters: DashMap<String, ConsecutiveCounters>,
}

impl BackendStats {
    pub fn new(interval: Duration, failure_status_codes: Vec<u16>) -> Self {
        let failure_status_codes = failure_status_codes
            .iter()
            .flat_map(|code| StatusCode::from_u16(*code).ok())
            .collect::<HashSet<StatusCode>>();
        // The estimators count their window in milliseconds and divide by
        // it. The config validation refuses a shorter one; this is for
        // whoever builds the stats without it.
        let interval = interval.max(Duration::from_millis(1));
        Self {
            interval,
            total: Rate::new(interval),
            failure: Rate::new(interval),
            failure_status_codes: if failure_status_codes.is_empty() {
                None
            } else {
                Some(failure_status_codes)
            },
            consecutive_counters: DashMap::new(),
        }
    }

    fn record(&self, address: &str, failure: bool) {
        // Both are observed every time, a success as no failure: an
        // estimator starts its next window when it is next looked at, and
        // one that only heard of failures kept the last window's failures
        // at full weight against requests that had long started to fade.
        self.total.observe(&address, 1);
        self.failure.observe(&address, isize::from(failure));
        // The counters exist after a backend's first request; look them up
        // by `&str` and only allocate the key for a new backend.
        if let Some(counters) = self.consecutive_counters.get(address) {
            counters.record(failure);
            return;
        }
        self.consecutive_counters
            .entry(address.to_string())
            .or_default()
            .record(failure);
    }

    /// A request that got no response at all. It is a failure like a bad
    /// status: it counts toward the consecutive failures and the failure
    /// rate, and toward the request total that rate is measured against.
    /// It used to touch only the failure estimator, so a backend that
    /// refused every connection never tripped `max_consecutive_failures`
    /// and its failure rate was measured against requests it never got.
    pub fn on_transport_failure(&self, address: &str) {
        self.record(address, true);
    }

    /// Records a response; returns whether it counts as a failure.
    pub fn on_response(&self, address: &str, status: StatusCode) -> bool {
        let failure = self.failure_status_codes.as_ref().map_or_else(
            || status.is_server_error(),
            |codes| codes.contains(&status),
        );
        self.record(address, failure);
        failure
    }

    /// The requests and failures of the last `interval`.
    ///
    /// All of the window that is being counted, and of the one before it
    /// the share that still lies within an interval from now. It used to
    /// be the previous window alone, a window that is over: a backend that
    /// started failing was not seen to for up to a whole interval (a
    /// minute by default), not at all in its first, and one that had
    /// recovered was still judged by the bad window behind it.
    #[inline]
    pub(crate) fn get_window_stats(&self, address: &str) -> WindowStats {
        let interval = self.interval.as_secs_f64();
        let recent = |rate: &Rate| {
            rate.rate_with(&address, |info| {
                info.prev_samples.max(0) as f64
                    * (1.0 - info.current_interval_fraction)
                    + info.curr_samples.max(0) as f64
            })
        };
        let total = recent(&self.total);
        // Two estimates, each rounded to its own clock tick: the failures
        // are among the requests whatever the arithmetic says.
        let failure = recent(&self.failure).min(total);
        let rps = total / interval;
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

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_consecutive_counters() {
        let stats = BackendStats::new(Duration::from_secs(60), vec![]);
        let addr = "127.0.0.1:8080";
        assert_eq!(false, stats.on_response(addr, StatusCode::OK));
        assert_eq!(false, stats.on_response(addr, StatusCode::NOT_FOUND));
        assert_eq!(2, stats.get_consecutive_successes(addr));
        assert_eq!(true, stats.on_response(addr, StatusCode::BAD_GATEWAY));
        // A connection failure is a failure like a 5xx.
        stats.on_transport_failure(addr);
        assert_eq!(2, stats.get_consecutive_failures(addr));
        assert_eq!(0, stats.get_consecutive_successes(addr));
        assert_eq!(false, stats.on_response(addr, StatusCode::OK));
        assert_eq!(0, stats.get_consecutive_failures(addr));

        // Configured failure codes replace the 5xx default.
        let stats = BackendStats::new(Duration::from_secs(60), vec![429]);
        assert_eq!(
            true,
            stats.on_response(addr, StatusCode::TOO_MANY_REQUESTS)
        );
        assert_eq!(false, stats.on_response(addr, StatusCode::BAD_GATEWAY));
    }

    /// Transport failures count in the total, so the failure rate is a
    /// share of the requests actually made.
    #[test]
    fn test_window_stats_counts_transport_failures() {
        let stats = BackendStats::new(Duration::from_secs(60), vec![]);
        let addr = "127.0.0.1:8080";
        for _ in 0..3 {
            stats.on_response(addr, StatusCode::OK);
        }
        stats.on_transport_failure(addr);
        let window = stats.get_window_stats(addr);
        assert_eq!(4, window.total_requests);
        assert_eq!(25.0, window.failure_rate_percent);
        assert_eq!(WindowStats::default(), stats.get_window_stats("unknown"));
    }

    /// Regression: the window was the one before the current one, a window
    /// that is over. Twenty failures in a row were nothing until the
    /// interval had passed - a minute by default - and a breaker that goes
    /// by the failure rate stayed closed that long.
    #[test]
    fn test_window_stats_see_the_current_window() {
        let stats = BackendStats::new(Duration::from_secs(60), vec![]);
        let addr = "127.0.0.1:8080";
        for _ in 0..20 {
            stats.on_transport_failure(addr);
        }
        let window = stats.get_window_stats(addr);
        assert_eq!(20, window.total_requests);
        assert_eq!(100.0, window.failure_rate_percent);

        // What is behind fades out as the next window goes by, it does
        // not stay whole until that one is over.
        let stats = BackendStats::new(Duration::from_millis(400), vec![]);
        for _ in 0..20 {
            stats.on_transport_failure(addr);
        }
        std::thread::sleep(Duration::from_millis(600));
        let faded = stats.get_window_stats(addr).total_requests;
        assert_eq!(true, (1..20).contains(&faded), "{faded}");
        std::thread::sleep(Duration::from_millis(900));
        assert_eq!(0, stats.get_window_stats(addr).total_requests);
    }

    /// Regression: the failures were counted by an estimator that only
    /// heard of failures, and it moved on to its next window when the next
    /// failure came, not when the requests' estimator did. Until then the
    /// failures of the window behind stood at full weight against requests
    /// that had half faded: four failures in ten, long over, and one new
    /// failure made a rate of 71%.
    #[test]
    fn test_window_stats_fade_failures_with_the_requests() {
        let stats = BackendStats::new(Duration::from_secs(1), vec![]);
        let addr = "127.0.0.1:8080";
        for index in 0..10 {
            let status = if index < 4 { 500 } else { 200 };
            stats.on_response(addr, StatusCode::from_u16(status).unwrap());
        }
        // Into the next window, where a request is what turns the page.
        std::thread::sleep(Duration::from_millis(1500));
        stats.on_response(addr, StatusCode::OK);
        std::thread::sleep(Duration::from_millis(300));
        stats.on_transport_failure(addr);

        let window = stats.get_window_stats(addr);
        assert_eq!(
            true,
            window.failure_rate_percent < 50.0,
            "{}",
            window.failure_rate_percent
        );
    }

    /// Regression: the estimate divides by the window in milliseconds, and
    /// a window of none took the process down with it.
    #[test]
    fn test_window_stats_with_no_interval() {
        for interval in [Duration::ZERO, Duration::from_micros(500)] {
            let stats = BackendStats::new(interval, vec![]);
            stats.on_transport_failure("127.0.0.1:8080");
            let window = stats.get_window_stats("127.0.0.1:8080");
            assert_eq!(true, window.failure_rate_percent <= 100.0);
        }
    }
}
