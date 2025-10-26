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

use crate::backend_stats::BackendStats;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

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
    /// The number of consecutive successes required to reset the circuit breaker to closed.
    pub half_open_consecutive_success_threshold: u32,

    /// The duration of the open state of the circuit breaker.
    pub open_duration: Duration,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        // Provides a reasonable set of default values
        Self {
            max_consecutive_failures: 5, // Trip after 5 consecutive failures
            max_failure_percent: 50.0,   // Trip if failure rate exceeds 50%
            min_requests_threshold: 10, // Only consider failure rate if >= 10 requests in the window
            half_open_consecutive_success_threshold: 5,
            open_duration: Duration::from_secs(10),
        }
    }
}

const STATE_CLOSED: u8 = 0;
const STATE_OPEN: u8 = 1;
const STATE_HALF_OPEN: u8 = 2;

struct BreakerStateData {
    /// The time point when the circuit breaker is opened
    open_until: Instant,
    /// The number of probes sent in the half-open state
    probes_sent: u32,
}

/// The complete state of a single backend
struct BackendCircuitState {
    /// The atomic state machine (99.9% of the time only read this)
    /// 0 = Closed, 1 = Open, 2 = HalfOpen
    current_state: AtomicU8,

    /// The additional data of the state (only locked when state is changed)
    data: Mutex<BreakerStateData>,
}

impl BackendCircuitState {
    fn new() -> Self {
        Self {
            current_state: AtomicU8::new(STATE_CLOSED),
            data: Mutex::new(BreakerStateData {
                open_until: Instant::now(),
                probes_sent: 0,
            }),
        }
    }
}

pub struct BackendCircuitStates {
    backend_states: DashMap<String, Arc<BackendCircuitState>>,
    config: CircuitBreakerConfig,
}

impl BackendCircuitStates {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            backend_states: DashMap::new(),
            config,
        }
    }
    fn get_or_create_backend_circuit_state(
        &self,
        address: &str,
    ) -> Arc<BackendCircuitState> {
        self.backend_states
            .entry(address.to_string())
            .or_insert_with(|| Arc::new(BackendCircuitState::new()))
            .clone()
    }
    fn check_open_state_non_blocking(
        &self,
        state: &BackendCircuitState,
    ) -> bool {
        // Try to get the lock
        let Ok(mut data) = state.data.try_lock() else {
            // The lock is being contested (for example, another thread is breaking it)
            return false;
        };

        // The lock was successfully acquired, check the timer
        if Instant::now() >= data.open_until {
            data.probes_sent = 1; // Send the first probe
            state
                .current_state
                .store(STATE_HALF_OPEN, Ordering::Relaxed);
            true // Accept (as the first probe)
        } else {
            false // Still in the cooling period
        }
    }
    fn check_half_open_state_non_blocking(
        &self,
        state: &BackendCircuitState,
    ) -> bool {
        let Ok(mut data) = state.data.try_lock() else {
            return false; // The lock is being contested, reject
        };

        if data.probes_sent
            < self.config.half_open_consecutive_success_threshold
        {
            data.probes_sent += 1;
            true // Accept (as a probe)
        } else {
            false // Probe count used up
        }
    }

    pub fn is_backend_acceptable(&self, address: &str) -> bool {
        let state = self.get_or_create_backend_circuit_state(address);

        // 1. Read the atomic state (no lock, very fast)
        let state_now = state.current_state.load(Ordering::Relaxed);

        match state_now {
            STATE_CLOSED => {
                // 99.9% of the time: the state is Closed, immediately allow.
                true
            },
            STATE_OPEN => {
                // The state is Open, we need to check the timer (rare)
                // This is a "slow path", we need a non-blocking check
                self.check_open_state_non_blocking(&state)
            },
            STATE_HALF_OPEN => {
                // The state is HalfOpen, we need to check the probe count (rare)
                // This is a "slow path", we need a non-blocking check
                self.check_half_open_state_non_blocking(&state)
            },
            _ => false, // Impossible state
        }
    }

    pub fn update_state_after_request(
        &self,
        address: &str,
        is_request_success: bool,
        stats: &BackendStats,
    ) {
        let state = self.get_or_create_backend_circuit_state(address);

        if is_request_success {
            // --- 99.9% 的情况：请求成功 ---

            // 1. 只读原子状态（无锁）
            let state_now = state.current_state.load(Ordering::Relaxed);

            if state_now == STATE_CLOSED {
                // success when state is Closed, do nothing
                return;
            }

            if state_now == STATE_HALF_OPEN {
                // success when state is HalfOpen, check if need to reset to Closed
                if stats.get_consecutive_successes(address)
                    >= self.config.half_open_consecutive_success_threshold
                {
                    state.current_state.store(STATE_CLOSED, Ordering::Relaxed);
                }
            }
        } else {
            //  check the state again
            let state_now = state.current_state.load(Ordering::Relaxed);
            // request failed
            let Ok(mut data) = state.data.try_lock() else {
                return;
            };

            match state_now {
                STATE_CLOSED => {
                    // check if need to trip the breaker
                    let mut is_fail = false;
                    let config = &self.config;
                    if config.max_consecutive_failures > 0
                        && stats.get_consecutive_failures(address)
                            >= config.max_consecutive_failures
                    {
                        is_fail = true
                    }
                    if !is_fail && config.max_failure_percent <= 100.0 {
                        let stats = stats.get_window_stats(address);
                        if stats.total_requests >= config.min_requests_threshold
                            && stats.failure_rate_percent
                                >= config.max_failure_percent
                        {
                            is_fail = true
                        }
                    }

                    if is_fail {
                        state
                            .current_state
                            .store(STATE_HALF_OPEN, Ordering::Relaxed);
                        *data = BreakerStateData {
                            open_until: Instant::now()
                                + self.config.open_duration,
                            probes_sent: 0,
                        };
                    }
                },
                STATE_HALF_OPEN => {
                    // current state is HalfOpen, set to Open if request fail
                    state.current_state.store(STATE_OPEN, Ordering::Relaxed);
                    *data = BreakerStateData {
                        open_until: Instant::now() + self.config.open_duration,
                        probes_sent: 0,
                    };
                },
                _ => {}, // Open 状态
            }
        }
    }
}
