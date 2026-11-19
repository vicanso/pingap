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

use super::{LOG_TARGET, now_ms};
use ahash::{AHashMap, RandomState};
use std::sync::Arc;
use std::sync::atomic::{AtomicIsize, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;
use tinyufo::TinyUfo;
use tracing::debug;

#[derive(Debug, Default)]
struct TtlLimit {
    count: AtomicUsize,
    /// Start of the current window. Zero once the window expired and the
    /// entry was reset; the next `inc` opens a new one.
    created_at: AtomicU64,
}

/// Counts per key within a window of time, for a rate limit: a key may be
/// counted `max` times within the `ttl` that its first count opens. The
/// keys are kept in a bounded TinyUFO cache of about `size` entries, so a
/// key that is pushed out loses its count (see [`TtlLruLimit::new`]).
pub struct TtlLruLimit {
    ttl: u64,
    /// Keys are stored as stable hashes so `validate`/`inc` can look up with
    /// `&str` without allocating a `String` on every call. TinyUFO itself only
    /// indexes by `hash_one(key)`, so a `u64` key is equivalent for lookup.
    /// Two keys that hash alike share a counter, which only makes the limit
    /// stricter for both.
    ///
    /// Values are shared, so `inc` bumps the counter in place instead of
    /// reading, adding and writing back: concurrent increments on one key do
    /// not lose each other.
    ufo: TinyUfo<u64, Arc<TtlLimit>>,
    max: usize,
    hasher: RandomState,
}

impl TtlLruLimit {
    /// Creates a new TTL-based LRU limit with the specified parameters.
    ///
    /// # Arguments
    ///
    /// * `size` - The maximum number of entries to store in the LRU cache
    /// * `ttl` - The time-to-live duration after which entries are considered expired
    /// * `max` - The maximum count allowed per key within the TTL window
    pub fn new(size: usize, ttl: Duration, max: usize) -> Self {
        Self {
            ttl: ttl.as_millis() as u64,
            max,
            ufo: TinyUfo::new(size, size),
            hasher: RandomState::new(),
        }
    }
    /// Creates a new compact TTL-based LRU limit with the specified parameters.
    ///
    /// # Arguments
    ///
    /// * `size` - The maximum number of entries to store in the LRU cache
    /// * `ttl` - The time-to-live duration after which entries are considered expired
    pub fn new_compact(size: usize, ttl: Duration, max: usize) -> Self {
        Self {
            ttl: ttl.as_millis() as u64,
            max,
            ufo: TinyUfo::new_compact(size, size),
            hasher: RandomState::new(),
        }
    }

    #[inline]
    fn hash_key(&self, key: &str) -> u64 {
        self.hasher.hash_one(key)
    }

    /// Validates whether a key has not exceeded its rate limit.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to validate
    ///
    /// # Returns
    ///
    /// Returns `true` if the key is within its limit or has expired, `false` otherwise.
    pub fn validate(&self, key: &str) -> bool {
        let key = self.hash_key(key);
        let Some(value) = self.ufo.get(&key) else {
            return true;
        };
        debug!(
            target: LOG_TARGET,
            key,
            ?value,
            "ttl lru limit"
        );
        let created_at = value.created_at.load(Ordering::Relaxed);
        // Reset and waiting for the next `inc` to open a window.
        if created_at == 0 {
            return true;
        }
        if now_ms().saturating_sub(created_at) > self.ttl {
            // Expired: reset in place, TinyUFO has no remove. An `inc` that
            // lands between the two stores is counted against the next
            // window, or lost; either way at most one off.
            value.created_at.store(0, Ordering::Relaxed);
            value.count.store(0, Ordering::Relaxed);
            return true;
        }
        value.count.load(Ordering::Relaxed) < self.max
    }
    /// Increments the counter for the specified key.
    /// If the key doesn't exist, creates a new entry with count 1.
    /// If the key exists but was reset (count = 0), updates its creation timestamp.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to increment
    pub fn inc(&self, key: &str) {
        let key = self.hash_key(key);
        if let Some(value) = self.ufo.get(&key) {
            // A reset entry opens a new window on its first increment.
            let _ = value.created_at.compare_exchange(
                0,
                now_ms(),
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
            value.count.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.ufo.put(
            key,
            Arc::new(TtlLimit {
                count: AtomicUsize::new(1),
                created_at: AtomicU64::new(now_ms()),
            }),
            1,
        );
    }
}

#[derive(Debug, Default)]
struct ExactRateWindow {
    epoch: u64,
    prev: u64,
    curr: u64,
}

/// Sliding-window exact per-key rate tracker backed by a bounded `TinyUfo`
/// cache, eliminating the hash collisions of fixed-size Count-Min Sketches
/// on high-cardinality key sets while keeping memory strictly bounded.
pub struct ExactRate {
    interval_ms: u64,
    interval: Duration,
    ufo: TinyUfo<u64, Arc<std::sync::Mutex<ExactRateWindow>>>,
    init_locks: [std::sync::Mutex<()>; 16],
    hasher: RandomState,
}

impl std::fmt::Debug for ExactRate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExactRate")
            .field("interval_ms", &self.interval_ms)
            .finish()
    }
}

fn exact_seconds_to_reset(
    interval: Duration,
    prev_samples: u64,
    curr_samples: u64,
    fraction: f64,
) -> u64 {
    let left = 1.0 - fraction;
    let windows = if curr_samples > 0 {
        left + 1.0
    } else if prev_samples > 0 {
        left
    } else {
        return 0;
    };
    (interval.as_secs_f64() * windows).ceil().max(1.0) as u64
}

impl ExactRate {
    /// Creates an exact sliding-window rate limiter holding up to `max_keys`
    /// hashed key entries for intervals of `interval`.
    pub fn new(max_keys: usize, interval: Duration) -> Self {
        let cap = max_keys.max(1);
        let interval_ms = u64::try_from(interval.as_millis())
            .unwrap_or(u64::MAX)
            .max(1);
        Self {
            interval_ms,
            interval,
            ufo: TinyUfo::new(cap, cap),
            init_locks: std::array::from_fn(|_| std::sync::Mutex::new(())),
            hasher: RandomState::new(),
        }
    }

    fn get_or_insert(
        &self,
        key_hash: u64,
        epoch: u64,
    ) -> Arc<std::sync::Mutex<ExactRateWindow>> {
        if let Some(window) = self.ufo.get(&key_hash) {
            return window;
        }
        let shard = (key_hash as usize) & (self.init_locks.len() - 1);
        let _guard = self.init_locks[shard]
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(window) = self.ufo.get(&key_hash) {
            return window;
        }
        let entry = Arc::new(std::sync::Mutex::new(ExactRateWindow {
            epoch,
            prev: 0,
            curr: 0,
        }));
        self.ufo.put(key_hash, Arc::clone(&entry), 1);
        entry
    }

    /// Evaluates the current sliding-window request rate for `key` against
    /// `max`, increments the current bucket only when within `max`, and
    /// returns `(estimated_count, reset_seconds)`.
    pub fn observe_and_check(&self, key: &str, max: f64) -> (f64, u64) {
        let now = now_ms();
        let epoch = now / self.interval_ms;
        let fraction =
            (now % self.interval_ms) as f64 / self.interval_ms as f64;
        let key_hash = self.hasher.hash_one(key);
        let window = self.get_or_insert(key_hash, epoch);

        let mut guard = window.lock().unwrap_or_else(|e| e.into_inner());
        if epoch > guard.epoch {
            if epoch == guard.epoch + 1 {
                guard.prev = guard.curr;
            } else {
                guard.prev = 0;
            }
            guard.curr = 0;
            guard.epoch = epoch;
        }
        let candidate =
            (guard.prev as f64) * (1.0 - fraction) + (guard.curr as f64) + 1.0;
        if candidate <= max {
            guard.curr += 1;
        }
        let reset = exact_seconds_to_reset(
            self.interval,
            guard.prev,
            guard.curr,
            fraction,
        );
        (candidate, reset)
    }
}

const EXACT_INFLIGHT_SHARDS: usize = 16;

#[derive(Debug)]
struct ExactInflightState {
    shards: [std::sync::Mutex<AHashMap<u64, Arc<AtomicIsize>>>;
        EXACT_INFLIGHT_SHARDS],
    max_keys: usize,
    active_keys: AtomicUsize,
}

/// Exact sharded concurrent-request tracker with an upper bound `max_keys` on
/// tracked distinct keys.
#[derive(Debug)]
pub struct ExactInflight {
    state: Arc<ExactInflightState>,
    hasher: RandomState,
}

/// RAII guard decrementing an [`ExactInflight`] key counter when dropped.
#[derive(Debug)]
pub struct ExactInflightGuard {
    state: Arc<ExactInflightState>,
    key_hash: u64,
    counter: Option<Arc<AtomicIsize>>,
}

impl ExactInflight {
    /// Creates an exact inflight counter bounded to `max_keys` active keys.
    pub fn new(max_keys: usize) -> Self {
        Self {
            state: Arc::new(ExactInflightState {
                shards: std::array::from_fn(|_| {
                    std::sync::Mutex::new(AHashMap::new())
                }),
                max_keys: max_keys.max(1),
                active_keys: AtomicUsize::new(0),
            }),
            hasher: RandomState::new(),
        }
    }

    /// Increments the active count for `key` and returns its RAII guard plus
    /// the updated concurrency value.
    pub fn incr(&self, key: &str) -> (ExactInflightGuard, isize) {
        let key_hash = self.hasher.hash_one(key);
        let shard_idx = (key_hash as usize) & (EXACT_INFLIGHT_SHARDS - 1);
        let counter = {
            let mut map = self.state.shards[shard_idx]
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(existing) = map.get(&key_hash) {
                Some(Arc::clone(existing))
            } else if self.state.active_keys.load(Ordering::Relaxed)
                >= self.state.max_keys
            {
                None
            } else {
                let entry = Arc::new(AtomicIsize::new(0));
                map.insert(key_hash, Arc::clone(&entry));
                self.state.active_keys.fetch_add(1, Ordering::Relaxed);
                Some(entry)
            }
        };
        let Some(counter) = counter else {
            return (
                ExactInflightGuard {
                    state: Arc::clone(&self.state),
                    key_hash,
                    counter: None,
                },
                1,
            );
        };
        let value = counter.fetch_add(1, Ordering::Relaxed) + 1;
        (
            ExactInflightGuard {
                state: Arc::clone(&self.state),
                key_hash,
                counter: Some(counter),
            },
            value,
        )
    }
}

impl Drop for ExactInflightGuard {
    fn drop(&mut self) {
        let Some(counter) = self.counter.take() else {
            return;
        };
        let remaining = counter.fetch_sub(1, Ordering::Relaxed) - 1;
        if remaining > 0 {
            return;
        }
        let shard_idx = (self.key_hash as usize) & (EXACT_INFLIGHT_SHARDS - 1);
        let mut map = self.state.shards[shard_idx]
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(stored) = map.get(&self.key_hash)
            && Arc::ptr_eq(stored, &counter)
            && stored.load(Ordering::Relaxed) <= 0
        {
            map.remove(&self.key_hash);
            self.state.active_keys.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod test {
    use super::TtlLruLimit;
    use pretty_assertions::assert_eq;
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn test_ttl_lru_limit() {
        for limit in [
            TtlLruLimit::new(5, Duration::from_millis(500), 3),
            TtlLruLimit::new_compact(5, Duration::from_millis(500), 3),
        ] {
            let key = "abc";
            assert_eq!(true, limit.validate(key));
            limit.inc(key);
            limit.inc(key);
            assert_eq!(true, limit.validate(key));
            limit.inc(key);
            assert_eq!(false, limit.validate(key));
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while !limit.validate(key) && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(20));
            }
            assert_eq!(true, limit.validate(key));
            // The expired window was reset; the next increments open a new
            // one that fills up again.
            limit.inc(key);
            limit.inc(key);
            limit.inc(key);
            assert_eq!(false, limit.validate(key));
        }
    }

    /// Concurrent increments on one key must all count: the limit is
    /// reached exactly when the increments add up to it.
    #[test]
    fn test_concurrent_inc_loses_nothing() {
        let limit = Arc::new(TtlLruLimit::new(5, Duration::from_secs(10), 800));
        // The first increment inserts the entry; do it alone so the threads
        // below all bump the same counter.
        limit.inc("abc");
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let limit = limit.clone();
                std::thread::spawn(move || {
                    for _ in 0..100 {
                        limit.inc("abc");
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().expect("thread");
        }
        // 801 >= 800: over the limit, which a lost increment would hide.
        assert_eq!(false, limit.validate("abc"));
    }

    #[test]
    fn test_exact_rate_high_cardinality_no_false_positive() {
        let rate = super::ExactRate::new(10_000, Duration::from_secs(60));
        for i in 0..3_000 {
            let key = format!("10.1.{}.{}", i / 256, i % 256);
            let (v1, reset1) = rate.observe_and_check(&key, 2.0);
            assert_eq!(1.0, v1, "{key}");
            assert_eq!(true, reset1 > 0);
            let (v2, _) = rate.observe_and_check(&key, 2.0);
            assert_eq!(2.0, v2, "{key}");
            let (v3, _) = rate.observe_and_check(&key, 2.0);
            assert_eq!(true, v3 > 2.0, "{key}");
        }
        // A key whose 3rd request was refused must still not pass on a 4th,
        // nor get over-counted indefinitely.
        let (v4, _) = rate.observe_and_check("10.1.0.1", 2.0);
        assert_eq!(true, v4 > 2.0 && v4 < 4.0);
    }

    #[test]
    fn test_exact_inflight_guard_drop() {
        let inflight = super::ExactInflight::new(100);
        let (g1, v1) = inflight.incr("192.0.2.1");
        let (g2, v2) = inflight.incr("192.0.2.1");
        assert_eq!(1, v1);
        assert_eq!(2, v2);
        drop(g1);
        let (g3, v3) = inflight.incr("192.0.2.1");
        assert_eq!(2, v3);
        drop(g2);
        drop(g3);
        assert_eq!(
            0,
            inflight
                .state
                .active_keys
                .load(std::sync::atomic::Ordering::Relaxed)
        );
        let (_g4, v4) = inflight.incr("192.0.2.1");
        assert_eq!(1, v4);
    }
}
