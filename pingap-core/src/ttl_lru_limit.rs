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
use ahash::RandomState;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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
            std::thread::sleep(Duration::from_millis(600));
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
}
