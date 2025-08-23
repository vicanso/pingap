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

use super::{now_ms, LOG_CATEGORY};
use std::time::Duration;
use tinyufo::TinyUfo;
use tracing::debug;

#[derive(Debug, Clone)]
struct TtlLimit {
    count: usize,
    created_at: u64,
}

pub struct TtlLruLimit {
    ttl: u64,
    ufo: TinyUfo<String, TtlLimit>,
    max: usize,
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
        }
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
        let mut should_reset = false;
        let mut valid = false;
        let key = key.to_string();

        if let Some(value) = self.ufo.get(&key) {
            debug!(
                category = LOG_CATEGORY,
                key,
                value = format!("{value:?}"),
                "ttl lru limit"
            );
            // validate expired first
            if now_ms().saturating_sub(value.created_at) > self.ttl {
                valid = true;
                should_reset = true;
            } else if value.count < self.max {
                valid = true;
            }
        } else {
            valid = true
        }
        if should_reset {
            // ufo does not support remove
            self.ufo.put(
                key,
                TtlLimit {
                    count: 0,
                    created_at: 0,
                },
                1,
            );
        }

        valid
    }
    /// Increments the counter for the specified key.
    /// If the key doesn't exist, creates a new entry with count 1.
    /// If the key exists but was reset (count = 0), updates its creation timestamp.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to increment
    pub fn inc(&self, key: &str) {
        let key = key.to_string();
        let data = if let Some(mut value) = self.ufo.get(&key) {
            // the reset value
            if value.created_at == 0 {
                value.created_at = now_ms();
            }
            value.count += 1;
            value
        } else {
            TtlLimit {
                count: 1,
                created_at: now_ms(),
            }
        };
        self.ufo.put(key, data, 1);
    }
}

#[cfg(test)]
mod test {
    use super::TtlLruLimit;
    use pretty_assertions::assert_eq;
    use std::time::Duration;

    #[test]
    fn test_ttl_lru_limit() {
        let limit = TtlLruLimit::new(5, Duration::from_millis(500), 3);

        let key = "abc";
        assert_eq!(true, limit.validate(key));
        limit.inc(key);
        limit.inc(key);
        assert_eq!(true, limit.validate(key));
        limit.inc(key);
        assert_eq!(false, limit.validate(key));
        std::thread::sleep(Duration::from_millis(600));
        coarsetime::Clock::update();
        assert_eq!(true, limit.validate(key));
    }
}
