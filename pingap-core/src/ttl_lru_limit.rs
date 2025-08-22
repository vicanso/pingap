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

#[derive(Debug, Clone, Copy)] // Use Copy for better performance on this small struct
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
    pub fn new(size: usize, ttl: Duration, max: usize) -> Self {
        Self {
            ttl: ttl.as_millis() as u64,
            max,
            ufo: TinyUfo::new(size, size),
        }
    }

    /// Creates a new compact TTL-based LRU limit.
    pub fn new_compact(size: usize, ttl: Duration, max: usize) -> Self {
        Self {
            ttl: ttl.as_millis() as u64,
            max,
            ufo: TinyUfo::new_compact(size, size),
        }
    }

    /// Checks if a key is within its limit and increments its count if it is.
    ///
    /// This is the primary method for rate limiting. It combines validation and
    /// incrementing into a single, atomic-feeling operation.
    ///
    /// # Arguments
    /// * `key` - The key to check and increment.
    ///
    /// # Returns
    /// * `true` if the request is allowed.
    /// * `false` if the key has exceeded its rate limit.
    pub fn check_and_inc(&self, key: &str) -> bool {
        // THE FIX: Create the owned `String` once at the start.
        // This is necessary because `tinyufo`'s `get` method requires `&String`.
        let key_owned = key.to_string();
        let now = now_ms();

        // Use a reference to the owned string for the `get` call.
        if let Some(mut limit) = self.ufo.get(&key_owned) {
            // Check if the entry has expired.
            if now.saturating_sub(limit.created_at) > self.ttl {
                // Expired: Reset the entry and allow the request.
                let new_limit = TtlLimit {
                    count: 1,
                    created_at: now,
                };
                // Move the owned string into `put`.
                self.ufo.put(key_owned, new_limit, 1);
                true
            } else if limit.count < self.max {
                // Not expired and under the limit: Increment and allow.
                limit.count += 1;
                // Move the owned string into `put`.
                self.ufo.put(key_owned, limit, 1);
                true
            } else {
                // Not expired and over the limit: Deny.
                debug!(
                    category = LOG_CATEGORY,
                    key,
                    limit = format!("{limit:?}"),
                    "ttl lru limit exceeded"
                );
                false
            }
        } else {
            // Key does not exist: Create a new entry and allow the request.
            let new_limit = TtlLimit {
                count: 1,
                created_at: now,
            };
            // Move the owned string into `put`.
            self.ufo.put(key_owned, new_limit, 1);
            true
        }
    }
}

#[cfg(test)]
mod test {
    use super::TtlLruLimit;
    use pretty_assertions::assert_eq;
    use std::time::Duration;

    #[test]
    fn test_ttl_lru_limit_check_and_inc() {
        let limit = TtlLruLimit::new(5, Duration::from_millis(500), 3);
        let key = "abc";

        // First 3 requests should be allowed.
        assert_eq!(true, limit.check_and_inc(key)); // count = 1
        assert_eq!(true, limit.check_and_inc(key)); // count = 2
        assert_eq!(true, limit.check_and_inc(key)); // count = 3

        // The 4th request should be denied.
        assert_eq!(false, limit.check_and_inc(key)); // count remains 3, denied

        // Wait for the TTL to expire.
        std::thread::sleep(Duration::from_millis(600));

        // After expiring, the next request should be allowed and the count reset to 1.
        assert_eq!(true, limit.check_and_inc(key));

        // The next request is also allowed as the count is now only 2.
        assert_eq!(true, limit.check_and_inc(key));
    }
}
