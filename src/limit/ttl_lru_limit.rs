// Copyright 2024 Tree xie.
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

use crate::util;
use log::debug;
use lru::LruCache;
use std::num::NonZeroUsize;
use std::time::Duration;
use tokio::sync::RwLock;

#[derive(Debug)]
struct TtlLimit {
    count: usize,
    created_at: Duration,
}

pub struct TtlLruLimit {
    ttl: Duration,
    lru: RwLock<LruCache<String, TtlLimit>>,
    max: usize,
}

impl TtlLruLimit {
    /// Create a ttl lru limit.
    pub fn new(size: usize, ttl: Duration, max: usize) -> Self {
        let capacity = NonZeroUsize::new(size.max(1)).unwrap();
        Self {
            ttl,
            max,
            lru: RwLock::new(LruCache::new(capacity)),
        }
    }
    /// Validate the value of key, return true if valid.
    pub async fn validate(&self, key: &str) -> bool {
        let mut g = self.lru.write().await;
        let mut should_reset = false;
        let mut valid = false;

        if let Some(value) = g.peek(key) {
            debug!("Ttl lru limit, key:{key}, value:{value:?}");
            // validate expired first
            if util::now() - value.created_at > self.ttl {
                valid = true;
                should_reset = true;
            } else if value.count < self.max {
                valid = true;
            }
        } else {
            valid = true
        }
        if should_reset {
            g.pop(key);
        }

        valid
    }
    /// Increase the value of key.
    pub async fn inc(&self, key: &str) {
        let mut g = self.lru.write().await;
        if let Some(value) = g.get_mut(key) {
            value.count += 1;
        } else {
            g.put(
                key.to_string(),
                TtlLimit {
                    count: 1,
                    created_at: util::now(),
                },
            );
        }
    }
}

#[cfg(test)]
mod test {
    use super::TtlLruLimit;
    use pretty_assertions::assert_eq;
    use std::time::Duration;

    #[tokio::test]
    async fn test_ttl_lru_limit() {
        let limit = TtlLruLimit::new(5, Duration::from_millis(500), 3);

        let key = "abc";
        assert_eq!(true, limit.validate(key).await);
        limit.inc(key).await;
        limit.inc(key).await;
        assert_eq!(true, limit.validate(key).await);
        limit.inc(key).await;
        assert_eq!(false, limit.validate(key).await);
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(true, limit.validate(key).await);
    }
}
