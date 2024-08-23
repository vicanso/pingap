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
use std::time::Duration;
use tinyufo::TinyUfo;
use tracing::debug;

#[derive(Debug, Clone)]
struct TtlLimit {
    count: usize,
    created_at: Duration,
}

pub struct TtlLruLimit {
    ttl: Duration,
    ufo: TinyUfo<String, TtlLimit>,
    max: usize,
}

impl TtlLruLimit {
    /// Create a ttl lru limit.
    pub fn new(size: usize, ttl: Duration, max: usize) -> Self {
        Self {
            ttl,
            max,
            ufo: TinyUfo::new(size, size),
        }
    }
    /// Validate the value of key, return true if valid.
    pub async fn validate(&self, key: &str) -> bool {
        let mut should_reset = false;
        let mut valid = false;
        let key = key.to_string();

        if let Some(value) = self.ufo.get(&key) {
            debug!(key, value = format!("{value:?}"), "ttl lru limit");
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
            // ufo does not support remove
            self.ufo.put(
                key,
                TtlLimit {
                    count: 0,
                    created_at: Duration::from_secs(0),
                },
                1,
            );
        }

        valid
    }
    /// Increase the value of key.
    pub async fn inc(&self, key: &str) {
        let key = key.to_string();
        let data = if let Some(mut value) = self.ufo.get(&key) {
            // the reset value
            if value.created_at.as_secs() == 0 {
                value.created_at = util::now();
            }
            value.count += 1;
            value
        } else {
            TtlLimit {
                count: 1,
                created_at: util::now(),
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
