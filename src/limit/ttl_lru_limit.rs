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

use lru::LruCache;
use std::num::NonZeroUsize;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

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
    pub fn new(size: NonZeroUsize, ttl: Duration, max: usize) -> Self {
        Self {
            ttl,
            max,
            lru: RwLock::new(LruCache::new(size)),
        }
    }
    pub async fn validate(&self, key: String) -> bool {
        let mut g = self.lru.write().await;
        let mut should_reset = false;
        let mut valid = false;

        if let Some(value) = g.peek(&key) {
            if value.count < self.max {
                valid = true;
            } else if SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                - value.created_at
                > self.ttl
            {
                valid = true;
                should_reset = true;
            }
        } else {
            valid = true
        }
        if should_reset {
            g.pop(&key);
        }

        valid
    }
    pub async fn inc(&self, key: String) {
        let mut g = self.lru.write().await;
        if let Some(value) = g.get_mut(&key) {
            value.count += 1;
        } else {
            g.put(
                key,
                TtlLimit {
                    count: 1,
                    created_at: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default(),
                },
            );
        }
    }
}
