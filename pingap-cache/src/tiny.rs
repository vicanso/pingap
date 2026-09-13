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

use super::http_cache::{CacheObject, HttpCacheStorage};
use super::{LOG_TARGET, Result};
use ahash::RandomState;
use async_trait::async_trait;
use pingap_core::TinyUfo;
use strum::EnumString;
use tracing::debug;

/// TinyUFO keyed by the hash of the cache key.
///
/// TinyUFO only ever stores `hash_one(key)` - a `String` key is hashed on
/// every call and then dropped - so hashing here first loses nothing and
/// saves the `String` that `&str` -> `&String` used to allocate on every
/// `get`, `put` and `remove`.
///
/// Weights are 4 KB pages (`CacheObject::get_weight`), so the weight limit
/// is also the most entries the cache can ever hold, which is what TinyUFO
/// wants as its size estimate: it sizes its frequency sketch and its index
/// from that number. An estimate in bytes made both hundreds of MB for a
/// cache that could never hold that many entries.
pub(crate) struct MemoryCache {
    ufo: TinyUfo<u64, CacheObject>,
    hasher: RandomState,
}

/// TinyUFO variant. `normal` (also `default`) is the lock-free index,
/// `compact` trades some speed for a smaller footprint.
#[derive(Debug, Clone, Copy, Default, EnumString)]
#[strum(ascii_case_insensitive)]
pub enum CacheMode {
    #[default]
    #[strum(serialize = "normal", serialize = "default")]
    Normal,
    Compact,
}

impl MemoryCache {
    pub(crate) fn new(mode: CacheMode, total_weight_limit: usize) -> Self {
        // TinyUFO's sketch is sized from a `1/items` error bound; zero items
        // makes that infinite.
        let limit = total_weight_limit.max(1);
        let ufo = match mode {
            CacheMode::Compact => TinyUfo::new_compact(limit, limit),
            CacheMode::Normal => TinyUfo::new(limit, limit),
        };
        Self {
            ufo,
            hasher: RandomState::new(),
        }
    }

    #[inline]
    fn hash(&self, key: &str) -> u64 {
        self.hasher.hash_one(key)
    }

    pub(crate) fn get(&self, key: &str) -> Option<CacheObject> {
        self.ufo.get(&self.hash(key))
    }

    pub(crate) fn put(&self, key: &str, data: CacheObject, weight: u16) {
        self.ufo.put(self.hash(key), data, weight);
    }

    pub(crate) fn remove(&self, key: &str) -> Option<CacheObject> {
        self.ufo.remove(&self.hash(key))
    }
}

/// The in-memory backend: a `MemoryCache` behind `HttpCacheStorage`.
pub struct TinyUfoCache {
    cache: MemoryCache,
}

impl TinyUfoCache {
    /// `total_weight_limit` is in 4 KB pages.
    pub fn new(mode: CacheMode, total_weight_limit: usize) -> Self {
        Self {
            cache: MemoryCache::new(mode, total_weight_limit),
        }
    }
}

#[async_trait]
impl HttpCacheStorage for TinyUfoCache {
    async fn get(
        &self,
        key: &str,
        namespace: &[u8],
    ) -> Result<Option<CacheObject>> {
        debug!(
            target: LOG_TARGET,
            key, namespace, "getting cache entry from TinyUfo storage"
        );
        Ok(self.cache.get(key))
    }

    async fn put(
        &self,
        key: &str,
        namespace: &[u8],
        data: CacheObject,
    ) -> Result<()> {
        let weight = data.get_weight();
        debug!(
            target: LOG_TARGET,
            key,
            namespace,
            weight,
            "storing cache entry in TinyUfo storage"
        );
        self.cache.put(key, data, weight);
        Ok(())
    }

    async fn remove(
        &self,
        key: &str,
        namespace: &[u8],
    ) -> Result<Option<CacheObject>> {
        debug!(
            target: LOG_TARGET,
            key, namespace, "removing cache entry from TinyUfo storage"
        );
        Ok(self.cache.remove(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use pretty_assertions::assert_eq;
    use std::str::FromStr;

    #[test]
    fn test_cache_mode() {
        for (value, compact) in [
            ("normal", false),
            ("default", false),
            ("Normal", false),
            ("compact", true),
            ("Compact", true),
        ] {
            let mode = CacheMode::from_str(value).expect(value);
            assert_eq!(compact, matches!(mode, CacheMode::Compact), "{value}");
        }
        assert_eq!(true, CacheMode::from_str("tiny").is_err());
    }

    #[tokio::test]
    async fn test_tiny_ufo_cache() {
        for mode in [CacheMode::Normal, CacheMode::Compact] {
            let cache = TinyUfoCache::new(mode, 10);
            let key = "key";
            let obj = CacheObject {
                meta: (
                    Bytes::from_static(b"Hello"),
                    Bytes::from_static(b"World"),
                ),
                body: Bytes::from_static(b"Hello World!"),
            };
            let result = cache.get(key, b"").await.unwrap();
            assert_eq!(true, result.is_none());
            cache.put(key, b"", obj.clone()).await.unwrap();
            let result = cache.get(key, b"").await.unwrap().unwrap();
            assert_eq!(obj, result);

            cache.remove(key, b"").await.unwrap().unwrap();
            let result = cache.get(key, b"").await.unwrap();
            assert_eq!(true, result.is_none());
        }
    }

    /// A zero weight limit must not blow up TinyUFO's sketch sizing.
    #[test]
    fn test_zero_limit() {
        let _ = TinyUfoCache::new(CacheMode::Normal, 0);
        let _ = TinyUfoCache::new(CacheMode::Compact, 0);
    }
}
