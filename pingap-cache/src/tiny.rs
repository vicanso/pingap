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
use super::{Result, LOG_CATEGORY};
use async_trait::async_trait;
use tinyufo::TinyUfo;
use tracing::debug;

/// Type alias for cache key
type CacheKey = String;

/// A cache implementation using TinyUfo algorithm for HTTP responses
///
/// TinyUfoCache provides an in-memory cache with a fixed memory limit and
/// automatic eviction of less frequently used items.
pub struct TinyUfoCache {
    cache: TinyUfo<CacheKey, CacheObject>,
}

impl TinyUfoCache {
    /// Creates a new TinyUfoCache instance
    ///
    /// # Arguments
    ///
    /// * `total_weight_limit` - The maximum total weight of items in the cache
    /// * `estimated_size` - Estimated number of items for internal capacity planning
    pub fn new(total_weight_limit: usize, estimated_size: usize) -> Self {
        Self {
            cache: TinyUfo::new(total_weight_limit, estimated_size / 32),
        }
    }
}

/// Creates a new TinyUfoCache instance
///
/// This is a convenience function that wraps `TinyUfoCache::new`
pub fn new_tiny_ufo_cache(
    total_weight_limit: usize,
    estimated_size: usize,
) -> TinyUfoCache {
    TinyUfoCache::new(total_weight_limit, estimated_size)
}

#[async_trait]
impl HttpCacheStorage for TinyUfoCache {
    /// Retrieves a cache entry by key and namespace
    ///
    /// # Arguments
    ///
    /// * `key` - The unique identifier for the cache entry
    /// * `namespace` - The namespace for the cache entry (currently unused)
    ///
    /// # Returns
    ///
    /// * `Result<Option<CacheObject>>` - Returns Ok(Some(object)) if found, Ok(None) if not found
    async fn get(
        &self,
        key: &str,
        namespace: &str,
    ) -> Result<Option<CacheObject>> {
        debug!(
            category = LOG_CATEGORY,
            key, namespace, "getting cache entry from TinyUfo storage"
        );
        Ok(self.cache.get(&key.to_string()))
    }

    /// Stores a cache entry with the given key, namespace, and weight
    ///
    /// # Arguments
    ///
    /// * `key` - The unique identifier for the cache entry
    /// * `namespace` - The namespace for the cache entry (currently unused)
    /// * `data` - The cache object to store
    ///
    /// # Returns
    ///
    /// * `Result<()>` - Returns Ok(()) on successful storage
    async fn put(
        &self,
        key: &str,
        namespace: &str,
        data: CacheObject,
    ) -> Result<()> {
        let weight = data.get_weight();
        debug!(
            category = LOG_CATEGORY,
            key,
            namespace,
            weight = weight,
            "storing cache entry in TinyUfo storage"
        );
        self.cache.put(key.to_string(), data, weight);
        Ok(())
    }

    /// Removes a cache entry by key and namespace
    ///
    /// # Arguments
    ///
    /// * `key` - The unique identifier for the cache entry to remove
    /// * `namespace` - The namespace for the cache entry (currently unused)
    ///
    /// # Returns
    ///
    /// * `Result<Option<CacheObject>>` - Returns Ok(Some(object)) if found and removed, Ok(None) if not found
    async fn remove(
        &self,
        key: &str,
        namespace: &str,
    ) -> Result<Option<CacheObject>> {
        debug!(
            category = LOG_CATEGORY,
            key, namespace, "removing cache entry from TinyUfo storage"
        );
        Ok(self.cache.remove(&key.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use pretty_assertions::assert_eq;
    #[tokio::test]
    async fn test_tiny_ufo_cache() {
        let cache = new_tiny_ufo_cache(10, 10);
        let key = "key";
        let obj = CacheObject {
            meta: (b"Hello".to_vec(), b"World".to_vec()),
            body: Bytes::from_static(b"Hello World!"),
        };
        let result = cache.get(key, "").await.unwrap();
        assert_eq!(true, result.is_none());
        cache.put(key, "", obj.clone()).await.unwrap();
        let result = cache.get(key, "").await.unwrap().unwrap();
        assert_eq!(obj, result);

        cache.remove(key, "").await.unwrap().unwrap();
        let result = cache.get(key, "").await.unwrap();
        assert_eq!(true, result.is_none());
    }
}
