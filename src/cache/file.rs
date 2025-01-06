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

use super::http_cache::{
    get_weight, CacheObject, HttpCacheStats, HttpCacheStorage,
};
use super::{Error, Result, PAGE_SIZE};
#[cfg(feature = "full")]
use crate::state::{CACHE_READING_TIME, CACHE_WRITING_TIME};
use crate::util;
use async_trait::async_trait;
use bytes::Bytes;
#[cfg(feature = "full")]
use prometheus::Histogram;
use scopeguard::defer;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::SystemTime;
use tinyufo::TinyUfo;
use tokio::fs;
use tracing::{debug, error, info};
use walkdir::WalkDir;

/// A file-based cache implementation that combines disk storage with in-memory caching
/// using TinyUfo for hot data.
pub struct FileCache {
    /// Base directory path where cache files are stored
    pub directory: String,
    /// Counter for current number of concurrent read operations
    reading: AtomicU32,
    /// Maximum allowed concurrent read operations before returning OverQuota error
    reading_max: u32,
    #[cfg(feature = "full")]
    /// Histogram metric for tracking cache read operation times
    read_time: Box<Histogram>,
    /// Counter for current number of concurrent write operations
    writing: AtomicU32,
    /// Maximum allowed concurrent write operations before returning OverQuota error
    writing_max: u32,
    #[cfg(feature = "full")]
    /// Histogram metric for tracking cache write operation times
    write_time: Box<Histogram>,
    /// Optional in-memory TinyUfo cache for frequently accessed items
    /// When enabled, reduces disk I/O by serving hot data from memory
    cache: Option<TinyUfo<String, CacheObject>>,
}

/// File cache parameters
#[derive(Debug, Clone)]
struct FileCacheParams {
    /// Cache directory
    directory: String,
    /// Max reading count
    reading_max: u32,
    /// Max writing count
    writing_max: u32,
    /// Max tinyufo cache size
    cache_max: usize,
}

impl Default for FileCacheParams {
    fn default() -> Self {
        Self {
            directory: String::new(),
            reading_max: 10_000,
            writing_max: 1_000,
            cache_max: 100,
        }
    }
}

fn parse_params(dir: &str) -> FileCacheParams {
    let (dir, query) = dir.split_once('?').unwrap_or((dir, ""));
    let mut params = FileCacheParams::default();

    if !query.is_empty() {
        let m = util::convert_query_map(query);
        params.reading_max = m
            .get("reading_max")
            .and_then(|v| v.parse().ok())
            .unwrap_or(params.reading_max);
        params.writing_max = m
            .get("writing_max")
            .and_then(|v| v.parse().ok())
            .unwrap_or(params.writing_max);
        params.cache_max = m
            .get("cache_max")
            .and_then(|v| v.parse().ok())
            .unwrap_or(params.cache_max);
    }
    params.directory = util::resolve_path(dir);
    params
}

/// Create a file cache and use tinyufo for hotspot data caching
pub fn new_file_cache(dir: &str) -> Result<FileCache> {
    let params = parse_params(dir);

    let path = Path::new(&params.directory);
    // directory not exist, create it
    if !path.exists() {
        std::fs::create_dir_all(path).map_err(|e| Error::Io { source: e })?;
    }
    info!(
        dir = params.directory,
        reading_max = params.reading_max,
        writing_max = params.writing_max,
        cache_max = params.cache_max,
        "new file cache"
    );
    let mut cache = None;
    if params.cache_max > 0 {
        cache =
            Some(TinyUfo::new(params.cache_max, params.cache_max * PAGE_SIZE));
    }

    Ok(FileCache {
        directory: params.directory,
        reading: AtomicU32::new(0),
        reading_max: params.reading_max,
        #[cfg(feature = "full")]
        read_time: CACHE_READING_TIME.clone(),
        writing: AtomicU32::new(0),
        writing_max: params.writing_max,
        #[cfg(feature = "full")]
        write_time: CACHE_WRITING_TIME.clone(),
        cache,
    })
}

impl FileCache {
    #[inline]
    fn get_file_path(&self, key: &str, namespace: &str) -> std::path::PathBuf {
        if namespace.is_empty() {
            Path::new(&self.directory).join(key)
        } else {
            Path::new(&self.directory).join(format!("{namespace}/{key}"))
        }
    }
}

#[async_trait]
impl HttpCacheStorage for FileCache {
    /// Retrieves a cache object by key and namespace.
    ///
    /// First checks the in-memory TinyUfo cache, then falls back to file system if not found.
    /// Enforces a maximum concurrent reading limit.
    ///
    /// # Arguments
    /// * `key` - The cache key
    /// * `namespace` - Optional namespace to organize cache entries
    ///
    /// # Returns
    /// * `Ok(Some(CacheObject))` - If cache entry is found and valid
    /// * `Ok(None)` - If entry doesn't exist or is invalid
    /// * `Err(Error::OverQuota)` - If max concurrent reads exceeded
    /// * `Err(Error::Io)` - On file system errors
    async fn get(
        &self,
        key: &str,
        namespace: &str,
    ) -> Result<Option<CacheObject>> {
        debug!(key, namespace, "get cache from file");
        // Early return if found in cache
        if let Some(cache) = &self.cache {
            if let Some(obj) = cache.get(&key.to_string()) {
                return Ok(Some(obj));
            }
        }

        #[cfg(feature = "full")]
        let start = SystemTime::now();
        let file = self.get_file_path(key, namespace);

        // add reading count
        let count = self.reading.fetch_add(1, Ordering::Relaxed);
        defer!(self.reading.fetch_sub(1, Ordering::Relaxed););
        if self.reading_max > 0 && count >= self.reading_max {
            return Err(Error::OverQuota {
                max: self.reading_max,
                message: "too many reading".to_string(),
            });
        }
        let result = fs::read(file).await;
        #[cfg(feature = "full")]
        self.read_time.observe(util::elapsed_second(start));

        let obj = match result {
            Ok(buf) if buf.len() >= 8 => {
                Ok(Some(CacheObject::from(Bytes::from(buf))))
            },
            Ok(_) => Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Io { source: e }),
        }?;
        if let Some(obj) = &obj {
            if let Some(cache) = &self.cache {
                let weight = get_weight(obj.body.len());
                cache.put(key.to_string(), obj.clone(), weight);
            }
        }
        Ok(obj)
    }
    /// Stores a cache object both in TinyUfo cache and on disk.
    ///
    /// # Arguments
    /// * `key` - The cache key
    /// * `namespace` - Optional namespace to organize cache entries  
    /// * `data` - The cache object to store
    /// * `weight` - Weight hint for the TinyUfo cache
    ///
    /// # Returns
    /// * `Ok(())` - On successful storage
    /// * `Err(Error::OverQuota)` - If max concurrent writes exceeded
    /// * `Err(Error::Io)` - On file system errors
    async fn put(
        &self,
        key: &str,
        namespace: &str,
        data: CacheObject,
        weight: u16,
    ) -> Result<()> {
        debug!(key, namespace, "put cache to file");
        if let Some(c) = &self.cache {
            c.put(key.to_string(), data.clone(), weight);
        }
        #[cfg(feature = "full")]
        let start = SystemTime::now();
        let buf: Bytes = data.into();
        let file = self.get_file_path(key, namespace);
        // add writing count
        let count = self.writing.fetch_add(1, Ordering::Relaxed);
        defer!(self.writing.fetch_sub(1, Ordering::Relaxed););
        if self.writing_max > 0 && count >= self.writing_max {
            return Err(Error::OverQuota {
                max: self.writing_max,
                message: "too many writing".to_string(),
            });
        }
        let result = fs::write(file, buf).await;
        #[cfg(feature = "full")]
        self.write_time.observe(util::elapsed_second(start));
        result.map_err(|e| Error::Io { source: e })
    }
    /// Removes a cache entry from both TinyUfo and disk storage.
    ///
    /// # Arguments
    /// * `key` - The cache key to remove
    /// * `namespace` - Optional namespace of the cache entry
    ///
    /// # Returns
    /// * `Ok(None)` - Always returns None as the removed object is not returned
    /// * `Err(Error::Io)` - On file system errors
    async fn remove(
        &self,
        key: &str,
        namespace: &str,
    ) -> Result<Option<CacheObject>> {
        debug!(key, namespace, "remove cache from file");
        if let Some(c) = &self.cache {
            c.remove(&key.to_string());
        }
        let file = self.get_file_path(key, namespace);
        fs::remove_file(file)
            .await
            .map_err(|e| Error::Io { source: e })?;
        Ok(None)
    }
    /// Returns current cache statistics.
    ///
    /// # Returns
    /// Statistics including current number of concurrent reads and writes
    #[inline]
    fn stats(&self) -> Option<HttpCacheStats> {
        Some(HttpCacheStats {
            reading: self.reading.load(Ordering::Relaxed),
            writing: self.writing.load(Ordering::Relaxed),
        })
    }
    /// Clears cache entries that were last accessed before the given timestamp.
    ///
    /// # Arguments
    /// * `access_before` - Remove entries last accessed before this time
    ///
    /// # Returns
    /// * `Ok((success, fail))` - Number of successfully and unsuccessfully removed entries
    async fn clear(&self, access_before: SystemTime) -> Result<(i32, i32)> {
        let mut success = 0;
        let mut fail = 0;
        for entry in WalkDir::new(&self.directory)
            .into_iter()
            .filter_map(|item| item.ok())
            .filter(|item| !item.path().is_dir())
        {
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            let Ok(accessed) = metadata.accessed() else {
                continue;
            };
            if accessed > access_before {
                continue;
            }
            match fs::remove_file(entry.path()).await {
                Ok(()) => {
                    success += 1;
                },
                Err(e) => {
                    fail += 1;
                    error!(
                        err = e.to_string(),
                        entry = entry.path().to_string_lossy().to_string(),
                        "remove cache file fail"
                    );
                },
            };
        }
        Ok((success, fail))
    }
}

#[cfg(test)]
mod tests {
    use super::{new_file_cache, parse_params};
    use crate::cache::http_cache::{CacheObject, HttpCacheStorage};
    use bytes::Bytes;
    use pretty_assertions::assert_eq;
    use std::time::{Duration, SystemTime};
    use tempfile::TempDir;

    #[test]
    fn test_parse_params() {
        let params = parse_params(
            "~/pingap?reading_max=1000&writing_max=500&cache_max=100",
        );
        assert_eq!(1000, params.reading_max);
        assert_eq!(500, params.writing_max);
        assert_eq!(100, params.cache_max);
    }

    #[tokio::test]
    async fn test_file_cache() {
        let dir = TempDir::new().unwrap();
        let namespace = "pingap";
        std::fs::create_dir(dir.path().join(namespace)).unwrap();
        let dir = dir.path().to_string_lossy().to_string();
        let cache = new_file_cache(&dir).unwrap();
        assert_eq!(
            true,
            cache
                .get_file_path("key", "")
                .to_string_lossy()
                .ends_with("/key")
        );
        assert_eq!(
            true,
            cache
                .get_file_path("key", "namespace")
                .to_string_lossy()
                .ends_with("/namespace/key")
        );

        let key = "key";
        let obj = CacheObject {
            meta: (b"Hello".to_vec(), b"World".to_vec()),
            body: Bytes::from_static(b"Hello World!"),
        };
        let result = cache.get(key, namespace).await.unwrap();
        assert_eq!(true, result.is_none());
        cache.put(key, namespace, obj.clone(), 1).await.unwrap();
        // tinyufo cache will be exist after put
        assert_eq!(
            true,
            cache
                .cache
                .as_ref()
                .unwrap()
                .get(&key.to_string())
                .is_some()
        );

        let result = cache.get(key, namespace).await.unwrap().unwrap();
        assert_eq!(obj, result);

        // empty tinyufo, get from file
        let cache = new_file_cache(&dir).unwrap();
        let result = cache.get(key, namespace).await.unwrap().unwrap();
        assert_eq!(obj, result);

        // check tinyufo cache
        // it will be exist after get from file
        assert_eq!(
            true,
            cache
                .cache
                .as_ref()
                .unwrap()
                .get(&key.to_string())
                .is_some()
        );

        cache.remove(key, namespace).await.unwrap();
        // tinyufo cache will be removed after remove
        assert_eq!(
            false,
            cache
                .cache
                .as_ref()
                .unwrap()
                .get(&key.to_string())
                .is_some()
        );
        let result = cache.get(key, namespace).await.unwrap();
        assert_eq!(true, result.is_none());

        cache.put(key, namespace, obj.clone(), 1).await.unwrap();
        cache
            .clear(
                SystemTime::now()
                    .checked_add(Duration::from_secs(365 * 24 * 3600))
                    .unwrap(),
            )
            .await
            .unwrap();
    }

    #[test]
    fn test_stats() {
        let dir = TempDir::new().unwrap();
        let dir = dir.into_path().to_string_lossy().to_string();
        let cache = new_file_cache(&dir).unwrap();
        assert_eq!(0, cache.stats().unwrap().reading);
        assert_eq!(0, cache.stats().unwrap().writing);
    }
}
