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

use super::http_cache::{
    CacheObject, HttpCacheClearStats, HttpCacheStats, HttpCacheStorage,
};
use super::{Error, Result, LOG_CATEGORY, PAGE_SIZE};
#[cfg(feature = "tracing")]
use super::{CACHE_READING_TIME, CACHE_WRITING_TIME};
use async_trait::async_trait;
use bytes::Bytes;
use humantime::parse_duration;
use path_absolutize::*;
use pingap_core::{convert_query_map, TinyUfo};
#[cfg(feature = "tracing")]
use prometheus::Histogram;
use scopeguard::defer;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime};
use substring::Substring;
use tokio::fs;
use tracing::{debug, error, info};
use urlencoding::decode;
use walkdir::WalkDir;

/// A file-based cache implementation that combines disk storage with in-memory caching
/// using TinyUfo for hot data.
pub struct FileCache {
    /// Base directory path where cache files are stored
    pub directory: String,
    /// Counter for current number of concurrent read operations
    reading: AtomicU32,
    /// Maximum allowed concurrent read operations
    reading_max: u32,
    #[cfg(feature = "tracing")]
    /// Histogram metric for tracking cache read operation times
    read_time: Box<Histogram>,
    /// Counter for current number of concurrent write operations
    writing: AtomicU32,
    /// Maximum allowed concurrent write operations
    writing_max: u32,
    #[cfg(feature = "tracing")]
    /// Histogram metric for tracking cache write operation times
    write_time: Box<Histogram>,
    /// Optional in-memory TinyUfo cache for frequently accessed items
    /// When enabled, reduces disk I/O by serving hot data from memory
    cache: Option<TinyUfo<String, CacheObject>>,
    /// Max tinyufo cache weight
    cache_file_max_weight: u16,
    /// Inactive duration when cache file will be removed regardless of their freshness.
    cache_inactive: Duration,
    /// Cache file path levels
    levels: Vec<u32>,
}

/// File cache parameters
#[derive(Debug, Clone)]
struct FileCacheParams {
    /// Cache directory
    directory: String,
    /// Inactive duration when cache file will be removed regardless of their freshness.
    inactive: Duration,
    /// Max reading count
    reading_max: u32,
    /// Max writing count
    writing_max: u32,
    /// Max tinyufo cache size
    cache_max: usize,
    /// Max tinyufo cache weight
    cache_file_max_weight: usize,
    // Cache file path levels
    levels: Vec<u32>,
}

impl Default for FileCacheParams {
    fn default() -> Self {
        Self {
            directory: String::new(),
            reading_max: 10_000,
            writing_max: 1_000,
            cache_max: 0,
            cache_file_max_weight: 1024 * 1024 / PAGE_SIZE,
            inactive: Duration::from_secs(48 * 3600),
            levels: vec![],
        }
    }
}

/// Resolves a path string to its absolute form.
/// If the path starts with '~', it will be expanded to the user's home directory.
/// Returns an empty string if the input path is empty.
///
/// # Arguments
/// * `path` - The path string to resolve
///
/// # Returns
/// The absolute path as a String
fn resolve_path(path: &str) -> String {
    if path.is_empty() {
        return "".to_string();
    }
    let mut p = path.to_string();
    if p.starts_with('~') {
        if let Some(home) = dirs::home_dir() {
            p = home.to_string_lossy().to_string() + p.substring(1, p.len());
        };
    }
    if let Ok(p) = Path::new(&p).absolutize() {
        p.to_string_lossy().to_string()
    } else {
        p
    }
}

fn parse_params(dir: &str) -> FileCacheParams {
    let (dir, query) = dir.split_once('?').unwrap_or((dir, ""));
    let mut params = FileCacheParams {
        directory: resolve_path(dir),
        ..Default::default()
    };

    if !query.is_empty() {
        let m = convert_query_map(query);
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
        params.cache_file_max_weight = m
            .get("cache_file_max_size")
            .and_then(|v| v.parse::<usize>().map(|v| v / PAGE_SIZE).ok())
            .unwrap_or(params.cache_file_max_weight);
        params.inactive = m
            .get("inactive")
            .and_then(|v| parse_duration(v).ok())
            .unwrap_or(params.inactive);
        params.levels = m
            .get("levels")
            .and_then(|v| {
                let mut valid = true;
                let mut levels = vec![];
                for item in decode(v.as_str()).unwrap_or_default().split(':') {
                    let Ok(value) = item.parse::<u32>() else {
                        valid = false;
                        break;
                    };
                    if value > 3 {
                        valid = false;
                        break;
                    }
                    levels.push(value);
                }
                if levels.len() > 2 {
                    return None;
                }
                if valid {
                    return Some(levels);
                }
                None
            })
            .unwrap_or(params.levels);
    }
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
        category = LOG_CATEGORY,
        dir = params.directory,
        levels = params
            .levels
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<String>>()
            .join(":"),
        reading_max = params.reading_max,
        writing_max = params.writing_max,
        cache_max = params.cache_max,
        cache_file_max_weight = params.cache_file_max_weight,
        "new file cache"
    );
    let mut cache = None;
    if params.cache_max > 0 {
        cache =
            Some(TinyUfo::new(params.cache_max, params.cache_max * PAGE_SIZE));
    }

    Ok(FileCache {
        directory: params.directory,
        cache_file_max_weight: params.cache_file_max_weight as u16,
        reading: AtomicU32::new(0),
        reading_max: params.reading_max,
        #[cfg(feature = "tracing")]
        read_time: CACHE_READING_TIME.clone(),
        writing: AtomicU32::new(0),
        writing_max: params.writing_max,
        #[cfg(feature = "tracing")]
        write_time: CACHE_WRITING_TIME.clone(),
        cache,
        cache_inactive: params.inactive,
        levels: params.levels,
    })
}

impl FileCache {
    #[inline]
    fn get_file_path(&self, key: &str, namespace: &str) -> std::path::PathBuf {
        let mut path = Path::new(&self.directory).to_path_buf();
        if !namespace.is_empty() {
            path = path.join(namespace);
        };
        if self.levels.is_empty() {
            return path.join(key);
        }
        let mut index = key.len() - 1;
        for level in self.levels.iter() {
            let level = *level as usize;
            let hex = key.substring(index - level, index);
            path = path.join(hex);
            index -= level;
        }
        path.join(key)
    }
}

/// Returns the elapsed time in seconds (as f64) since the given SystemTime
#[cfg(feature = "tracing")]
#[inline]
fn elapsed_second(time: SystemTime) -> f64 {
    time.elapsed().unwrap_or_default().as_millis() as f64 / 1000.0
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
        namespace: &[u8],
    ) -> Result<Option<CacheObject>> {
        // Early return if found in cache
        if let Some(cache) = &self.cache {
            if let Some(obj) = cache.get(&key.to_string()) {
                debug!(
                    category = LOG_CATEGORY,
                    key, namespace, "get cache from tinyufo"
                );
                return Ok(Some(obj));
            }
        }

        #[cfg(feature = "tracing")]
        let start = SystemTime::now();
        let file = self.get_file_path(
            key,
            std::string::String::from_utf8_lossy(namespace).as_ref(),
        );

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
        #[cfg(feature = "tracing")]
        self.read_time.observe(elapsed_second(start));

        let obj = match result {
            Ok(buf) if buf.len() >= 8 => {
                Ok(Some(CacheObject::from(Bytes::from(buf))))
            },
            Ok(_) => Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Io { source: e }),
        }?;
        // cache get from file, but not in tinyufo, put it to tinyufo
        if let Some(cache) = &self.cache {
            if let Some(obj) = &obj {
                let weight = obj.get_weight();
                cache.put(key.to_string(), obj.clone(), weight);
            }
        }
        debug!(
            category = LOG_CATEGORY,
            key,
            namespace =
                std::string::String::from_utf8_lossy(namespace).to_string(),
            "get cache from file"
        );
        Ok(obj)
    }
    /// Stores a cache object both in TinyUfo cache and on disk.
    ///
    /// # Arguments
    /// * `key` - The cache key
    /// * `namespace` - Optional namespace to organize cache entries  
    /// * `data` - The cache object to store
    ///
    /// # Returns
    /// * `Ok(())` - On successful storage
    /// * `Err(Error::OverQuota)` - If max concurrent writes exceeded
    /// * `Err(Error::Io)` - On file system errors
    async fn put(
        &self,
        key: &str,
        namespace: &[u8],
        data: CacheObject,
    ) -> Result<()> {
        if let Some(c) = &self.cache {
            let weight = data.get_weight();
            if weight < self.cache_file_max_weight {
                debug!(
                    category = LOG_CATEGORY,
                    key, namespace, "put cache to tinyufo"
                );
                c.put(key.to_string(), data.clone(), weight);
            }
        }
        #[cfg(feature = "tracing")]
        let start = SystemTime::now();
        let buf: Bytes = data.into();
        let file = self.get_file_path(
            key,
            std::string::String::from_utf8_lossy(namespace).as_ref(),
        );
        // add writing count
        let count = self.writing.fetch_add(1, Ordering::Relaxed);
        defer!(self.writing.fetch_sub(1, Ordering::Relaxed););
        if self.writing_max > 0 && count >= self.writing_max {
            return Err(Error::OverQuota {
                max: self.writing_max,
                message: "too many writing".to_string(),
            });
        }
        if let Some(parent) = file.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| Error::Io { source: e })?;
        }
        let result = fs::write(file, buf).await;
        #[cfg(feature = "tracing")]
        self.write_time.observe(elapsed_second(start));
        let _ = result.map_err(|e| Error::Io { source: e })?;
        debug!(
            category = LOG_CATEGORY,
            key,
            namespace =
                std::string::String::from_utf8_lossy(namespace).to_string(),
            "put cache to file"
        );
        Ok(())
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
        namespace: &[u8],
    ) -> Result<Option<CacheObject>> {
        if let Some(c) = &self.cache {
            debug!(
                category = LOG_CATEGORY,
                key, namespace, "remove cache from tinyufo"
            );
            c.remove(&key.to_string());
        }
        let file = self.get_file_path(
            key,
            std::string::String::from_utf8_lossy(namespace).as_ref(),
        );
        fs::remove_file(file)
            .await
            .map_err(|e| Error::Io { source: e })?;
        debug!(
            category = LOG_CATEGORY,
            key, namespace, "remove cache from file"
        );
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
    /// * `Ok(HttpCacheClearStats)` - Clear stats
    async fn clear(
        &self,
        access_before: SystemTime,
    ) -> Result<HttpCacheClearStats> {
        let mut success = 0;
        let mut fail = 0;
        let description = format!(
            "clear cache file, directory: {}, access before: {:?}",
            self.directory, access_before
        );
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
            let path = entry.path();
            let file = path.to_string_lossy().to_string();
            match fs::remove_file(path).await {
                Ok(()) => {
                    info!(
                        category = LOG_CATEGORY,
                        file, "remove cache file success"
                    );
                    success += 1;
                },
                Err(e) => {
                    fail += 1;
                    error!(
                        category = LOG_CATEGORY,
                        error = %e,
                        file,
                        "remove cache file fail"
                    );
                },
            };
        }
        Ok(HttpCacheClearStats {
            success,
            fail,
            description,
        })
    }
    fn inactive(&self) -> Option<Duration> {
        Some(self.cache_inactive)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use pretty_assertions::assert_eq;
    use std::fs::File;
    use std::time::{Duration, SystemTime};
    use tempfile::{tempdir, TempDir};

    /// Tests the `parse_params` function with various query string configurations.
    #[test]
    fn test_parse_params() {
        let params = parse_params(
              "~/pingap?reading_max=1000&writing_max=500&cache_max=100&inactive=10m&levels=1:2",
          );
        assert_eq!(params.reading_max, 1000);
        assert_eq!(params.writing_max, 500);
        assert_eq!(params.cache_max, 100);
        assert_eq!(params.inactive, Duration::from_secs(600));
        assert_eq!(params.levels, vec![1, 2]);
        assert!(params
            .directory
            .starts_with(dirs::home_dir().unwrap().to_str().unwrap()));
    }

    /// Tests `parse_params` with invalid and default values.
    #[test]
    fn test_parse_params_defaults_and_invalid() {
        let params = parse_params("/tmp/cache?reading_max=abc&levels=1:a:2");
        // Should fall back to default for invalid integer.
        assert_eq!(params.reading_max, 10_000);
        // Should return empty for invalid level format.
        assert!(params.levels.is_empty());
    }

    /// A comprehensive test for the FileCache functionality.
    #[tokio::test]
    async fn test_file_cache_integration() {
        let dir = tempdir().unwrap();
        let dir_path_str = dir.path().to_str().unwrap();
        let namespace = b"my-namespace";

        let cache_config =
            format!("{}?cache_max=100&cache_file_max_size=1024", dir_path_str);
        let cache = new_file_cache(&cache_config).unwrap();

        let key = "my-test-key";
        let obj = CacheObject {
            meta: (b"Meta-Key".to_vec(), b"Meta-Value".to_vec()),
            body: Bytes::from_static(b"Hello World!"),
        };

        // 1. Initial GET should be a cache miss.
        assert!(
            cache.get(key, namespace).await.unwrap().is_none(),
            "Initial get should be a miss"
        );

        // 2. PUT an object into the cache.
        cache.put(key, namespace, obj.clone()).await.unwrap();

        // 3. GET should now be a cache hit from the in-memory cache.
        let cached_obj = cache.get(key, namespace).await.unwrap().unwrap();
        assert_eq!(obj, cached_obj);

        // Verify it exists in the TinyUfo cache.
        assert!(cache
            .cache
            .as_ref()
            .unwrap()
            .get(&key.to_string())
            .is_some());

        // --- Test fallback from file ---
        // Create a new cache instance to simulate a fresh start with no in-memory cache.
        let fresh_cache = new_file_cache(&cache_config).unwrap();

        // 4. GET from the new instance should be a hit from the file.
        let file_obj = fresh_cache.get(key, namespace).await.unwrap().unwrap();
        assert_eq!(obj, file_obj);

        // 5. After reading from the file, it should now be populated in the new instance's in-memory cache.
        assert!(fresh_cache
            .cache
            .as_ref()
            .unwrap()
            .get(&key.to_string())
            .is_some());

        // 6. Test REMOVE.
        fresh_cache.remove(key, namespace).await.unwrap();

        // Verify it's gone from both in-memory and file caches.
        assert!(fresh_cache
            .cache
            .as_ref()
            .unwrap()
            .get(&key.to_string())
            .is_none());
        assert!(
            fresh_cache.get(key, namespace).await.unwrap().is_none(),
            "Get after remove should be a miss"
        );
    }

    /// Tests the `clear` functionality for removing old files.
    #[tokio::test]
    async fn test_cache_clear() {
        let dir = tempdir().unwrap();
        let cache = new_file_cache(dir.path().to_str().unwrap()).unwrap();

        // Create a file and set its access time to be in the past.
        let old_file_path = cache.get_file_path("old_key", "ns");
        fs::create_dir_all(old_file_path.parent().unwrap())
            .await
            .unwrap();
        File::create(&old_file_path).unwrap();
        let old_time = SystemTime::now() - Duration::from_secs(3600);
        filetime::set_file_atime(
            &old_file_path,
            filetime::FileTime::from_system_time(old_time),
        )
        .unwrap();

        // Create a new file with a recent access time.
        let new_file_path = cache.get_file_path("new_key", "ns");
        File::create(&new_file_path).unwrap();

        // Clear files accessed more than 10 minutes ago.
        let access_before = SystemTime::now() - Duration::from_secs(600);
        let stats = cache.clear(access_before).await.unwrap();

        assert_eq!(stats.success, 1);
        assert_eq!(stats.fail, 0);

        // Verify that the old file was deleted and the new one remains.
        assert!(!old_file_path.exists());
        assert!(new_file_path.exists());
    }

    /// Tests the `get_file_path` with and without path levels.
    #[test]
    fn test_get_file_path() {
        let dir = tempdir().unwrap();

        // Case 1: No levels.
        let cache_no_levels =
            new_file_cache(dir.path().to_str().unwrap()).unwrap();
        let path1 = cache_no_levels.get_file_path("mykey", "namespace");
        assert!(path1.to_string_lossy().ends_with("/namespace/mykey"));

        // Case 2: With levels. Key must be long enough.
        let cache_with_levels_config =
            format!("{}?levels=1:2", dir.path().to_str().unwrap());
        let cache_with_levels =
            new_file_cache(&cache_with_levels_config).unwrap();
        let key = "abcdef123456";
        let path2 = cache_with_levels.get_file_path(key, "ns");
        assert!(path2.to_string_lossy().ends_with("/ns/5/34/abcdef123456"));
    }

    #[tokio::test]
    async fn test_file_cache() {
        let dir = TempDir::new().unwrap();
        let namespace = b"pingap";
        std::fs::create_dir(
            dir.path()
                .join(std::string::String::from_utf8_lossy(namespace).as_ref()),
        )
        .unwrap();
        let dir = format!("{}?cache_max=100", dir.path().to_string_lossy());
        let cache = new_file_cache(&dir).unwrap();

        let key = "key";
        let obj = CacheObject {
            meta: (b"Hello".to_vec(), b"World".to_vec()),
            body: Bytes::from_static(b"Hello World!"),
        };
        let result = cache.get(key, namespace).await.unwrap();
        assert_eq!(true, result.is_none());
        cache.put(key, namespace, obj.clone()).await.unwrap();
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

        cache.put(key, namespace, obj.clone()).await.unwrap();
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
        let dir = dir.keep().to_string_lossy().to_string();
        let cache = new_file_cache(&dir).unwrap();
        assert_eq!(0, cache.stats().unwrap().reading);
        assert_eq!(0, cache.stats().unwrap().writing);
    }

    #[test]
    fn test_resolve_path() {
        assert_eq!(
            dirs::home_dir().unwrap().to_string_lossy().to_string(),
            resolve_path("~/")
        );

        assert_eq!("", resolve_path(""));

        let path = resolve_path("../pingap");
        assert_eq!(true, path.ends_with("/pingap"));
        assert_eq!(false, path.starts_with(".."));
    }
}
