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
#[cfg(feature = "tracing")]
use super::{CACHE_READING_TIME, CACHE_WRITING_TIME};
use super::{Error, LOG_TARGET, PAGE_SIZE, Result};
use async_trait::async_trait;
use bytes::Bytes;
use bytesize::ByteSize;
use chrono::{DateTime, Local};
use path_absolutize::*;
use pingap_core::TinyUfo;
#[cfg(feature = "tracing")]
use prometheus::Histogram;
use scopeguard::defer;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, SystemTime};
use tokio::fs;
use tracing::{debug, error, info, warn};
use walkdir::WalkDir;

/// Distinguishes the temporary files of concurrent `put`s within this process;
/// the pid in the file name distinguishes processes.
static TMP_FILE_SEQ: AtomicU64 = AtomicU64::new(0);

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
    /// Max total size of on-disk cache files in bytes; 0 means unlimited.
    max_size: u64,
    /// Approximate current on-disk usage (bytes). Maintained on put/remove/clear
    /// and initialised by a directory walk at construction time.
    current_size: AtomicU64,
}

fn split_levels<'de, D>(deserializer: D) -> Result<Vec<u32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = String::deserialize(deserializer)?;

    let mut valid = true;
    let mut levels = vec![];
    for item in s.split(':') {
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
        return Ok(vec![]);
    }
    if valid {
        return Ok(levels);
    }
    Ok(vec![])
}

/// File cache parameters
#[derive(Debug, PartialEq, Deserialize, Serialize, Default)]
struct FileCacheParams {
    /// Cache directory
    #[serde(default)]
    directory: String,
    /// Inactive duration when cache file will be removed regardless of their freshness.
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    inactive: Option<Duration>,
    /// Max reading count
    reading_max: Option<u32>,
    /// Max writing count
    writing_max: Option<u32>,
    /// Max tinyufo cache size
    #[serde(default)]
    cache_max: usize,
    /// Max tinyufo cache weight
    cache_file_max_weight: Option<usize>,
    // Cache file path levels
    #[serde(default)]
    #[serde(deserialize_with = "split_levels")]
    levels: Vec<u32>,
    /// Max total on-disk cache size (e.g. `max_size=10gb`). 0 / unset = unlimited.
    max_size: Option<ByteSize>,
}

impl TryFrom<&str> for FileCacheParams {
    type Error = Error;
    fn try_from(value: &str) -> Result<Self> {
        let (dir, query) = value.split_once('?').unwrap_or((value, ""));
        let mut params = if query.is_empty() {
            FileCacheParams::default()
        } else {
            serde_qs::from_str(query).map_err(|e| Error::Invalid {
                message: e.to_string(),
            })?
        };
        params.directory = resolve_path(dir);
        Ok(params)
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
fn resolve_path(path_str: &str) -> String {
    if path_str.is_empty() {
        return String::new();
    }
    let path = if let Some(stripped) = path_str.strip_prefix("~/") {
        dirs::home_dir()
            .map(|home| home.join(stripped))
            .unwrap_or_else(|| PathBuf::from(path_str))
    } else {
        PathBuf::from(path_str)
    };

    path.absolutize().map_or_else(
        |_| path.to_string_lossy().into_owned(),
        |p| p.to_string_lossy().into_owned(),
    )
}

impl FileCache {
    /// Create a file cache and use tinyufo for hotspot data caching
    pub fn new(dir: &str) -> Result<Self> {
        let params = FileCacheParams::try_from(dir)?;

        let path = Path::new(&params.directory);
        // directory not exist, create it
        if !path.exists() {
            std::fs::create_dir_all(path)
                .map_err(|e| Error::Io { source: e })?;
        }
        let max_size = params.max_size.map(|s| s.as_u64()).unwrap_or(0);
        // One-shot walk so the budget starts from real usage rather than zero
        // (which would otherwise allow a large overshoot after restart).
        let current_size = measure_dir_size(&params.directory);
        info!(
            target: LOG_TARGET,
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
            max_size,
            current_size,
            "new file cache"
        );
        let mut cache = None;
        if params.cache_max > 0 {
            cache = Some(TinyUfo::new(
                params.cache_max,
                params.cache_max * PAGE_SIZE,
            ));
        }

        Ok(FileCache {
            directory: params.directory,
            cache_file_max_weight: params
                .cache_file_max_weight
                .unwrap_or(1024 * 1024 / PAGE_SIZE)
                as u16,
            reading: AtomicU32::new(0),
            reading_max: params.reading_max.unwrap_or(10_000),
            #[cfg(feature = "tracing")]
            read_time: CACHE_READING_TIME.clone(),
            writing: AtomicU32::new(0),
            writing_max: params.writing_max.unwrap_or(1_000),
            #[cfg(feature = "tracing")]
            write_time: CACHE_WRITING_TIME.clone(),
            cache,
            cache_inactive: params
                .inactive
                .unwrap_or(Duration::from_secs(48 * 3600)),
            levels: params.levels,
            max_size,
            current_size: AtomicU64::new(current_size),
        })
    }

    /// Best-effort disk budget: free at least `need` bytes by deleting the
    /// least-recently-accessed files until `current_size + need <= max_size`.
    /// Returns early if `max_size` is unlimited or nothing more can be removed.
    async fn ensure_disk_space(&self, need: u64) {
        if self.max_size == 0 {
            return;
        }
        // Cap eviction work per put so a pathological directory cannot stall
        // a single write forever.
        const MAX_EVICT: usize = 64;
        for _ in 0..MAX_EVICT {
            let cur = self.current_size.load(Ordering::Relaxed);
            if cur.saturating_add(need) <= self.max_size {
                return;
            }
            if !self.evict_oldest_file().await {
                return;
            }
        }
    }

    /// Removes the least-recently-accessed cache file. Returns `false` when
    /// the directory is empty or nothing could be deleted.
    async fn evict_oldest_file(&self) -> bool {
        let mut oldest: Option<(SystemTime, PathBuf, u64)> = None;
        for entry in WalkDir::new(&self.directory)
            .into_iter()
            .filter_map(|item| item.ok())
            .filter(|item| item.path().is_file())
        {
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            // Skip in-progress temps; the writer still owns them.
            if entry.path().extension().is_some_and(|ext| ext == "tmp") {
                continue;
            }
            let accessed =
                metadata.accessed().unwrap_or(SystemTime::UNIX_EPOCH);
            let len = metadata.len();
            let replace = match &oldest {
                None => true,
                Some((t, _, _)) => accessed < *t,
            };
            if replace {
                oldest = Some((accessed, entry.path().to_path_buf(), len));
            }
        }
        let Some((_, path, len)) = oldest else {
            return false;
        };
        match fs::remove_file(&path).await {
            Ok(()) => {
                self.current_size.fetch_sub(len, Ordering::Relaxed);
                debug!(
                    target: LOG_TARGET,
                    file = %path.display(),
                    len,
                    "evict cache file for max_size budget"
                );
                true
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.current_size.fetch_sub(len, Ordering::Relaxed);
                true
            },
            Err(e) => {
                warn!(
                    target: LOG_TARGET,
                    error = %e,
                    file = %path.display(),
                    "evict cache file fail"
                );
                false
            },
        }
    }
    #[inline]
    fn get_file_path(&self, key: &str, namespace: &str) -> std::path::PathBuf {
        let mut path = Path::new(&self.directory).to_path_buf();
        if !namespace.is_empty() {
            path.push(namespace);
        };
        if self.levels.is_empty() {
            path.push(key);
            return path;
        }
        let mut current_len = key.len() - 1;
        for level in self.levels.iter() {
            let level = *level as usize;
            if current_len > level {
                path.push(&key[current_len - level..current_len]);
                current_len -= level;
            }
        }
        path.push(key);
        path
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
    /// * `Ok(None)` - If entry doesn't exist, is invalid, or concurrent
    ///   reads are over quota (treated as a miss so the request falls back
    ///   to origin instead of 5xx)
    /// * `Err(Error::Io)` - On file system errors
    async fn get(
        &self,
        key: &str,
        namespace: &[u8],
    ) -> Result<Option<CacheObject>> {
        // Early return if found in cache
        if let Some(cache) = &self.cache
            && let Some(obj) = cache.get(&key.to_string())
        {
            debug!(
                target: LOG_TARGET,
                key, namespace, "get cache from tinyufo"
            );
            return Ok(Some(obj));
        }

        #[cfg(feature = "tracing")]
        let start = SystemTime::now();
        let namespace_str = std::str::from_utf8(namespace).unwrap_or_default();
        let file = self.get_file_path(key, namespace_str);

        // add reading count
        let count = self.reading.fetch_add(1, Ordering::Relaxed);
        defer!(self.reading.fetch_sub(1, Ordering::Relaxed););
        // Over quota: degrade to a miss (origin fetch) rather than 5xx.
        if self.reading_max > 0 && count >= self.reading_max {
            debug!(
                target: LOG_TARGET,
                key,
                max = self.reading_max,
                "file cache read over quota, treat as miss"
            );
            return Ok(None);
        }
        let result = fs::read(&file).await;
        #[cfg(feature = "tracing")]
        self.read_time.observe(elapsed_second(start));

        let obj = match result {
            Ok(buf) => match CacheObject::try_from(Bytes::from(buf)) {
                Ok(obj) => Ok(Some(obj)),
                // A truncated file (crash or full disk mid write) is a miss,
                // not an error: an error would surface as a 5xx on every hit of
                // this key while the file kept lying on disk. Remove it so the
                // next request re-fetches and rewrites it.
                Err(e) => {
                    warn!(
                        target: LOG_TARGET,
                        key,
                        error = %e,
                        "remove corrupt cache file"
                    );
                    let len =
                        fs::metadata(&file).await.map(|m| m.len()).unwrap_or(0);
                    if fs::remove_file(&file).await.is_ok() {
                        self.current_size.fetch_sub(len, Ordering::Relaxed);
                    }
                    Ok(None)
                },
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Io { source: e }),
        }?;
        // cache get from file, but not in tinyufo, put it to tinyufo
        if let Some(cache) = &self.cache
            && let Some(obj) = &obj
        {
            let weight = obj.get_weight();
            cache.put(key.to_string(), obj.clone(), weight);
        }
        debug!(
            target: LOG_TARGET,
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
    /// * `Ok(())` - On successful storage, or when concurrent writes are
    ///   over quota (disk write is skipped; memory layer may still hold it)
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
                    target: LOG_TARGET,
                    key, namespace, "put cache to tinyufo"
                );
                c.put(key.to_string(), data.clone(), weight);
            }
        }
        #[cfg(feature = "tracing")]
        let start = SystemTime::now();
        let buf: Bytes = data.into();
        let namespace_str = std::str::from_utf8(namespace).unwrap_or_default();
        let file = self.get_file_path(key, namespace_str);
        // add writing count
        let count = self.writing.fetch_add(1, Ordering::Relaxed);
        defer!(self.writing.fetch_sub(1, Ordering::Relaxed););
        // Over quota: skip the disk write instead of failing the response.
        // Hot data may already be in TinyUfo above.
        if self.writing_max > 0 && count >= self.writing_max {
            debug!(
                target: LOG_TARGET,
                key,
                max = self.writing_max,
                "file cache write over quota, skip disk put"
            );
            return Ok(());
        }
        if let Some(parent) = file.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| Error::Io { source: e })?;
        }
        // Write to a temporary file and rename it over the final path. Writing
        // the final path directly is not atomic: a concurrent `get` could read
        // a half written file, and a crash or a full disk would leave one
        // behind permanently. The rename also means a reader only ever sees
        // either the old complete object or the new complete object.
        //
        // The suffix carries the pid because two instances share the cache
        // directory during a zero-downtime upgrade, and a per-process counter
        // keeps concurrent writes of the same key inside one process apart.
        let new_len = buf.len() as u64;
        // Account for overwriting an existing object so the budget stays honest.
        let old_len = fs::metadata(&file).await.map(|m| m.len()).unwrap_or(0);
        let net_add = new_len.saturating_sub(old_len);
        self.ensure_disk_space(net_add).await;

        let tmp = file.with_file_name(format!(
            "{}.{}.{}.tmp",
            file.file_name()
                .map(|name| name.to_string_lossy())
                .unwrap_or_default(),
            std::process::id(),
            TMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed),
        ));
        let result = async {
            fs::write(&tmp, &buf).await?;
            if let Err(e) = fs::rename(&tmp, &file).await {
                // Never leave the temporary file behind: nothing else knows
                // about it, so nothing else would ever clean it up.
                let _ = fs::remove_file(&tmp).await;
                return Err(e);
            }
            Ok(())
        }
        .await;
        #[cfg(feature = "tracing")]
        self.write_time.observe(elapsed_second(start));
        let _ = result.map_err(|e| Error::Io { source: e })?;
        // current = current - old + new
        let _ = self.current_size.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |cur| Some(cur.saturating_sub(old_len).saturating_add(new_len)),
        );
        debug!(
            target: LOG_TARGET,
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
                target: LOG_TARGET,
                key, namespace, "remove cache from tinyufo"
            );
            c.remove(&key.to_string());
        }
        let file = self.get_file_path(
            key,
            std::string::String::from_utf8_lossy(namespace).as_ref(),
        );
        let old_len = fs::metadata(&file).await.map(|m| m.len()).unwrap_or(0);
        match fs::remove_file(&file).await {
            Ok(()) => {
                self.current_size.fetch_sub(old_len, Ordering::Relaxed);
                debug!(
                    target: LOG_TARGET,
                    key, namespace, "remove cache from file"
                );
            },
            // Already gone (e.g. external cleanup) — same as a cache miss on
            // get, not an operational error.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
            Err(e) => return Err(Error::Io { source: e }),
        }
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
        let datetime_local: DateTime<Local> = access_before.into();

        let description = format!(
            "clear cache file, directory: {}, access before: {datetime_local}",
            self.directory
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
            let len = metadata.len();
            match fs::remove_file(path).await {
                Ok(()) => {
                    self.current_size.fetch_sub(len, Ordering::Relaxed);
                    info!(
                        target: LOG_TARGET,
                        file, "remove cache file success"
                    );
                    success += 1;
                },
                Err(e) => {
                    fail += 1;
                    error!(
                        target: LOG_TARGET,
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

/// Sum of file sizes under `directory` (skips missing paths). Used once at
/// construction so the `max_size` budget starts from real disk usage.
fn measure_dir_size(directory: &str) -> u64 {
    WalkDir::new(directory)
        .into_iter()
        .filter_map(|item| item.ok())
        .filter(|item| item.path().is_file())
        .filter_map(|item| item.metadata().ok())
        .map(|m| m.len())
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use pretty_assertions::assert_eq;
    use std::fs::File;
    use std::time::{Duration, SystemTime};
    use tempfile::{TempDir, tempdir};

    /// Tests the `parse_params` function with various query string configurations.
    #[test]
    fn test_parse_params() {
        let params = FileCacheParams::try_from(
              "~/pingap?reading_max=1000&writing_max=500&cache_max=100&inactive=10m&levels=1:2&max_size=10mb",
          ).unwrap();
        assert_eq!(params.reading_max, Some(1000));
        assert_eq!(params.writing_max, Some(500));
        assert_eq!(params.cache_max, 100);
        assert_eq!(params.inactive, Some(Duration::from_secs(600)));
        assert_eq!(params.levels, vec![1, 2]);
        assert_eq!(params.max_size, Some(ByteSize::mb(10)));
        assert!(
            params
                .directory
                .starts_with(dirs::home_dir().unwrap().to_str().unwrap())
        );
    }

    #[tokio::test]
    async fn test_read_write_over_quota_degrades() {
        let dir = tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        // Only one concurrent read/write allowed.
        let cache =
            FileCache::new(&format!("{path}?reading_max=1&writing_max=1"))
                .unwrap();
        // Force the counters into the over-quota region without a real concurrent peer.
        cache.reading.store(1, Ordering::Relaxed);
        cache.writing.store(1, Ordering::Relaxed);

        let obj = CacheObject {
            meta: (b"k".to_vec(), b"v".to_vec()),
            body: Bytes::from_static(b"body"),
        };
        // Write over quota: Ok, no error, no 5xx path.
        cache.put("k", b"", obj.clone()).await.unwrap();
        // File should not have been written.
        assert_eq!(true, cache.get("k", b"").await.unwrap().is_none());

        // Seed a file under the limit for the read path.
        cache.writing.store(0, Ordering::Relaxed);
        cache.put("k", b"", obj).await.unwrap();
        cache.reading.store(1, Ordering::Relaxed);
        // Read over quota: miss, not error.
        assert_eq!(true, cache.get("k", b"").await.unwrap().is_none());
    }

    /// A comprehensive test for the FileCache functionality.
    #[tokio::test]
    async fn test_file_cache_integration() {
        let dir = tempdir().unwrap();
        let dir_path_str = dir.path().to_str().unwrap();
        let namespace = b"my-namespace";

        let cache_config =
            format!("{}?cache_max=100&cache_file_max_size=1024", dir_path_str);
        let cache = FileCache::new(&cache_config).unwrap();

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
        assert!(
            cache
                .cache
                .as_ref()
                .unwrap()
                .get(&key.to_string())
                .is_some()
        );

        // --- Test fallback from file ---
        // Create a new cache instance to simulate a fresh start with no in-memory cache.
        let fresh_cache = FileCache::new(&cache_config).unwrap();

        // 4. GET from the new instance should be a hit from the file.
        let file_obj = fresh_cache.get(key, namespace).await.unwrap().unwrap();
        assert_eq!(obj, file_obj);

        // 5. After reading from the file, it should now be populated in the new instance's in-memory cache.
        assert!(
            fresh_cache
                .cache
                .as_ref()
                .unwrap()
                .get(&key.to_string())
                .is_some()
        );

        // 6. Test REMOVE.
        fresh_cache.remove(key, namespace).await.unwrap();

        // Verify it's gone from both in-memory and file caches.
        assert!(
            fresh_cache
                .cache
                .as_ref()
                .unwrap()
                .get(&key.to_string())
                .is_none()
        );
        assert!(
            fresh_cache.get(key, namespace).await.unwrap().is_none(),
            "Get after remove should be a miss"
        );
    }

    /// Tests the `clear` functionality for removing old files.
    #[tokio::test]
    async fn test_cache_clear() {
        let dir = tempdir().unwrap();
        let cache = FileCache::new(dir.path().to_str().unwrap()).unwrap();

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
            FileCache::new(dir.path().to_str().unwrap()).unwrap();
        let path1 = cache_no_levels.get_file_path("mykey", "namespace");
        assert!(path1.to_string_lossy().ends_with("/namespace/mykey"));

        // Case 2: With levels. Key must be long enough.
        let cache_with_levels_config =
            format!("{}?levels=1:2", dir.path().to_str().unwrap());
        let cache_with_levels =
            FileCache::new(&cache_with_levels_config).unwrap();
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
        let cache = FileCache::new(&dir).unwrap();

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
        let cache = FileCache::new(&dir).unwrap();
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

    #[tokio::test]
    async fn test_corrupt_cache_file_is_a_miss_and_removed() {
        let dir = TempDir::new().unwrap();
        // no tinyufo, so every get goes to the file
        let cache =
            FileCache::new(dir.path().to_string_lossy().as_ref()).unwrap();

        let key = "corrupt";
        let obj = CacheObject {
            meta: (b"Hello".to_vec(), b"World".to_vec()),
            body: Bytes::from_static(b"Hello World!"),
        };
        cache.put(key, b"", obj.clone()).await.unwrap();
        let file = cache.get_file_path(key, "");

        // Truncate the file to what a crash mid write leaves behind: an intact
        // header whose declared meta sizes exceed the bytes present.
        let full = std::fs::read(&file).unwrap();
        std::fs::write(&file, &full[0..10]).unwrap();

        // A miss, not an error - and certainly not a panic.
        let result = cache.get(key, b"").await.unwrap();
        assert_eq!(true, result.is_none());
        // The poisoned file is gone, so the next put/get cycle heals it.
        assert_eq!(false, file.exists());

        cache.put(key, b"", obj.clone()).await.unwrap();
        assert_eq!(obj, cache.get(key, b"").await.unwrap().unwrap());
        // The atomic write leaves no temporary files behind.
        let leftover = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry.file_name().to_string_lossy().ends_with(".tmp")
            })
            .count();
        assert_eq!(0, leftover);
    }

    #[test]
    fn test_stats() {
        let dir = TempDir::new().unwrap();
        let dir = dir.keep().to_string_lossy().to_string();
        let cache = FileCache::new(&dir).unwrap();
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
