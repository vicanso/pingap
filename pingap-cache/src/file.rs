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
use super::tiny::{CacheMode, MemoryCache};
#[cfg(feature = "tracing")]
use super::{CACHE_READING_TIME, CACHE_WRITING_TIME};
use super::{Error, LOG_TARGET, PAGE_SIZE, Result};
use async_trait::async_trait;
use bytes::Bytes;
use bytesize::ByteSize;
use chrono::{DateTime, Local};
use path_absolutize::*;
#[cfg(feature = "tracing")]
use prometheus::Histogram;
use scopeguard::defer;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
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
    /// Hot layer in front of the disk, `None` unless `cache_max` is set.
    cache: Option<MemoryCache>,
    /// Largest object (in pages) admitted to the hot layer.
    cache_file_max_weight: u16,
    /// Inactive duration when cache file will be removed regardless of their freshness.
    cache_inactive: Duration,
    /// Cache file path levels
    levels: Vec<u32>,
    /// Max total size of on-disk cache files in bytes; 0 means unlimited.
    max_size: u64,
    /// Approximate current on-disk usage (bytes). Maintained on put/remove/clear
    /// and initialised by a directory walk at construction time. Only kept
    /// while `max_size` is set; without a budget nothing reads it.
    current_size: AtomicU64,
    /// Set while a `put` is evicting for the budget. The others skip the
    /// walk and write, so a burst of writes over budget costs one directory
    /// walk, not one per write.
    evicting: AtomicBool,
}

/// `levels=1:2`: up to two levels, each 1 to 3 characters of the key. A
/// value outside that is an error rather than silently no levels, which
/// would put every file in one flat directory.
fn split_levels<'de, D>(deserializer: D) -> Result<Vec<u32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = String::deserialize(deserializer)?;
    let s = s.trim();
    if s.is_empty() {
        return Ok(vec![]);
    }
    let invalid = || {
        serde::de::Error::custom(format!(
            "levels {s:?} is invalid, expected up to two numbers from 1 to 3 such as 1:2"
        ))
    };
    let levels = s
        .split(':')
        .map(|item| item.parse::<u32>().ok().filter(|v| (1..=3).contains(v)))
        .collect::<Option<Vec<u32>>>()
        .ok_or_else(invalid)?;
    if levels.len() > 2 {
        return Err(invalid());
    }
    Ok(levels)
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
    /// Hot layer size in pages; 0 disables it
    #[serde(default)]
    cache_max: usize,
    /// Largest object (in pages) admitted to the hot layer
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
                message: format!("file cache params {value} is invalid: {e}"),
            })?
        };
        params.directory = resolve_path(dir);
        Ok(params)
    }
}

/// Resolves a path string to its absolute form.
/// If the path starts with '~', it will be expanded to the user's home directory.
/// Returns an empty string if the input path is empty.
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

/// The namespace as a path component. It comes from the cache key's user
/// tag, which is a `&str`, so this only ever fails on a hand-made key.
#[inline]
fn namespace_str(namespace: &[u8]) -> &str {
    std::str::from_utf8(namespace).unwrap_or_default()
}

/// One file of a directory walk: what eviction and the inactive sweep need.
struct CacheFile {
    path: PathBuf,
    len: u64,
    accessed: SystemTime,
}

/// Lists the files under `dir`. `skip_tmp` leaves in-flight temporaries to
/// the `put` that owns them; the inactive sweep keeps them, since one older
/// than the inactive window was abandoned by a writer that died.
fn walk_cache_files(dir: &Path, skip_tmp: bool) -> Vec<CacheFile> {
    WalkDir::new(dir)
        .into_iter()
        .filter_map(|item| item.ok())
        .filter(|item| item.file_type().is_file())
        .filter(|item| {
            !skip_tmp
                || !item.path().extension().is_some_and(|ext| ext == "tmp")
        })
        .filter_map(|item| {
            let metadata = item.metadata().ok()?;
            Some(CacheFile {
                len: metadata.len(),
                accessed: metadata.accessed().unwrap_or(SystemTime::UNIX_EPOCH),
                path: item.into_path(),
            })
        })
        .collect()
}

/// `walk_cache_files` on the blocking pool: the walk stats every file, and
/// eviction and purge run inside requests, on worker threads that would
/// otherwise stall for the duration.
async fn list_cache_files(dir: PathBuf, skip_tmp: bool) -> Vec<CacheFile> {
    tokio::task::spawn_blocking(move || walk_cache_files(&dir, skip_tmp))
        .await
        .unwrap_or_default()
}

/// Sum of file sizes under `directory` (skips missing paths). Used once at
/// construction so the `max_size` budget starts from real disk usage.
fn measure_dir_size(directory: &str) -> u64 {
    walk_cache_files(Path::new(directory), false)
        .iter()
        .map(|file| file.len)
        .sum()
}

/// Removes every directory under `dir` that is empty, deepest first, and
/// finally `dir` itself. Best effort: a concurrent write recreates what it
/// needs.
fn remove_empty_dirs(dir: &Path) {
    let mut dirs: Vec<PathBuf> = WalkDir::new(dir)
        .into_iter()
        .filter_map(|item| item.ok())
        .filter(|item| item.file_type().is_dir())
        .map(|item| item.into_path())
        .collect();
    dirs.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for dir in dirs {
        let _ = std::fs::remove_dir(&dir);
    }
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
        let current_size = if max_size > 0 {
            measure_dir_size(&params.directory)
        } else {
            0
        };
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
        let cache = (params.cache_max > 0)
            .then(|| MemoryCache::new(CacheMode::Normal, params.cache_max));

        Ok(FileCache {
            directory: params.directory,
            cache_file_max_weight: params
                .cache_file_max_weight
                .unwrap_or(1024 * 1024 / PAGE_SIZE)
                .min(u16::MAX as usize)
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
            evicting: AtomicBool::new(false),
        })
    }

    /// Whether the on-disk budget is tracked at all.
    #[inline]
    fn has_budget(&self) -> bool {
        self.max_size > 0
    }

    /// Accounts `len` bytes leaving the disk. Saturating: the counter is an
    /// estimate (files can be removed behind our back) and must never wrap
    /// into a number that makes every write look over budget.
    fn track_removed(&self, len: u64) {
        if !self.has_budget() {
            return;
        }
        let _ = self.current_size.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |cur| Some(cur.saturating_sub(len)),
        );
    }

    /// Accounts an object of `new_len` bytes replacing one of `old_len`.
    fn track_written(&self, old_len: u64, new_len: u64) {
        if !self.has_budget() {
            return;
        }
        let _ = self.current_size.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |cur| Some(cur.saturating_sub(old_len).saturating_add(new_len)),
        );
    }

    /// Size of the file at `path`, when the budget needs it.
    async fn tracked_len(&self, path: &Path) -> u64 {
        if !self.has_budget() {
            return 0;
        }
        fs::metadata(path).await.map(|m| m.len()).unwrap_or(0)
    }

    /// Removes the file at `path` and accounts for it. `Ok(false)` when it
    /// was already gone.
    async fn remove_tracked(&self, path: &Path) -> std::io::Result<bool> {
        let len = self.tracked_len(path).await;
        match fs::remove_file(path).await {
            Ok(()) => {
                self.track_removed(len);
                Ok(true)
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Makes room for `need` more bytes under `max_size` by deleting the
    /// least recently accessed files first. Returns whether the write may
    /// go ahead: an object larger than the whole budget never fits, and
    /// evicting everything for it would only empty the cache.
    ///
    /// One directory walk, then deletions in access order until the budget
    /// holds. The walk used to be repeated for every single file evicted,
    /// which on a large directory made one over-budget write cost dozens
    /// of full walks.
    async fn ensure_disk_space(&self, need: u64) -> bool {
        if !self.has_budget() {
            return true;
        }
        if need > self.max_size {
            return false;
        }
        let over = |need: u64| {
            self.current_size
                .load(Ordering::Relaxed)
                .saturating_add(need)
                > self.max_size
        };
        if !over(need) {
            return true;
        }
        // Another put is already evicting; let it finish the job.
        if self
            .evicting
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return true;
        }
        defer!(self.evicting.store(false, Ordering::Release));

        let mut files =
            list_cache_files(PathBuf::from(&self.directory), true).await;
        files.sort_by_key(|file| file.accessed);
        let mut evicted = 0u64;
        let mut count = 0u32;
        for file in files {
            if !over(need) {
                break;
            }
            match fs::remove_file(&file.path).await {
                Ok(()) => {
                    self.track_removed(file.len);
                    evicted += file.len;
                    count += 1;
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    self.track_removed(file.len);
                },
                Err(e) => {
                    warn!(
                        target: LOG_TARGET,
                        error = %e,
                        file = %file.path.display(),
                        "evict cache file fail"
                    );
                },
            }
        }
        debug!(
            target: LOG_TARGET,
            count,
            evicted,
            current_size = self.current_size.load(Ordering::Relaxed),
            max_size = self.max_size,
            "evict cache files for max_size budget"
        );
        true
    }

    #[inline]
    fn get_file_path(&self, key: &str, namespace: &str) -> PathBuf {
        let mut path = Path::new(&self.directory).to_path_buf();
        if !namespace.is_empty() {
            path.push(namespace);
        };
        if self.levels.is_empty() {
            path.push(key);
            return path;
        }
        let mut current_len = key.len().saturating_sub(1);
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

    /// Puts an object read from or written to disk into the hot layer,
    /// unless it is too large for it.
    fn put_hot(&self, key: &str, obj: &CacheObject) {
        let Some(cache) = &self.cache else {
            return;
        };
        let weight = obj.get_weight();
        if weight >= self.cache_file_max_weight {
            return;
        }
        debug!(target: LOG_TARGET, key, weight, "put cache to tinyufo");
        cache.put(key, obj.clone(), weight);
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
            && let Some(obj) = cache.get(key)
        {
            debug!(
                target: LOG_TARGET,
                key, namespace, "get cache from tinyufo"
            );
            return Ok(Some(obj));
        }

        #[cfg(feature = "tracing")]
        let start = SystemTime::now();
        let file = self.get_file_path(key, namespace_str(namespace));

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
                Ok(obj) => Some(obj),
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
                    let _ = self.remove_tracked(&file).await;
                    None
                },
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(Error::Io { source: e }),
        };
        // cache get from file, but not in tinyufo, put it to tinyufo
        if let Some(obj) = &obj {
            self.put_hot(key, obj);
        }
        debug!(
            target: LOG_TARGET,
            key,
            namespace = namespace_str(namespace),
            "get cache from file"
        );
        Ok(obj)
    }
    /// Stores a cache object both in TinyUfo cache and on disk.
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
        self.put_hot(key, &data);
        #[cfg(feature = "tracing")]
        let start = SystemTime::now();
        let buf: Bytes = data.into();
        let file = self.get_file_path(key, namespace_str(namespace));
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
        let new_len = buf.len() as u64;
        // Account for overwriting an existing object so the budget stays honest.
        let old_len = self.tracked_len(&file).await;
        if !self
            .ensure_disk_space(new_len.saturating_sub(old_len))
            .await
        {
            debug!(
                target: LOG_TARGET,
                key,
                size = new_len,
                max_size = self.max_size,
                "cache object is larger than max_size, skip disk put"
            );
            return Ok(());
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
        result.map_err(|e| Error::Io { source: e })?;
        self.track_written(old_len, new_len);
        debug!(
            target: LOG_TARGET,
            key,
            namespace = namespace_str(namespace),
            "put cache to file"
        );
        Ok(())
    }
    /// Removes a cache entry from both TinyUfo and disk storage.
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
            c.remove(key);
        }
        let file = self.get_file_path(key, namespace_str(namespace));
        // Already gone (e.g. external cleanup) is the same as a cache miss
        // on get, not an operational error.
        let removed = self
            .remove_tracked(&file)
            .await
            .map_err(|e| Error::Io { source: e })?;
        if removed {
            debug!(
                target: LOG_TARGET,
                key, namespace, "remove cache from file"
            );
        }
        Ok(None)
    }
    /// Returns current cache statistics.
    #[inline]
    fn stats(&self) -> Option<HttpCacheStats> {
        Some(HttpCacheStats {
            reading: self.reading.load(Ordering::Relaxed),
            writing: self.writing.load(Ordering::Relaxed),
        })
    }
    /// Clears cache entries that were last accessed before the given timestamp.
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
        let files =
            list_cache_files(PathBuf::from(&self.directory), false).await;
        for file in files.into_iter().filter(|f| f.accessed <= access_before) {
            match fs::remove_file(&file.path).await {
                Ok(()) => {
                    self.track_removed(file.len);
                    debug!(
                        target: LOG_TARGET,
                        file = %file.path.display(),
                        "remove cache file success"
                    );
                    success += 1;
                },
                // Removed by a purge or an eviction in the meantime.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
                Err(e) => {
                    fail += 1;
                    error!(
                        target: LOG_TARGET,
                        error = %e,
                        file = %file.path.display(),
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

    /// Removes every cached object under `<directory>/<namespace>`.
    ///
    /// Only works with a non-empty namespace: it is the one part of the cache
    /// key that survives hashing (as a directory), so it is the one granularity
    /// beyond an exact key that can be purged without an index. An empty
    /// namespace would mean walking the backend root, where other namespaces'
    /// directories are indistinguishable from level directories.
    async fn purge_namespace(
        &self,
        namespace: &str,
    ) -> Result<Option<HttpCacheClearStats>> {
        if namespace.is_empty()
            || namespace.contains('/')
            || namespace.contains('\\')
            || namespace.contains("..")
        {
            return Err(Error::Invalid {
                message: format!(
                    "purge namespace requires a plain non-empty namespace, got {namespace:?}"
                ),
            });
        }
        let dir = Path::new(&self.directory).join(namespace);
        let description = format!(
            "purge cache namespace, directory: {}",
            dir.to_string_lossy()
        );
        let mut success = 0;
        let mut fail = 0;
        // In-flight temporaries still belong to their writer; the rename
        // that follows will land the object post-purge, which is the same
        // as a write that started after the purge.
        for file in list_cache_files(dir.clone(), true).await {
            match fs::remove_file(&file.path).await {
                Ok(()) => {
                    self.track_removed(file.len);
                    // The file name IS the combined cache key hash, which is
                    // also the hot layer's key - so the memory copy can be
                    // dropped too and a purged object cannot keep being
                    // served from tinyufo.
                    if let Some(cache) = &self.cache
                        && let Some(name) =
                            file.path.file_name().and_then(|name| name.to_str())
                    {
                        cache.remove(name);
                    }
                    success += 1;
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
                Err(e) => {
                    fail += 1;
                    error!(
                        target: LOG_TARGET,
                        error = %e,
                        file = %file.path.display(),
                        "purge cache file fail"
                    );
                },
            }
        }
        // Best effort: drop now-empty level directories and the namespace
        // directory itself; a concurrent write recreates what it needs.
        let _ =
            tokio::task::spawn_blocking(move || remove_empty_dirs(&dir)).await;
        info!(
            target: LOG_TARGET,
            namespace, success, fail, "purge cache namespace"
        );
        Ok(Some(HttpCacheClearStats {
            success,
            fail,
            description,
        }))
    }
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
            meta: (Bytes::from_static(b"k"), Bytes::from_static(b"v")),
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
            meta: (
                Bytes::from_static(b"Meta-Key"),
                Bytes::from_static(b"Meta-Value"),
            ),
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
        assert!(cache.cache.as_ref().unwrap().get(key).is_some());

        // --- Test fallback from file ---
        // Create a new cache instance to simulate a fresh start with no in-memory cache.
        let fresh_cache = FileCache::new(&cache_config).unwrap();

        // 4. GET from the new instance should be a hit from the file.
        let file_obj = fresh_cache.get(key, namespace).await.unwrap().unwrap();
        assert_eq!(obj, file_obj);

        // 5. After reading from the file, it should now be populated in the new instance's in-memory cache.
        assert!(fresh_cache.cache.as_ref().unwrap().get(key).is_some());

        // 6. Test REMOVE.
        fresh_cache.remove(key, namespace).await.unwrap();

        // Verify it's gone from both in-memory and file caches.
        assert!(fresh_cache.cache.as_ref().unwrap().get(key).is_none());
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
            meta: (Bytes::from_static(b"Hello"), Bytes::from_static(b"World")),
            body: Bytes::from_static(b"Hello World!"),
        };
        let result = cache.get(key, namespace).await.unwrap();
        assert_eq!(true, result.is_none());
        cache.put(key, namespace, obj.clone()).await.unwrap();
        // tinyufo cache will be exist after put
        assert_eq!(true, cache.cache.as_ref().unwrap().get(key).is_some());

        let result = cache.get(key, namespace).await.unwrap().unwrap();
        assert_eq!(obj, result);

        // empty tinyufo, get from file
        let cache = FileCache::new(&dir).unwrap();
        let result = cache.get(key, namespace).await.unwrap().unwrap();
        assert_eq!(obj, result);

        // check tinyufo cache
        // it will be exist after get from file
        assert_eq!(true, cache.cache.as_ref().unwrap().get(key).is_some());

        cache.remove(key, namespace).await.unwrap();
        // tinyufo cache will be removed after remove
        assert_eq!(false, cache.cache.as_ref().unwrap().get(key).is_some());
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
    async fn test_purge_namespace() {
        let dir = TempDir::new().unwrap();
        // tinyufo enabled: a purge has to clear the hot layer too, or the
        // purged object would keep being served from memory.
        let cache = FileCache::new(&format!(
            "{}?cache_max=100",
            dir.path().to_string_lossy()
        ))
        .unwrap();
        let obj = CacheObject {
            meta: (Bytes::from_static(b"Hello"), Bytes::from_static(b"World")),
            body: Bytes::from_static(b"Hello World!"),
        };
        cache.put("key-a1", b"ns-a", obj.clone()).await.unwrap();
        cache.put("key-a2", b"ns-a", obj.clone()).await.unwrap();
        cache.put("key-b", b"ns-b", obj.clone()).await.unwrap();

        let stats = cache.purge_namespace("ns-a").await.unwrap().unwrap();
        assert_eq!(2, stats.success);
        assert_eq!(0, stats.fail);

        // Gone from disk AND memory (a get would prefer tinyufo).
        assert_eq!(true, cache.get("key-a1", b"ns-a").await.unwrap().is_none());
        assert_eq!(true, cache.get("key-a2", b"ns-a").await.unwrap().is_none());
        // The other namespace is untouched.
        assert_eq!(obj, cache.get("key-b", b"ns-b").await.unwrap().unwrap());
        // The namespace directory itself is removed.
        assert_eq!(false, dir.path().join("ns-a").exists());

        // Idempotent.
        let stats = cache.purge_namespace("ns-a").await.unwrap().unwrap();
        assert_eq!(0, stats.success);

        // Guard rails: an empty or traversal namespace is rejected.
        for bad in ["", "../ns-a", "a/b", "a\\b"] {
            assert_eq!(
                true,
                cache.purge_namespace(bad).await.is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[tokio::test]
    async fn test_corrupt_cache_file_is_a_miss_and_removed() {
        let dir = TempDir::new().unwrap();
        // no tinyufo, so every get goes to the file
        let cache =
            FileCache::new(dir.path().to_string_lossy().as_ref()).unwrap();

        let key = "corrupt";
        let obj = CacheObject {
            meta: (Bytes::from_static(b"Hello"), Bytes::from_static(b"World")),
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

    /// `levels` outside 1..=3 or with more than two entries is an error
    /// rather than silently no levels.
    #[test]
    fn test_split_levels_rejects_invalid() {
        for bad in ["a", "1:2:3", "4", "0", "1:"] {
            let err = FileCacheParams::try_from(
                format!("/tmp/pingap?levels={bad}").as_str(),
            )
            .expect_err(bad)
            .to_string();
            assert!(err.contains("levels"), "{bad}: {err}");
        }
        for (value, expected) in
            [("", vec![]), ("1", vec![1]), ("3:2", vec![3, 2])]
        {
            assert_eq!(
                expected,
                FileCacheParams::try_from(
                    format!("/tmp/pingap?levels={value}").as_str()
                )
                .unwrap()
                .levels,
                "{value}"
            );
        }
    }

    /// The disk budget evicts the least recently accessed files first, and
    /// an object larger than the whole budget is skipped instead of
    /// emptying the cache for it.
    #[tokio::test]
    async fn test_max_size_evicts_least_recently_accessed() {
        let dir = tempdir().unwrap();
        // Each object is 8 (header) + 2 (meta) + 1024 bytes; two fit.
        let cache = FileCache::new(&format!(
            "{}?max_size=2200",
            dir.path().to_str().unwrap()
        ))
        .unwrap();
        let obj = |fill: u8| CacheObject {
            meta: (Bytes::from_static(b"k"), Bytes::from_static(b"v")),
            body: Bytes::from(vec![fill; 1024]),
        };
        cache.put("a", b"", obj(1)).await.unwrap();
        cache.put("b", b"", obj(2)).await.unwrap();
        assert_eq!(2068, cache.current_size.load(Ordering::Relaxed));
        // `a` is the one nobody touched for an hour.
        filetime::set_file_atime(
            cache.get_file_path("a", ""),
            filetime::FileTime::from_system_time(
                SystemTime::now() - Duration::from_secs(3600),
            ),
        )
        .unwrap();

        cache.put("c", b"", obj(3)).await.unwrap();
        assert_eq!(true, cache.get("a", b"").await.unwrap().is_none());
        assert_eq!(obj(2), cache.get("b", b"").await.unwrap().unwrap());
        assert_eq!(obj(3), cache.get("c", b"").await.unwrap().unwrap());
        assert_eq!(2068, cache.current_size.load(Ordering::Relaxed));

        // Larger than the budget: not written, nothing evicted for it.
        let big = CacheObject {
            meta: (Bytes::from_static(b"k"), Bytes::from_static(b"v")),
            body: Bytes::from(vec![0; 4096]),
        };
        cache.put("d", b"", big).await.unwrap();
        assert_eq!(true, cache.get("d", b"").await.unwrap().is_none());
        assert_eq!(true, cache.get("b", b"").await.unwrap().is_some());
        assert_eq!(true, cache.get("c", b"").await.unwrap().is_some());
        assert_eq!(2068, cache.current_size.load(Ordering::Relaxed));
    }

    /// An object too large for the hot layer stays out of it on the read
    /// path too, not only on the write path.
    #[tokio::test]
    async fn test_hot_layer_admission_on_read() {
        let dir = tempdir().unwrap();
        let cache = FileCache::new(&format!(
            "{}?cache_max=100&cache_file_max_weight=2",
            dir.path().to_str().unwrap()
        ))
        .unwrap();
        let big = CacheObject {
            meta: (Bytes::from_static(b"k"), Bytes::from_static(b"v")),
            body: Bytes::from(vec![0; PAGE_SIZE * 3]),
        };
        cache.put("big", b"", big.clone()).await.unwrap();
        let hot = cache.cache.as_ref().unwrap();
        assert_eq!(true, hot.get("big").is_none());
        assert_eq!(big, cache.get("big", b"").await.unwrap().unwrap());
        assert_eq!(true, hot.get("big").is_none());

        let small = CacheObject {
            meta: (Bytes::from_static(b"k"), Bytes::from_static(b"v")),
            body: Bytes::from_static(b"small"),
        };
        cache.put("small", b"", small.clone()).await.unwrap();
        assert_eq!(true, hot.get("small").is_some());
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
