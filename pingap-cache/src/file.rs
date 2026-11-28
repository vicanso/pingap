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
    BinaryMeta, CacheObject, HitBody, HttpCacheClearStats, HttpCacheStats,
    HttpCacheStorage, META_SIZE_LENGTH, StreamingMissWriter,
};
use super::tiny::{CacheMode, MemoryCache};
#[cfg(feature = "tracing")]
use super::{CACHE_READING_TIME, CACHE_WRITING_TIME};
use super::{Error, LOG_TARGET, PAGE_SIZE, Result};
use ahash::AHashMap;
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use bytesize::ByteSize;
use parking_lot::{Mutex, RwLock};
use path_absolutize::*;
#[cfg(feature = "tracing")]
use prometheus::Histogram;
use scopeguard::defer;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, SystemTime};
use tokio::sync::watch;
use tracing::{debug, error, info, warn};
use walkdir::WalkDir;

/// Distinguishes the temporary files of concurrent `put`s within this process;
/// the pid in the file name distinguishes processes.
static TMP_FILE_SEQ: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
enum ColdReadState {
    Pending,
    Hit(CacheObject),
    Miss,
    IoError(std::io::ErrorKind, String),
    Cancelled,
}

struct ColdReadSlot {
    tx: watch::Sender<ColdReadState>,
}

enum ColdReadRole<'a> {
    Leader(ColdReadGuard<'a>),
    Follower(watch::Receiver<ColdReadState>),
}

struct ColdReadGuard<'a> {
    cold_reads: &'a Mutex<AHashMap<PathBuf, Arc<ColdReadSlot>>>,
    file: PathBuf,
    slot: Arc<ColdReadSlot>,
    published: bool,
}

impl ColdReadGuard<'_> {
    fn is_current(&self) -> bool {
        self.cold_reads
            .lock()
            .get(&self.file)
            .is_some_and(|cur| Arc::ptr_eq(cur, &self.slot))
    }

    fn publish(mut self, state: ColdReadState) {
        self.published = true;
        {
            let mut map = self.cold_reads.lock();
            if map
                .get(&self.file)
                .is_some_and(|cur| Arc::ptr_eq(cur, &self.slot))
            {
                map.remove(&self.file);
            }
        }
        let _ = self.slot.tx.send(state);
    }
}

impl Drop for ColdReadGuard<'_> {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        {
            let mut map = self.cold_reads.lock();
            if map
                .get(&self.file)
                .is_some_and(|cur| Arc::ptr_eq(cur, &self.slot))
            {
                map.remove(&self.file);
            }
        }
        self.slot.tx.send_if_modified(|state| {
            if matches!(state, ColdReadState::Pending) {
                *state = ColdReadState::Cancelled;
                true
            } else {
                false
            }
        });
    }
}

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
    writing: Arc<AtomicU32>,
    /// Maximum allowed concurrent write operations
    writing_max: u32,
    #[cfg(feature = "tracing")]
    /// Histogram metric for tracking cache write operation times
    write_time: Box<Histogram>,
    /// Hot layer in front of the disk, `None` unless `cache_max` is set.
    /// The hot layer, behind a lock so that a namespace purge can replace
    /// it whole: its entries cannot be listed, and some of them have no
    /// file to find them by.
    cache: Option<Arc<RwLock<MemoryCache>>>,
    /// The weight limit the hot layer is built with.
    cache_max: usize,
    /// Largest object (in pages) admitted to the hot layer.
    cache_file_max_weight: u16,
    /// Inactive duration when cache file will be removed regardless of their freshness.
    cache_inactive: Duration,
    /// Cache file path levels
    levels: Vec<u32>,
    /// Max total size of on-disk cache files in bytes; 0 means unlimited.
    max_size: u64,
    /// Approximate current on-disk usage (bytes). Maintained on put/remove/clear
    /// and initialised by a bounded directory walk at construction time. Only
    /// kept while `max_size` is set; without a budget nothing reads it.
    current_size: Arc<AtomicU64>,
    /// True when the startup bounded scan stopped before seeing every entry
    /// and a full post-fork background scan still needs to resync `current_size`.
    size_scan_pending: Arc<AtomicBool>,
    /// Set while a `put` is evicting for the budget. The others skip the
    /// walk and write, so a burst of writes over budget costs one directory
    /// walk, not one per write.
    evicting: Arc<AtomicBool>,
    /// Per-path single-flight slots coalescing concurrent cold disk reads.
    cold_reads: Arc<Mutex<AHashMap<PathBuf, Arc<ColdReadSlot>>>>,
    #[cfg(test)]
    cold_disk_reads: AtomicU64,
    /// When the file of an object was last marked as read, in seconds; by
    /// a hash of its key, see [`FileCache::touch`].
    touched: Box<[AtomicU64]>,
    /// Coalesced file paths waiting for their `atime` to be updated in batch.
    pending_touches: Arc<Mutex<Vec<PathBuf>>>,
    /// Whether an async touch-batch drainer task is currently active.
    touch_flushing: Arc<AtomicBool>,
}

/// Maximum number of entries visited synchronously during startup `FileCache::new`.
const INITIAL_SCAN_ENTRY_LIMIT: usize = 1024;

/// Batch threshold that triggers immediate touch flushing without waiting `TOUCH_FLUSH_DELAY`.
const TOUCH_BATCH_SIZE: usize = 64;
/// Delay before flushing a smaller batch of pending `atime` updates.
const TOUCH_FLUSH_DELAY: Duration = Duration::from_millis(50);

/// Staging buffer threshold (128 KiB) before dispatching streaming `.tmp` writes.
const STREAMING_STAGE_SIZE: usize = 128 * 1024;

/// The share of `max_size` an eviction frees, as its divisor: a tenth.
const EVICT_ROOM_DIVISOR: u64 = 10;

/// How often, at most, the file of an object is marked as read.
const TOUCH_INTERVAL: u32 = 60;
/// How soon an object may take a slot of the table below from another.
const TOUCH_TAKEOVER: u32 = 1;
/// The size of the table that keeps, for the objects last marked, which
/// one it was and when: half a megabyte, so that objects seldom share a
/// slot. Those that do take turns, see [`FileCache::touch`].
const TOUCH_SLOTS: usize = 65536;

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
pub(crate) struct FileCacheParams {
    /// Cache directory, resolved: `d`, `./d` and `d?inactive=1h` are one
    /// directory.
    #[serde(default)]
    pub(crate) directory: String,
    /// Inactive duration when cache file will be removed regardless of their freshness.
    #[serde(default)]
    #[serde(with = "pingap_util::duration_serde")]
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

/// The home directory of the user this process runs as, see
/// `pingap_util::home_dir`: a home that is an empty path is none.
fn home_dir() -> Option<PathBuf> {
    std::env::home_dir().filter(|home| !home.as_os_str().is_empty())
}

/// Resolves a path string to its absolute form.
/// If the path starts with '~', it will be expanded to the user's home directory.
/// Returns an empty string if the input path is empty.
fn resolve_path(path_str: &str) -> String {
    if path_str.is_empty() {
        return String::new();
    }
    let path = if let Some(stripped) = path_str.strip_prefix("~/") {
        home_dir()
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

/// The length of a cache key: the hex form of a 128 bit hash.
const CACHE_KEY_LEN: usize = 32;

/// Whether `name` is the name of a cached object, which is its key as
/// pingora writes it: 32 hex digits in lower case. Nothing looser, so that
/// as little as possible of what else may be in the directory looks like
/// one; `test_cache_file_names` holds this against the keys pingora gives.
fn is_cache_key(name: &str) -> bool {
    name.len() == CACHE_KEY_LEN
        && name
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Whether `name` is the temporary file of a write, `<key>.<pid>.<seq>.tmp`.
fn is_cache_tmp_file(name: &str) -> bool {
    let is_number =
        |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    name.strip_suffix(".tmp")
        .and_then(|rest| rest.rsplit_once('.'))
        .and_then(|(rest, seq)| Some((rest.rsplit_once('.')?, seq)))
        .is_some_and(|((key, pid), seq)| {
            is_cache_key(key) && is_number(pid) && is_number(seq)
        })
}

/// Lists the files under `dir` that the cache wrote: the objects, and their
/// temporaries unless `skip_tmp`. The directory is the operator's, and
/// anything else in it is not the cache's to count, evict or sweep - a
/// directory shared with other data used to lose every file that had not
/// been read for `inactive`.
///
/// `skip_tmp` leaves in-flight temporaries to the `put` that owns them; the
/// inactive sweep keeps them, since one older than the inactive window was
/// abandoned by a writer that died.
#[inline]
fn is_cache_file(entry: &walkdir::DirEntry, skip_tmp: bool) -> bool {
    if !entry.file_type().is_file() {
        return false;
    }
    let name = entry.file_name().to_string_lossy();
    is_cache_key(&name) || (!skip_tmp && is_cache_tmp_file(&name))
}

fn walk_cache_files(dir: &Path, skip_tmp: bool) -> Vec<CacheFile> {
    WalkDir::new(dir)
        .into_iter()
        .filter_map(|item| item.ok())
        .filter(|item| is_cache_file(item, skip_tmp))
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

/// Distinguishes the temporary files of concurrent writes with `<key>.<pid>.<seq>.tmp`.
fn temp_path_for(file: &Path) -> PathBuf {
    file.with_file_name(format!(
        "{}.{}.{}.tmp",
        file.file_name()
            .map(|name| name.to_string_lossy())
            .unwrap_or_default(),
        std::process::id(),
        TMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed),
    ))
}

/// Opens a new temporary file, creating missing parent directories only when
/// `File::create` reports `ErrorKind::NotFound`.
fn create_temp_file(tmp: &Path) -> std::io::Result<std::fs::File> {
    match std::fs::File::create(tmp) {
        Ok(file) => Ok(file),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) =
                tmp.parent().filter(|p| !p.as_os_str().is_empty())
            {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::File::create(tmp)
        },
        Err(e) => Err(e),
    }
}

/// Accounts `len` bytes leaving the disk. Saturating: the counter is an
/// estimate (files can be removed behind our back) and must never wrap
/// into a number that makes every write look over budget.
fn track_removed_atomic(has_budget: bool, current_size: &AtomicU64, len: u64) {
    if !has_budget || len == 0 {
        return;
    }
    current_size.update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
        cur.saturating_sub(len)
    });
}

/// Adjusts `current_size` by the exact signed size delta `new_len - old_len`.
fn track_written_delta_atomic(
    has_budget: bool,
    current_size: &AtomicU64,
    old_len: u64,
    new_len: u64,
) {
    if !has_budget || old_len == new_len {
        return;
    }
    if new_len >= old_len {
        current_size.fetch_add(new_len - old_len, Ordering::Relaxed);
    } else {
        let diff = old_len - new_len;
        current_size.update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
            cur.saturating_sub(diff)
        });
    }
}

fn apply_touch_batch(files: &[PathBuf]) {
    if files.is_empty() {
        return;
    }
    let times = std::fs::FileTimes::new().set_accessed(SystemTime::now());
    for file in files {
        // Opened for writing, which Windows asks for before it lets
        // the times of a file be set. An object that is in memory
        // only has no file.
        let _ = std::fs::OpenOptions::new()
            .write(true)
            .open(file)
            .and_then(|f| f.set_times(times));
    }
}

fn flush_pending_touches_sync(pending_touches: &Mutex<Vec<PathBuf>>) {
    let batch = {
        let mut guard = pending_touches.lock();
        if guard.is_empty() {
            return;
        }
        std::mem::take(&mut *guard)
    };
    apply_touch_batch(&batch);
}

fn rearm_touch_drainer(
    pending_touches: &Mutex<Vec<PathBuf>>,
    touch_flushing: &AtomicBool,
) -> bool {
    touch_flushing.store(false, Ordering::Release);
    std::sync::atomic::fence(Ordering::SeqCst);
    !pending_touches.lock().is_empty()
        && touch_flushing
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
}

async fn drain_pending_touches(
    pending_touches: Arc<Mutex<Vec<PathBuf>>>,
    touch_flushing: Arc<AtomicBool>,
) {
    loop {
        let len = pending_touches.lock().len();
        if len > 0 && len < TOUCH_BATCH_SIZE {
            tokio::time::sleep(TOUCH_FLUSH_DELAY).await;
        }
        while !pending_touches.lock().is_empty() {
            let pending = pending_touches.clone();
            let _ = tokio::task::spawn_blocking(move || {
                flush_pending_touches_sync(&pending);
            })
            .await;
        }
        if !rearm_touch_drainer(&pending_touches, &touch_flushing) {
            break;
        }
    }
}

/// Makes room for `need` more bytes under `max_size` by deleting the least
/// recently accessed files synchronously inside a blocking task.
/// Returns `(allowed, evicted_any)`.
fn evict_disk_space_sync(
    dir: &Path,
    max_size: u64,
    need: u64,
    current_size: &AtomicU64,
    evicting: &AtomicBool,
    pending_touches: &Mutex<Vec<PathBuf>>,
) -> (bool, bool) {
    if max_size == 0 {
        return (true, false);
    }
    if need > max_size {
        return (false, false);
    }
    let over =
        current_size.load(Ordering::Relaxed).saturating_add(need) > max_size;
    if !over {
        return (true, false);
    }
    // Another put is already evicting; let it finish the job.
    if evicting
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return (true, false);
    }
    defer!(evicting.store(false, Ordering::Release));

    flush_pending_touches_sync(pending_touches);
    let mut files = walk_cache_files(dir, true);
    // The counter is an estimate: two writes of one key, a file removed
    // by another process or by hand, and it is off, for good. With the
    // whole directory listed here anyway, it is set to what is there.
    let real_size: u64 = files.iter().map(|file| file.len).sum();
    current_size.store(real_size, Ordering::Relaxed);
    if real_size.saturating_add(need) <= max_size {
        return (true, false);
    }
    // Room for this object, and when that is less, for a tenth of the
    // budget. With no more freed than the one object needed the cache
    // was full again after it, and every write from then on walked the
    // whole directory to evict one file: forty milliseconds a write at
    // twenty thousand files.
    let room = need.max(max_size / EVICT_ROOM_DIVISOR);
    let keep = max_size.saturating_sub(room);
    let bytes_to_free = real_size.saturating_sub(keep);
    order_oldest_for_eviction(
        &mut files,
        bytes_to_free.saturating_add(bytes_to_free / 4),
    );
    let mut evicted = 0u64;
    let mut count = 0u32;
    let mut evicted_any = false;
    for file in files {
        if current_size.load(Ordering::Relaxed) <= keep {
            break;
        }
        match std::fs::remove_file(&file.path) {
            Ok(()) => {
                track_removed_atomic(true, current_size, file.len);
                evicted += file.len;
                count += 1;
                evicted_any = true;
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                track_removed_atomic(true, current_size, file.len);
                evicted_any = true;
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
        current_size = current_size.load(Ordering::Relaxed),
        max_size,
        "evict cache files for max_size budget"
    );
    (true, evicted_any)
}

fn remove_tracked_sync(
    path: &Path,
    has_budget: bool,
    current_size: &AtomicU64,
) -> std::io::Result<bool> {
    let len = if has_budget {
        std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
    } else {
        0
    };
    match std::fs::remove_file(path) {
        Ok(()) => {
            track_removed_atomic(has_budget, current_size, len);
            Ok(true)
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

fn validate_meta_lengths(meta: &BinaryMeta) -> Result<(u32, u32)> {
    let meta0_len =
        u32::try_from(meta.0.len()).map_err(|_| Error::Invalid {
            message: "meta0 exceeds u32::MAX".to_string(),
        })?;
    let meta1_len =
        u32::try_from(meta.1.len()).map_err(|_| Error::Invalid {
            message: "meta1 exceeds u32::MAX".to_string(),
        })?;
    Ok((meta0_len, meta1_len))
}

#[inline]
fn encode_cache_header(
    meta0_len: u32,
    meta1_len: u32,
) -> [u8; META_SIZE_LENGTH] {
    let mut header = [0u8; META_SIZE_LENGTH];
    header[..4].copy_from_slice(&meta0_len.to_be_bytes());
    header[4..].copy_from_slice(&meta1_len.to_be_bytes());
    header
}

fn write_cache_header_and_meta(
    writer: &mut impl std::io::Write,
    meta: &BinaryMeta,
    meta0_len: u32,
    meta1_len: u32,
) -> std::io::Result<()> {
    let header = encode_cache_header(meta0_len, meta1_len);
    writer.write_all(&header)?;
    writer.write_all(&meta.0)?;
    writer.write_all(&meta.1)
}

#[allow(clippy::too_many_arguments)]
fn put_file_sync(
    dir: &Path,
    file: &Path,
    data: &CacheObject,
    meta0_len: u32,
    meta1_len: u32,
    new_len: u64,
    max_size: u64,
    current_size: &AtomicU64,
    evicting: &AtomicBool,
    pending_touches: &Mutex<Vec<PathBuf>>,
) -> Result<bool> {
    use std::io::{BufWriter, Write};
    let has_budget = max_size > 0;
    let mut old_len = if has_budget {
        std::fs::metadata(file).map(|m| m.len()).unwrap_or(0)
    } else {
        0
    };
    if has_budget {
        let need = new_len.saturating_sub(old_len);
        let (allowed, evicted_any) = evict_disk_space_sync(
            dir,
            max_size,
            need,
            current_size,
            evicting,
            pending_touches,
        );
        if !allowed {
            return Ok(false);
        }
        if evicted_any {
            old_len = std::fs::metadata(file).map(|m| m.len()).unwrap_or(0);
        }
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
    let tmp = temp_path_for(file);
    let write_result = (|| -> std::io::Result<()> {
        let dst = create_temp_file(&tmp)?;
        let mut writer = BufWriter::new(dst);
        write_cache_header_and_meta(
            &mut writer,
            &data.meta,
            meta0_len,
            meta1_len,
        )?;
        writer.write_all(&data.body)?;
        writer.flush()?;
        drop(writer);
        std::fs::rename(&tmp, file)
    })();
    if let Err(e) = write_result {
        // Never leave the temporary file behind: nothing else knows about
        // it, so nothing else would ever clean it up.
        let _ = std::fs::remove_file(&tmp);
        return Err(Error::Io { source: e });
    }
    track_written_delta_atomic(has_budget, current_size, old_len, new_len);
    Ok(true)
}

enum DiskUpdateMetaOutcome {
    Updated,
    NotFound,
    Corrupt,
}

fn update_meta_file_sync(
    file: &Path,
    meta: &BinaryMeta,
    new_meta0_len: u32,
    new_meta1_len: u32,
    has_budget: bool,
    current_size: &AtomicU64,
) -> Result<DiskUpdateMetaOutcome> {
    use std::io::{BufWriter, ErrorKind, Read, Seek, SeekFrom, Write};
    let mut src = match std::fs::File::open(file) {
        Ok(f) => f,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            return Ok(DiskUpdateMetaOutcome::NotFound);
        },
        Err(e) => return Err(Error::Io { source: e }),
    };
    let old_len = src.metadata().map_err(|e| Error::Io { source: e })?.len();
    let mut header = [0u8; 8];
    match src.read_exact(&mut header) {
        Ok(()) => {},
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
            drop(src);
            if std::fs::remove_file(file).is_ok() {
                track_removed_atomic(has_budget, current_size, old_len);
            }
            return Ok(DiskUpdateMetaOutcome::Corrupt);
        },
        Err(e) => return Err(Error::Io { source: e }),
    }
    // `CacheObject` stores big-endian `u32` metadata lengths.
    let old_meta0_len =
        u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as u64;
    let old_meta1_len =
        u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as u64;
    let body_offset = 8u64
        .saturating_add(old_meta0_len)
        .saturating_add(old_meta1_len);
    if old_len < body_offset {
        drop(src);
        if std::fs::remove_file(file).is_ok() {
            track_removed_atomic(has_budget, current_size, old_len);
        }
        return Ok(DiskUpdateMetaOutcome::Corrupt);
    }
    src.seek(SeekFrom::Start(body_offset))
        .map_err(|e| Error::Io { source: e })?;

    let mut new_header = [0u8; 8];
    new_header[..4].copy_from_slice(&new_meta0_len.to_be_bytes());
    new_header[4..].copy_from_slice(&new_meta1_len.to_be_bytes());

    let tmp = temp_path_for(file);
    let write_result = (|| -> std::io::Result<u64> {
        let dst = create_temp_file(&tmp)?;
        let mut writer = BufWriter::new(dst);
        writer.write_all(&new_header)?;
        writer.write_all(&meta.0)?;
        writer.write_all(&meta.1)?;
        let copied = std::io::copy(&mut src, &mut writer)?;
        writer.flush()?;
        drop(writer);
        drop(src);
        std::fs::rename(&tmp, file)?;
        Ok(copied)
    })();
    let copied = match write_result {
        Ok(copied) => copied,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(Error::Io { source: e });
        },
    };
    let new_len = 8u64
        .saturating_add(new_meta0_len as u64)
        .saturating_add(new_meta1_len as u64)
        .saturating_add(copied);
    track_written_delta_atomic(has_budget, current_size, old_len, new_len);
    Ok(DiskUpdateMetaOutcome::Updated)
}

fn remove_corrupt_cache_file(
    file: &Path,
    key: &str,
    has_budget: bool,
    current_size: &AtomicU64,
    len: u64,
    reason: &str,
) {
    warn!(
        target: LOG_TARGET,
        key,
        reason,
        "remove corrupt cache file"
    );
    if std::fs::remove_file(file).is_ok() {
        track_removed_atomic(has_budget, current_size, len);
    }
}

enum ColdHitInspect {
    Miss,
    FallbackToGet,
    Disk {
        meta: BinaryMeta,
        body_offset: u64,
        body_len: usize,
    },
}

fn read_cache_header_sync(
    src: &mut std::fs::File,
    file_len: u64,
) -> std::io::Result<std::result::Result<(usize, usize, u64), &'static str>> {
    use std::io::{ErrorKind, Read};
    let mut header = [0u8; 8];
    match src.read_exact(&mut header) {
        Ok(()) => {},
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
            return Ok(Err("cache object is truncated, shorter than header"));
        },
        Err(e) => return Err(e),
    }
    // `CacheObject` stores big-endian `u32` metadata lengths.
    let meta0_len =
        u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    let meta1_len =
        u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
    let body_offset = 8u64
        .saturating_add(meta0_len as u64)
        .saturating_add(meta1_len as u64);
    if file_len < body_offset {
        return Ok(Err("cache object is truncated before metadata end"));
    }
    let (Ok(meta0_len), Ok(meta1_len)) =
        (usize::try_from(meta0_len), usize::try_from(meta1_len))
    else {
        return Ok(Err("cache metadata size exceeds usize"));
    };
    Ok(Ok((meta0_len, meta1_len, body_offset)))
}

fn inspect_cache_file_sync(
    file: &Path,
    key: &str,
    has_budget: bool,
    current_size: &AtomicU64,
    has_hot: bool,
    hot_max_weight: u16,
    hot_cache_max: usize,
) -> std::io::Result<ColdHitInspect> {
    use std::io::{ErrorKind, Read};
    let mut src = match std::fs::File::open(file) {
        Ok(f) => f,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            return Ok(ColdHitInspect::Miss);
        },
        Err(e) => return Err(e),
    };
    let file_len = src.metadata()?.len();
    let (meta0_len, meta1_len, body_offset) =
        match read_cache_header_sync(&mut src, file_len)? {
            Ok(parsed) => parsed,
            Err(reason) => {
                drop(src);
                remove_corrupt_cache_file(
                    file,
                    key,
                    has_budget,
                    current_size,
                    file_len,
                    reason,
                );
                return Ok(ColdHitInspect::Miss);
            },
        };
    let body_len_u64 = file_len - body_offset;
    let Ok(body_len) = usize::try_from(body_len_u64) else {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "cached body length exceeds usize::MAX",
        ));
    };
    let fits_hot = has_hot
        && usize::try_from(file_len - 8).is_ok_and(|payload_len| {
            let weight = super::http_cache::payload_weight(payload_len);
            weight < hot_max_weight && (weight as usize) <= hot_cache_max
        });
    if fits_hot || body_len_u64 <= super::http_cache::HIT_CHUNK_SIZE as u64 {
        return Ok(ColdHitInspect::FallbackToGet);
    }

    let mut meta0 = vec![0u8; meta0_len];
    let mut meta1 = vec![0u8; meta1_len];
    match src
        .read_exact(&mut meta0)
        .and_then(|()| src.read_exact(&mut meta1))
    {
        Ok(()) => Ok(ColdHitInspect::Disk {
            meta: (Bytes::from(meta0), Bytes::from(meta1)),
            body_offset,
            body_len,
        }),
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
            drop(src);
            remove_corrupt_cache_file(
                file,
                key,
                has_budget,
                current_size,
                file_len,
                "cache object truncated while reading metadata",
            );
            Ok(ColdHitInspect::Miss)
        },
        Err(e) => Err(e),
    }
}

fn read_cache_file_sync(
    file: &Path,
    key: &str,
    has_budget: bool,
    current_size: &AtomicU64,
) -> std::io::Result<Option<CacheObject>> {
    match std::fs::read(file) {
        Ok(buf) => {
            let len = buf.len() as u64;
            match CacheObject::try_from(Bytes::from(buf)) {
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
                    if std::fs::remove_file(file).is_ok() {
                        track_removed_atomic(has_budget, current_size, len);
                    }
                    Ok(None)
                },
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

struct ClearFilesResult {
    success: i32,
    fail: i32,
    removed_bytes: u64,
    hot_keys: Vec<String>,
}

fn clear_files_sync(
    dir: &Path,
    access_before: SystemTime,
    pending_touches: &Mutex<Vec<PathBuf>>,
) -> ClearFilesResult {
    flush_pending_touches_sync(pending_touches);
    let mut success = 0;
    let mut fail = 0;
    let mut removed_bytes = 0u64;
    let mut hot_keys = Vec::new();
    for file in walk_cache_files(dir, false)
        .into_iter()
        .filter(|f| f.accessed <= access_before)
    {
        let removed = match std::fs::remove_file(&file.path) {
            Ok(()) => {
                removed_bytes = removed_bytes.saturating_add(file.len);
                debug!(
                    target: LOG_TARGET,
                    file = %file.path.display(),
                    "remove cache file success"
                );
                success += 1;
                true
            },
            // Removed by a purge or an eviction in the meantime.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
            Err(e) => {
                fail += 1;
                error!(
                    target: LOG_TARGET,
                    error = %e,
                    file = %file.path.display(),
                    "remove cache file fail"
                );
                false
            },
        };
        // Evict only the swept entry from the hot layer; unlike
        // `purge_namespace`, `clear` must leave active hot entries intact.
        if removed
            && let Some(name) = file.path.file_name().and_then(|n| n.to_str())
            && is_cache_key(name)
        {
            hot_keys.push(name.to_string());
        }
    }
    ClearFilesResult {
        success,
        fail,
        removed_bytes,
        hot_keys,
    }
}

async fn wait_cold_read(
    rx: &mut watch::Receiver<ColdReadState>,
) -> Option<Result<Option<CacheObject>>> {
    loop {
        let state = rx.borrow_and_update().clone();
        match state {
            ColdReadState::Pending => {
                if rx.changed().await.is_err() {
                    return None;
                }
            },
            ColdReadState::Hit(obj) => return Some(Ok(Some(obj))),
            ColdReadState::Miss => return Some(Ok(None)),
            ColdReadState::IoError(kind, msg) => {
                return Some(Err(Error::Io {
                    source: std::io::Error::new(kind, msg),
                }));
            },
            ColdReadState::Cancelled => return None,
        }
    }
}

/// Sum of cache file sizes under `directory` (skips missing paths), stopping
/// once visited `WalkDir` entries exceed `max_entries`. Returns `(sum, complete)`.
fn measure_dir_size_bounded(
    directory: &str,
    max_entries: usize,
) -> (u64, bool) {
    let mut total = 0u64;
    let mut visited = 0usize;
    for item in WalkDir::new(directory) {
        visited += 1;
        if visited > max_entries {
            return (total, false);
        }
        let Ok(entry) = item else {
            continue;
        };
        if !is_cache_file(&entry, false) {
            continue;
        }
        if let Ok(meta) = entry.metadata() {
            total = total.saturating_add(meta.len());
        }
    }
    (total, true)
}

/// Sum of file sizes under `directory` (skips missing paths).
fn measure_dir_size(directory: &str) -> u64 {
    measure_dir_size_bounded(directory, usize::MAX).0
}

/// Partitions and sorts only the oldest prefix of `files` needed to free at
/// least `bytes_to_free` bytes, avoiding an O(N log N) full sort of the entire
/// directory when evicting a small fraction (~10%) of a large file cache.
fn order_oldest_for_eviction(files: &mut [CacheFile], bytes_to_free: u64) {
    if files.len() <= 256 || bytes_to_free == 0 {
        files.sort_unstable_by_key(|file| file.accessed);
        return;
    }
    let window = (files.len() / 8).max(256);
    let mut ordered = 0usize;
    let mut covered_bytes = 0u64;
    while ordered < files.len() && covered_bytes < bytes_to_free {
        let remaining = &mut files[ordered..];
        let take = window.min(remaining.len());
        if take < remaining.len() {
            remaining.select_nth_unstable_by_key(take - 1, |f| f.accessed);
        }
        let chunk = &mut remaining[..take];
        chunk.sort_unstable_by_key(|f| f.accessed);
        covered_bytes = covered_bytes
            .saturating_add(chunk.iter().map(|f| f.len).sum::<u64>());
        ordered += take;
    }
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
        Self::new_with_scan_limit_inner(dir, INITIAL_SCAN_ENTRY_LIMIT)
    }

    #[cfg(test)]
    pub(crate) fn new_with_scan_limit(
        dir: &str,
        scan_limit: usize,
    ) -> Result<Self> {
        Self::new_with_scan_limit_inner(dir, scan_limit)
    }

    fn new_with_scan_limit_inner(dir: &str, scan_limit: usize) -> Result<Self> {
        let params = FileCacheParams::try_from(dir)?;

        let path = Path::new(&params.directory);
        // directory not exist, create it
        if !path.exists() {
            std::fs::create_dir_all(path)
                .map_err(|e| Error::Io { source: e })?;
        }
        let max_size = params.max_size.map(|s| s.as_u64()).unwrap_or(0);
        // Bounded startup walk keeps daemon boot fast on large cache dirs;
        // if truncated, the full resync runs post-fork in the background.
        let (current_size, scan_complete) = if max_size > 0 {
            measure_dir_size_bounded(&params.directory, scan_limit)
        } else {
            (0, true)
        };
        let size_scan_pending =
            Arc::new(AtomicBool::new(max_size > 0 && !scan_complete));
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
            scan_complete,
            "new file cache"
        );
        let max_pages = crate::max_safe_memory_pages();
        let cache_max = if params.cache_max > max_pages {
            warn!(
                target: LOG_TARGET,
                requested_pages = params.cache_max,
                capped_pages = max_pages,
                "file cache hot-layer cache_max exceeds safe available memory, capping"
            );
            max_pages
        } else {
            params.cache_max
        };
        let cache = (cache_max > 0).then(|| {
            Arc::new(RwLock::new(MemoryCache::new(
                CacheMode::Normal,
                cache_max,
            )))
        });

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
            writing: Arc::new(AtomicU32::new(0)),
            writing_max: params.writing_max.unwrap_or(1_000),
            #[cfg(feature = "tracing")]
            write_time: CACHE_WRITING_TIME.clone(),
            cache,
            cache_max,
            cache_inactive: params
                .inactive
                .unwrap_or(Duration::from_secs(48 * 3600)),
            levels: params.levels,
            max_size,
            current_size: Arc::new(AtomicU64::new(current_size)),
            size_scan_pending,
            evicting: Arc::new(AtomicBool::new(false)),
            cold_reads: Arc::new(Mutex::new(AHashMap::new())),
            #[cfg(test)]
            cold_disk_reads: AtomicU64::new(0),
            touched: (0..TOUCH_SLOTS).map(|_| AtomicU64::new(0)).collect(),
            pending_touches: Arc::new(Mutex::new(Vec::new())),
            touch_flushing: Arc::new(AtomicBool::new(false)),
        })
    }

    fn maybe_schedule_full_size_scan(&self) {
        if !self.size_scan_pending.load(Ordering::Relaxed) {
            return;
        }
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        if self
            .size_scan_pending
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let dir = self.directory.clone();
        let current_size = self.current_size.clone();
        let evicting = self.evicting.clone();
        tokio::task::spawn_blocking(move || {
            if evicting
                .compare_exchange(
                    false,
                    true,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                return;
            }
            defer!(evicting.store(false, Ordering::Release));
            let real_size = measure_dir_size(&dir);
            current_size.store(real_size, Ordering::Relaxed);
            debug!(
                target: LOG_TARGET,
                directory = dir,
                real_size,
                "completed deferred full cache directory size scan"
            );
        });
    }

    /// Whether the on-disk budget is tracked at all.
    #[inline]
    fn has_budget(&self) -> bool {
        self.max_size > 0
    }

    /// Accounts `len` bytes leaving the disk.
    fn track_removed(&self, len: u64) {
        track_removed_atomic(self.has_budget(), &self.current_size, len);
    }

    /// Drops any in-flight cold-read slot for `file` so subsequent cold reads
    /// observe mutations and an in-flight reader skips `put_hot`.
    fn invalidate_cold_read(&self, file: &Path) {
        self.cold_reads.lock().remove(file);
    }

    fn acquire_cold_read_role(&self, file: &Path) -> ColdReadRole<'_> {
        let mut map = self.cold_reads.lock();
        if let Some(slot) = map.get(file) {
            return ColdReadRole::Follower(slot.tx.subscribe());
        }
        let (tx, _rx) = watch::channel(ColdReadState::Pending);
        let slot = Arc::new(ColdReadSlot { tx });
        map.insert(file.to_path_buf(), slot.clone());
        ColdReadRole::Leader(ColdReadGuard {
            cold_reads: &self.cold_reads,
            file: file.to_path_buf(),
            slot,
            published: false,
        })
    }

    async fn run_cold_read_leader(
        &self,
        key: &str,
        ns: &str,
        file: &Path,
        guard: ColdReadGuard<'_>,
    ) -> Result<Option<CacheObject>> {
        // Re-check hot layer once after winning leadership in case a concurrent
        // `put` or finished reader populated TinyUFO right before we inserted.
        if let Some(obj) = self.get_hot(key) {
            self.touch(key, ns);
            guard.publish(ColdReadState::Hit(obj.clone()));
            return Ok(Some(obj));
        }

        #[cfg(feature = "tracing")]
        let start = SystemTime::now();

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
            guard.publish(ColdReadState::Miss);
            return Ok(None);
        }

        #[cfg(test)]
        self.cold_disk_reads.fetch_add(1, Ordering::Relaxed);

        let file_path = file.to_path_buf();
        let has_budget = self.has_budget();
        let current_size = self.current_size.clone();
        let key_owned = key.to_string();
        let read_outcome = tokio::task::spawn_blocking(move || {
            read_cache_file_sync(
                &file_path,
                &key_owned,
                has_budget,
                &current_size,
            )
        })
        .await
        .map_err(|e| Error::Invalid {
            message: format!("file cache read task failed: {e}"),
        })?;
        #[cfg(feature = "tracing")]
        self.read_time.observe(elapsed_second(start));

        let obj = match read_outcome {
            Ok(obj) => obj,
            Err(e) => {
                guard.publish(ColdReadState::IoError(e.kind(), e.to_string()));
                return Err(Error::Io { source: e });
            },
        };

        if let Some(obj) = &obj {
            if guard.is_current() {
                self.put_hot(key, obj);
            }
            self.touch(key, ns);
            guard.publish(ColdReadState::Hit(obj.clone()));
        } else {
            guard.publish(ColdReadState::Miss);
        }

        debug!(
            target: LOG_TARGET,
            key,
            namespace = ns,
            "get cache from file"
        );
        Ok(obj)
    }

    fn apply_hot_meta(
        &self,
        key: &str,
        mut obj: CacheObject,
        meta: BinaryMeta,
    ) -> bool {
        obj.meta = meta;
        let weight = obj.get_weight();
        if weight >= self.cache_file_max_weight
            || weight as usize > self.cache_max
        {
            self.remove_hot(key);
            return false;
        }
        self.put_hot(key, &obj);
        true
    }

    /// Marks the file of `key` as read now, when that has not been done
    /// within the last minute.
    ///
    /// The sweep of inactive files and the eviction for `max_size` go by
    /// the time a file was last read, and used to leave the keeping of it
    /// to the file system. That knows nothing of an object served from the
    /// hot layer: the more an object was asked for, the older its file
    /// looked, and it was the first to be evicted and gone after
    /// `inactive` however often it was served. On a file system mounted
    /// `noatime` no read was ever recorded, and `inactive` counted from
    /// the write.
    fn touch(&self, key: &str, namespace: &str) {
        let hash = key.bytes().fold(0u64, |hash, byte| {
            hash.wrapping_mul(31).wrapping_add(byte as u64)
        });
        let slot = &self.touched[hash as usize % self.touched.len()];
        // A slot says who was marked last and when, in one word: the time
        // in the high half, the rest of the hash in the low one.
        let owner = (hash >> 16) as u32;
        let now = pingap_core::now_sec() as u32;
        let last = slot.load(Ordering::Relaxed);
        let (marked_at, marked) = ((last >> 32) as u32, last as u32);
        // Once a minute for the object that holds the slot. Another one
        // takes it over after a second: a slot shared by an object that
        // is asked for all the time and one that is asked for now and
        // then goes to the second whenever it comes, where one mark a
        // minute for the slot went to the first every time.
        let wait = if marked == owner {
            TOUCH_INTERVAL
        } else {
            TOUCH_TAKEOVER
        };
        let next = (now as u64) << 32 | owner as u64;
        if now.saturating_sub(marked_at) < wait
            || slot
                .compare_exchange(
                    last,
                    next,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_err()
        {
            return;
        }
        let file = self.get_file_path(key, namespace);
        self.schedule_touch_flush(file);
    }

    fn schedule_touch_flush(&self, file: PathBuf) {
        self.pending_touches.lock().push(file);
        if self
            .touch_flushing
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(drain_pending_touches(
                self.pending_touches.clone(),
                self.touch_flushing.clone(),
            ));
        } else {
            loop {
                flush_pending_touches_sync(&self.pending_touches);
                if !rearm_touch_drainer(
                    &self.pending_touches,
                    &self.touch_flushing,
                ) {
                    break;
                }
            }
        }
    }

    #[inline]
    fn get_file_path(&self, key: &str, namespace: &str) -> PathBuf {
        cache_file_path(
            Path::new(&self.directory),
            &self.levels,
            key,
            namespace,
        )
    }

    /// Runs `f` on the hot layer, when there is one. The lock is only ever
    /// held for the one call, and a writer that panicked leaves the cache
    /// as usable as before.
    fn with_hot<T>(&self, f: impl FnOnce(&MemoryCache) -> T) -> Option<T> {
        let cache = self.cache.as_ref()?;
        let cache = cache.read();
        Some(f(&cache))
    }

    fn get_hot(&self, key: &str) -> Option<CacheObject> {
        self.with_hot(|cache| cache.get(key)).flatten()
    }

    fn remove_hot(&self, key: &str) {
        self.with_hot(|cache| cache.remove(key));
    }

    /// Empties the hot layer by putting a new one in its place.
    fn reset_hot(&self) {
        if let Some(cache) = &self.cache {
            *cache.write() =
                MemoryCache::new(CacheMode::Normal, self.cache_max);
        }
    }

    /// Puts an object read from or written to disk into the hot layer,
    /// unless it is too large for it.
    fn put_hot(&self, key: &str, obj: &CacheObject) {
        let weight = obj.get_weight();
        if weight >= self.cache_file_max_weight {
            return;
        }
        debug!(target: LOG_TARGET, key, weight, "put cache to tinyufo");
        self.with_hot(|cache| cache.put(key, obj.clone(), weight));
    }
}

/// Returns the elapsed time in seconds (as f64) since the given SystemTime
#[cfg(feature = "tracing")]
#[inline]
fn elapsed_second(time: SystemTime) -> f64 {
    time.elapsed().unwrap_or_default().as_millis() as f64 / 1000.0
}

struct WritingCounterGuard<'a> {
    writing: &'a AtomicU32,
    active: bool,
}

impl<'a> WritingCounterGuard<'a> {
    fn acquire(writing: &'a AtomicU32, max: u32) -> Option<Self> {
        let prev = writing.fetch_add(1, Ordering::Relaxed);
        if max > 0 && prev >= max {
            writing.fetch_sub(1, Ordering::Relaxed);
            return None;
        }
        Some(Self {
            writing,
            active: true,
        })
    }

    fn disarm(&mut self) {
        self.active = false;
    }
}

impl Drop for WritingCounterGuard<'_> {
    fn drop(&mut self) {
        if self.active {
            self.writing.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

struct StreamingInitParams {
    dir: PathBuf,
    file: PathBuf,
    meta: BinaryMeta,
    meta0_len: u32,
    meta1_len: u32,
    header_len: u64,
    content_length: Option<u64>,
    max_size: u64,
    current_size: Arc<AtomicU64>,
    evicting: Arc<AtomicBool>,
    pending_touches: Arc<Mutex<Vec<PathBuf>>>,
    cancelled: Arc<AtomicBool>,
}

fn init_streaming_file_sync(
    params: StreamingInitParams,
) -> Result<Option<(PathBuf, std::fs::File)>> {
    if params.max_size > 0 {
        let expected_len =
            params.content_length.map_or(params.header_len, |cl| {
                params.header_len.saturating_add(cl)
            });
        if expected_len > params.max_size {
            return Ok(None);
        }
        if params.content_length.is_some() {
            let old_len = std::fs::metadata(&params.file)
                .map(|m| m.len())
                .unwrap_or(0);
            let need = expected_len.saturating_sub(old_len);
            let (allowed, _) = evict_disk_space_sync(
                &params.dir,
                params.max_size,
                need,
                &params.current_size,
                &params.evicting,
                &params.pending_touches,
            );
            if !allowed {
                return Ok(None);
            }
        }
    }
    let tmp = temp_path_for(&params.file);
    let write_result = (|| -> std::io::Result<std::fs::File> {
        let mut dst = create_temp_file(&tmp)?;
        write_cache_header_and_meta(
            &mut dst,
            &params.meta,
            params.meta0_len,
            params.meta1_len,
        )?;
        Ok(dst)
    })();
    match write_result {
        Ok(dst) => {
            if params.cancelled.load(Ordering::Acquire) {
                drop(dst);
                let _ = std::fs::remove_file(&tmp);
                return Ok(None);
            }
            Ok(Some((tmp, dst)))
        },
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(Error::Io { source: e })
        },
    }
}

fn write_chunks_sync(
    mut file: std::fs::File,
    first: Option<Bytes>,
    second: Option<Bytes>,
) -> std::io::Result<std::fs::File> {
    use std::io::Write;
    if let Some(chunk) = first {
        file.write_all(&chunk)?;
    }
    if let Some(chunk) = second {
        file.write_all(&chunk)?;
    }
    Ok(file)
}

struct StreamingFinishParams {
    dir: PathBuf,
    file: PathBuf,
    tmp_path: PathBuf,
    tmp_file: std::fs::File,
    tail: Bytes,
    new_len: u64,
    max_size: u64,
    current_size: Arc<AtomicU64>,
    evicting: Arc<AtomicBool>,
    pending_touches: Arc<Mutex<Vec<PathBuf>>>,
}

fn finish_streaming_file_sync(params: StreamingFinishParams) -> Result<bool> {
    use std::io::Write;
    let StreamingFinishParams {
        dir,
        file,
        tmp_path,
        mut tmp_file,
        tail,
        new_len,
        max_size,
        current_size,
        evicting,
        pending_touches,
    } = params;
    let finish_result = (|| -> std::io::Result<bool> {
        if !tail.is_empty() {
            tmp_file.write_all(&tail)?;
        }
        tmp_file.flush()?;
        drop(tmp_file);

        let has_budget = max_size > 0;
        if has_budget && new_len > max_size {
            let _ = std::fs::remove_file(&tmp_path);
            return Ok(false);
        }
        let mut old_len = if has_budget {
            std::fs::metadata(&file).map(|m| m.len()).unwrap_or(0)
        } else {
            0
        };
        if has_budget {
            let need = new_len.saturating_sub(old_len);
            let (allowed, evicted_any) = evict_disk_space_sync(
                &dir,
                max_size,
                need,
                &current_size,
                &evicting,
                &pending_touches,
            );
            if !allowed {
                let _ = std::fs::remove_file(&tmp_path);
                return Ok(false);
            }
            if evicted_any {
                old_len =
                    std::fs::metadata(&file).map(|m| m.len()).unwrap_or(0);
            }
        }
        std::fs::rename(&tmp_path, &file)?;
        track_written_delta_atomic(has_budget, &current_size, old_len, new_len);
        Ok(true)
    })();
    match finish_result {
        Ok(written) => Ok(written),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_path);
            Err(Error::Io { source: e })
        },
    }
}

struct FileStreamingMissWriter {
    dir: PathBuf,
    file: PathBuf,
    key: String,
    tmp_path: Option<PathBuf>,
    tmp_file: Option<std::fs::File>,
    stage: BytesMut,
    header_len: u64,
    bytes_received: u64,
    max_size: u64,
    current_size: Arc<AtomicU64>,
    evicting: Arc<AtomicBool>,
    pending_touches: Arc<Mutex<Vec<PathBuf>>>,
    cold_reads: Arc<Mutex<AHashMap<PathBuf, Arc<ColdReadSlot>>>>,
    hot_cache: Option<Arc<RwLock<MemoryCache>>>,
    writing: Arc<AtomicU32>,
    holding_writing: bool,
    aborted: bool,
    finished: bool,
    #[cfg(feature = "tracing")]
    write_time: Box<Histogram>,
    #[cfg(feature = "tracing")]
    start: SystemTime,
}

impl FileStreamingMissWriter {
    fn skipped(cache: &FileCache) -> Self {
        Self {
            dir: PathBuf::new(),
            file: PathBuf::new(),
            key: String::new(),
            tmp_path: None,
            tmp_file: None,
            stage: BytesMut::new(),
            header_len: 0,
            bytes_received: 0,
            max_size: 0,
            current_size: cache.current_size.clone(),
            evicting: cache.evicting.clone(),
            pending_touches: cache.pending_touches.clone(),
            cold_reads: cache.cold_reads.clone(),
            hot_cache: None,
            writing: cache.writing.clone(),
            holding_writing: false,
            aborted: true,
            finished: true,
            #[cfg(feature = "tracing")]
            write_time: cache.write_time.clone(),
            #[cfg(feature = "tracing")]
            start: SystemTime::now(),
        }
    }

    fn release_writing(&mut self) {
        if self.holding_writing {
            self.holding_writing = false;
            self.writing.fetch_sub(1, Ordering::Relaxed);
        }
    }

    async fn abort_and_cleanup(&mut self) {
        self.aborted = true;
        self.finished = true;
        self.stage.clear();
        self.release_writing();
        let file = self.tmp_file.take();
        let tmp_path = self.tmp_path.take();
        if file.is_some() || tmp_path.is_some() {
            let _ = tokio::task::spawn_blocking(move || {
                drop(file);
                if let Some(path) = tmp_path {
                    let _ = std::fs::remove_file(&path);
                }
            })
            .await;
        }
    }

    async fn flush_chunks(
        &mut self,
        first: Option<Bytes>,
        second: Option<Bytes>,
    ) -> Result<()> {
        let Some(file) = self.tmp_file.take() else {
            return Ok(());
        };
        let res = tokio::task::spawn_blocking(move || {
            write_chunks_sync(file, first, second)
        })
        .await;
        match res {
            Ok(Ok(file)) => {
                self.tmp_file = Some(file);
                Ok(())
            },
            Ok(Err(e)) => {
                self.abort_and_cleanup().await;
                Err(Error::Io { source: e })
            },
            Err(e) => {
                self.abort_and_cleanup().await;
                Err(Error::Invalid {
                    message: format!("file cache streaming write failed: {e}"),
                })
            },
        }
    }
}

impl Drop for FileStreamingMissWriter {
    fn drop(&mut self) {
        self.release_writing();
        if !self.finished
            && let Some(tmp_path) = self.tmp_path.take()
        {
            drop(self.tmp_file.take());
            let _ = std::fs::remove_file(&tmp_path);
        }
    }
}

#[async_trait]
impl StreamingMissWriter for FileStreamingMissWriter {
    async fn write_chunk(&mut self, data: Bytes) -> Result<()> {
        if self.aborted || data.is_empty() {
            return Ok(());
        }
        self.bytes_received =
            self.bytes_received.saturating_add(data.len() as u64);
        let new_total = self.header_len.saturating_add(self.bytes_received);
        if self.max_size > 0 && new_total > self.max_size {
            debug!(
                target: LOG_TARGET,
                key = self.key,
                size = new_total,
                max_size = self.max_size,
                "streaming cache object exceeds max_size, aborting disk write"
            );
            self.abort_and_cleanup().await;
            return Ok(());
        }
        if self.stage.len().saturating_add(data.len()) < STREAMING_STAGE_SIZE {
            self.stage.extend_from_slice(&data);
            return Ok(());
        }
        let staged =
            (!self.stage.is_empty()).then(|| self.stage.split().freeze());
        self.flush_chunks(staged, Some(data)).await
    }

    async fn finish(mut self: Box<Self>) -> Result<()> {
        if self.aborted {
            self.finished = true;
            self.release_writing();
            return Ok(());
        }
        let tail = self.stage.split().freeze();
        let (Some(tmp_path), Some(tmp_file)) =
            (self.tmp_path.clone(), self.tmp_file.take())
        else {
            self.finished = true;
            self.release_writing();
            return Ok(());
        };
        self.cold_reads.lock().remove(&self.file);
        let new_len = self.header_len.saturating_add(self.bytes_received);
        let params = StreamingFinishParams {
            dir: self.dir.clone(),
            file: self.file.clone(),
            tmp_path,
            tmp_file,
            tail,
            new_len,
            max_size: self.max_size,
            current_size: self.current_size.clone(),
            evicting: self.evicting.clone(),
            pending_touches: self.pending_touches.clone(),
        };
        let result = tokio::task::spawn_blocking(move || {
            finish_streaming_file_sync(params)
        })
        .await
        .map_err(|e| Error::Invalid {
            message: format!("file cache streaming finish failed: {e}"),
        });
        self.tmp_path = None;
        self.finished = true;
        self.release_writing();
        let written = result??;
        #[cfg(feature = "tracing")]
        self.write_time.observe(elapsed_second(self.start));
        self.cold_reads.lock().remove(&self.file);
        if written && let Some(hot) = &self.hot_cache {
            hot.read().remove(&self.key);
        }
        Ok(())
    }
}

fn cache_file_path(
    root: &Path,
    levels: &[u32],
    key: &str,
    namespace: &str,
) -> PathBuf {
    let mut path = root.to_path_buf();
    if !namespace.is_empty() {
        path.push(namespace);
    }
    if levels.is_empty() {
        path.push(key);
        return path;
    }
    let mut current_len = key.len().saturating_sub(1);
    for level in levels {
        let level = *level as usize;
        if current_len > level {
            path.push(&key[current_len - level..current_len]);
            current_len -= level;
        }
    }
    path.push(key);
    path
}

fn read_cache_meta_header_sync(
    file: &Path,
) -> Option<pingora::cache::CacheMeta> {
    use std::io::Read;
    let mut src = std::fs::File::open(file).ok()?;
    let file_len = src.metadata().ok()?.len();
    let (meta0_len, meta1_len, _) =
        match read_cache_header_sync(&mut src, file_len) {
            Ok(Ok(parsed)) => parsed,
            _ => return None,
        };
    let mut meta0 = vec![0u8; meta0_len];
    let mut meta1 = vec![0u8; meta1_len];
    src.read_exact(&mut meta0).ok()?;
    src.read_exact(&mut meta1).ok()?;
    pingora::cache::CacheMeta::deserialize(&meta0, &meta1).ok()
}

fn meta_matches_any_tag(
    meta: &pingora::cache::CacheMeta,
    wanted: &[String],
) -> bool {
    meta.headers()
        .get_all("cache-tag")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(|c: char| c == ',' || c.is_ascii_whitespace()))
        .filter(|t| !t.is_empty())
        .any(|tag| wanted.iter().any(|w| w == tag))
}

fn infer_file_namespace(
    root: &Path,
    levels: &[u32],
    file: &Path,
    key: &str,
    scope: Option<&str>,
) -> Option<String> {
    if let Some(ns) = scope {
        return (cache_file_path(root, levels, key, ns) == file)
            .then(|| ns.to_string());
    }
    let rel = file.strip_prefix(root).ok()?;
    let mut parts = Vec::with_capacity(levels.len() + 2);
    for comp in rel.components() {
        let std::path::Component::Normal(name) = comp else {
            return None;
        };
        parts.push(name.to_str()?);
    }
    if parts.len() == levels.len() + 1 {
        return (cache_file_path(root, levels, key, "") == file)
            .then(String::new);
    }
    if parts.len() == levels.len() + 2 {
        let ns = parts[0];
        return (cache_file_path(root, levels, key, ns) == file)
            .then(|| ns.to_string());
    }
    None
}

fn find_keys_by_tags_sync(
    root: &Path,
    levels: &[u32],
    namespace: Option<&str>,
    tags: &[String],
) -> Vec<(String, String)> {
    let walk_root = match namespace {
        Some(ns) if !ns.is_empty() => root.join(ns),
        _ => root.to_path_buf(),
    };
    if !walk_root.exists() {
        return Vec::new();
    }
    let walker = match namespace {
        Some("") => {
            let depth = levels.len() + 1;
            WalkDir::new(&walk_root).min_depth(depth).max_depth(depth)
        },
        _ => WalkDir::new(&walk_root),
    };
    let mut matches = Vec::new();
    for entry in walker.into_iter().filter_map(|item| item.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let Some(key) = entry.file_name().to_str() else {
            continue;
        };
        if !is_cache_key(key) {
            continue;
        }
        let Some(ns) =
            infer_file_namespace(root, levels, entry.path(), key, namespace)
        else {
            continue;
        };
        if let Some(meta) = read_cache_meta_header_sync(entry.path())
            && meta_matches_any_tag(&meta, tags)
        {
            matches.push((key.to_string(), ns));
        }
    }
    matches
}

#[async_trait]
impl HttpCacheStorage for FileCache {
    /// Retrieves a cache object by key and namespace.
    ///
    /// First checks the in-memory TinyUfo cache, then falls back to file system if not found,
    /// coalescing concurrent cold disk reads for the same path.
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
        self.maybe_schedule_full_size_scan();
        let ns = namespace_str(namespace);
        // Early return if found in cache
        if let Some(obj) = self.get_hot(key) {
            debug!(
                target: LOG_TARGET,
                key, namespace, "get cache from tinyufo"
            );
            self.touch(key, ns);
            return Ok(Some(obj));
        }

        let file = self.get_file_path(key, ns);
        loop {
            match self.acquire_cold_read_role(&file) {
                ColdReadRole::Follower(mut rx) => {
                    match wait_cold_read(&mut rx).await {
                        Some(Ok(Some(obj))) => {
                            self.touch(key, ns);
                            debug!(
                                target: LOG_TARGET,
                                key,
                                namespace = ns,
                                "get cache from coalesced cold read"
                            );
                            return Ok(Some(obj));
                        },
                        Some(Ok(None)) => return Ok(None),
                        Some(Err(e)) => return Err(e),
                        None => continue,
                    }
                },
                ColdReadRole::Leader(guard) => {
                    return self
                        .run_cold_read_leader(key, ns, &file, guard)
                        .await;
                },
            }
        }
    }

    async fn lookup_hit(
        &self,
        key: &str,
        namespace: &[u8],
    ) -> Result<Option<(BinaryMeta, HitBody)>> {
        self.maybe_schedule_full_size_scan();
        let ns = namespace_str(namespace);
        if let Some(obj) = self.get_hot(key) {
            debug!(
                target: LOG_TARGET,
                key, namespace, "get cache from tinyufo"
            );
            self.touch(key, ns);
            return Ok(Some((obj.meta, HitBody::Memory(obj.body))));
        }

        let file = self.get_file_path(key, ns);
        let inspect = {
            #[cfg(feature = "tracing")]
            let start = SystemTime::now();
            let count = self.reading.fetch_add(1, Ordering::Relaxed);
            defer!(self.reading.fetch_sub(1, Ordering::Relaxed););
            if self.reading_max > 0 && count >= self.reading_max {
                debug!(
                    target: LOG_TARGET,
                    key,
                    max = self.reading_max,
                    "file cache read over quota, treat as miss"
                );
                return Ok(None);
            }

            let file_path = file.clone();
            let has_budget = self.has_budget();
            let current_size = self.current_size.clone();
            let key_owned = key.to_string();
            let has_hot = self.cache.is_some();
            let hot_max_weight = self.cache_file_max_weight;
            let hot_cache_max = self.cache_max;
            let outcome = tokio::task::spawn_blocking(move || {
                inspect_cache_file_sync(
                    &file_path,
                    &key_owned,
                    has_budget,
                    &current_size,
                    has_hot,
                    hot_max_weight,
                    hot_cache_max,
                )
            })
            .await
            .map_err(|e| Error::Invalid {
                message: format!("file cache lookup_hit task failed: {e}"),
            })?
            .map_err(|e| Error::Io { source: e })?;
            #[cfg(feature = "tracing")]
            if !matches!(outcome, ColdHitInspect::FallbackToGet) {
                self.read_time.observe(elapsed_second(start));
            }
            outcome
        };

        match inspect {
            ColdHitInspect::Miss => Ok(None),
            ColdHitInspect::FallbackToGet => Ok(self
                .get(key, namespace)
                .await?
                .map(|obj| (obj.meta, HitBody::Memory(obj.body)))),
            ColdHitInspect::Disk {
                meta,
                body_offset,
                body_len,
            } => {
                #[cfg(test)]
                self.cold_disk_reads.fetch_add(1, Ordering::Relaxed);
                self.touch(key, ns);
                debug!(
                    target: LOG_TARGET,
                    key,
                    namespace = ns,
                    body_offset,
                    body_len,
                    "lookup disk cache hit"
                );
                Ok(Some((
                    meta,
                    HitBody::Disk {
                        path: file,
                        body_offset,
                        body_len,
                    },
                )))
            },
        }
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
        self.maybe_schedule_full_size_scan();
        let ns = namespace_str(namespace);
        self.put_hot(key, &data);
        #[cfg(feature = "tracing")]
        let start = SystemTime::now();
        let (meta0_len, meta1_len) = validate_meta_lengths(&data.meta)?;
        let new_len = (META_SIZE_LENGTH as u64)
            .saturating_add(meta0_len as u64)
            .saturating_add(meta1_len as u64)
            .saturating_add(data.body.len() as u64);
        let file = self.get_file_path(key, ns);
        self.invalidate_cold_read(&file);
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
        let dir = PathBuf::from(&self.directory);
        let max_size = self.max_size;
        let current_size = self.current_size.clone();
        let evicting = self.evicting.clone();
        let pending_touches = self.pending_touches.clone();
        let file_for_write = file.clone();
        let written = tokio::task::spawn_blocking(move || {
            put_file_sync(
                &dir,
                &file_for_write,
                &data,
                meta0_len,
                meta1_len,
                new_len,
                max_size,
                &current_size,
                &evicting,
                &pending_touches,
            )
        })
        .await
        .map_err(|e| Error::Invalid {
            message: format!("file cache put task failed: {e}"),
        })??;
        #[cfg(feature = "tracing")]
        self.write_time.observe(elapsed_second(start));
        self.invalidate_cold_read(&file);
        if !written {
            debug!(
                target: LOG_TARGET,
                key,
                size = new_len,
                max_size = self.max_size,
                "cache object is larger than max_size, skip disk put"
            );
            return Ok(());
        }
        debug!(
            target: LOG_TARGET,
            key,
            namespace = ns,
            "put cache to file"
        );
        Ok(())
    }

    fn max_hot_body_bytes(&self) -> Option<usize> {
        Some(if self.cache.is_some() {
            (self.cache_file_max_weight as usize).saturating_mul(PAGE_SIZE)
        } else {
            0
        })
    }

    async fn begin_streaming_put(
        &self,
        key: &str,
        namespace: &[u8],
        meta: BinaryMeta,
        content_length: Option<u64>,
    ) -> Result<Option<Box<dyn StreamingMissWriter>>> {
        self.maybe_schedule_full_size_scan();
        let (meta0_len, meta1_len) = validate_meta_lengths(&meta)?;
        let header_len = (META_SIZE_LENGTH as u64)
            .saturating_add(meta0_len as u64)
            .saturating_add(meta1_len as u64);

        let Some(mut writing_guard) =
            WritingCounterGuard::acquire(&self.writing, self.writing_max)
        else {
            debug!(
                target: LOG_TARGET,
                key,
                max = self.writing_max,
                "file cache streaming write over quota, skip disk put"
            );
            return Ok(Some(Box::new(FileStreamingMissWriter::skipped(self))));
        };

        let ns = namespace_str(namespace);
        let file = self.get_file_path(key, ns);
        self.invalidate_cold_read(&file);

        let cancelled = Arc::new(AtomicBool::new(false));
        let cancel_guard = scopeguard::guard(cancelled.clone(), |c| {
            c.store(true, Ordering::Release);
        });
        let init_params = StreamingInitParams {
            dir: PathBuf::from(&self.directory),
            file: file.clone(),
            meta,
            meta0_len,
            meta1_len,
            header_len,
            content_length,
            max_size: self.max_size,
            current_size: self.current_size.clone(),
            evicting: self.evicting.clone(),
            pending_touches: self.pending_touches.clone(),
            cancelled,
        };
        let init_outcome = tokio::task::spawn_blocking(move || {
            init_streaming_file_sync(init_params)
        })
        .await
        .map_err(|e| Error::Invalid {
            message: format!("file cache streaming init failed: {e}"),
        })??;
        let _ = scopeguard::ScopeGuard::into_inner(cancel_guard);

        let Some((tmp_path, tmp_file)) = init_outcome else {
            return Ok(Some(Box::new(FileStreamingMissWriter::skipped(self))));
        };
        writing_guard.disarm();
        Ok(Some(Box::new(FileStreamingMissWriter {
            dir: PathBuf::from(&self.directory),
            file,
            key: key.to_string(),
            tmp_path: Some(tmp_path),
            tmp_file: Some(tmp_file),
            stage: BytesMut::with_capacity(STREAMING_STAGE_SIZE),
            header_len,
            bytes_received: 0,
            max_size: self.max_size,
            current_size: self.current_size.clone(),
            evicting: self.evicting.clone(),
            pending_touches: self.pending_touches.clone(),
            cold_reads: self.cold_reads.clone(),
            hot_cache: self.cache.clone(),
            writing: self.writing.clone(),
            holding_writing: true,
            aborted: false,
            finished: false,
            #[cfg(feature = "tracing")]
            write_time: self.write_time.clone(),
            #[cfg(feature = "tracing")]
            start: SystemTime::now(),
        })))
    }

    /// Updates metadata of an existing entry in the hot layer and on disk
    /// without loading or allocating the body buffer.
    async fn update_meta(
        &self,
        key: &str,
        namespace: &[u8],
        meta: BinaryMeta,
    ) -> Result<bool> {
        let new_meta0_len =
            u32::try_from(meta.0.len()).map_err(|_| Error::Invalid {
                message: "meta0 exceeds u32::MAX".to_string(),
            })?;
        let new_meta1_len =
            u32::try_from(meta.1.len()).map_err(|_| Error::Invalid {
                message: "meta1 exceeds u32::MAX".to_string(),
            })?;
        let hot_obj = self.get_hot(key);
        let hot_meta = meta.clone();

        #[cfg(feature = "tracing")]
        let start = SystemTime::now();
        let file = self.get_file_path(key, namespace_str(namespace));
        let has_budget = self.has_budget();
        let current_size = self.current_size.clone();
        let file_for_update = file.clone();
        let _writing = self.writing.fetch_add(1, Ordering::Relaxed);
        defer!(self.writing.fetch_sub(1, Ordering::Relaxed););

        let outcome = tokio::task::spawn_blocking(move || {
            update_meta_file_sync(
                &file_for_update,
                &meta,
                new_meta0_len,
                new_meta1_len,
                has_budget,
                &current_size,
            )
        })
        .await
        .map_err(|e| Error::Invalid {
            message: format!("file cache update_meta task failed: {e}"),
        })??;
        #[cfg(feature = "tracing")]
        self.write_time.observe(elapsed_second(start));

        match outcome {
            DiskUpdateMetaOutcome::Updated => {
                self.invalidate_cold_read(&file);
                if let Some(obj) = hot_obj {
                    self.apply_hot_meta(key, obj, hot_meta);
                }
                Ok(true)
            },
            DiskUpdateMetaOutcome::NotFound => {
                if let Some(obj) = hot_obj {
                    Ok(self.apply_hot_meta(key, obj, hot_meta))
                } else {
                    Ok(false)
                }
            },
            DiskUpdateMetaOutcome::Corrupt => {
                self.invalidate_cold_read(&file);
                if hot_obj.is_some() {
                    self.remove_hot(key);
                }
                warn!(
                    target: LOG_TARGET,
                    key, "remove corrupt cache file during update_meta"
                );
                Ok(false)
            },
        }
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
        if self.cache.is_some() {
            debug!(
                target: LOG_TARGET,
                key, namespace, "remove cache from tinyufo"
            );
            self.remove_hot(key);
        }
        let file = self.get_file_path(key, namespace_str(namespace));
        self.invalidate_cold_read(&file);
        let has_budget = self.has_budget();
        let current_size = self.current_size.clone();
        let file_for_rm = file.clone();
        // Already gone (e.g. external cleanup) is the same as a cache miss
        // on get, not an operational error.
        let removed = tokio::task::spawn_blocking(move || {
            remove_tracked_sync(&file_for_rm, has_budget, &current_size)
        })
        .await
        .map_err(|e| Error::Invalid {
            message: format!("file cache remove task failed: {e}"),
        })?
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
        self.maybe_schedule_full_size_scan();
        let dt_utc = time::OffsetDateTime::from(access_before);
        let offset = time::UtcOffset::local_offset_at(dt_utc)
            .unwrap_or(time::UtcOffset::UTC);
        let dt = dt_utc.to_offset(offset);
        let datetime_local = dt
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| dt.to_string());

        let description = format!(
            "clear cache file, directory: {}, access before: {datetime_local}",
            self.directory
        );
        let dir = PathBuf::from(&self.directory);
        let pending_touches = self.pending_touches.clone();
        let cleared = tokio::task::spawn_blocking(move || {
            clear_files_sync(&dir, access_before, &pending_touches)
        })
        .await
        .map_err(|e| Error::Invalid {
            message: format!("file cache clear task failed: {e}"),
        })?;
        self.track_removed(cleared.removed_bytes);
        if !cleared.hot_keys.is_empty() {
            self.cold_reads.lock().clear();
            self.with_hot(|cache| {
                for name in &cleared.hot_keys {
                    cache.remove(name);
                }
            });
        }
        Ok(HttpCacheClearStats {
            success: cleared.success,
            fail: cleared.fail,
            description,
        })
    }
    fn inactive(&self) -> Option<Duration> {
        Some(self.cache_inactive)
    }

    /// Gives up the hot layer. The instance lives on, as whoever still
    /// holds it may be serving a request.
    fn retire(&self) {
        if let Some(cache) = &self.cache {
            *cache.write() = MemoryCache::new(CacheMode::Normal, 1);
        }
        self.pending_touches.lock().clear();
        self.size_scan_pending.store(false, Ordering::Relaxed);
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
        // In-flight temporaries still belong to their writer; the rename
        // that follows will land the object post-purge, which is the same
        // as a write that started after the purge.
        let dir_for_delete = dir.clone();
        let (success, fail, removed_bytes) =
            tokio::task::spawn_blocking(move || {
                let mut success = 0;
                let mut fail = 0;
                let mut removed_bytes = 0u64;
                for file in walk_cache_files(&dir_for_delete, true) {
                    match std::fs::remove_file(&file.path) {
                        Ok(()) => {
                            removed_bytes =
                                removed_bytes.saturating_add(file.len);
                            success += 1;
                        },
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        },
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
                (success, fail, removed_bytes)
            })
            .await
            .map_err(|e| Error::Invalid {
                message: format!("file cache purge task failed: {e}"),
            })?;
        self.track_removed(removed_bytes);
        self.cold_reads.lock().clear();
        // The memory copies go as well, all of them. Dropping the copy of
        // each file that was removed, as this used to, missed the objects
        // that are in memory only - a write that was skipped over quota or
        // for want of disk space still puts its object there - and those
        // went on being served after the purge. The hot layer cannot be
        // searched by namespace, so it is replaced: the other namespaces
        // read their objects back from disk.
        self.reset_hot();
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

    async fn find_keys_by_tags(
        &self,
        namespace: Option<&str>,
        tags: &[String],
    ) -> Result<Vec<(String, String)>> {
        if tags.is_empty() {
            return Ok(Vec::new());
        }
        if let Some(ns) = namespace
            && (ns.contains('/') || ns.contains('\\') || ns.contains(".."))
        {
            return Err(Error::Invalid {
                message: format!(
                    "find keys by tags requires a plain namespace, got {ns:?}"
                ),
            });
        }
        let root = PathBuf::from(&self.directory);
        let levels = self.levels.clone();
        let ns_owned = namespace.map(str::to_string);
        let tags_owned = tags.to_vec();
        tokio::task::spawn_blocking(move || {
            find_keys_by_tags_sync(
                &root,
                &levels,
                ns_owned.as_deref(),
                &tags_owned,
            )
        })
        .await
        .map_err(|e| Error::Invalid {
            message: format!("file cache tag scan task failed: {e}"),
        })
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

    /// A key of the shape `CacheKey::combined` gives, which is the only
    /// kind of file the directory walks take for the cache's own.
    fn key(label: &str) -> String {
        let hex: String = label.bytes().map(|b| format!("{b:02x}")).collect();
        format!("{hex:0<32}")
    }

    fn set_atime(path: impl AsRef<Path>, atime: SystemTime) {
        std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_accessed(atime))
            .unwrap();
    }

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
                .starts_with(home_dir().unwrap().to_str().unwrap())
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
        assert!(cache.get_hot(key).is_some());

        // --- Test fallback from file ---
        // Create a new cache instance to simulate a fresh start with no in-memory cache.
        let fresh_cache = FileCache::new(&cache_config).unwrap();

        // 4. GET from the new instance should be a hit from the file.
        let file_obj = fresh_cache.get(key, namespace).await.unwrap().unwrap();
        assert_eq!(obj, file_obj);

        // 5. After reading from the file, it should now be populated in the new instance's in-memory cache.
        assert!(fresh_cache.get_hot(key).is_some());

        // 6. Test REMOVE.
        fresh_cache.remove(key, namespace).await.unwrap();

        // Verify it's gone from both in-memory and file caches.
        assert!(fresh_cache.get_hot(key).is_none());
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
        let old_file_path = cache.get_file_path(&key("old"), "ns");
        std::fs::create_dir_all(old_file_path.parent().unwrap()).unwrap();
        File::create(&old_file_path).unwrap();
        let old_time = SystemTime::now() - Duration::from_secs(3600);
        set_atime(&old_file_path, old_time);

        // Create a new file with a recent access time.
        let new_file_path = cache.get_file_path(&key("new"), "ns");
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

    /// Regression: `clear` must evict swept entries from the TinyUFO hot
    /// layer without dropping active hot entries.
    #[tokio::test]
    async fn test_cache_clear_evicts_hot_layer() {
        let dir = tempdir().unwrap();
        let cache = FileCache::new(&format!(
            "{}?cache_max=100",
            dir.path().to_str().unwrap()
        ))
        .unwrap();

        let old_key = key("old");
        let fresh_key = key("fresh");
        let old_obj = CacheObject {
            meta: (Bytes::from_static(b"k"), Bytes::from_static(b"old")),
            body: Bytes::from_static(b"old body"),
        };
        let fresh_obj = CacheObject {
            meta: (Bytes::from_static(b"k"), Bytes::from_static(b"fresh")),
            body: Bytes::from_static(b"fresh body"),
        };

        cache.put(&old_key, b"ns", old_obj).await.unwrap();
        cache
            .put(&fresh_key, b"ns", fresh_obj.clone())
            .await
            .unwrap();
        assert_eq!(true, cache.get_hot(&old_key).is_some());
        assert_eq!(true, cache.get_hot(&fresh_key).is_some());

        let old_file_path = cache.get_file_path(&old_key, "ns");
        let fresh_file_path = cache.get_file_path(&fresh_key, "ns");
        set_atime(
            &old_file_path,
            SystemTime::now() - Duration::from_secs(3600),
        );

        let access_before = SystemTime::now() - Duration::from_secs(600);
        let stats = cache.clear(access_before).await.unwrap();
        assert_eq!(1, stats.success);
        assert_eq!(0, stats.fail);

        // Aged entry is gone from both disk and the TinyUFO hot layer.
        assert_eq!(false, old_file_path.exists());
        assert_eq!(true, cache.get_hot(&old_key).is_none());
        assert_eq!(true, cache.get(&old_key, b"ns").await.unwrap().is_none());

        // Fresh entry remains in both disk and the TinyUFO hot layer.
        assert_eq!(true, fresh_file_path.exists());
        assert_eq!(true, cache.get_hot(&fresh_key).is_some());
        assert_eq!(
            Some(fresh_obj),
            cache.get(&fresh_key, b"ns").await.unwrap()
        );
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
        assert_eq!(true, cache.get_hot(key).is_some());

        let result = cache.get(key, namespace).await.unwrap().unwrap();
        assert_eq!(obj, result);

        // empty tinyufo, get from file
        let cache = FileCache::new(&dir).unwrap();
        let result = cache.get(key, namespace).await.unwrap().unwrap();
        assert_eq!(obj, result);

        // check tinyufo cache
        // it will be exist after get from file
        assert_eq!(true, cache.get_hot(key).is_some());

        cache.remove(key, namespace).await.unwrap();
        // tinyufo cache will be removed after remove
        assert_eq!(false, cache.get_hot(key).is_some());
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
        cache
            .put(&key("key-a1"), b"ns-a", obj.clone())
            .await
            .unwrap();
        cache
            .put(&key("key-a2"), b"ns-a", obj.clone())
            .await
            .unwrap();
        cache
            .put(&key("key-b"), b"ns-b", obj.clone())
            .await
            .unwrap();

        let stats = cache.purge_namespace("ns-a").await.unwrap().unwrap();
        assert_eq!(2, stats.success);
        assert_eq!(0, stats.fail);

        // Gone from disk AND memory (a get would prefer tinyufo).
        assert_eq!(
            true,
            cache.get(&key("key-a1"), b"ns-a").await.unwrap().is_none()
        );
        assert_eq!(
            true,
            cache.get(&key("key-a2"), b"ns-a").await.unwrap().is_none()
        );
        // The other namespace is untouched.
        assert_eq!(
            obj,
            cache.get(&key("key-b"), b"ns-b").await.unwrap().unwrap()
        );
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
        cache.put(&key("a"), b"", obj(1)).await.unwrap();
        cache.put(&key("b"), b"", obj(2)).await.unwrap();
        assert_eq!(2068, cache.current_size.load(Ordering::Relaxed));
        // `a` is the one nobody touched for an hour.
        set_atime(
            cache.get_file_path(&key("a"), ""),
            SystemTime::now() - Duration::from_secs(3600),
        );

        cache.put(&key("c"), b"", obj(3)).await.unwrap();
        assert_eq!(true, cache.get(&key("a"), b"").await.unwrap().is_none());
        assert_eq!(obj(2), cache.get(&key("b"), b"").await.unwrap().unwrap());
        assert_eq!(obj(3), cache.get(&key("c"), b"").await.unwrap().unwrap());
        assert_eq!(2068, cache.current_size.load(Ordering::Relaxed));

        // Larger than the budget: not written, nothing evicted for it.
        let big = CacheObject {
            meta: (Bytes::from_static(b"k"), Bytes::from_static(b"v")),
            body: Bytes::from(vec![0; 4096]),
        };
        cache.put(&key("d"), b"", big).await.unwrap();
        assert_eq!(true, cache.get(&key("d"), b"").await.unwrap().is_none());
        assert_eq!(true, cache.get(&key("b"), b"").await.unwrap().is_some());
        assert_eq!(true, cache.get(&key("c"), b"").await.unwrap().is_some());
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
        assert_eq!(true, cache.get_hot("big").is_none());
        assert_eq!(big, cache.get("big", b"").await.unwrap().unwrap());
        assert_eq!(true, cache.get_hot("big").is_none());

        let small = CacheObject {
            meta: (Bytes::from_static(b"k"), Bytes::from_static(b"v")),
            body: Bytes::from_static(b"small"),
        };
        cache.put("small", b"", small.clone()).await.unwrap();
        assert_eq!(true, cache.get_hot("small").is_some());
    }

    /// Regression: an object that is in memory only - its disk write was
    /// skipped - has no file for a namespace purge to find, and went on
    /// being served after the purge.
    #[tokio::test]
    async fn test_purge_namespace_reaches_memory_only_objects() {
        let dir = tempdir().unwrap();
        let cache = FileCache::new(&format!(
            "{}?cache_max=100&writing_max=1",
            dir.path().to_str().unwrap()
        ))
        .unwrap();
        let obj = CacheObject {
            meta: (Bytes::from_static(b"k"), Bytes::from_static(b"v")),
            body: Bytes::from_static(b"body"),
        };
        cache
            .put(&key("on-disk"), b"ns", obj.clone())
            .await
            .unwrap();
        // Over the write quota: the object goes to memory and not to disk.
        cache.writing.store(1, Ordering::Relaxed);
        cache
            .put(&key("memory-only"), b"ns", obj.clone())
            .await
            .unwrap();
        cache.writing.store(0, Ordering::Relaxed);
        assert_eq!(
            false,
            cache.get_file_path(&key("memory-only"), "ns").exists()
        );
        assert_eq!(
            true,
            cache
                .get(&key("memory-only"), b"ns")
                .await
                .unwrap()
                .is_some()
        );

        let stats = cache.purge_namespace("ns").await.unwrap().unwrap();
        assert_eq!(1, stats.success);
        assert_eq!(
            true,
            cache.get(&key("on-disk"), b"ns").await.unwrap().is_none()
        );
        assert_eq!(
            true,
            cache
                .get(&key("memory-only"), b"ns")
                .await
                .unwrap()
                .is_none()
        );
        // The cache keeps working after the purge.
        cache.put(&key("again"), b"ns", obj.clone()).await.unwrap();
        assert_eq!(Some(obj), cache.get(&key("again"), b"ns").await.unwrap());
    }

    /// The disk usage counter is an estimate that nothing used to correct.
    /// When a write has to make room the directory is listed anyway, and
    /// the counter is set to what is there.
    #[tokio::test]
    async fn test_disk_usage_is_resynced_when_evicting() {
        let dir = tempdir().unwrap();
        let cache = FileCache::new(&format!(
            "{}?cache_max=0&max_size=64kb",
            dir.path().to_str().unwrap()
        ))
        .unwrap();
        let obj = CacheObject {
            meta: (Bytes::from_static(b"k"), Bytes::from_static(b"v")),
            body: Bytes::from(vec![0; 1024]),
        };
        cache.put(&key("a"), b"", obj.clone()).await.unwrap();
        let real = cache.current_size.load(Ordering::Relaxed);
        assert_eq!(true, real > 1024);

        // Drifted up to where the next write does not seem to fit, as
        // after files were removed behind its back.
        cache.current_size.store(63_500, Ordering::Relaxed);
        cache.put(&key("b"), b"", obj.clone()).await.unwrap();
        // Nothing had to be evicted, and the counter is the two files.
        assert_eq!(true, cache.get(&key("a"), b"").await.unwrap().is_some());
        assert_eq!(2 * real, cache.current_size.load(Ordering::Relaxed));
    }

    /// Regression: the sweeps took every regular file under the directory
    /// for a cached object, so a directory shared with other data lost
    /// whatever had not been read for `inactive`, and with `max_size` the
    /// least recently read file whatever its name.
    #[tokio::test]
    async fn test_sweeps_leave_foreign_files_alone() {
        let dir = tempdir().unwrap();
        let three_days_ago =
            SystemTime::now() - Duration::from_secs(3 * 24 * 3600);
        let age = |path: &Path| {
            set_atime(path, three_days_ago);
        };
        let notes = dir.path().join("notes.txt");
        std::fs::write(&notes, vec![0; 4096]).unwrap();
        age(&notes);
        // Not a key either: too short, and not the temporary of a key.
        let short = dir.path().join("abcdef");
        std::fs::write(&short, b"x").unwrap();
        age(&short);
        let other_tmp = dir.path().join("upload.tmp");
        std::fs::write(&other_tmp, b"x").unwrap();
        age(&other_tmp);
        std::fs::create_dir(dir.path().join("ns")).unwrap();
        let nested = dir.path().join("ns").join("data.db");
        std::fs::write(&nested, b"x").unwrap();
        age(&nested);

        // The budget starts from the cache's own files, which is none.
        let cache = FileCache::new(&format!(
            "{}?max_size=2200",
            dir.path().to_str().unwrap()
        ))
        .unwrap();
        assert_eq!(0, cache.current_size.load(Ordering::Relaxed));

        let obj = |fill: u8| CacheObject {
            meta: (Bytes::from_static(b"k"), Bytes::from_static(b"v")),
            body: Bytes::from(vec![fill; 1024]),
        };
        cache.put(&key("a"), b"", obj(1)).await.unwrap();
        cache.put(&key("b"), b"ns", obj(2)).await.unwrap();
        // A third object needs room: the oldest of the cache's files goes,
        // not the older file that is not the cache's.
        cache.put(&key("c"), b"", obj(3)).await.unwrap();
        assert_eq!(2068, cache.current_size.load(Ordering::Relaxed));

        // An abandoned temporary of the cache is the sweep's to remove.
        let abandoned = dir.path().join(format!("{}.4242.7.tmp", key("gone")));
        std::fs::write(&abandoned, b"half").unwrap();
        age(&abandoned);
        age(&cache.get_file_path(&key("c"), ""));

        let stats = cache
            .clear(SystemTime::now() - Duration::from_secs(48 * 3600))
            .await
            .unwrap();
        assert_eq!(2, stats.success);
        assert_eq!(0, stats.fail);
        assert_eq!(false, abandoned.exists());
        assert_eq!(false, cache.get_file_path(&key("c"), "").exists());

        cache.purge_namespace("ns").await.unwrap();

        for file in [&notes, &short, &other_tmp, &nested] {
            assert_eq!(true, file.exists(), "{} is gone", file.display());
        }
    }

    /// Regression: an object served from the hot layer was never read
    /// from its file, whose access time stayed where the write had left
    /// it. The objects asked for most were the first the eviction took
    /// and were swept after `inactive` like ones nobody wanted.
    #[tokio::test]
    async fn test_a_hit_in_the_hot_layer_keeps_the_file() {
        let dir = tempdir().unwrap();
        let cache = FileCache::new(&format!(
            "{}?cache_max=100",
            dir.path().to_str().unwrap()
        ))
        .unwrap();
        let obj = CacheObject {
            meta: (Bytes::from_static(b"k"), Bytes::from_static(b"v")),
            body: Bytes::from_static(b"body"),
        };
        let name = key("hot");
        cache.put(&name, b"", obj.clone()).await.unwrap();
        let file = cache.get_file_path(&name, "");
        let three_days_ago =
            SystemTime::now() - Duration::from_secs(3 * 24 * 3600);
        let age = || {
            set_atime(&file, three_days_ago);
        };
        let accessed = || std::fs::metadata(&file).unwrap().accessed().unwrap();
        age();

        // From memory, and the file is marked all the same.
        assert_eq!(true, cache.get_hot(&name).is_some());
        assert_eq!(Some(obj.clone()), cache.get(&name, b"").await.unwrap());
        for _ in 0..200 {
            if accessed() > three_days_ago + Duration::from_secs(3600) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            true,
            accessed() > three_days_ago + Duration::from_secs(3600),
            "the file was not marked as read"
        );
        let stats = cache
            .clear(SystemTime::now() - Duration::from_secs(48 * 3600))
            .await
            .unwrap();
        assert_eq!(0, stats.success);
        assert_eq!(true, file.exists());

        // Not on every hit: once a minute.
        age();
        cache.get(&name, b"").await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            true,
            accessed() < three_days_ago + Duration::from_secs(3600)
        );

        // An object that shares the slot with one that is asked for all
        // the time is not kept out of it for good.
        let slot_of = |key: &str| {
            key.bytes().fold(0u64, |hash, byte| {
                hash.wrapping_mul(31).wrapping_add(byte as u64)
            }) as usize
                % TOUCH_SLOTS
        };
        let neighbour = (0..)
            .map(|index| format!("{index:032x}"))
            .find(|key| key != &name && slot_of(key) == slot_of(&name))
            .unwrap();
        cache.put(&neighbour, b"", obj.clone()).await.unwrap();
        let neighbour_file = cache.get_file_path(&neighbour, "");
        set_atime(&neighbour_file, three_days_ago);
        // The slot is the first object's, marked a moment ago.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        cache.get(&neighbour, b"").await.unwrap();
        let marked = || {
            std::fs::metadata(&neighbour_file)
                .unwrap()
                .accessed()
                .unwrap()
                > three_days_ago + Duration::from_secs(3600)
        };
        for _ in 0..200 {
            if marked() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(true, marked(), "the neighbour was not marked as read");
    }

    /// Regression: an eviction freed what the one object needed and no
    /// more, so the cache was full again after it and every write that
    /// followed walked the whole directory to evict one file.
    #[tokio::test]
    async fn test_eviction_frees_room_for_the_writes_to_come() {
        let dir = tempdir().unwrap();
        let each = 1024 + 2 + 8;
        let cache = FileCache::new(&format!(
            "{}?max_size={}",
            dir.path().to_str().unwrap(),
            100 * each
        ))
        .unwrap();
        let obj = CacheObject {
            meta: (Bytes::from_static(b"k"), Bytes::from_static(b"v")),
            body: Bytes::from(vec![7u8; 1024]),
        };
        let name = |index: u32| format!("{index:032x}");
        let count = || {
            std::fs::read_dir(dir.path())
                .unwrap()
                .filter_map(|entry| entry.ok())
                .count()
        };
        // Full to the byte, the lower the index the longer ago it was read.
        for index in 0..100 {
            cache.put(&name(index), b"", obj.clone()).await.unwrap();
            set_atime(
                cache.get_file_path(&name(index), ""),
                SystemTime::now() - Duration::from_secs(3600 - index as u64),
            );
        }
        assert_eq!(100, count());

        // One more: a tenth of the budget goes, the ten read longest ago.
        cache.put(&name(100), b"", obj.clone()).await.unwrap();
        assert_eq!(91, count());
        assert_eq!(false, cache.get_file_path(&name(9), "").exists());
        assert_eq!(true, cache.get_file_path(&name(10), "").exists());

        // Which is room for the next nine without another eviction.
        for index in 101..110 {
            cache.put(&name(index), b"", obj.clone()).await.unwrap();
        }
        assert_eq!(100, count());
        assert_eq!(true, cache.get_file_path(&name(10), "").exists());
        assert_eq!(100 * each, cache.current_size.load(Ordering::Relaxed));
    }

    #[test]
    fn test_cache_file_names() {
        // What pingora gives as the key of an object.
        use pingora::cache::key::CacheHashKey;
        let combined = pingora::cache::CacheKey::new("ns", "/path").combined();
        assert_eq!(true, is_cache_key(&combined), "{combined}");
        assert_eq!(true, is_cache_key(&key("a")));
        for name in ["", "notes.txt", "abcdef", &format!("{}.bak", key("a"))] {
            assert_eq!(false, is_cache_key(name), "{name}");
        }
        // 32 characters, but not hex; hex, but not the way it is written
        // or as long as a key is.
        assert_eq!(false, is_cache_key("0123456789abcdef0123456789abcdeg"));
        assert_eq!(false, is_cache_key("0123456789ABCDEF0123456789ABCDEF"));
        assert_eq!(false, is_cache_key(&"0123456789abcdef".repeat(4)));

        assert_eq!(true, is_cache_tmp_file(&format!("{combined}.812.3.tmp")));
        for name in [
            "upload.tmp".to_string(),
            format!("{combined}.tmp"),
            format!("{combined}.812.tmp"),
            format!("{combined}.a.3.tmp"),
            format!("{combined}.812.3.tmp.bak"),
            "abcdef.812.3.tmp".to_string(),
        ] {
            assert_eq!(false, is_cache_tmp_file(&name), "{name}");
        }
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
            home_dir().unwrap().to_string_lossy().to_string(),
            resolve_path("~/")
        );

        assert_eq!("", resolve_path(""));

        let path = resolve_path("../pingap");
        assert_eq!(true, path.ends_with("/pingap"));
        assert_eq!(false, path.starts_with(".."));
    }

    #[test]
    fn test_order_oldest_for_eviction() {
        let base = SystemTime::UNIX_EPOCH;
        let mut files: Vec<CacheFile> = (0..1000u64)
            .rev()
            .map(|i| CacheFile {
                len: 100,
                accessed: base + Duration::from_secs(i),
                path: PathBuf::from(format!("f-{i}")),
            })
            .collect();

        // Freeing 10% (10,000 of 100,000 bytes) needs the oldest 100 files in
        // exact ascending access-time order without sorting all 1000 entries.
        order_oldest_for_eviction(&mut files, 10_000);
        for (idx, item) in files.iter().take(100).enumerate() {
            assert_eq!(base + Duration::from_secs(idx as u64), item.accessed);
        }
    }

    #[tokio::test]
    async fn test_update_meta_cold_disk_only() {
        let dir = tempdir().unwrap();
        let cache = FileCache::new(&format!(
            "{}?cache_max=0&max_size=1mb",
            dir.path().to_str().unwrap()
        ))
        .unwrap();

        let body: Vec<u8> =
            (0..(64 * 1024 + 123)).map(|i| (i % 251) as u8).collect();
        let obj = CacheObject {
            meta: (
                Bytes::from_static(b"meta0-initial"),
                Bytes::from_static(b"meta1-initial"),
            ),
            body: Bytes::from(body.clone()),
        };
        let k = key("cold-meta");
        assert_eq!(
            false,
            cache
                .update_meta(
                    &k,
                    b"ns",
                    (Bytes::from_static(b"a"), Bytes::from_static(b"b"))
                )
                .await
                .unwrap()
        );

        cache.put(&k, b"ns", obj).await.unwrap();
        let initial_file_len = (8 + 13 + 13 + body.len()) as u64;
        assert_eq!(
            initial_file_len,
            cache.current_size.load(Ordering::Relaxed)
        );

        // Grow metadata.
        let bigger_meta =
            (Bytes::from(vec![b'x'; 256]), Bytes::from(vec![b'y'; 128]));
        assert_eq!(
            true,
            cache
                .update_meta(&k, b"ns", bigger_meta.clone())
                .await
                .unwrap()
        );
        let grown_file_len = (8 + 256 + 128 + body.len()) as u64;
        assert_eq!(grown_file_len, cache.current_size.load(Ordering::Relaxed));

        // Verify big-endian header bytes directly on disk.
        let raw = std::fs::read(cache.get_file_path(&k, "ns")).unwrap();
        assert_eq!(256u32, u32::from_be_bytes(raw[0..4].try_into().unwrap()));
        assert_eq!(128u32, u32::from_be_bytes(raw[4..8].try_into().unwrap()));

        let loaded = cache.get(&k, b"ns").await.unwrap().unwrap();
        assert_eq!(bigger_meta, loaded.meta);
        assert_eq!(body.as_slice(), loaded.body.as_ref());

        // Shrink metadata (negative signed delta).
        let smaller_meta =
            (Bytes::from_static(b"m0"), Bytes::from_static(b"m1"));
        assert_eq!(
            true,
            cache
                .update_meta(&k, b"ns", smaller_meta.clone())
                .await
                .unwrap()
        );
        let shrunk_file_len = (8 + 2 + 2 + body.len()) as u64;
        assert_eq!(shrunk_file_len, cache.current_size.load(Ordering::Relaxed));
        let loaded = cache.get(&k, b"ns").await.unwrap().unwrap();
        assert_eq!(smaller_meta, loaded.meta);
        assert_eq!(body.as_slice(), loaded.body.as_ref());

        // Empty-body entry also preserves 0-byte body cleanly.
        let empty_key = key("cold-empty");
        cache
            .put(
                &empty_key,
                b"ns",
                CacheObject {
                    meta: (Bytes::from_static(b"a"), Bytes::from_static(b"b")),
                    body: Bytes::new(),
                },
            )
            .await
            .unwrap();
        let new_empty_meta =
            (Bytes::from_static(b"abcd"), Bytes::from_static(b"ef"));
        assert_eq!(
            true,
            cache
                .update_meta(&empty_key, b"ns", new_empty_meta.clone())
                .await
                .unwrap()
        );
        let loaded_empty = cache.get(&empty_key, b"ns").await.unwrap().unwrap();
        assert_eq!(new_empty_meta, loaded_empty.meta);
        assert_eq!(true, loaded_empty.body.is_empty());
    }

    #[tokio::test]
    async fn test_update_meta_hot_layer_and_disk() {
        let dir = tempdir().unwrap();
        let cfg = format!(
            "{}?cache_max=100&max_size=1mb",
            dir.path().to_str().unwrap()
        );
        let cache = FileCache::new(&cfg).unwrap();
        let k = key("hot-and-disk");
        let obj = CacheObject {
            meta: (Bytes::from_static(b"old0"), Bytes::from_static(b"old1")),
            body: Bytes::from_static(b"hot-and-disk-body"),
        };
        cache.put(&k, b"ns", obj).await.unwrap();
        assert!(cache.get_hot(&k).is_some());

        let new_meta = (
            Bytes::from_static(b"new-meta-0"),
            Bytes::from_static(b"new-meta-1-longer"),
        );
        assert_eq!(
            true,
            cache
                .update_meta(&k, b"ns", new_meta.clone())
                .await
                .unwrap()
        );

        let hot = cache.get_hot(&k).unwrap();
        assert_eq!(new_meta, hot.meta);
        assert_eq!(b"hot-and-disk-body", hot.body.as_ref());

        let expected_len =
            (8 + new_meta.0.len() + new_meta.1.len() + 17) as u64;
        assert_eq!(expected_len, cache.current_size.load(Ordering::Relaxed));

        // Fresh FileCache with empty hot layer observes updated metadata from disk.
        let cold = FileCache::new(&cfg).unwrap();
        let disk = cold.get(&k, b"ns").await.unwrap().unwrap();
        assert_eq!(new_meta, disk.meta);
        assert_eq!(b"hot-and-disk-body", disk.body.as_ref());
    }

    #[tokio::test]
    async fn test_update_meta_memory_only() {
        let dir = tempdir().unwrap();
        let cache = FileCache::new(&format!(
            "{}?cache_max=100&writing_max=1",
            dir.path().to_str().unwrap()
        ))
        .unwrap();
        let k = key("mem-only");
        let obj = CacheObject {
            meta: (Bytes::from_static(b"m0"), Bytes::from_static(b"m1")),
            body: Bytes::from_static(b"memory-only-body"),
        };
        cache.writing.store(1, Ordering::Relaxed);
        cache.put(&k, b"ns", obj).await.unwrap();
        cache.writing.store(0, Ordering::Relaxed);

        assert_eq!(false, cache.get_file_path(&k, "ns").exists());
        let new_meta =
            (Bytes::from_static(b"fresh0"), Bytes::from_static(b"fresh1"));
        assert_eq!(
            true,
            cache
                .update_meta(&k, b"ns", new_meta.clone())
                .await
                .unwrap()
        );
        assert_eq!(false, cache.get_file_path(&k, "ns").exists());

        let loaded = cache.get(&k, b"ns").await.unwrap().unwrap();
        assert_eq!(new_meta, loaded.meta);
        assert_eq!(b"memory-only-body", loaded.body.as_ref());
    }

    #[tokio::test]
    async fn test_update_meta_corrupt_file_removed() {
        let dir = tempdir().unwrap();
        let cfg = format!(
            "{}?cache_max=0&max_size=1mb",
            dir.path().to_str().unwrap()
        );
        let cache = FileCache::new(&cfg).unwrap();

        let k_short = key("corrupt-short");
        let k_trunc = key("corrupt-trunc");
        let obj = CacheObject {
            meta: (
                Bytes::from_static(b"header0"),
                Bytes::from_static(b"header1"),
            ),
            body: Bytes::from_static(b"body-bytes"),
        };
        cache.put(&k_short, b"ns", obj.clone()).await.unwrap();
        cache.put(&k_trunc, b"ns", obj).await.unwrap();

        let p_short = cache.get_file_path(&k_short, "ns");
        let p_trunc = cache.get_file_path(&k_trunc, "ns");
        // Overwrite with < 8 bytes and with header claiming more bytes than present.
        let full = std::fs::read(&p_trunc).unwrap();
        std::fs::write(&p_short, &full[..4]).unwrap();
        std::fs::write(&p_trunc, &full[..10]).unwrap();

        // Reload so `current_size` matches the corrupt files on disk (14 bytes).
        let cache = FileCache::new(&cfg).unwrap();
        assert_eq!(14, cache.current_size.load(Ordering::Relaxed));

        let new_meta = (Bytes::from_static(b"n0"), Bytes::from_static(b"n1"));
        assert_eq!(
            false,
            cache
                .update_meta(&k_short, b"ns", new_meta.clone())
                .await
                .unwrap()
        );
        assert_eq!(false, p_short.exists());
        assert_eq!(10, cache.current_size.load(Ordering::Relaxed));

        assert_eq!(
            false,
            cache.update_meta(&k_trunc, b"ns", new_meta).await.unwrap()
        );
        assert_eq!(false, p_trunc.exists());
        assert_eq!(0, cache.current_size.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn test_put_creates_nested_dirs_lazily_on_not_found() {
        let dir = tempdir().unwrap();
        let cache = FileCache::new(&format!(
            "{}?levels=1:2&max_size=1mb",
            dir.path().to_str().unwrap()
        ))
        .unwrap();
        let k = key("nested");
        let obj1 = CacheObject {
            meta: (Bytes::from_static(b"m0"), Bytes::from_static(b"m1")),
            body: Bytes::from_static(b"first-body"),
        };
        let obj2 = CacheObject {
            meta: (Bytes::from_static(b"m00"), Bytes::from_static(b"m11")),
            body: Bytes::from_static(b"second-body-longer"),
        };
        assert_eq!(false, dir.path().join("ns").exists());
        cache.put(&k, b"ns", obj1.clone()).await.unwrap();
        assert_eq!(true, cache.get_file_path(&k, "ns").exists());
        assert_eq!(Some(obj1), cache.get(&k, b"ns").await.unwrap());
        assert_eq!(22, cache.current_size.load(Ordering::Relaxed));

        cache.put(&k, b"ns", obj2.clone()).await.unwrap();
        assert_eq!(Some(obj2), cache.get(&k, b"ns").await.unwrap());
        assert_eq!(32, cache.current_size.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn test_cold_read_single_flight() {
        let dir = tempdir().unwrap();
        let cfg_no_hot =
            format!("{}?cache_max=0", dir.path().to_str().unwrap());
        let writer = FileCache::new(&cfg_no_hot).unwrap();
        let k = key("single-flight");
        let obj = CacheObject {
            meta: (Bytes::from_static(b"sf0"), Bytes::from_static(b"sf1")),
            body: Bytes::from(vec![42u8; 32 * 1024]),
        };
        writer.put(&k, b"ns", obj.clone()).await.unwrap();

        let file_path = writer.get_file_path(&k, "ns");
        let three_days_ago =
            SystemTime::now() - Duration::from_secs(3 * 24 * 3600);
        set_atime(&file_path, three_days_ago);

        // Concurrent cold reads with `cache_max=0` (no hot-layer shortcut)
        // coalesce onto a single disk read while updating `touch`.
        // On a current-thread executor `join!` polls every future up to its
        // first `.await` before the leader resumes past `spawn_blocking`.
        let reader = FileCache::new(&cfg_no_hot).unwrap();
        let (r1, r2, r3, r4, r5, r6, r7, r8) = tokio::join!(
            reader.get(&k, b"ns"),
            reader.get(&k, b"ns"),
            reader.get(&k, b"ns"),
            reader.get(&k, b"ns"),
            reader.get(&k, b"ns"),
            reader.get(&k, b"ns"),
            reader.get(&k, b"ns"),
            reader.get(&k, b"ns"),
        );
        for res in [r1, r2, r3, r4, r5, r6, r7, r8] {
            assert_eq!(obj, res.unwrap().unwrap());
        }
        assert_eq!(1, reader.cold_disk_reads.load(Ordering::Relaxed));
        for _ in 0..200 {
            if std::fs::metadata(&file_path).unwrap().accessed().unwrap()
                > three_days_ago + Duration::from_secs(3600)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            true,
            std::fs::metadata(&file_path).unwrap().accessed().unwrap()
                > three_days_ago + Duration::from_secs(3600),
            "file access time was not updated after coalesced cold read"
        );

        // Multi-task concurrent reads with hot layer enabled also succeed identically.
        let cfg_hot = format!("{}?cache_max=100", dir.path().to_str().unwrap());
        let hot_reader = Arc::new(FileCache::new(&cfg_hot).unwrap());
        let barrier = Arc::new(tokio::sync::Barrier::new(16));
        let mut handles = Vec::with_capacity(16);
        for _ in 0..16 {
            let hot_reader = hot_reader.clone();
            let barrier = barrier.clone();
            let k = k.clone();
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                hot_reader.get(&k, b"ns").await
            }));
        }
        for handle in handles {
            assert_eq!(obj, handle.await.unwrap().unwrap().unwrap());
        }
        assert_eq!(1, hot_reader.cold_disk_reads.load(Ordering::Relaxed));

        // Leader cancellation wakes followers cleanly and lets them re-elect a leader.
        let ColdReadRole::Leader(leader_guard) =
            reader.acquire_cold_read_role(&file_path)
        else {
            panic!("expected Leader");
        };
        let ColdReadRole::Follower(mut rx) =
            reader.acquire_cold_read_role(&file_path)
        else {
            panic!("expected Follower");
        };
        drop(leader_guard);
        assert_eq!(true, wait_cold_read(&mut rx).await.is_none());
        assert_eq!(Some(obj), reader.get(&k, b"ns").await.unwrap());
    }

    #[tokio::test]
    async fn test_lookup_hit_cold_large_disk_object() {
        use super::super::http_cache::{
            CompleteHit, DiskHit, HttpCache, is_hit_read_to_the_end,
        };
        use pingora::cache::key::CacheHashKey;
        use pingora::cache::{CacheKey, CacheMeta, Storage};

        let dir = tempdir().unwrap();
        // `cache_file_max_weight = 4` (16 KiB) with 150 KiB body ensures cold disk path.
        let cfg = format!(
            "{}?cache_max=100&cache_file_max_weight=4",
            dir.path().to_str().unwrap()
        );
        let writer = FileCache::new(&cfg).unwrap();

        let now = SystemTime::now();
        let mut resp = pingora::http::ResponseHeader::build(200, None).unwrap();
        resp.insert_header("etag", "\"cold-disk\"").unwrap();
        let meta =
            CacheMeta::new(now + Duration::from_secs(60), now, 0, 0, resp);
        let (meta0, meta1) = meta.serialize().unwrap();
        let large_body: Vec<u8> =
            (0..150_000u32).map(|i| (i % 251) as u8).collect();
        let mut cache_key = CacheKey::new("ns", "/large-object");
        cache_key.user_tag = "ns".to_string();
        let combined = cache_key.combined();
        let large_obj = CacheObject {
            meta: (Bytes::from(meta0.clone()), Bytes::from(meta1.clone())),
            body: Bytes::from(large_body.clone()),
        };
        writer.put(&combined, b"ns", large_obj).await.unwrap();
        assert_eq!(true, writer.get_hot(&combined).is_none());

        let file_path = writer.get_file_path(&combined, "ns");
        let three_days_ago =
            SystemTime::now() - Duration::from_secs(3 * 24 * 3600);
        set_atime(&file_path, three_days_ago);

        // Fresh FileCache with empty hot layer serves lazy `HitBody::Disk` and updates atime.
        let reader = Arc::new(FileCache::new(&cfg).unwrap());
        let (looked_meta, hit_body) =
            reader.lookup_hit(&combined, b"ns").await.unwrap().unwrap();
        assert_eq!(
            (Bytes::from(meta0.clone()), Bytes::from(meta1.clone())),
            looked_meta
        );
        let expected_offset = (8 + meta0.len() + meta1.len()) as u64;
        assert_eq!(
            HitBody::Disk {
                path: file_path.clone(),
                body_offset: expected_offset,
                body_len: large_body.len(),
            },
            hit_body
        );
        assert_eq!(true, reader.get_hot(&combined).is_none());

        for _ in 0..200 {
            if std::fs::metadata(&file_path).unwrap().accessed().unwrap()
                > three_days_ago + Duration::from_secs(3600)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            true,
            std::fs::metadata(&file_path).unwrap().accessed().unwrap()
                > three_days_ago + Duration::from_secs(3600)
        );

        let http_cache: &'static HttpCache = Box::leak(Box::new(
            HttpCache::new(Some(reader.directory.clone()), reader.clone(), 0),
        ));
        let span = pingora::cache::trace::Span::inactive().handle();

        // 1. HEAD lookup does not read body bytes.
        let (head_meta, head_hit) =
            http_cache.lookup(&cache_key, &span).await.unwrap().unwrap();
        assert_eq!(
            Some(b"\"cold-disk\"".as_slice()),
            head_meta.headers().get("etag").map(|v| v.as_bytes())
        );
        assert_eq!(true, head_hit.as_any().downcast_ref::<DiskHit>().is_some());
        assert_eq!(false, is_hit_read_to_the_end(head_hit.as_any()));
        head_hit
            .finish(http_cache, &cache_key, &span)
            .await
            .unwrap();

        // 2. Range seek reads only the requested slice.
        let (_, mut range_hit) =
            http_cache.lookup(&cache_key, &span).await.unwrap().unwrap();
        assert_eq!(true, range_hit.can_seek());
        range_hit.seek(1000, Some(140_000)).unwrap();
        let mut range_buf = vec![];
        let mut range_ends = vec![];
        while let Some(piece) = range_hit.read_body().await.unwrap() {
            range_ends.push(is_hit_read_to_the_end(range_hit.as_any()));
            range_buf.extend_from_slice(&piece);
        }
        assert_eq!(vec![false, false, true], range_ends);
        assert_eq!(&large_body[1000..140_000], range_buf.as_slice());

        // 3. Full multi-chunk streaming read + `is_hit_read_to_the_end`.
        let (_, mut full_hit) =
            http_cache.lookup(&cache_key, &span).await.unwrap().unwrap();
        let mut full_buf = vec![];
        let mut full_ends = vec![];
        while let Some(piece) = full_hit.read_body().await.unwrap() {
            full_ends.push(is_hit_read_to_the_end(full_hit.as_any()));
            full_buf.extend_from_slice(&piece);
        }
        assert_eq!(vec![false, false, true], full_ends);
        assert_eq!(large_body, full_buf);

        // 4. Objects fitting the hot layer or <= 64 KiB fall back to `get` + `CompleteHit`.
        let hot_cfg = format!("{}?cache_max=100", dir.path().to_str().unwrap());
        let hot_reader = Arc::new(FileCache::new(&hot_cfg).unwrap());
        let mut medium_key = CacheKey::new("ns", "/medium-fits-hot");
        medium_key.user_tag = "ns".to_string();
        let medium_body: Vec<u8> =
            (0..80_000u32).map(|i| (i % 251) as u8).collect();
        let medium_obj = CacheObject {
            meta: (Bytes::from(meta0), Bytes::from(meta1)),
            body: Bytes::from(medium_body.clone()),
        };
        hot_reader
            .put(&medium_key.combined(), b"ns", medium_obj)
            .await
            .unwrap();
        hot_reader.remove_hot(&medium_key.combined());
        assert_eq!(true, hot_reader.get_hot(&medium_key.combined()).is_none());

        let hot_http: &'static HttpCache = Box::leak(Box::new(HttpCache::new(
            Some(hot_reader.directory.clone()),
            hot_reader.clone(),
            0,
        )));
        let (_, mut mem_hit) =
            hot_http.lookup(&medium_key, &span).await.unwrap().unwrap();
        assert_eq!(
            true,
            mem_hit.as_any().downcast_ref::<CompleteHit>().is_some()
        );
        assert_eq!(true, hot_reader.get_hot(&medium_key.combined()).is_some());
        let mut mem_buf = vec![];
        while let Some(piece) = mem_hit.read_body().await.unwrap() {
            mem_buf.extend_from_slice(&piece);
        }
        assert_eq!(medium_body, mem_buf);
    }

    #[tokio::test]
    async fn test_lookup_hit_truncated_file_is_miss_and_removed() {
        let dir = tempdir().unwrap();
        let cfg = format!(
            "{}?cache_max=0&max_size=1mb",
            dir.path().to_str().unwrap()
        );
        let cache = FileCache::new(&cfg).unwrap();

        let k_short = key("lookup-short");
        let k_trunc = key("lookup-trunc");
        let obj = CacheObject {
            meta: (
                Bytes::from_static(b"header0"),
                Bytes::from_static(b"header1"),
            ),
            body: Bytes::from(vec![7u8; 100_000]),
        };
        cache.put(&k_short, b"ns", obj.clone()).await.unwrap();
        cache.put(&k_trunc, b"ns", obj).await.unwrap();

        let p_short = cache.get_file_path(&k_short, "ns");
        let p_trunc = cache.get_file_path(&k_trunc, "ns");
        let full = std::fs::read(&p_trunc).unwrap();
        std::fs::write(&p_short, &full[..4]).unwrap();
        std::fs::write(&p_trunc, &full[..12]).unwrap();

        let cache = FileCache::new(&cfg).unwrap();
        assert_eq!(16, cache.current_size.load(Ordering::Relaxed));

        assert_eq!(
            true,
            cache.lookup_hit(&k_short, b"ns").await.unwrap().is_none()
        );
        assert_eq!(false, p_short.exists());
        assert_eq!(12, cache.current_size.load(Ordering::Relaxed));

        assert_eq!(
            true,
            cache.lookup_hit(&k_trunc, b"ns").await.unwrap().is_none()
        );
        assert_eq!(false, p_trunc.exists());
        assert_eq!(0, cache.current_size.load(Ordering::Relaxed));
    }

    fn count_tmp_files(dir: &Path) -> usize {
        WalkDir::new(dir)
            .into_iter()
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry.file_type().is_file()
                    && entry.file_name().to_string_lossy().ends_with(".tmp")
            })
            .count()
    }

    #[tokio::test]
    async fn test_bounded_startup_scan_resyncs_in_background() {
        let dir = tempdir().unwrap();
        let cfg = format!(
            "{}?cache_max=0&max_size=10mb",
            dir.path().to_str().unwrap()
        );
        let writer = FileCache::new(&cfg).unwrap();
        let obj = CacheObject {
            meta: (Bytes::from_static(b"m0"), Bytes::from_static(b"m1")),
            body: Bytes::from(vec![9u8; 1024]),
        };
        let file_len = (8 + 2 + 2 + 1024) as u64;
        for idx in 0..10 {
            writer
                .put(&key(&format!("b{idx}")), b"", obj.clone())
                .await
                .unwrap();
        }
        assert_eq!(10 * file_len, writer.current_size.load(Ordering::Relaxed));

        let reader = FileCache::new_with_scan_limit(&cfg, 3).unwrap();
        assert_eq!(true, reader.size_scan_pending.load(Ordering::Relaxed));
        assert_eq!(
            true,
            reader.current_size.load(Ordering::Relaxed) < 10 * file_len
        );

        assert_eq!(
            true,
            reader.get(&key("missing"), b"").await.unwrap().is_none()
        );
        for _ in 0..200 {
            if reader.current_size.load(Ordering::Relaxed) == 10 * file_len
                && !reader.size_scan_pending.load(Ordering::Relaxed)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(false, reader.size_scan_pending.load(Ordering::Relaxed));
        assert_eq!(10 * file_len, reader.current_size.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn test_touch_batch_flushed_before_clear() {
        let dir = tempdir().unwrap();
        let cfg = format!("{}?cache_max=100", dir.path().to_str().unwrap());
        let cache = FileCache::new(&cfg).unwrap();
        let obj = CacheObject {
            meta: (Bytes::from_static(b"k"), Bytes::from_static(b"v")),
            body: Bytes::from_static(b"hot-body"),
        };
        let name = key("flush-before-clear");
        cache.put(&name, b"", obj.clone()).await.unwrap();
        let file = cache.get_file_path(&name, "");
        let three_days_ago =
            SystemTime::now() - Duration::from_secs(3 * 24 * 3600);
        set_atime(&file, three_days_ago);

        // Hot hit queues `touch` into `pending_touches` (50ms delay).
        assert_eq!(Some(obj), cache.get(&name, b"").await.unwrap());
        // Calling `clear` immediately flushes `pending_touches` before reading atime.
        let stats = cache
            .clear(SystemTime::now() - Duration::from_secs(48 * 3600))
            .await
            .unwrap();
        assert_eq!(0, stats.success);
        assert_eq!(true, file.exists());
    }

    #[tokio::test]
    async fn test_streaming_large_miss_round_trip_known_and_unknown_len() {
        use super::super::http_cache::{DiskHit, HttpCache};
        use pingora::cache::key::CacheHashKey;
        use pingora::cache::storage::MissFinishType;
        use pingora::cache::{CacheKey, CacheMeta, Storage};

        let dir = tempdir().unwrap();
        let cfg = format!(
            "{}?cache_max=100&cache_file_max_weight=4&max_size=2mb",
            dir.path().to_str().unwrap()
        );
        let file_cache = Arc::new(FileCache::new(&cfg).unwrap());
        let http_cache: &'static HttpCache =
            Box::leak(Box::new(HttpCache::new(
                Some(file_cache.directory.clone()),
                file_cache.clone(),
                0,
            )));
        let span = pingora::cache::trace::Span::inactive().handle();
        let now = SystemTime::now();

        // 1. Known Content-Length > cache_file_max_weight (16 KiB) & >= 64 KiB,
        //    also overwriting a stale small entry in the hot layer.
        let known_key = CacheKey::new("/stream-known", "ns");
        file_cache
            .put(
                &known_key.combined(),
                b"ns",
                CacheObject {
                    meta: (
                        Bytes::from_static(b"old0"),
                        Bytes::from_static(b"old1"),
                    ),
                    body: Bytes::from_static(b"stale-small"),
                },
            )
            .await
            .unwrap();
        assert_eq!(true, file_cache.get_hot(&known_key.combined()).is_some());

        let known_body: Vec<u8> =
            (0..280_000u32).map(|i| (i % 251) as u8).collect();
        let mut known_resp =
            pingora::http::ResponseHeader::build(200, None).unwrap();
        known_resp
            .insert_header("content-length", known_body.len().to_string())
            .unwrap();
        known_resp
            .insert_header("etag", "\"stream-known\"")
            .unwrap();
        let known_meta = CacheMeta::new(
            now + Duration::from_secs(60),
            now,
            0,
            0,
            known_resp,
        );
        let (km0, km1) = known_meta.serialize().unwrap();

        let mut known_miss = http_cache
            .get_miss_handler(&known_key, &known_meta, &span)
            .await
            .unwrap();
        for chunk in [
            &known_body[..1000],
            &known_body[1000..66_536],
            &known_body[66_536..216_536],
            &known_body[216_536..],
        ] {
            known_miss
                .write_body(Bytes::copy_from_slice(chunk), false)
                .await
                .unwrap();
        }
        let finish = known_miss.finish().await.unwrap();
        match finish {
            MissFinishType::Created(size) => {
                assert_eq!(known_body.len() + km0.len() + km1.len(), size);
            },
            _ => panic!("expected MissFinishType::Created"),
        }
        assert_eq!(0, file_cache.stats().unwrap().writing);
        assert_eq!(0, count_tmp_files(dir.path()));
        assert_eq!(true, file_cache.get_hot(&known_key.combined()).is_none());

        let known_file_len = std::fs::metadata(
            file_cache.get_file_path(&known_key.combined(), "ns"),
        )
        .unwrap()
        .len();
        assert_eq!(
            known_file_len,
            file_cache.current_size.load(Ordering::Relaxed)
        );

        let (looked_meta, mut known_hit) =
            http_cache.lookup(&known_key, &span).await.unwrap().unwrap();
        assert_eq!(
            Some(b"\"stream-known\"".as_slice()),
            looked_meta.headers().get("etag").map(|v| v.as_bytes())
        );
        assert_eq!(
            true,
            known_hit.as_any().downcast_ref::<DiskHit>().is_some()
        );
        let mut read_known = Vec::new();
        while let Some(piece) = known_hit.read_body().await.unwrap() {
            read_known.extend_from_slice(&piece);
        }
        assert_eq!(known_body, read_known);

        // 2. Unknown Content-Length spilling past 64 KiB across small chunks.
        let unknown_key = CacheKey::new("/stream-unknown", "ns");
        let unknown_body: Vec<u8> =
            (0..200_000u32).map(|i| ((i * 7) % 253) as u8).collect();
        let mut unknown_resp =
            pingora::http::ResponseHeader::build(200, None).unwrap();
        unknown_resp
            .insert_header("etag", "\"stream-unknown\"")
            .unwrap();
        let unknown_meta = CacheMeta::new(
            now + Duration::from_secs(60),
            now,
            0,
            0,
            unknown_resp,
        );
        let (um0, um1) = unknown_meta.serialize().unwrap();

        let mut unknown_miss = http_cache
            .get_miss_handler(&unknown_key, &unknown_meta, &span)
            .await
            .unwrap();
        for chunk in unknown_body.chunks(30_000) {
            unknown_miss
                .write_body(Bytes::copy_from_slice(chunk), false)
                .await
                .unwrap();
        }
        let finish = unknown_miss.finish().await.unwrap();
        match finish {
            MissFinishType::Created(size) => {
                assert_eq!(unknown_body.len() + um0.len() + um1.len(), size);
            },
            _ => panic!("expected MissFinishType::Created"),
        }
        assert_eq!(0, file_cache.stats().unwrap().writing);
        assert_eq!(0, count_tmp_files(dir.path()));

        let unknown_file_len = std::fs::metadata(
            file_cache.get_file_path(&unknown_key.combined(), "ns"),
        )
        .unwrap()
        .len();
        assert_eq!(
            known_file_len + unknown_file_len,
            file_cache.current_size.load(Ordering::Relaxed)
        );

        let (looked_meta, mut unknown_hit) = http_cache
            .lookup(&unknown_key, &span)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            Some(b"\"stream-unknown\"".as_slice()),
            looked_meta.headers().get("etag").map(|v| v.as_bytes())
        );
        assert_eq!(
            true,
            unknown_hit.as_any().downcast_ref::<DiskHit>().is_some()
        );
        let mut read_unknown = Vec::new();
        while let Some(piece) = unknown_hit.read_body().await.unwrap() {
            read_unknown.extend_from_slice(&piece);
        }
        assert_eq!(unknown_body, read_unknown);
    }

    #[tokio::test]
    async fn test_streaming_miss_drop_cleans_up_tmp_and_writing() {
        use super::super::http_cache::HttpCache;
        use pingora::cache::key::CacheHashKey;
        use pingora::cache::{CacheKey, CacheMeta, Storage};

        let dir = tempdir().unwrap();
        let cfg = format!(
            "{}?cache_max=100&cache_file_max_weight=4&max_size=2mb",
            dir.path().to_str().unwrap()
        );
        let file_cache = Arc::new(FileCache::new(&cfg).unwrap());
        let http_cache: &'static HttpCache =
            Box::leak(Box::new(HttpCache::new(
                Some(file_cache.directory.clone()),
                file_cache.clone(),
                0,
            )));
        let span = pingora::cache::trace::Span::inactive().handle();
        let now = SystemTime::now();

        let cache_key = CacheKey::new("/abort-mid-stream", "ns");
        let mut resp = pingora::http::ResponseHeader::build(200, None).unwrap();
        resp.insert_header("content-length", "300000").unwrap();
        let meta =
            CacheMeta::new(now + Duration::from_secs(60), now, 0, 0, resp);

        let mut miss = http_cache
            .get_miss_handler(&cache_key, &meta, &span)
            .await
            .unwrap();
        assert_eq!(1, file_cache.stats().unwrap().writing);
        assert_eq!(1, count_tmp_files(dir.path()));

        miss.write_body(Bytes::from(vec![3u8; 140_000]), false)
            .await
            .unwrap();
        assert_eq!(1, file_cache.stats().unwrap().writing);
        assert_eq!(1, count_tmp_files(dir.path()));

        drop(miss);
        assert_eq!(0, file_cache.stats().unwrap().writing);
        assert_eq!(0, count_tmp_files(dir.path()));
        assert_eq!(
            false,
            file_cache
                .get_file_path(&cache_key.combined(), "ns")
                .exists()
        );
        assert_eq!(0, file_cache.current_size.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn test_streaming_miss_exceeds_max_size_cleans_up() {
        use super::super::http_cache::HttpCache;
        use pingora::cache::key::CacheHashKey;
        use pingora::cache::{CacheKey, CacheMeta, Storage};

        let dir = tempdir().unwrap();
        let cfg = format!(
            "{}?cache_max=0&max_size=150000",
            dir.path().to_str().unwrap()
        );
        let file_cache = Arc::new(FileCache::new(&cfg).unwrap());
        let http_cache: &'static HttpCache =
            Box::leak(Box::new(HttpCache::new(
                Some(file_cache.directory.clone()),
                file_cache.clone(),
                0,
            )));
        let span = pingora::cache::trace::Span::inactive().handle();
        let now = SystemTime::now();

        let keep_key = key("keep-existing");
        let keep_obj = CacheObject {
            meta: (Bytes::from_static(b"k"), Bytes::from_static(b"v")),
            body: Bytes::from(vec![1u8; 10_000]),
        };
        file_cache.put(&keep_key, b"ns", keep_obj).await.unwrap();
        let kept_size = file_cache.current_size.load(Ordering::Relaxed);

        // 1. Known Content-Length exceeding max_size skips without creating `.tmp` or evicting.
        let known_big = CacheKey::new("/too-big-known", "ns");
        let mut resp = pingora::http::ResponseHeader::build(200, None).unwrap();
        resp.insert_header("content-length", "200000").unwrap();
        let meta =
            CacheMeta::new(now + Duration::from_secs(60), now, 0, 0, resp);
        let mut miss = http_cache
            .get_miss_handler(&known_big, &meta, &span)
            .await
            .unwrap();
        miss.write_body(Bytes::from(vec![2u8; 200_000]), true)
            .await
            .unwrap();
        miss.finish().await.unwrap();
        assert_eq!(0, file_cache.stats().unwrap().writing);
        assert_eq!(0, count_tmp_files(dir.path()));
        assert_eq!(
            false,
            file_cache
                .get_file_path(&known_big.combined(), "ns")
                .exists()
        );
        assert_eq!(true, file_cache.get_file_path(&keep_key, "ns").exists());
        assert_eq!(kept_size, file_cache.current_size.load(Ordering::Relaxed));

        // 2. Unknown Content-Length crossing max_size mid-stream aborts and removes `.tmp`.
        let unknown_big = CacheKey::new("/too-big-unknown", "ns");
        let resp = pingora::http::ResponseHeader::build(200, None).unwrap();
        let meta =
            CacheMeta::new(now + Duration::from_secs(60), now, 0, 0, resp);
        let mut miss = http_cache
            .get_miss_handler(&unknown_big, &meta, &span)
            .await
            .unwrap();
        for _ in 0..5 {
            miss.write_body(Bytes::from(vec![4u8; 40_000]), false)
                .await
                .unwrap();
        }
        miss.finish().await.unwrap();
        assert_eq!(0, file_cache.stats().unwrap().writing);
        assert_eq!(0, count_tmp_files(dir.path()));
        assert_eq!(
            false,
            file_cache
                .get_file_path(&unknown_big.combined(), "ns")
                .exists()
        );
        assert_eq!(true, file_cache.get_file_path(&keep_key, "ns").exists());
        assert_eq!(kept_size, file_cache.current_size.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn test_file_cache_find_keys_by_tags_cold_header_only() {
        use super::super::http_cache::HttpCache;
        use pingora::cache::key::CacheHashKey;
        use pingora::cache::{CacheKey, CacheMeta};

        let dir = tempdir().unwrap();
        let cfg =
            format!("{}?cache_max=0&levels=1:2", dir.path().to_str().unwrap());
        let file_cache = Arc::new(FileCache::new(&cfg).unwrap());
        let now = SystemTime::now();

        let seed_disk = async |primary: &str, ns: &str, tags: &str| {
            let key = CacheKey::new(primary, ns);
            let mut resp =
                pingora::http::ResponseHeader::build(200, None).unwrap();
            if !tags.is_empty() {
                resp.insert_header("cache-tag", tags).unwrap();
            }
            let meta =
                CacheMeta::new(now + Duration::from_secs(60), now, 0, 0, resp);
            let (m0, m1) = meta.serialize().unwrap();
            let obj = CacheObject {
                meta: (Bytes::from(m0), Bytes::from(m1)),
                body: Bytes::from(vec![7u8; 100_000]),
            };
            file_cache
                .put(&key.combined(), ns.as_bytes(), obj)
                .await
                .unwrap();
            key
        };

        let k_a1 = seed_disk("ns-aGET:a.com/1", "ns-a", "news, featured").await;
        let _k_a2 = seed_disk("ns-aGET:a.com/2", "ns-a", "sports").await;
        let k_b1 = seed_disk("ns-bGET:b.com/1", "ns-b", "news").await;
        let k_empty = seed_disk("GET:c.com/1", "", "news").await;

        // Place a truncated file in ns-a to verify corrupt files are skipped safely.
        let corrupt_path = file_cache.get_file_path(&key("corrupt"), "ns-a");
        std::fs::create_dir_all(corrupt_path.parent().unwrap()).unwrap();
        std::fs::write(&corrupt_path, b"short").unwrap();

        // Simulate cold restart with fresh FileCache + fresh HttpCache (empty meta_index).
        let cold = Arc::new(FileCache::new(&cfg).unwrap());
        let found_a = cold
            .find_keys_by_tags(Some("ns-a"), &["news".to_string()])
            .await
            .unwrap();
        assert_eq!(vec![(k_a1.combined(), "ns-a".to_string())], found_a);

        let found_empty = cold
            .find_keys_by_tags(Some(""), &["news".to_string()])
            .await
            .unwrap();
        assert_eq!(vec![(k_empty.combined(), "".to_string())], found_empty);

        let found_all = cold
            .find_keys_by_tags(None, &["news".to_string()])
            .await
            .unwrap();
        assert_eq!(3, found_all.len());

        // `HttpCache::purge_by_tags` on a fresh instance still finds and removes cold entries on disk.
        let http_cache =
            HttpCache::new(Some(cold.directory.clone()), cold.clone(), 0);
        let purged = http_cache
            .purge_by_tags(Some("ns-a"), &["news".to_string()])
            .await
            .unwrap();
        assert_eq!(1, purged.len());
        assert_eq!(k_a1.combined(), purged[0].key);
        assert!(cold.get(&k_a1.combined(), b"ns-a").await.unwrap().is_none());
        assert!(cold.get(&k_b1.combined(), b"ns-b").await.unwrap().is_some());
        assert!(cold.get(&k_empty.combined(), b"").await.unwrap().is_some());
    }
}
