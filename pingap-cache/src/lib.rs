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

use bytesize::ByteSize;
use serde::Deserialize;
use snafu::Snafu;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use tracing::{info, warn};

mod file;
mod http_cache;
mod tiny;

pub static PAGE_SIZE: usize = 4096;

/// Category name for cache related logging
pub static LOG_TARGET: &str = "pingap::cache";

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Io error: {source}"))]
    Io { source: std::io::Error },
    #[snafu(display("{message}"))]
    Invalid { message: String },
    #[snafu(display("Over quota error, max: {max}, {message}"))]
    OverQuota { max: u32, message: String },
    #[snafu(display("{message}"))]
    Prometheus { message: String },
}
pub type Result<T, E = Error> = std::result::Result<T, E>;

impl From<Error> for pingora::BError {
    fn from(value: Error) -> Self {
        pingap_core::new_internal_error(500, value)
    }
}

fn new_tiny_ufo_cache(mode: CacheMode, size: usize) -> HttpCache {
    HttpCache {
        directory: None,
        cache: Arc::new(tiny::TinyUfoCache::new(mode, size / PAGE_SIZE)),
        max_size: size as u64,
    }
}
fn new_file_cache(dir: &str) -> Result<HttpCache> {
    let cache = FileCache::new(dir)?;
    Ok(HttpCache {
        directory: Some(cache.directory.clone()),
        cache: Arc::new(cache),
        max_size: 0,
    })
}

thread_local! {
    static DRY_RUN: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

/// What [`new_cache_backend`] gives out in a dry run when there is no
/// backend to give: a memory cache of one page, never used.
static DRY_RUN_BACKEND: LazyLock<HttpCache> =
    LazyLock::new(|| new_tiny_ufo_cache(CacheMode::default(), PAGE_SIZE));

/// Runs `f`, on this thread, with the cache backends left as they are:
/// [`new_cache_backend`] checks the setting it is given and returns the
/// backend that is there, or a stand-in, without creating, replacing or
/// sizing anything.
///
/// For building a `cache` plugin only to see whether its configuration is
/// valid, inside a process that is serving. Built for real, a setting that
/// is then refused had already made its directory, taken the place of the
/// backend the running plugin uses, or fixed the size of the one memory
/// cache for the life of the process.
pub fn dry_run<T>(f: impl FnOnce() -> T) -> T {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            DRY_RUN.set(self.0);
        }
    }
    let _restore = Restore(DRY_RUN.replace(true));
    f()
}

/// Whether this thread is inside [`dry_run`].
pub fn is_dry_run() -> bool {
    DRY_RUN.get()
}

/// File backends by the directory they store in, each with the
/// parameters it was built from; each is leaked once and shared.
///
/// One per directory, not one per setting. The whole setting used to be
/// the key, parameters included, so `inactive=1h` changed to `7d` on a
/// reload made a second cache of the same directory and left the first
/// in the list: its hourly sweep went on deleting what had not been read
/// for an hour.
type FileBackends =
    HashMap<String, (file::FileCacheParams, &'static HttpCache)>;
static BACKENDS: LazyLock<Mutex<FileBackends>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

type MemoryBackendEntry = ((CacheMode, usize), &'static HttpCache);
static MEMORY_BACKEND: LazyLock<Mutex<Option<MemoryBackendEntry>>> =
    LazyLock::new(|| Mutex::new(None));

/// Default cap when `max_size` is omitted (or when available memory is unknown).
const DEFAULT_MAX_MEMORY_SIZE: usize = 1024 * 1024 * 1024;

/// Maximum safe memory budget for TinyUFO so upfront index/sketch allocation
/// and cached pages never exceed host/container memory and fail startup.
pub(crate) fn max_safe_memory_bytes(available_memory: usize) -> usize {
    if available_memory > 0 {
        (available_memory / 2).max(PAGE_SIZE)
    } else {
        DEFAULT_MAX_MEMORY_SIZE
    }
}

pub(crate) fn max_safe_memory_pages() -> usize {
    let available = AVAILABLE_MEMORY.load(Ordering::Relaxed) as usize;
    max_safe_memory_bytes(available) / PAGE_SIZE
}

pub(crate) fn get_file_backends() -> Vec<&'static HttpCache> {
    BACKENDS
        .lock()
        .map(|backends| backends.values().map(|(_, cache)| *cache).collect())
        .unwrap_or_default()
}

static AVAILABLE_MEMORY: AtomicU64 = AtomicU64::new(0);

pub fn update_available_memory(available_memory: u64) {
    AVAILABLE_MEMORY.store(available_memory, Ordering::Relaxed);
}

/// `max_size` accepts either an absolute size with a unit (`100mb`) or a bare
/// number, which is a percentage of the memory budget (`20` means 20%).
///
/// The two have to be told apart while parsing: `ByteSize` turns both into a
/// byte count, and a magnitude test cannot distinguish `5mb` from "5 percent".
#[derive(Debug, PartialEq, Clone, Copy)]
enum MaxSize {
    Percent(usize),
    Bytes(usize),
}

impl MaxSize {
    fn resolve(&self, budget: usize) -> usize {
        match self {
            Self::Percent(percent) => budget * (*percent).min(100) / 100,
            Self::Bytes(size) => *size,
        }
    }
}

fn parse_max_size<'de, D>(deserializer: D) -> Result<Option<MaxSize>, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let s: String = String::deserialize(deserializer)?;
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    if s.chars().all(|c| c.is_ascii_digit()) {
        let percent = s.parse::<usize>().map_err(serde::de::Error::custom)?;
        return Ok(Some(MaxSize::Percent(percent)));
    }
    let size = ByteSize::from_str(s)
        .map_err(|e| serde::de::Error::custom(e.to_string()))?;
    Ok(Some(MaxSize::Bytes(size.as_u64() as usize)))
}

#[derive(Debug, PartialEq, Deserialize, Default)]
struct MemoryCacheParams {
    #[serde(default)]
    #[serde(deserialize_with = "parse_max_size")]
    max_size: Option<MaxSize>,
    mode: Option<String>,
}
impl TryFrom<&str> for MemoryCacheParams {
    type Error = Error;
    fn try_from(value: &str) -> Result<Self> {
        let params = if let Some((_, query)) = value.split_once('?') {
            serde_qs::from_str(query).map_err(|e| Error::Invalid {
                message: format!("memory cache params {value} is invalid: {e}"),
            })?
        } else {
            MemoryCacheParams::default()
        };
        Ok(params)
    }
}

impl MemoryCacheParams {
    fn cache_mode(&self) -> Result<CacheMode> {
        let Some(mode) = self.mode.as_deref() else {
            return Ok(CacheMode::default());
        };
        CacheMode::from_str(mode).map_err(|_| Error::Invalid {
            message: format!(
                "memory cache mode {mode} is invalid, expected normal or compact"
            ),
        })
    }
}

/// Resolves the memory cache size in bytes, returning `(size, Some(requested))`
/// when an explicit byte request had to be clamped to `safe_ceiling` to avoid
/// exceeding available memory at startup.
fn resolve_memory_cache_size(
    max_size: Option<MaxSize>,
    available_memory: usize,
) -> (usize, Option<usize>) {
    let safe_ceiling = max_safe_memory_bytes(available_memory);
    match max_size {
        None => {
            let default_budget = if available_memory > 0 {
                available_memory / 4
            } else {
                ByteSize::mb(256).as_u64() as usize
            };
            (
                default_budget
                    .min(DEFAULT_MAX_MEMORY_SIZE)
                    .min(safe_ceiling),
                None,
            )
        },
        Some(MaxSize::Percent(percent)) => {
            (MaxSize::Percent(percent).resolve(safe_ceiling), None)
        },
        Some(MaxSize::Bytes(requested)) => {
            if requested > safe_ceiling {
                (safe_ceiling, Some(requested))
            } else {
                (requested, None)
            }
        },
    }
}

fn get_or_update_memory_backend(
    params: MemoryCacheParams,
    cache_mode: CacheMode,
) -> Result<&'static HttpCache> {
    let mut guard = MEMORY_BACKEND.lock().map_err(|e| Error::Invalid {
        message: e.to_string(),
    })?;
    if is_dry_run() {
        return Ok(guard
            .as_ref()
            .map_or(&*DRY_RUN_BACKEND, |(_, backend)| *backend));
    }
    let available_memory = AVAILABLE_MEMORY.load(Ordering::Relaxed) as usize;
    let (size, capped_from) =
        resolve_memory_cache_size(params.max_size, available_memory);
    if let Some(((mode, current_size), backend)) = *guard
        && mode == cache_mode
        && current_size == size
    {
        return Ok(backend);
    }
    if let Some(requested) = capped_from {
        warn!(
            target: LOG_TARGET,
            requested = ByteSize(requested as u64).to_string(),
            capped = ByteSize(size as u64).to_string(),
            available = ByteSize(available_memory as u64).to_string(),
            "memory cache max_size exceeds safe available memory, capping"
        );
    }
    // Retire the previous TinyUFO storage BEFORE allocating the new one so
    // old + new caches never coexist at full size during hot-reload resizing.
    if let Some((previous, replaced)) = guard.take() {
        replaced.cache.retire();
        info!(
            target: LOG_TARGET,
            previous = ?previous,
            size = ByteSize(size as u64).to_string(),
            cache_mode = ?cache_mode,
            "memory cache backend retired for resize"
        );
    }
    let cache = new_tiny_ufo_cache(cache_mode, size);
    info!(
        target: LOG_TARGET,
        size = ByteSize(size as u64).to_string(),
        cache_mode = ?cache_mode,
        "init memory cache backend success"
    );
    let cache_ref: &'static HttpCache = Box::leak(Box::new(cache));
    *guard = Some(((cache_mode, size), cache_ref));
    Ok(cache_ref)
}

fn get_or_init_file_backend(directory: &str) -> Result<&'static HttpCache> {
    // What a setting says, not how it is written: the same directory with
    // the same parameters is the same cache, whatever the spelling of the
    // path or the order of the parameters.
    let params = file::FileCacheParams::try_from(directory)?;
    {
        let cache_backends = BACKENDS.lock().map_err(|e| Error::Invalid {
            message: e.to_string(),
        })?;
        let existing = cache_backends.get(&params.directory);
        if is_dry_run() {
            return Ok(
                existing.map_or(&*DRY_RUN_BACKEND, |(_, backend)| *backend)
            );
        }
        if let Some((_, backend)) = existing.filter(|(used, _)| *used == params)
        {
            return Ok(backend);
        }
    }

    // Build outside BACKENDS lock so initial directory walk (`measure_dir_size`)
    // does not stall other cache backends or background sweep lookups.
    let cache = new_file_cache(directory).map_err(|e| Error::Invalid {
        message: e.to_string(),
    })?;
    info!(
        target: LOG_TARGET,
        inactive = cache.cache.inactive().map(|v| v.as_secs()),
        "init file cache backend success"
    );

    let mut cache_backends = BACKENDS.lock().map_err(|e| Error::Invalid {
        message: e.to_string(),
    })?;
    if let Some((_, backend)) = cache_backends
        .get(&params.directory)
        .filter(|(used, _)| *used == params)
    {
        return Ok(backend);
    }
    let cache_ref: &'static HttpCache = Box::leak(Box::new(cache));
    // Other parameters take the directory over. The cache they replace
    // stays valid for the requests still using it, but is swept no more
    // and gives up its hot layer.
    let replaced =
        cache_backends.insert(params.directory.clone(), (params, cache_ref));
    drop(cache_backends);

    if let Some((previous, old)) = replaced {
        info!(
            target: LOG_TARGET,
            previous = ?previous,
            current = directory,
            "file cache backend replaced"
        );
        old.cache.retire();
    }

    Ok(cache_ref)
}

/// Returns the backend for `directory`: the process-wide memory backend for
/// an empty value or `memory://...`, otherwise the file backend rooted at
/// that path, created on first use and shared afterwards. Invalid
/// parameters are an error here rather than silently the defaults, so a
/// typo in `max_size` or `mode` fails the plugin instead of the cache
/// quietly running with another size.
pub fn new_cache_backend(directory: &str) -> Result<&'static HttpCache> {
    if directory.is_empty() || directory.starts_with("memory://") {
        let params = MemoryCacheParams::try_from(directory)?;
        let cache_mode = params.cache_mode()?;
        return get_or_update_memory_backend(params, cache_mode);
    }
    get_or_init_file_backend(directory)
}

pub use http_cache::{
    CacheObject, HttpCache, is_hit_read_to_the_end, new_storage_clear_service,
};
pub use tiny::memory_cache_evictions;

#[cfg(feature = "tracing")]
mod prom;
#[cfg(feature = "tracing")]
pub use prom::{CACHE_READING_TIME, CACHE_WRITING_TIME};

use crate::file::FileCache;
use crate::tiny::CacheMode;

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::time::Duration;
    use tempfile::TempDir;

    #[test]
    fn test_convert_error() {
        let err = Error::Invalid {
            message: "invalid error".to_string(),
        };

        let b_error: pingora::BError = err.into();

        assert_eq!(
            " HTTPStatus context: invalid error cause:  InternalError",
            b_error.to_string()
        );

        assert_eq!(
            "no meta found",
            Error::Invalid {
                message: "no meta found".to_string(),
            }
            .to_string()
        );
        let io = Error::Io {
            source: std::io::Error::other("disk full"),
        };
        assert_eq!("Io error: disk full", io.to_string());
        assert_eq!(
            "Over quota error, max: 10, readers",
            Error::OverQuota {
                max: 10,
                message: "readers".to_string(),
            }
            .to_string()
        );
        assert_eq!(
            "duplicate metric",
            Error::Prometheus {
                message: "duplicate metric".to_string(),
            }
            .to_string()
        );
    }

    #[test]
    fn test_cache() {
        let _ = new_tiny_ufo_cache(CacheMode::Compact, 1024);

        let dir = TempDir::new().unwrap();
        let result = new_file_cache(&dir.keep().to_string_lossy());
        assert_eq!(true, result.is_ok());
    }

    /// Regression: the backends were kept by the whole setting, so the
    /// same directory with another `inactive` was a second cache. The
    /// first stayed in the list, and its sweep went on deleting by the
    /// value that had been replaced.
    #[test]
    fn test_file_backend_is_one_per_directory() {
        let dir = TempDir::new().unwrap().keep();
        let dir = dir.to_string_lossy();
        let swept_by = || {
            get_file_backends()
                .into_iter()
                .filter(|backend| backend.directory.as_deref() == Some(&*dir))
                .map(|backend| backend.cache.inactive())
                .collect::<Vec<_>>()
        };

        let first = new_cache_backend(&format!("{dir}?inactive=1h")).unwrap();
        // The same setting is the same backend.
        let again = new_cache_backend(&format!("{dir}?inactive=1h")).unwrap();
        assert_eq!(true, std::ptr::eq(first, again));
        assert_eq!(vec![Some(Duration::from_secs(3600))], swept_by());

        // Another setting takes the directory over.
        let second = new_cache_backend(&format!("{dir}?inactive=7d")).unwrap();
        assert_eq!(false, std::ptr::eq(first, second));
        assert_eq!(vec![Some(Duration::from_secs(7 * 24 * 3600))], swept_by());

        // The same setting written another way - the path, the order of
        // the parameters - is the same backend, not a third one that
        // takes the directory from the second.
        let other =
            new_cache_backend(&format!("{dir}?inactive=7d&reading_max=5"))
                .unwrap();
        for setting in [
            format!("{dir}/./?inactive=7d&reading_max=5"),
            format!("{dir}?reading_max=5&inactive=7d"),
        ] {
            let again = new_cache_backend(&setting).unwrap();
            assert_eq!(true, std::ptr::eq(other, again), "{setting}");
        }
        assert_eq!(1, swept_by().len());
    }

    /// A dry run checks the setting and leaves the backends alone: no
    /// directory made, nothing registered, the backend of a directory not
    /// replaced by the setting that is only being tried.
    #[test]
    fn test_dry_run_leaves_the_backends_alone() {
        let root = TempDir::new().unwrap().keep();
        let fresh = root.join("fresh");
        let fresh = fresh.to_string_lossy();
        let registered = |dir: &str| {
            get_file_backends()
                .into_iter()
                .filter(|backend| backend.directory.as_deref() == Some(dir))
                .map(|backend| backend.cache.inactive())
                .collect::<Vec<_>>()
        };

        let backend = dry_run(|| {
            assert_eq!(true, is_dry_run());
            new_cache_backend(&format!("{fresh}?inactive=1m")).unwrap()
        });
        assert_eq!(false, is_dry_run());
        assert_eq!(None, backend.directory);
        assert_eq!(false, std::path::Path::new(&*fresh).exists());
        assert_eq!(true, registered(&fresh).is_empty());
        // The setting is still checked.
        let err = dry_run(|| new_cache_backend(&format!("{fresh}?levels=9")));
        assert_eq!(true, err.is_err());
        let err = dry_run(|| new_cache_backend("memory://?mode=nope"));
        assert_eq!(true, err.is_err());

        // A directory in use keeps the backend it has.
        let live = new_cache_backend(&format!("{fresh}?inactive=1h")).unwrap();
        let tried =
            dry_run(|| new_cache_backend(&format!("{fresh}?inactive=1m")))
                .unwrap();
        assert_eq!(true, std::ptr::eq(live, tried));
        assert_eq!(vec![Some(Duration::from_secs(3600))], registered(&fresh));
    }

    #[test]
    fn test_memory_cache_max_size() {
        let parse =
            |value: &str| MemoryCacheParams::try_from(value).unwrap().max_size;

        assert_eq!(None, parse("memory://pingap"));
        assert_eq!(None, parse("memory://pingap?max_size="));
        // Whitespace is trimmed before the empty check, so it is unset.
        assert_eq!(None, parse("memory://pingap?max_size=%20%20"));

        // A bare number is a percentage of the budget.
        assert_eq!(Some(MaxSize::Percent(0)), parse("memory://?max_size=0"));
        assert_eq!(Some(MaxSize::Percent(20)), parse("memory://?max_size=20"));
        // A value with a unit is an absolute size, even a small one: `5mb`
        // used to be read as "5 percent" and clamped up to the whole budget.
        assert_eq!(
            Some(MaxSize::Bytes(5_000_000)),
            parse("memory://?max_size=5mb")
        );
        assert_eq!(
            Some(MaxSize::Bytes(100_000_000)),
            parse("memory://?max_size=100mb")
        );
        // The unit is matched without regard to case. `kb` is SI, `kib` is
        // a power of two.
        assert_eq!(
            Some(MaxSize::Bytes(1_000)),
            parse("memory://?max_size=1KB")
        );
        assert_eq!(
            Some(MaxSize::Bytes(1_024)),
            parse("memory://?max_size=1kib")
        );

        let budget = 1_000_000_000;
        assert_eq!(0, MaxSize::Percent(0).resolve(budget));
        assert_eq!(200_000_000, MaxSize::Percent(20).resolve(budget));
        // Percentages above 100 are clamped rather than overshooting.
        assert_eq!(budget, MaxSize::Percent(500).resolve(budget));
        assert_eq!(5_000_000, MaxSize::Bytes(5_000_000).resolve(budget));
    }

    /// A typo used to fall back to the defaults without a word.
    #[test]
    fn test_memory_cache_invalid_params() {
        assert_eq!(
            "memory cache mode tiny is invalid, expected normal or compact",
            new_cache_backend("memory://?mode=tiny")
                .err()
                .expect("error")
                .to_string()
        );
        assert_eq!(
            true,
            new_cache_backend("memory://?max_size=lots")
                .err()
                .expect("error")
                .to_string()
                .starts_with(
                    "memory cache params memory://?max_size=lots is invalid: "
                )
        );
        assert_eq!(
            true,
            MemoryCacheParams::try_from("memory://?mode=Compact")
                .unwrap()
                .cache_mode()
                .is_ok()
        );
    }

    #[test]
    fn test_resolve_memory_cache_size() {
        let gib = 1024 * 1024 * 1024;
        let mib = 1024 * 1024;

        // Large-RAM host (64 GiB): unset stays capped at 1 GiB, explicit >1 GiB
        // works up to safe ceiling (32 GiB), and >32 GiB clamps safely.
        let host_64g = 64 * gib;
        assert_eq!((gib, None), resolve_memory_cache_size(None, host_64g));
        assert_eq!(
            (8 * gib, None),
            resolve_memory_cache_size(Some(MaxSize::Bytes(8 * gib)), host_64g)
        );
        assert_eq!(
            (32 * gib, Some(40 * gib)),
            resolve_memory_cache_size(Some(MaxSize::Bytes(40 * gib)), host_64g)
        );
        assert_eq!(
            (16 * gib, None),
            resolve_memory_cache_size(Some(MaxSize::Percent(50)), host_64g)
        );

        // Constrained container (512 MiB): explicit 2 GiB clamps to 256 MiB so
        // TinyUFO never allocates beyond available memory at startup.
        let container_512m = 512 * mib;
        assert_eq!(
            (128 * mib, None),
            resolve_memory_cache_size(None, container_512m)
        );
        assert_eq!(
            (256 * mib, Some(2 * gib)),
            resolve_memory_cache_size(
                Some(MaxSize::Bytes(2 * gib)),
                container_512m
            )
        );

        // Unknown available memory (0): default 256 MB, safe ceiling 1 GiB.
        assert_eq!(
            (ByteSize::mb(256).as_u64() as usize, None),
            resolve_memory_cache_size(None, 0)
        );
        assert_eq!(
            (gib, Some(4 * gib)),
            resolve_memory_cache_size(Some(MaxSize::Bytes(4 * gib)), 0)
        );
    }

    #[tokio::test]
    async fn test_memory_backend_resize_and_retire() {
        let first = new_cache_backend("memory://?max_size=64kib").unwrap();
        let same = new_cache_backend("memory://?max_size=64kib").unwrap();
        assert_eq!(true, std::ptr::eq(first, same));
        assert_eq!(64 * 1024, first.max_size);

        first
            .cache
            .put(
                "k1",
                b"ns",
                CacheObject {
                    meta: (
                        bytes::Bytes::from_static(b"m1"),
                        bytes::Bytes::from_static(b"m2"),
                    ),
                    body: bytes::Bytes::from_static(b"hello"),
                },
            )
            .await
            .unwrap();
        assert_eq!(true, first.cache.get("k1", b"ns").await.unwrap().is_some());

        // Dry run validates without replacing or retiring the live backend.
        let tried =
            dry_run(|| new_cache_backend("memory://?max_size=128kib")).unwrap();
        assert_eq!(true, std::ptr::eq(first, tried));
        assert_eq!(true, first.cache.get("k1", b"ns").await.unwrap().is_some());

        // Changing max_size retires `first`'s storage and installs a new backend.
        let resized = new_cache_backend("memory://?max_size=128kib").unwrap();
        assert_eq!(false, std::ptr::eq(first, resized));
        assert_eq!(128 * 1024, resized.max_size);
        assert_eq!(true, first.cache.get("k1", b"ns").await.unwrap().is_none());

        // Changing mode also replaces the backend.
        let compact =
            new_cache_backend("memory://?max_size=128kib&mode=compact")
                .unwrap();
        assert_eq!(false, std::ptr::eq(resized, compact));
    }
}
