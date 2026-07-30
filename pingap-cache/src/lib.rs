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
use std::sync::OnceLock;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use tracing::info;

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

fn new_tiny_ufo_cache(mode: &str, size: usize) -> HttpCache {
    let mode = CacheMode::from_str(mode).unwrap_or_default();
    HttpCache {
        directory: None,
        cache: Arc::new(tiny::TinyUfoCache::new(mode, size / PAGE_SIZE, size)),
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

struct CacheBackendProvider {
    cache_backends: Mutex<HashMap<String, &'static HttpCache>>,
}

static BACKENDS: LazyLock<CacheBackendProvider> =
    LazyLock::new(|| CacheBackendProvider {
        cache_backends: Mutex::new(HashMap::new()),
    });

static MEMORY_BACKEND: OnceLock<HttpCache> = OnceLock::new();

const MAX_MEMORY_SIZE: usize = 1024 * 1024 * 1024;

pub(crate) fn get_file_backends() -> Vec<&'static HttpCache> {
    if let Ok(backends) = BACKENDS.cache_backends.lock() {
        backends.values().copied().collect()
    } else {
        Vec::new()
    }
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
                message: e.to_string(),
            })?
        } else {
            MemoryCacheParams::default()
        };
        Ok(params)
    }
}

fn try_init_memory_backend(value: &str) -> &'static HttpCache {
    MEMORY_BACKEND.get_or_init(|| {
        let params = MemoryCacheParams::try_from(value).unwrap_or_default();
        let available_memory =
            AVAILABLE_MEMORY.load(Ordering::Relaxed) as usize;
        let max_memory = if available_memory > 0 {
            available_memory / 4
        } else {
            ByteSize::mb(256).as_u64() as usize
        };

        // Determine cache size from config, or take the whole budget
        let mut size = params
            .max_size
            .map(|max_size| max_size.resolve(max_memory))
            .unwrap_or(max_memory);

        let cache_mode = params.mode.unwrap_or_default();

        size = size.min(MAX_MEMORY_SIZE);
        info!(
            target: LOG_TARGET,
            size = ByteSize(size as u64).to_string(),
            cache_mode,
            "init memory cache backend success"
        );
        new_tiny_ufo_cache(&cache_mode, size)
    })
}

pub fn new_cache_backend(directory: &str) -> Result<&'static HttpCache> {
    if directory.is_empty() || directory.starts_with("memory://") {
        return Ok(try_init_memory_backend(directory));
    }
    let mut cache_backends =
        BACKENDS.cache_backends.lock().map_err(|e| Error::Invalid {
            message: e.to_string(),
        })?;
    if let Some(backend) = cache_backends.get(directory) {
        return Ok(backend);
    }

    // Use file-based cache if directory is specified
    let cache = new_file_cache(directory).map_err(|e| Error::Invalid {
        message: e.to_string(),
    })?;
    info!(
        target: LOG_TARGET,
        inactive = cache.cache.inactive().map(|v| v.as_secs()),
        "init file cache backend success"
    );

    let cache_ref: &'static HttpCache = Box::leak(Box::new(cache));
    cache_backends.insert(directory.to_string(), cache_ref);

    Ok(cache_ref)
}

pub use http_cache::{CacheObject, HttpCache, new_storage_clear_service};

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
    }

    #[test]
    fn test_cache() {
        let _ = new_tiny_ufo_cache("compact", 1024);

        let dir = TempDir::new().unwrap();
        let result = new_file_cache(&dir.keep().to_string_lossy());
        assert_eq!(true, result.is_ok());
    }

    #[test]
    fn test_memory_cache_max_size() {
        let parse =
            |value: &str| MemoryCacheParams::try_from(value).unwrap().max_size;

        assert_eq!(None, parse("memory://pingap"));
        assert_eq!(None, parse("memory://pingap?max_size="));

        // A bare number is a percentage of the budget.
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

        let budget = 1_000_000_000;
        assert_eq!(200_000_000, MaxSize::Percent(20).resolve(budget));
        // Percentages above 100 are clamped rather than overshooting.
        assert_eq!(budget, MaxSize::Percent(500).resolve(budget));
        assert_eq!(5_000_000, MaxSize::Bytes(5_000_000).resolve(budget));
    }
}
