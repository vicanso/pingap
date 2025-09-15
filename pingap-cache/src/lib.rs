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
use once_cell::sync::Lazy;
use once_cell::sync::OnceCell;
use pingap_core::parse_query_string;
use snafu::Snafu;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;
use tracing::info;

mod file;
mod http_cache;
mod tiny;

pub static PAGE_SIZE: usize = 4096;

/// Category name for cache related logging
pub static LOG_CATEGORY: &str = "cache";

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
    HttpCache {
        directory: None,
        cache: Arc::new(tiny::new_tiny_ufo_cache(mode, size / PAGE_SIZE, size)),
        max_size: size as u64,
    }
}
fn new_file_cache(dir: &str) -> Result<HttpCache> {
    let cache = file::new_file_cache(dir)?;
    Ok(HttpCache {
        directory: Some(cache.directory.clone()),
        cache: Arc::new(cache),
        max_size: 0,
    })
}

struct CacheBackendProvider {
    cache_backends: Mutex<HashMap<String, &'static HttpCache>>,
}

static BACKENDS: Lazy<CacheBackendProvider> =
    Lazy::new(|| CacheBackendProvider {
        cache_backends: Mutex::new(HashMap::new()),
    });

static MEMORY_BACKEND: OnceCell<HttpCache> = OnceCell::new();

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

fn try_init_memory_backend(value: &str) -> &'static HttpCache {
    MEMORY_BACKEND.get_or_init(|| {
        let query = parse_query_string(value);
        let cache_max_size = query.get("max_size");
        let available_memory =
            AVAILABLE_MEMORY.load(Ordering::Relaxed) as usize;
        let max_memory = if available_memory > 0 {
            available_memory / 2
        } else {
            ByteSize::mb(256).as_u64() as usize
        };

        // Determine cache size from config or use default MAX_MEMORY_SIZE
        let mut size = if let Some(cache_max_size) = cache_max_size {
            if let Ok(value) = cache_max_size.parse::<u8>() {
                max_memory * (value.min(100) as usize) / 100
            } else {
                ByteSize::from_str(cache_max_size)
                    .map(|item| item.as_u64() as usize)
                    .unwrap_or(max_memory)
            }
        } else {
            max_memory
        };

        let cache_mode = query.get("mode").cloned().unwrap_or_default();

        size = size.min(MAX_MEMORY_SIZE);
        info!(
            category = LOG_CATEGORY,
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
        category = LOG_CATEGORY,
        inactive = cache.cache.inactive().map(|v| v.as_secs()),
        "init file cache backend success"
    );

    let cache_ref: &'static HttpCache = Box::leak(Box::new(cache));
    cache_backends.insert(directory.to_string(), cache_ref);

    Ok(cache_ref)
}

pub use http_cache::{new_storage_clear_service, HttpCache};

#[cfg(feature = "tracing")]
mod prom;
#[cfg(feature = "tracing")]
pub use prom::{CACHE_READING_TIME, CACHE_WRITING_TIME};

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
}
