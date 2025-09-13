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
use memory_stats::memory_stats;
use once_cell::sync::Lazy;
use once_cell::sync::OnceCell;
use pingap_core::convert_query_map;
use snafu::Snafu;
use std::collections::HashMap;
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
    }
}
fn new_file_cache(dir: &str) -> Result<HttpCache> {
    let cache = file::new_file_cache(dir)?;
    Ok(HttpCache {
        directory: Some(cache.directory.clone()),
        cache: Arc::new(cache),
    })
}

#[derive(Debug, Default)]
pub struct CacheBackendOption {
    /// Directory to store cache files
    pub cache_directory: Option<String>,
    pub cache_max_size: Option<ByteSize>,
}

struct CacheBackendProvider {
    cache_backends: Mutex<HashMap<String, &'static HttpCache>>,
}

static BACKENDS: Lazy<CacheBackendProvider> =
    Lazy::new(|| CacheBackendProvider {
        cache_backends: Mutex::new(HashMap::new()),
    });

static MEMORY_BACKEND: OnceCell<HttpCache> = OnceCell::new();

const MAX_MEMORY_SIZE: usize = 100 * 1024 * 1024;

fn try_init_memory_backend(
    cache_directory: &str,
    cache_max_size: Option<ByteSize>,
) -> &'static HttpCache {
    MEMORY_BACKEND.get_or_init(|| {
        // Determine cache size from config or use default MAX_MEMORY_SIZE
        let mut size = if let Some(cache_max_size) = cache_max_size {
            cache_max_size.as_u64() as usize
        } else {
            MAX_MEMORY_SIZE
        };
        let max_memory = if let Some(value) = memory_stats() {
            value.physical_mem * 1024 / 2
        } else {
            ByteSize::mb(256).as_u64() as usize
        };
        let mut cache_mode = "".to_string();

        if let Some((_, query)) = cache_directory.split_once('?') {
            let query_map = convert_query_map(query);
            cache_mode = query_map.get("mode").cloned().unwrap_or_default();
        }

        size = size.min(max_memory);
        info!(
            category = LOG_CATEGORY,
            size, cache_mode, "init memory cache backend success"
        );
        new_tiny_ufo_cache(&cache_mode, size)
    })
}

pub fn new_cache_backend(
    option: CacheBackendOption,
) -> Result<&'static HttpCache> {
    // Get optional cache directory from config
    let cache_directory = if let Some(cache_directory) = &option.cache_directory
    {
        cache_directory.trim().to_string()
    } else {
        "".to_string()
    };

    if cache_directory.is_empty() || cache_directory.starts_with("memory://") {
        return Ok(try_init_memory_backend(
            cache_directory.as_str(),
            option.cache_max_size,
        ));
    }
    let mut cache_backends =
        BACKENDS.cache_backends.lock().map_err(|e| Error::Invalid {
            message: e.to_string(),
        })?;
    if let Some(backend) = cache_backends.get(&cache_directory) {
        return Ok(backend);
    }

    // Use file-based cache if directory is specified
    let cache =
        new_file_cache(&cache_directory).map_err(|e| Error::Invalid {
            message: e.to_string(),
        })?;
    info!(
        category = LOG_CATEGORY,
        inactive = cache.cache.inactive().map(|v| v.as_secs()),
        "init file cache backend success"
    );

    let cache_ref: &'static HttpCache = Box::leak(Box::new(cache));
    cache_backends.insert(cache_directory, cache_ref);

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
