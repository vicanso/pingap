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
use pingap_core::convert_query_map;
use snafu::Snafu;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

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

const MAX_MEMORY_SIZE: usize = 100 * 1024 * 1024;
static CACHED_INIT: AtomicBool = AtomicBool::new(false);

/// Check if the cache backend has been initialized
pub fn is_cache_backend_init() -> bool {
    CACHED_INIT.load(Ordering::Relaxed)
}

#[derive(Debug, Default)]
pub struct CacheBackendOption {
    /// Directory to store cache files
    pub cache_directory: Option<String>,
    /// Maximum size of cache storage
    pub cache_max_size: Option<ByteSize>,
}

pub struct CacheBackend {
    pub cache: HttpCache,
    pub cache_type: String,
    pub size: usize,
    pub cache_mode: String,
}

pub fn new_cache_backend(option: CacheBackendOption) -> Result<CacheBackend> {
    // Determine cache size from config or use default MAX_MEMORY_SIZE
    let mut size = if let Some(cache_max_size) = option.cache_max_size {
        cache_max_size.as_u64() as usize
    } else {
        MAX_MEMORY_SIZE
    };

    let mut cache_type = "memory";
    let mut cache_mode = "".to_string();
    // Get optional cache directory from config
    let cache_directory = if let Some(cache_directory) = &option.cache_directory
    {
        cache_directory.trim().to_string()
    } else {
        "".to_string()
    };

    // Choose between file-based or memory-based cache
    let cache = if !cache_directory.is_empty()
        && !cache_directory.starts_with("memory://")
    {
        // Use file-based cache if directory is specified
        cache_type = "file";
        new_file_cache(cache_directory.as_str()).map_err(|e| {
            Error::Invalid {
                message: e.to_string(),
            }
        })?
    } else {
        // For memory cache, limit size to half of available physical memory
        // or fallback to 256MB if memory stats unavailable
        let max_memory = if let Some(value) = memory_stats() {
            value.physical_mem * 1024 / 2
        } else {
            ByteSize::mb(256).as_u64() as usize
        };

        if let Some((_, query)) = cache_directory.split_once('?') {
            let query_map = convert_query_map(query);
            cache_mode = query_map.get("mode").cloned().unwrap_or_default();
        }

        size = size.min(max_memory);
        // Create memory-based tiny UFO cache
        new_tiny_ufo_cache(&cache_mode, size)
    };

    Ok(CacheBackend {
        cache,
        cache_type: cache_type.to_string(),
        size,
        cache_mode: cache_mode.to_string(),
    })
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
