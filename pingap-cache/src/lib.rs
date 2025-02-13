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
use once_cell::sync::OnceCell;
// use pingap_config::get_current_config;
use snafu::Snafu;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
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
        pingap_core::new_internal_error(500, value.to_string())
    }
}

fn new_tiny_ufo_cache(size: usize) -> HttpCache {
    HttpCache {
        directory: None,
        cache: Arc::new(tiny::new_tiny_ufo_cache(size / PAGE_SIZE, size)),
    }
}
fn new_file_cache(dir: &str) -> Result<HttpCache> {
    let cache = file::new_file_cache(dir)?;
    Ok(HttpCache {
        directory: Some(cache.directory.clone()),
        cache: Arc::new(cache),
    })
}

static CACHE_BACKEND: OnceCell<HttpCache> = OnceCell::new();
const MAX_MEMORY_SIZE: usize = 100 * 1024 * 1024;
static CACHED_INIT: AtomicBool = AtomicBool::new(false);

/// Check if the cache backend has been initialized
pub fn is_cache_backend_init() -> bool {
    CACHED_INIT.load(Ordering::Relaxed)
}

pub struct CacheBackendOption {
    /// Directory to store cache files
    pub cache_directory: Option<String>,
    /// Maximum size of cache storage
    pub cache_max_size: Option<ByteSize>,
}

/// Get the cache backend
pub fn get_cache_backend(
    option: &CacheBackendOption,
) -> Result<&'static HttpCache> {
    // Get or initialize the global cache backend using OnceCell
    CACHE_BACKEND.get_or_try_init(|| {
        // let basic_conf = &get_current_config().basic;
        // Determine cache size from config or use default MAX_MEMORY_SIZE
        let mut size = if let Some(cache_max_size) = option.cache_max_size {
            cache_max_size.as_u64() as usize
        } else {
            MAX_MEMORY_SIZE
        };

        let mut cache_type = "memory";
        // Get optional cache directory from config
        let cache_directory =
            if let Some(cache_directory) = &option.cache_directory {
                cache_directory.trim().to_string()
            } else {
                "".to_string()
            };

        // Choose between file-based or memory-based cache
        let cache = if !cache_directory.is_empty() {
            // Use file-based cache if directory is specified
            cache_type = "file";
            new_file_cache(cache_directory.as_str()).map_err(|e| {
                Error::Invalid {
                    message: e.to_string(),
                }
            })?
        } else {
            // For memory cache, limit size to half of available physical memory
            // or fallback to 4GB if memory stats unavailable
            let max_memory = if let Some(value) = memory_stats() {
                value.physical_mem * 1024 / 2
            } else {
                ByteSize::gb(4).as_u64() as usize
            };
            size = size.min(max_memory);
            // Create memory-based tiny UFO cache
            new_tiny_ufo_cache(size)
        };
        CACHED_INIT.store(true, Ordering::Relaxed);

        // Log cache initialization details
        info!(
            category = LOG_CATEGORY,
            size = ByteSize::b(size as u64).to_string(),
            cache_type,
            "init cache backend success"
        );
        Ok(cache)
    })
}

pub use http_cache::{new_storage_clear_service, HttpCache};

#[cfg(feature = "full")]
mod prom;
#[cfg(feature = "full")]
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
    fn test_is_cache_backend_init() {
        assert_eq!(false, is_cache_backend_init());
    }
    #[test]
    fn test_cache() {
        let _ = new_tiny_ufo_cache(1024);

        let dir = TempDir::new().unwrap();
        let result = new_file_cache(&dir.into_path().to_string_lossy());
        assert_eq!(true, result.is_ok());
    }
}
