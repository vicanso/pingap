// Copyright 2024 Tree xie.
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

use crate::util;
use snafu::Snafu;
use std::sync::Arc;

mod file;
mod http_cache;
mod tiny;

pub static PAGE_SIZE: usize = 4096;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Io error: {source}"))]
    Io { source: std::io::Error },
    #[snafu(display("{message}"))]
    Invalid { message: String },
    #[snafu(display("Over quota error, max: {max}, {message}"))]
    OverQuota { max: u32, message: String },
}
pub type Result<T, E = Error> = std::result::Result<T, E>;

impl From<Error> for pingora::BError {
    fn from(value: Error) -> Self {
        util::new_internal_error(500, value.to_string())
    }
}

pub fn new_tiny_ufo_cache(size: usize) -> HttpCache {
    HttpCache {
        directory: None,
        cached: Arc::new(tiny::new_tiny_ufo_cache(size / PAGE_SIZE, size)),
    }
}
pub fn new_file_cache(dir: &str) -> Result<HttpCache> {
    let cache = file::new_file_cache(dir)?;
    Ok(HttpCache {
        directory: Some(cache.directory.clone()),
        cached: Arc::new(cache),
    })
}

pub use http_cache::{new_file_storage_clear_service, HttpCache};

#[cfg(test)]
mod tests {
    use super::{new_file_cache, new_tiny_ufo_cache, Error};
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
        let _ = new_tiny_ufo_cache(1024);

        let dir = TempDir::new().unwrap();
        let result = new_file_cache(&dir.into_path().to_string_lossy());
        assert_eq!(true, result.is_ok());
    }
}
