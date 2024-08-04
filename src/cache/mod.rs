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
        cached: Arc::new(tiny::new_tiny_ufo_cache(size / 1024, size / 1024)),
    }
}
pub fn new_file_cache(dir: &str) -> Result<HttpCache> {
    Ok(HttpCache {
        cached: Arc::new(file::new_file_cache(dir)?),
    })
}

pub use http_cache::HttpCache;
