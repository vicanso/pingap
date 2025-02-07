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

mod process;

pub use process::*;

#[cfg(feature = "full")]
use snafu::Snafu;
#[cfg(feature = "full")]
#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("{source}"))]
    Url { source: url::ParseError },
    #[snafu(display("{message}"))]
    Prometheus { message: String },
}
#[cfg(feature = "full")]
pub type Result<T, E = Error> = std::result::Result<T, E>;

pub const LOG_CATEGORY: &str = "performance";

#[cfg(feature = "full")]
mod prom;
#[cfg(feature = "full")]
pub use prom::{
    new_prometheus, new_prometheus_push_service, Prometheus,
    CACHE_READING_TIME, CACHE_WRITING_TIME,
};
