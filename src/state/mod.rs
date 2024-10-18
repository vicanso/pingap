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

use snafu::Snafu;

mod ctx;
mod process;
#[cfg(feature = "full")]
mod prom;
pub use ctx::*;
pub use process::*;
#[cfg(feature = "full")]
pub use prom::{
    new_prometheus, new_prometheus_push_service, Prometheus,
    CACHE_READING_TIME, CACHE_WRITING_TIME,
};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("{source}"))]
    Url { source: url::ParseError },
    #[snafu(display("{message}"))]
    Prometheus { message: String },
}
pub type Result<T, E = Error> = std::result::Result<T, E>;
