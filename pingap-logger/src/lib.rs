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

use snafu::Snafu;
use tracing::error;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::Directive;

mod access;
mod async_logger;
mod file_appender;
#[cfg(unix)]
mod syslog;
mod writer;

const LOG_TARGET: &str = "pingap::logger";

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("IO error {source}"))]
    Io { source: std::io::Error },
    #[snafu(display("Invalid {message}"))]
    Invalid { message: String },
}

pub fn new_env_filter(level: &str) -> EnvFilter {
    let mut initial_filter = EnvFilter::from_default_env();
    for item in level.split(",") {
        match item.parse::<Directive>() {
            Ok(directive) => {
                initial_filter = initial_filter.add_directive(directive);
            },
            Err(e) => {
                error!(
                    target: LOG_TARGET,
                    error = e.to_string(),
                    "parse directive fail"
                );
            },
        };
    }
    initial_filter
}

pub use access::*;
pub use async_logger::*;
pub use writer::*;
