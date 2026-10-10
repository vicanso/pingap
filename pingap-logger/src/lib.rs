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
mod filter;
#[cfg(unix)]
mod syslog;
mod target;
mod writer;

const LOG_TARGET: &str = "pingap::logger";

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("IO error {source}"))]
    Io { source: std::io::Error },
    #[snafu(display("Invalid {message}"))]
    Invalid { message: String },
}

/// The level of the log where nothing names one.
pub const DEFAULT_LOG_LEVEL: &str = "INFO";

/// The level the log has without one of its own: what `RUST_LOG` says,
/// and `INFO` where that says nothing.
///
/// An empty `RUST_LOG` is one that says nothing. Taken for a level, the
/// log had no directive at all, which to the filter means errors only.
pub fn default_log_level() -> String {
    std::env::var("RUST_LOG")
        .ok()
        .filter(|level| !level.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_LOG_LEVEL.to_string())
}

/// The filter of the application log for `level` (`basic.log_level`),
/// which may name targets as `RUST_LOG` does.
///
/// An empty one is no level, and the log then has its default
/// ([`default_log_level`]). It used to be given no directive, and a filter
/// without one passes errors only: taking `log_level` out of the
/// configuration silenced everything else at the next reload, the access
/// log lines that go to the application log among it.
pub fn new_env_filter(level: &str) -> EnvFilter {
    let default;
    let level = if level.trim().is_empty() {
        default = default_log_level();
        default.as_str()
    } else {
        level
    };
    let mut initial_filter = EnvFilter::from_default_env();
    for item in level.split(',').map(str::trim).filter(|s| !s.is_empty()) {
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
pub use file_appender::LogFiles;
pub use filter::AccessLogFilter;
pub use writer::*;

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::level_filters::LevelFilter;
    use tracing_subscriber::layer::Filter;

    /// No level is the default one, not the filter's own "errors only".
    /// Regression: `log_level` taken out of the configuration left the
    /// log with errors alone at the next reload, and so did every restart
    /// of a process that was started without `RUST_LOG`.
    #[test]
    fn test_env_filter_of_no_level() {
        let hint = |level: &str| {
            Filter::<tracing_subscriber::Registry>::max_level_hint(
                &new_env_filter(level),
            )
        };
        // A `RUST_LOG` of the test run is a part of every filter: there
        // is nothing to hold these to with one set.
        let of_env = std::env::var("RUST_LOG")
            .ok()
            .filter(|level| !level.trim().is_empty());
        if of_env.is_none() {
            assert_eq!(Some(LevelFilter::DEBUG), hint("debug"));
            assert_eq!(Some(LevelFilter::ERROR), hint("error"));
            assert_eq!("INFO", default_log_level());
            assert_eq!(Some(LevelFilter::INFO), hint(""));
            assert_eq!(Some(LevelFilter::INFO), hint("  "));
        }
    }
}
