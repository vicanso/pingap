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

use once_cell::sync::Lazy;
use snafu::Snafu;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub static LOG_CATEGORY: &str = "core";

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Invalid error: {message}"))]
    Invalid { message: String },
    #[snafu(display("Plugin {category} not found"))]
    NotFound { category: String },
}

/// Creates a new internal error
pub fn new_internal_error(status: u16, message: String) -> pingora::BError {
    pingora::Error::because(
        pingora::ErrorType::HTTPStatus(status),
        message,
        pingora::Error::new(pingora::ErrorType::InternalError),
    )
}

// 2022-05-07: 1651852800
// const SUPER_TIMESTAMP: u64 = 1651852800;
static SUPER_TIMESTAMP: Lazy<SystemTime> = Lazy::new(|| {
    UNIX_EPOCH
        .checked_add(Duration::from_secs(1651852800))
        .unwrap_or(SystemTime::now())
});

/// Returns the number of seconds elapsed since SUPER_TIMESTAMP
/// Returns 0 if the current time is before SUPER_TIMESTAMP
pub fn get_super_ts() -> u32 {
    if let Ok(value) = SystemTime::now().duration_since(*SUPER_TIMESTAMP) {
        value.as_secs() as u32
    } else {
        0
    }
}

static HOST_NAME: Lazy<String> = Lazy::new(|| {
    hostname::get()
        .unwrap_or_default()
        .to_str()
        .unwrap_or_default()
        .to_string()
});

/// Returns the system hostname.
///
/// Returns:
/// * `&'static str` - The system's hostname as a string slice
pub fn get_hostname() -> &'static str {
    HOST_NAME.as_str()
}

#[inline]
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

mod ctx;
mod http_header;
mod http_response;
mod notification;
mod plugin;
mod service;
mod ttl_lru_limit;

pub use ctx::*;
pub use http_header::*;
pub use http_response::*;
pub use notification::*;
pub use plugin::*;
pub use service::*;
pub use ttl_lru_limit::*;
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_internal_error() {
        let err = new_internal_error(500, "Internal Server Error".to_string());
        assert_eq!(
            err.to_string().trim(),
            "HTTPStatus context: Internal Server Error cause:  InternalError"
        );
    }
}
