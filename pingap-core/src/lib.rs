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

pub static LOG_CATEGORY: &str = "core";

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("invalid error, {message}"))]
    Invalid { message: String },
    #[snafu(display("plugin {category} not found"))]
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

mod ctx;
mod http_header;
mod http_response;
mod notification;
mod plugin;
mod service;
mod ttl_lru_limit;
mod util;

pub use ctx::*;
pub use http_header::*;
pub use http_response::*;
pub use notification::*;
pub use pingora_limits::inflight::*;
pub use pingora_limits::rate::*;
pub use plugin::*;
pub use service::*;
pub use tinyufo::TinyUfo;
pub use ttl_lru_limit::*;
pub use util::*;

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
