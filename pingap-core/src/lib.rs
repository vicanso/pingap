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

static LOG_TARGET: &str = "pingap::core";

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("invalid error, {message}"))]
    Invalid { message: String },
    #[snafu(display("{category} not found"))]
    NotFound { category: String },
}

/// Creates a new internal error
pub fn new_internal_error(
    status: u16,
    message: impl ToString,
) -> pingora::BError {
    pingora::Error::because(
        pingora::ErrorType::HTTPStatus(status),
        message.to_string(),
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
pub use pingora_limits::inflight::{Guard, Inflight};
pub use pingora_limits::rate::Rate;
pub use plugin::*;
pub use service::*;
pub use tinyufo::TinyUfo;
pub use ttl_lru_limit::*;
pub use util::*;

/// Builds an HTTP/1 session that has read `GET <url>` with `headers`, for
/// tests that need a real `Session` without a socket.
#[cfg(test)]
pub(crate) async fn new_test_session(
    headers: &[&str],
    url: &str,
) -> pingora::proxy::Session {
    let headers = headers.join("\r\n");
    let input_header = format!("GET {url} HTTP/1.1\r\n{headers}\r\n\r\n");
    let mock_io = tokio_test::io::Builder::new()
        .read(input_header.as_bytes())
        .build();
    let mut session = pingora::proxy::Session::new_h1(Box::new(mock_io));
    session
        .read_request()
        .await
        .expect("the test request must parse");
    session
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_internal_error() {
        let err = new_internal_error(500, "Internal Server Error");
        assert_eq!(
            err.to_string().trim(),
            "HTTPStatus context: Internal Server Error cause:  InternalError"
        );
    }

    #[tokio::test]
    async fn test_new_test_session() {
        let session = new_test_session(
            &["Host: github.com", "user-agent: pingap/0.1.1"],
            "/",
        )
        .await;
        assert_eq!(
            b"pingap/0.1.1",
            session.get_header("user-agent").unwrap().as_bytes()
        );
        assert_eq!("/", session.req_header().uri.path());
    }
}
