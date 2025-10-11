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

pub static LOG_TARGET: &str = "pingap::core";

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("invalid error, {message}"))]
    Invalid { message: String },
    #[snafu(display("plugin {category} not found"))]
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
pub use pingora_limits::inflight::*;
pub use pingora_limits::rate::*;
pub use plugin::*;
pub use service::*;
pub use tinyufo::TinyUfo;
pub use ttl_lru_limit::*;
pub use util::*;

#[allow(dead_code)]
#[cfg(test)]
fn new_get_session(
    headers: Vec<String>,
    url: String,
) -> std::sync::mpsc::Receiver<Option<pingora::proxy::Session>> {
    let (tx, rx) = std::sync::mpsc::sync_channel(0);
    std::thread::spawn(move || {
        match tokio::runtime::Runtime::new() {
            Ok(rt) => {
                let send = async move {
                    let headers = headers.join("\r\n");
                    let input_header =
                        format!("GET {url} HTTP/1.1\r\n{headers}\r\n\r\n");
                    let mock_io = tokio_test::io::Builder::new()
                        .read(input_header.as_bytes())
                        .build();

                    let mut session =
                        pingora::proxy::Session::new_h1(Box::new(mock_io));
                    session.read_request().await.unwrap();
                    let _ = tx.send(Some(session));
                };
                rt.block_on(send);
            },
            Err(_e) => {
                let _ = tx.send(None);
            },
        };
    });
    rx
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

    #[test]
    fn test_new_get_session() {
        let session = new_get_session(
            vec!["user-agent: pingap/0.1.1".to_string()],
            "https://github.com".to_string(),
        )
        .recv()
        .unwrap()
        .unwrap();
        assert_eq!(
            b"pingap/0.1.1",
            session.get_header("user-agent").unwrap().as_bytes()
        );
    }
}
