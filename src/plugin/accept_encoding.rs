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

use super::{get_bool_conf, get_hash_key, get_str_conf, Error, Plugin, Result};
use crate::config::{PluginConf, PluginStep};
use crate::http_extra::HttpResponse;
use crate::state::State;
use async_trait::async_trait;
use pingora::proxy::Session;
use smallvec::SmallVec;
use tracing::debug;

/// A plugin that filters and modifies the Accept-Encoding header of incoming HTTP requests.
/// It ensures that only supported compression algorithms are passed to upstream servers.
pub struct AcceptEncoding {
    /// List of supported compression encodings (e.g., "gzip", "br", "zstd").
    /// These encodings are matched against the client's Accept-Encoding header.
    /// Only encodings present in this list will be preserved in the request.
    encodings: Vec<String>,

    /// Controls whether multiple encodings can be forwarded to the upstream server.
    /// - When `Some(true)`: Only the first matching encoding will be used
    /// - When `Some(false)`: All matching encodings will be included
    /// - When `None`: Behaves the same as `Some(false)`
    only_one_encoding: Option<bool>,

    /// A unique identifier for this plugin instance.
    /// Used for internal tracking and debugging purposes.
    hash_value: String,

    /// Specifies the phase in the request processing pipeline when this plugin should execute.
    /// This plugin typically runs in the EarlyRequest phase to modify headers before forwarding.
    plugin_step: PluginStep,
}

impl TryFrom<&PluginConf> for AcceptEncoding {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);
        let only_one_encoding = get_bool_conf(value, "only_one_encoding");
        let mut encodings = vec![];
        for encoding in get_str_conf(value, "encodings").split(",") {
            let v = encoding.trim();
            if !v.is_empty() {
                encodings.push(v.to_string());
            }
        }

        Ok(Self {
            encodings,
            only_one_encoding: Some(only_one_encoding),
            hash_value,
            plugin_step: PluginStep::EarlyRequest,
        })
    }
}

impl AcceptEncoding {
    /// Creates a new AcceptEncoding plugin instance from the provided configuration.
    ///
    /// # Arguments
    /// * `params` - Plugin configuration containing encoding settings
    ///
    /// # Returns
    /// * `Result<Self>` - A new AcceptEncoding instance or an error if configuration is invalid
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new accept encoding plugin");
        Self::try_from(params)
    }
}

#[async_trait]
impl Plugin for AcceptEncoding {
    /// Returns the unique hash key for this plugin instance
    #[inline]
    fn hash_key(&self) -> String {
        self.hash_value.clone()
    }

    /// Processes the HTTP request by filtering the Accept-Encoding header.
    ///
    /// # Arguments
    /// * `step` - Current plugin processing step
    /// * `session` - HTTP session containing request/response data
    /// * `_ctx` - State context (unused in this implementation)
    ///
    /// # Returns
    /// * `pingora::Result<Option<HttpResponse>>` - None if processing should continue,
    ///   or a response if the request should be terminated
    #[inline]
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        _ctx: &mut State,
    ) -> pingora::Result<Option<HttpResponse>> {
        // Skip if not in the correct plugin step
        if step != self.plugin_step {
            return Ok(None);
        }
        let header = session.req_header_mut();

        // Get the Accept-Encoding header from the request
        let Some(accept_encoding) =
            header.headers.get(http::header::ACCEPT_ENCODING)
        else {
            return Ok(None);
        };
        let accept_encoding = accept_encoding.to_str().unwrap_or_default();

        let only_one_encoding = self.only_one_encoding.unwrap_or_default();
        let mut new_accept_encodings: SmallVec<[String; 3]> =
            SmallVec::with_capacity(self.encodings.len());

        // Filter the accepted encodings based on our supported list
        for encoding in self.encodings.iter() {
            // If only_one_encoding is true, stop after finding the first match
            if only_one_encoding && !new_accept_encodings.is_empty() {
                break;
            }
            // Add encoding if it's in the Accept-Encoding header
            if accept_encoding.contains(encoding) {
                new_accept_encodings.push(encoding.to_string());
            }
        }

        // Remove the header if no supported encodings found
        // Otherwise, set the header to our filtered list
        if new_accept_encodings.is_empty() {
            header.remove_header(&http::header::ACCEPT_ENCODING);
        } else {
            let _ = header.insert_header(
                http::header::ACCEPT_ENCODING,
                new_accept_encodings.join(", "),
            );
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::AcceptEncoding;
    use crate::state::State;
    use crate::{config::PluginConf, config::PluginStep, plugin::Plugin};
    use pingora::modules::http::HttpModules;
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    #[test]
    fn test_accept_encoding_params() {
        let params = AcceptEncoding::try_from(
            &toml::from_str::<PluginConf>(
                r###"
encodings = "zstd, br, gzip"
only_one_encoding = true
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!("zstd,br,gzip", params.encodings.join(","));
        assert_eq!(true, params.only_one_encoding.unwrap_or_default());
    }

    #[tokio::test]
    async fn test_accept_conding() {
        let accept_encoding = AcceptEncoding::try_from(
            &toml::from_str::<PluginConf>(
                r###"
encodings = "zstd, br, gzip"
only_one_encoding = true
"###,
            )
            .unwrap(),
        )
        .unwrap();

        // zstd
        let headers = ["Accept-Encoding: gzip, zstd"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1_with_modules(
            Box::new(mock_io),
            &HttpModules::new(),
        );
        session.read_request().await.unwrap();
        let _ = accept_encoding
            .handle_request(
                PluginStep::EarlyRequest,
                &mut session,
                &mut State::default(),
            )
            .await
            .unwrap();

        assert_eq!(
            "zstd",
            session
                .req_header()
                .headers
                .get("Accept-Encoding")
                .unwrap()
                .to_str()
                .unwrap()
        );

        // multi accept encoding
        let accept_encoding = AcceptEncoding::try_from(
            &toml::from_str::<PluginConf>(
                r###"
encodings = "zstd, br, gzip"
"###,
            )
            .unwrap(),
        )
        .unwrap();
        let headers = ["Accept-Encoding: gzip, br, zstd"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1_with_modules(
            Box::new(mock_io),
            &HttpModules::new(),
        );
        session.read_request().await.unwrap();
        let _ = accept_encoding
            .handle_request(
                PluginStep::EarlyRequest,
                &mut session,
                &mut State::default(),
            )
            .await
            .unwrap();

        assert_eq!(
            "zstd, br, gzip",
            session
                .req_header()
                .headers
                .get("Accept-Encoding")
                .unwrap()
                .to_str()
                .unwrap()
        );

        let headers = ["Accept-Encoding: snappy"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1_with_modules(
            Box::new(mock_io),
            &HttpModules::new(),
        );
        session.read_request().await.unwrap();
        let _ = accept_encoding
            .handle_request(
                PluginStep::EarlyRequest,
                &mut session,
                &mut State::default(),
            )
            .await
            .unwrap();

        assert_eq!(
            true,
            session
                .req_header()
                .headers
                .get("Accept-Encoding")
                .is_none()
        );
    }
}
