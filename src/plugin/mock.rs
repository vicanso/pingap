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

use super::{get_str_conf, Error, Plugin, Result};
use crate::config::{PluginCategory, PluginConf, PluginStep};
use crate::http_extra::{convert_headers, HttpResponse};
use crate::plugin::{get_hash_key, get_int_conf, get_str_slice_conf};
use crate::state::State;
use async_trait::async_trait;
use http::StatusCode;
use humantime::parse_duration;
use pingora::proxy::Session;
use std::time::Duration;
use tokio::time::sleep;
use tracing::debug;

/// MockResponse provides a configurable way to return mock HTTP responses for testing and development.
/// It can match specific paths and introduce artificial delays to simulate various scenarios.
pub struct MockResponse {
    /// The URL path to match against incoming requests.
    /// - If empty string: matches all paths
    /// - If set: must exactly match the request path
    ///     Example: "/api/users" will only mock requests to that exact path
    pub path: String,

    /// Determines at which point in the request lifecycle this mock should execute.
    /// Only supports two phases:
    /// - Request: Early in the cycle, before any upstream processing
    /// - ProxyUpstream: Just before the request would be sent to the upstream server
    ///     This allows testing different failure scenarios and response behaviors
    pub plugin_step: PluginStep,

    /// The pre-configured HTTP response that will be returned when this mock is triggered.
    /// Contains:
    /// - status: HTTP status code (defaults to 200 OK)
    /// - headers: Optional response headers
    /// - body: Response body content
    ///     This response is constructed once during initialization for better performance
    pub resp: HttpResponse,

    /// Optional artificial delay before sending the mock response.
    /// Useful for:
    /// - Testing timeout handling
    /// - Simulating slow network conditions
    /// - Load testing with controlled response times
    ///     Format: Standard Duration (e.g., 500ms, 1s, 1m)
    pub delay: Option<Duration>,

    /// Unique identifier for this plugin instance.
    /// - Generated from the plugin configuration
    /// - Used internally for plugin management
    /// - Not exposed publicly as it's an implementation detail
    hash_value: String,
}

impl MockResponse {
    /// Creates a new mock response handler from a plugin configuration.
    ///
    /// # Parameters
    /// - params: PluginConf containing the following optional fields:
    ///   - path: String - URL path to match
    ///   - status: int - HTTP status code (defaults to 200 OK if not specified)
    ///   - headers: []string - Response headers in "Key: Value" format
    ///   - data: string - Response body content
    ///   - delay: string - Human-readable duration (e.g., "500ms", "1s") to delay response
    ///
    /// # Returns
    /// Result<MockResponse> - Configured mock handler or error if configuration is invalid
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new mock plugin");

        // Generate unique hash for this configuration
        let hash_value = get_hash_key(params);

        // Extract all configuration parameters
        let path = get_str_conf(params, "path"); // Path to match (empty = match all)
        let status = get_int_conf(params, "status") as u16; // HTTP status code
        let headers = get_str_slice_conf(params, "headers"); // Response headers
        let data = get_str_conf(params, "data"); // Response body

        // Parse delay duration if specified
        // Supports human-readable formats like "500ms", "1s", "1m"
        let delay = get_str_conf(params, "delay");
        let delay = if !delay.is_empty() {
            let d = parse_duration(&delay).map_err(|e| Error::Invalid {
                category: PluginCategory::Mock.to_string(),
                message: e.to_string(),
            })?;
            Some(d)
        } else {
            None
        };

        // Construct the HTTP response with defaults
        let mut resp = HttpResponse {
            status: StatusCode::OK, // Default to 200 OK
            body: data.into(),
            ..Default::default()
        };

        // Override status code if specified
        if status > 0 {
            resp.status =
                StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
        }

        // Add headers if specified
        if !headers.is_empty() {
            if let Ok(headers) = convert_headers(&headers) {
                resp.headers = Some(headers);
            }
        }

        Ok(MockResponse {
            hash_value,
            resp,
            plugin_step: PluginStep::Request,
            path,
            delay,
        })
    }
}

#[async_trait]
impl Plugin for MockResponse {
    /// Returns the unique identifier for this plugin instance
    #[inline]
    fn hash_key(&self) -> String {
        self.hash_value.clone()
    }

    /// Handles incoming requests and returns mock responses when appropriate.
    ///
    /// # Parameters
    /// - step: Current execution phase
    /// - session: Contains request details including URL path
    /// - _ctx: State context (unused in mock plugin)
    ///
    /// # Returns
    /// - Ok(None) if request should proceed normally
    /// - Ok(Some(HttpResponse)) to return mock response
    /// - Err(...) if processing fails
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        _ctx: &mut State,
    ) -> pingora::Result<Option<HttpResponse>> {
        // Only process if we're in the correct execution phase
        if step != self.plugin_step {
            return Ok(None);
        }

        // Check if request path matches our configured path (if any)
        if !self.path.is_empty() && session.req_header().uri.path() != self.path
        {
            return Ok(None);
        }

        // Implement artificial delay if configured
        if let Some(d) = self.delay {
            sleep(d).await;
        }

        // Return our pre-configured mock response
        Ok(Some(self.resp.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::MockResponse;
    use crate::state::State;
    use crate::{config::PluginConf, config::PluginStep, plugin::Plugin};
    use bytes::Bytes;
    use http::StatusCode;
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    #[test]
    fn test_mock_params() {
        let params = MockResponse::new(
            &toml::from_str::<PluginConf>(
                r###"
path = "/"
status = 500
headers = [
    "Content-Type: application/json"
]
data = "{\"message\":\"Mock Service Unavailable\"}"
"###,
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!("/", params.path);
    }

    #[tokio::test]
    async fn test_mock_response() {
        let params = toml::from_str::<PluginConf>(
            r###"
path = "/vicanso/pingap"
status = 500
headers = [
    "Content-Type: application/json"
]
data = "{\"message\":\"Mock Service Unavailable\"}"
"###,
        )
        .unwrap();

        let mock = MockResponse::new(&params).unwrap();

        let headers = ["Accept-Encoding: gzip"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let result = mock
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut State::default(),
            )
            .await
            .unwrap();

        assert_eq!(true, result.is_some());

        let resp = result.unwrap();
        assert_eq!(StatusCode::INTERNAL_SERVER_ERROR, resp.status);
        assert_eq!(
            r###"Some([("content-type", "application/json")])"###,
            format!("{:?}", resp.headers)
        );
        assert_eq!(
            Bytes::from_static(b"{\"message\":\"Mock Service Unavailable\"}"),
            resp.body
        );

        let headers = ["Accept-Encoding: gzip"].join("\r\n");
        let input_header =
            format!("GET /vicanso?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let result = mock
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut State::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result.is_none());
    }
}
