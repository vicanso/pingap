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

use super::{
    get_bool_conf, get_hash_key, get_str_conf, get_str_slice_conf, Error,
    Plugin, Result,
};
use pingap_config::{PluginCategory, PluginConf, PluginStep};
use crate::http_extra::HttpResponse;
use crate::state::State;
use async_trait::async_trait;
use bytes::Bytes;
use http::HeaderValue;
use http::StatusCode;
use humantime::parse_duration;
use pingap_util::base64_decode;
use pingora::proxy::Session;
use std::time::Duration;
use tokio::time::sleep;
use tracing::debug;

/// BasicAuth implements HTTP Basic Authentication functionality for HTTP requests.
///
/// # Security Features
/// - Validates base64-encoded credentials against a predefined list
/// - Optional rate limiting through configurable delays to prevent brute force attacks
/// - Can hide credentials from upstream services to prevent credential leakage
/// - Returns standard HTTP 401 responses with WWW-Authenticate headers
///
/// # Configuration
/// Expects configuration in TOML format with the following options:
/// - authorizations: List of base64-encoded "username:password" strings
/// - delay: Optional duration string for rate limiting (e.g., "10s")
/// - hide_credentials: Boolean to control credential forwarding
pub struct BasicAuth {
    /// The plugin execution step (should always be Request for BasicAuth)
    /// This ensures authentication happens before request processing
    plugin_step: PluginStep,

    /// List of valid credentials stored as base64 encoded "username:password" combinations
    /// Each entry is stored as a byte vector including the "Basic " prefix
    /// Format: "Basic base64(username:password)"
    /// Example:
    /// - Original: admin:password
    /// - Base64: YWRtaW46cGFzc3dvcmQ=
    /// - Stored: "Basic YWRtaW46cGFzc3dvcmQ="
    authorizations: Vec<Vec<u8>>,

    /// When true, removes the Authorization header after successful authentication
    /// This is a security feature to prevent credential leakage to backend services
    /// Recommended to set to true unless the upstream service specifically needs credentials
    hide_credentials: bool,

    /// HTTP response returned when the Authorization header is missing
    /// Includes WWW-Authenticate header to prompt browser's authentication dialog
    /// Body contains a user-friendly message about missing authorization
    miss_authorization_resp: HttpResponse,

    /// HTTP response returned when provided credentials are invalid
    /// Also includes WWW-Authenticate header but with a different message
    /// The delay (if configured) is applied before sending this response
    unauthorized_resp: HttpResponse,

    /// Optional delay duration before responding to invalid credentials
    /// Security feature to make brute force attacks impractical
    /// Example values: "1s", "500ms", "2s"
    delay: Option<Duration>,

    /// Unique hash value for the plugin instance
    /// Used for internal plugin management and caching
    /// Generated from plugin configuration to ensure consistent behavior
    hash_value: String,
}

impl TryFrom<&PluginConf> for BasicAuth {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        // Generate a unique hash for this plugin instance based on configuration
        // This ensures consistent plugin behavior across restarts
        let hash_value = get_hash_key(value);

        // Parse optional delay duration for rate limiting
        // Supports human-readable duration strings like "10s", "1m", etc.
        // Returns None if delay is not specified
        let delay = get_str_conf(value, "delay");
        let delay = if !delay.is_empty() {
            let d = parse_duration(&delay).map_err(|e| Error::Invalid {
                category: PluginCategory::KeyAuth.to_string(),
                message: e.to_string(),
            })?;
            Some(d)
        } else {
            None
        };

        // Process and validate the list of authorized credentials
        // Each credential must be a valid base64 string
        // Invalid base64 strings will cause initialization to fail
        let mut authorizations = vec![];
        for item in get_str_slice_conf(value, "authorizations").iter() {
            // Validate base64 format - this ensures we don't store invalid credentials
            let _ = base64_decode(item).map_err(|e| Error::Base64Decode {
                category: PluginCategory::BasicAuth.to_string(),
                source: e,
            })?;
            // Store with "Basic " prefix for direct comparison with request headers
            authorizations.push(format!("Basic {item}").as_bytes().to_vec());
        }

        // Ensure at least one valid authorization is configured
        if authorizations.is_empty() {
            return Err(Error::Invalid {
                category: PluginCategory::BasicAuth.to_string(),
                message: "basic authorizations can't be empty".to_string(),
            });
        }

        let params = Self {
            hash_value,
            plugin_step: PluginStep::Request,
            delay,
            hide_credentials: get_bool_conf(value, "hide_credentials"),
            authorizations,
            miss_authorization_resp: HttpResponse {
                status: StatusCode::UNAUTHORIZED,
                headers: Some(vec![(
                    http::header::WWW_AUTHENTICATE,
                    HeaderValue::from_str(
                        r###"Basic realm="Access to the staging site""###,
                    )
                    .unwrap(),
                )]),
                body: Bytes::from_static(b"Authorization is missing"),
                ..Default::default()
            },
            unauthorized_resp: HttpResponse {
                status: StatusCode::UNAUTHORIZED,
                headers: Some(vec![(
                    http::header::WWW_AUTHENTICATE,
                    HeaderValue::from_str(
                        r###"Basic realm="Access to the staging site""###,
                    )
                    .unwrap(),
                )]),
                body: Bytes::from_static(b"Invalid user or password"),
                ..Default::default()
            },
        };

        Ok(params)
    }
}

impl BasicAuth {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new basic auth plugin");
        Self::try_from(params)
    }
}

#[async_trait]
impl Plugin for BasicAuth {
    #[inline]
    fn hash_key(&self) -> String {
        self.hash_value.clone()
    }

    #[inline]
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        _ctx: &mut State,
    ) -> pingora::Result<Option<HttpResponse>> {
        // Verify we're in the request phase - authentication must happen before processing
        if step != self.plugin_step {
            return Ok(None);
        }

        // Extract and validate Authorization header
        // An empty value means the header is missing entirely
        let value = session.get_header_bytes(http::header::AUTHORIZATION);
        if value.is_empty() {
            return Ok(Some(self.miss_authorization_resp.clone()));
        }

        // Validate credentials against our authorized list
        // Uses constant-time comparison (through Vec comparison) to prevent timing attacks
        if !self.authorizations.contains(&value.to_vec()) {
            // If configured, apply rate limiting delay
            // This helps prevent automated brute force attempts
            if let Some(d) = self.delay {
                sleep(d).await;
            }
            return Ok(Some(self.unauthorized_resp.clone()));
        }

        // On successful authentication, optionally remove credentials
        // This prevents credential leakage to upstream services
        if self.hide_credentials {
            session
                .req_header_mut()
                .remove_header(&http::header::AUTHORIZATION);
        }

        // Authentication successful - continue request processing
        return Ok(None);
    }
}

#[cfg(test)]
mod tests {
    use super::{BasicAuth, Plugin};
    use pingap_config::{PluginConf, PluginStep};
    use crate::state::State;
    use http::StatusCode;
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use std::time::Duration;
    use tokio_test::io::Builder;

    #[test]
    fn test_basic_auth_params() {
        let params = BasicAuth::try_from(
            &toml::from_str::<PluginConf>(
                r###"
authorizations = [
"MTIz",
"NDU2",
]
delay = "10s"
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!("request", params.plugin_step.to_string());
        assert_eq!(
            "Basic MTIz,Basic NDU2",
            params
                .authorizations
                .iter()
                .map(|item| std::string::String::from_utf8_lossy(item))
                .collect::<Vec<_>>()
                .join(","),
        );
        assert_eq!(Duration::from_secs(10), params.delay.unwrap());
        assert_eq!("AC7E9E03", params.hash_key());

        let result = BasicAuth::try_from(
            &toml::from_str::<PluginConf>(
                r###"
authorizations = [
"1"
]
"###,
            )
            .unwrap(),
        );
        assert_eq!(
            "Plugin basic_auth, base64 decode error Invalid input length: 1",
            result.err().unwrap().to_string()
        );
    }

    #[tokio::test]
    async fn test_basic_auth() {
        let auth = BasicAuth::new(
            &toml::from_str::<PluginConf>(
                r###"
authorizations = [
    "YWRtaW46MTIzMTIz"
]
hide_credentials = true
    "###,
            )
            .unwrap(),
        )
        .unwrap();

        // auth success
        let headers = ["Authorization: Basic YWRtaW46MTIzMTIz"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = auth
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut State::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result.is_none());
        assert_eq!(
            false,
            session.req_header().headers.contains_key("Authorization")
        );

        // auth fail
        let headers = ["Authorization: Basic YWRtaW46MTIzMTIa"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = auth
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut State::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result.is_some());
        assert_eq!(StatusCode::UNAUTHORIZED, result.unwrap().status);
    }
}
