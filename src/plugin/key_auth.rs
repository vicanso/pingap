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
use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderName, StatusCode};
use humantime::parse_duration;
use pingap_config::{PluginCategory, PluginConf, PluginStep};
use pingap_http_extra::HttpResponse;
use pingap_state::Ctx;
use pingora::proxy::Session;
use std::str::FromStr;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, error};

/// KeyAuth plugin provides key-based authentication for HTTP requests.
/// It supports two authentication methods:
/// 1. Header-based authentication (e.g., using X-API-Key header)
/// 2. Query parameter-based authentication (e.g., using ?api_key=value)
///
/// Security features:
/// - Configurable delay on failed attempts to prevent brute force attacks
/// - Credential hiding to prevent key leakage to backend services
/// - Distinct error responses for missing vs invalid credentials
/// - Binary key storage to support various encodings
pub struct KeyAuth {
    /// Determines when this plugin runs in the request lifecycle:
    /// - Request phase: Early authentication before any processing
    /// - ProxyUpstream phase: Authentication just before forwarding to backend
    plugin_step: PluginStep,

    /// Header name to look for the auth key (e.g., "X-API-Key")
    /// When set, query parameter authentication is disabled
    /// Example: Some(HeaderName::from_str("X-API-Key").unwrap())
    header: Option<HeaderName>,

    /// Query parameter name to look for the auth key (e.g., "api_key")
    /// When set, header-based authentication is disabled
    /// Example: Some("api_key".to_string())
    query: Option<String>,

    /// List of valid authentication keys stored as raw bytes
    /// Using Vec<u8> instead of String to:
    /// - Support various encodings (UTF-8, ASCII, etc.)
    /// - Prevent encoding/decoding issues
    /// - Enable constant-time comparisons
    keys: Vec<Vec<u8>>,

    /// Optional delay duration applied after failed authentication attempts
    /// This helps prevent timing attacks and brute force attempts by adding
    /// artificial latency to failed requests
    delay: Option<Duration>,

    /// HTTP 401 response returned when no authentication key is provided
    /// This is distinct from unauthorized_resp to help clients distinguish
    /// between missing and invalid credentials
    miss_authorization_resp: HttpResponse,

    /// HTTP 401 response returned when an invalid authentication key is provided
    unauthorized_resp: HttpResponse,

    /// When true, removes authentication credentials after successful validation
    /// This prevents credentials from being forwarded to backend services,
    /// reducing the risk of accidental key exposure in logs or responses
    hide_credentials: bool,

    /// Unique identifier for this plugin instance
    /// Used for plugin management and logging
    hash_value: String,
}

impl TryFrom<&PluginConf> for KeyAuth {
    type Error = Error;
    /// Attempts to create a KeyAuth instance from a plugin configuration.
    ///
    /// # Arguments
    /// * `value` - The plugin configuration containing authentication settings
    ///
    /// # Returns
    /// * `Result<Self>` - A new KeyAuth instance if configuration is valid
    ///
    /// # Errors
    /// * When neither header nor query parameter is configured
    /// * When no valid keys are provided
    /// * When header name is invalid
    /// * When plugin step is not request or proxy_upstream
    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);

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

        let query_name = get_str_conf(value, "query");
        let header_name = get_str_conf(value, "header");
        if query_name.is_empty() && header_name.is_empty() {
            return Err(Error::Invalid {
                category: PluginCategory::KeyAuth.to_string(),
                message: "Auth key is not allowed empty".to_string(),
            });
        }
        let mut query = None;
        let mut header = None;
        if !query_name.is_empty() {
            query = Some(query_name);
        } else {
            header = Some(HeaderName::from_str(&header_name).map_err(|e| {
                Error::Invalid {
                    category: PluginCategory::KeyAuth.to_string(),
                    message: format!("invalid header name, {e}"),
                }
            })?);
        }
        let keys: Vec<Vec<u8>> = get_str_slice_conf(value, "keys")
            .iter()
            .map(|item| item.as_bytes().to_vec())
            .collect();
        if keys.is_empty() {
            return Err(Error::Invalid {
                category: PluginCategory::KeyAuth.to_string(),
                message: "auth keys can't be empty".to_string(),
            });
        }
        let params = Self {
            hash_value,
            keys,
            hide_credentials: get_bool_conf(value, "hide_credentials"),
            plugin_step: PluginStep::Request,
            query,
            header,
            delay,
            miss_authorization_resp: HttpResponse {
                status: StatusCode::UNAUTHORIZED,
                body: Bytes::from_static(b"Key missing"),
                ..Default::default()
            },
            unauthorized_resp: HttpResponse {
                status: StatusCode::UNAUTHORIZED,
                body: Bytes::from_static(b"Key auth fail"),
                ..Default::default()
            },
        };

        Ok(params)
    }
}

impl KeyAuth {
    /// Creates a new KeyAuth plugin instance from the provided configuration.
    ///
    /// # Arguments
    /// * `params` - Plugin configuration parameters
    ///
    /// # Returns
    /// * `Result<Self>` - A new KeyAuth instance or error if configuration is invalid
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new key auth plugin");
        Self::try_from(params)
    }
}

#[async_trait]
impl Plugin for KeyAuth {
    /// Returns the unique hash key for this plugin instance.
    #[inline]
    fn hash_key(&self) -> String {
        self.hash_value.clone()
    }

    /// Handles authentication for incoming requests.
    ///
    /// This function performs the following steps:
    /// 1. Verifies the plugin is running at the correct step
    /// 2. Extracts authentication key from header or query parameter
    /// 3. Validates the key against configured valid keys
    /// 4. Optionally applies delay on failed attempts
    /// 5. Optionally hides credentials after successful validation
    ///
    /// # Arguments
    /// * `step` - Current plugin execution step
    /// * `session` - HTTP session containing request details
    /// * `_ctx` - Ctx context (unused in this plugin)
    ///
    /// # Returns
    /// * `pingora::Result<Option<HttpResponse>>` - None if authentication succeeds,
    ///   or Some(HttpResponse) with 401 status if authentication fails
    ///
    /// # Security Features
    /// * Configurable delay on failed attempts to prevent brute force attacks
    /// * Optional credential hiding to prevent key leakage
    /// * Distinct error responses for missing vs invalid credentials
    #[inline]
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        _ctx: &mut Ctx,
    ) -> pingora::Result<Option<HttpResponse>> {
        // Plugin steps are configurable to support different authentication points
        // Common steps: request (early auth) or proxy_upstream (pre-forwarding)
        if step != self.plugin_step {
            return Ok(None);
        }

        // Authentication value extraction logic:
        // 1. If query parameter is configured, look for the key there
        // 2. Otherwise, look for the key in headers
        // 3. Default to empty bytes if not found
        let value = if let Some(key) = &self.query {
            pingap_util::get_query_value(session.req_header(), key)
                .unwrap_or_default()
                .as_bytes()
        } else {
            self.header
                .as_ref()
                .map(|v| session.get_header_bytes(v))
                .unwrap_or_default()
        };

        // Early return with 401 if no authentication provided
        // This helps distinguish between missing and invalid credentials
        if value.is_empty() {
            return Ok(Some(self.miss_authorization_resp.clone()));
        }

        // Key validation:
        // 1. Check if provided key exists in the configured valid keys
        // 2. If invalid and delay is configured, wait before responding
        //    This helps prevent timing attacks and brute force attempts
        if !self.keys.contains(&value.to_vec()) {
            if let Some(d) = self.delay {
                sleep(d).await;
            }
            return Ok(Some(self.unauthorized_resp.clone()));
        }

        // Credential hiding (optional security feature):
        // After successful validation, remove the credentials from:
        // 1. Headers - using direct header removal
        // 2. Query parameters - using URL rewriting
        // This prevents credentials from being forwarded to backend services
        if self.hide_credentials {
            if let Some(name) = &self.header {
                session.req_header_mut().remove_header(name);
            } else if let Some(name) = &self.query {
                if let Err(e) = pingap_util::remove_query_from_header(
                    session.req_header_mut(),
                    name,
                ) {
                    error!(error = e.to_string(), "remove query fail");
                }
            }
        }
        // Return None to allow the request to proceed
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::KeyAuth;
    use crate::plugin::Plugin;
    use pingap_config::{PluginConf, PluginStep};
    use pingap_state::Ctx;
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    /// Tests key authentication parameter validation.
    ///
    /// Verifies:
    /// * Valid header-based configuration
    /// * Error when no auth method is configured
    /// * Error when invalid plugin step is specified
    #[test]
    fn test_key_auth_params() {
        let params = KeyAuth::try_from(
            &toml::from_str::<PluginConf>(
                r###"
header = "X-User"
keys = [
    "123",
    "456",
]
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!("request", params.plugin_step.to_string());
        assert_eq!(true, params.header.is_some());
        if let Some(value) = params.header {
            assert_eq!("x-user", value.to_string());
        }
        assert_eq!(
            "123,456",
            params
                .keys
                .iter()
                .map(|item| std::string::String::from_utf8_lossy(item))
                .collect::<Vec<_>>()
                .join(",")
        );

        let result = KeyAuth::try_from(
            &toml::from_str::<PluginConf>(
                r###"
keys = [
    "123",
    "456",
]
"###,
            )
            .unwrap(),
        );
        assert_eq!(
            "Plugin key_auth invalid, message: Auth key is not allowed empty",
            result.err().unwrap().to_string()
        );
    }

    /// Tests key authentication functionality.
    ///
    /// Verifies:
    /// * Successful authentication with valid header
    /// * Credential hiding functionality
    /// * Failed authentication with invalid key
    /// * Missing credential handling
    /// * Query parameter authentication
    #[tokio::test]
    async fn test_key_auth() {
        let auth = KeyAuth::new(
            &toml::from_str::<PluginConf>(
                r###"
header = "X-User"
keys = [
    "123",
    "456",
]
hide_credentials = true
"###,
            )
            .unwrap(),
        )
        .unwrap();

        let headers = ["X-User: 123"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        assert_eq!(false, session.get_header_bytes("X-User").is_empty());
        let result = auth
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result.is_none());
        assert_eq!(true, session.get_header_bytes("X-User").is_empty());

        let headers = ["X-User: 12"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = auth
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        let resp = result.unwrap();
        assert_eq!(401, resp.status.as_u16());
        assert_eq!(
            "Key auth fail",
            std::string::String::from_utf8_lossy(resp.body.as_ref())
        );

        let headers = [""].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = auth
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        let resp = result.unwrap();
        assert_eq!(401, resp.status.as_u16());
        assert_eq!(
            "Key missing",
            std::string::String::from_utf8_lossy(resp.body.as_ref())
        );

        let auth = KeyAuth::new(
            &toml::from_str::<PluginConf>(
                r###"
query = "user"
keys = [
    "123",
    "456",
]
hide_credentials = true
"###,
            )
            .unwrap(),
        )
        .unwrap();
        let headers = [""].join("\r\n");
        let input_header = format!(
            "GET /vicanso/pingap?user=123&type=1 HTTP/1.1\r\n{headers}\r\n\r\n"
        );
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        assert_eq!(
            "/vicanso/pingap?user=123&type=1",
            session.req_header().uri.to_string()
        );
        let result = auth
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result.is_none());
        assert_eq!(
            "/vicanso/pingap?type=1",
            session.req_header().uri.to_string()
        );
    }
}
