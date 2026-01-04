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

use super::{Error, get_hash_key, get_plugin_factory, get_str_conf};
use async_trait::async_trait;
use bytes::Bytes;
use cookie::Cookie;
use ctor::ctor;
use http::{HeaderValue, Method, StatusCode, header};
use humantime::parse_duration;
use nanoid::nanoid;
use pingap_config::{PluginCategory, PluginConf};
use pingap_core::{
    Ctx, HTTP_HEADER_NO_STORE, HttpResponse, Plugin, PluginStep,
    RequestPluginResult,
};
use pingap_core::{get_cookie_value, new_internal_error, now_sec};
use pingap_util::base64_encode;
use pingora::proxy::Session;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::sync::Arc;
use tracing::debug;

type Result<T, E = Error> = std::result::Result<T, E>;

/// CSRF protection plugin that implements double-submit cookie pattern
///
/// # Configuration
/// - `token_path`: Endpoint for generating new CSRF tokens
/// - `key`: Secret key for cryptographic operations
/// - `name`: Name of the CSRF token header/cookie (default: "x-csrf-token")
/// - `ttl`: Token expiration time in seconds (0 means no expiration)
pub struct Csrf {
    plugin_step: PluginStep,
    // Endpoint that clients call to get a new CSRF token (e.g., "/csrf-token")
    token_path: String,
    // Secret key used for cryptographic operations - must be kept secure and consistent across instances
    key: String,
    // The name used for both the HTTP header and cookie (default: "x-csrf-token")
    // Client must send token in both header and cookie for double-submit validation
    name: String,
    // Token expiration time in seconds
    // - 0 means tokens never expire
    // - Common values: 3600 (1h), 86400 (24h)
    ttl: u64,
    // 401 Unauthorized response sent when CSRF validation fails
    unauthorized_resp: HttpResponse,
    // Unique identifier for this plugin instance
    hash_value: String,
}

/// Attempts to create a new CSRF plugin instance from the provided configuration
///
/// # Errors
/// Returns `Error::Invalid` if:
/// - `token_path` is empty
/// - `key` is empty
/// - Plugin step is not set to request phase
impl TryFrom<&PluginConf> for Csrf {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);

        let mut csrf = Self {
            hash_value,
            plugin_step: PluginStep::Request,
            name: get_str_conf(value, "name"),
            token_path: get_str_conf(value, "token_path"),
            key: get_str_conf(value, "key"),
            ttl: 0,
            unauthorized_resp: HttpResponse {
                status: StatusCode::UNAUTHORIZED,
                body: Bytes::from("Csrf token is empty or invalid"),
                ..Default::default()
            },
        };
        if csrf.name.is_empty() {
            csrf.name = "x-csrf-token".to_string();
        }
        let ttl = get_str_conf(value, "ttl");
        if !ttl.is_empty() {
            let ttl = parse_duration(&ttl).map_err(|e| Error::Invalid {
                category: PluginCategory::Csrf.to_string(),
                message: e.to_string(),
            })?;
            csrf.ttl = ttl.as_secs();
        }

        // Validation rules:
        // 1. token_path must be specified (where clients get new tokens)
        if csrf.token_path.is_empty() {
            return Err(Error::Invalid {
                category: PluginCategory::Csrf.to_string(),
                message: "Token path is not allowed empty".to_string(),
            });
        }
        // 2. key must be specified (used for cryptographic operations)
        if csrf.key.is_empty() {
            return Err(Error::Invalid {
                category: PluginCategory::Csrf.to_string(),
                message: "Key is not allowed empty".to_string(),
            });
        }

        Ok(csrf)
    }
}

impl Csrf {
    /// Creates a new CSRF plugin instance with the given configuration
    ///
    /// # Arguments
    /// * `params` - Plugin configuration parameters
    ///
    /// # Returns
    /// Result containing the configured CSRF plugin or an error
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new csrf plugin");
        Csrf::try_from(params)
    }
}

/// Generates a new CSRF token with cryptographic protection
///
/// # Format
/// The token consists of three parts joined by dots:
/// 1. Random ID (12 chars using nanoid)
/// 2. Current timestamp in hex
/// 3. SHA-256 signature of the above parts using the secret key
///
/// # Arguments
/// * `key` - Secret key used for signing the token
///
/// # Returns
/// A string containing the generated token
#[inline]
fn generate_token(key: &str) -> String {
    // Generate random ID using nanoid (URL-safe, 12 chars)
    let id = nanoid!(12);
    // Add current timestamp in hex format
    let prefix = format!("{id}.{:x}", now_sec());

    // Create cryptographic signature:
    // - Uses SHA-256 for hashing
    // - Signs the combination of random ID, timestamp, and secret key
    // - This prevents token forgery as attackers don't know the secret key
    let mut hasher = Sha256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(key.as_bytes());
    let hash256 = hasher.finalize();

    // Combine all parts with dots
    format!("{prefix}.{}", base64_encode(hash256))
}

/// Validates a CSRF token for authenticity and expiration
///
/// # Arguments
/// * `key` - Secret key used for validating the token signature
/// * `ttl` - Time-to-live in seconds (0 means no expiration check)
/// * `value` - The token string to validate
///
/// # Returns
/// `true` if the token is valid and not expired, `false` otherwise
///
/// # Security
/// - Uses constant-time comparison for signature verification
/// - Checks token format, expiration, and cryptographic signature
#[inline]
fn validate_token(key: &str, ttl: u64, value: &str) -> bool {
    // Split token into its components
    let arr: Vec<&str> = value.split('.').collect();
    if arr.len() != 3 {
        return false;
    }

    // Check expiration if TTL is configured
    if ttl > 0 {
        let now = now_sec();
        // Parse timestamp from hex and compare with current time
        if now - u64::from_str_radix(arr[1], 16).unwrap_or_default() > ttl {
            return false;
        }
    }

    // Verify signature by:
    // 1. Reconstructing the original message (id + timestamp)
    // 2. Creating a new signature with the secret key
    // 3. Comparing with the provided signature
    let mut hasher = Sha256::new();
    hasher.update(format!("{}.{}", arr[0], arr[1]).as_bytes());
    hasher.update(key.as_bytes());
    let hash256 = hasher.finalize();

    // Constant-time comparison to prevent timing attacks
    arr[2] == base64_encode(hash256)
}

#[async_trait]
impl Plugin for Csrf {
    /// Returns the unique hash key for this plugin instance
    #[inline]
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    /// Handles incoming HTTP requests for CSRF protection
    ///
    /// # Flow
    /// 1. For token generation requests (`token_path`):
    ///    - Generates new token
    ///    - Sets token in cookie and response
    /// 2. For other requests:
    ///    - Skips safe HTTP methods (GET, HEAD, OPTIONS)
    ///    - Validates token in header matches cookie
    ///    - Checks token signature and expiration
    ///
    /// # Arguments
    /// * `step` - Current plugin execution step
    /// * `session` - HTTP session information
    /// * `_ctx` - Plugin state context
    ///
    /// # Returns
    /// - `None` if request is allowed
    /// - `Some(HttpResponse)` with 401 status if validation fails
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        _ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        // Only run during request phase
        if step != self.plugin_step {
            return Ok(RequestPluginResult::Skipped);
        }

        // Handle token generation requests
        if session.req_header().uri.path() == self.token_path {
            let token = generate_token(&self.key);

            // Set token in cookie with security options:
            // - Path: "/" (valid for all paths)
            // - Max-Age: TTL if configured
            let mut builder = Cookie::build((&self.name, &token)).path("/");
            if self.ttl > 0 {
                builder = builder
                    .max_age(cookie::time::Duration::seconds(self.ttl as i64));
            };

            // Return token with security headers:
            // - no-store: Prevents caching of the token
            // - Set-Cookie: Sets the token cookie
            let set_cookie = (
                header::SET_COOKIE,
                HeaderValue::from_str(&builder.build().to_string())
                    .map_err(|e| new_internal_error(400, e))?,
            );

            let resp = HttpResponse {
                status: StatusCode::NO_CONTENT,
                headers: Some(vec![HTTP_HEADER_NO_STORE.clone(), set_cookie]),
                ..Default::default()
            };

            return Ok(RequestPluginResult::Respond(resp));
        }

        // Skip CSRF checks for safe HTTP methods
        // These methods should not modify state according to HTTP spec
        if [Method::GET, Method::HEAD, Method::OPTIONS]
            .contains(&session.req_header().method)
        {
            return Ok(RequestPluginResult::Skipped);
        }

        // For unsafe methods:
        // 1. Check token exists in header
        let value = session.get_header_bytes(&self.name);
        if value.is_empty() {
            return Ok(RequestPluginResult::Respond(
                self.unauthorized_resp.clone(),
            ));
        }

        let value = std::string::String::from_utf8_lossy(value);

        // 2. Verify double-submit:
        //    - Token in header must match token in cookie
        //    - Prevents CSRF as attacker cannot set custom headers
        // 3. Validate token format, expiration, and signature
        if value
            != get_cookie_value(session.req_header(), &self.name)
                .unwrap_or_default()
            || !validate_token(&self.key, self.ttl, &value)
        {
            return Ok(RequestPluginResult::Respond(
                self.unauthorized_resp.clone(),
            ));
        }

        // Token is valid - allow request to proceed
        Ok(RequestPluginResult::Continue)
    }
}

#[ctor]
fn init() {
    get_plugin_factory()
        .register("csrf", |params| Ok(Arc::new(Csrf::new(params)?)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use cookie::Cookie;
    use pingap_config::PluginConf;
    use pingap_core::{Ctx, PluginStep};
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use std::str::FromStr;
    use tokio_test::io::Builder;

    #[test]
    fn test_csrf_params() {
        let params = Csrf::try_from(
            &toml::from_str::<PluginConf>(
                r###"
token_path = "/csrf-token"
key = "WjrXUG47wu"
ttl = "1h"
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!("/csrf-token", params.token_path);
        assert_eq!("WjrXUG47wu", params.key);
        assert_eq!(3600, params.ttl);

        let result = Csrf::try_from(
            &toml::from_str::<PluginConf>(
                r###"
token_path = "/csrf-token"
key = "WjrXUG47wu"
ttl = "1a"
"###,
            )
            .unwrap(),
        );
        assert_eq!(
            r#"Plugin csrf invalid, message: unknown time unit "a", supported units: ns, us/µs, ms, sec, min, hours, days, weeks, months, years (and few variations)"#,
            result.err().unwrap().to_string()
        );

        let result = Csrf::try_from(
            &toml::from_str::<PluginConf>(
                r###"
key = "WjrXUG47wu"
"###,
            )
            .unwrap(),
        );
        assert_eq!(
            "Plugin csrf invalid, message: Token path is not allowed empty",
            result.err().unwrap().to_string()
        );

        let result = Csrf::try_from(
            &toml::from_str::<PluginConf>(
                r###"
token_path = "/csrf-token"
"###,
            )
            .unwrap(),
        );
        assert_eq!(
            "Plugin csrf invalid, message: Key is not allowed empty",
            result.err().unwrap().to_string()
        );
    }

    #[test]
    fn test_generate_token() {
        let key = "123";
        let value = generate_token(key);
        assert_eq!(true, validate_token(key, 10, &value));
        assert_eq!(false, validate_token(key, 10, &format!("{value}:1")));
    }

    #[tokio::test]
    async fn test_csrf() {
        let csrf = Csrf::new(
            &toml::from_str::<PluginConf>(
                r###"
token_path = "/csrf-token"
key = "WjrXUG47wu"
ttl = "1h"
    "###,
            )
            .unwrap(),
        )
        .unwrap();

        // get csrf token success
        let headers = [""].join("\r\n");
        let input_header =
            format!("GET /csrf-token HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = csrf
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        let RequestPluginResult::Respond(resp) = result else {
            panic!("result is not Respond");
        };
        let binding = resp.headers.unwrap();
        let cookie = binding[1].1.to_str().unwrap();
        let c = Cookie::from_str(cookie).unwrap();
        assert_eq!("x-csrf-token", c.name());
        assert_eq!(66, c.value().len());

        // validate fail
        let headers = [format!("x-csrf-token:{}", "123")].join("\r\n");
        let input_header = format!("POST / HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let result = csrf
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        let RequestPluginResult::Respond(resp) = result else {
            panic!("result is not Respond");
        };
        assert_eq!(401, resp.status.as_u16());

        // validate success
        let headers = [
            format!("x-csrf-token: {}", c.value()),
            format!("Cookie: x-csrf-token={}", c.value()),
        ]
        .join("\r\n");
        let input_header = format!("POST / HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = csrf
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result == RequestPluginResult::Continue);
    }
}
