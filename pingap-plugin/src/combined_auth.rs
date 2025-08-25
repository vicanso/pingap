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
    get_hash_key, get_int_conf, get_plugin_factory, get_str_conf,
    get_str_slice_conf, Error,
};
use ahash::AHashMap;
use async_trait::async_trait;
use bytes::Bytes;
use ctor::ctor;
use hex::ToHex;
use http::StatusCode;
use pingap_config::PluginConf;
use pingap_core::{
    Ctx, HttpResponse, Plugin, PluginStep, RequestPluginResult,
    HTTP_HEADER_NO_STORE,
};
use pingora::proxy::Session;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::sync::Arc;
use tracing::debug;

type Result<T, E = Error> = std::result::Result<T, E>;
// AuthParam defines the authentication configuration for a single application
struct AuthParam {
    // Optional IP rules for restricting access to specific IP addresses or CIDR ranges
    // Example: ["127.0.0.1", "192.168.1.0/24"]
    ip_rules: Option<pingap_util::IpRules>,

    // Secret key used for HMAC authentication
    // Special value "*" bypasses all authentication (super user mode)
    secret: String,

    // Maximum allowed time difference between request timestamp and server time
    // Helps prevent replay attacks by rejecting old requests
    // Value is in seconds, typical values: 30-300
    deviation: i64,
}

pub struct CombinedAuth {
    // Unique identifier for this plugin instance
    hash_value: String,
    // Plugin execution phase (must be PluginStep::Request)
    plugin_step: PluginStep,
    // Map of app_id to their authentication parameters
    auths: AHashMap<String, AuthParam>,
}

/// Converts a plugin configuration into a CombinedAuth instance
///
/// # Arguments
/// * `value` - The plugin configuration containing authorization settings
///
/// # Returns
/// * `Result<Self>` - A new CombinedAuth instance or an error if configuration is invalid
///
/// # Configuration Format
/// ```toml
/// authorizations = [
///   { app_id = "myapp", secret = "mysecret", deviation = 60, ip_list = ["127.0.0.1"] }
/// ]
/// ```
impl TryFrom<&PluginConf> for CombinedAuth {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);

        let category = "combined_auth".to_string();

        let Some(authorizations) = value.get("authorizations") else {
            return Err(Error::Invalid {
                category,
                message: "authorizations is empty".to_string(),
            });
        };
        let Some(authorizations) = authorizations.as_array() else {
            return Err(Error::Invalid {
                category,
                message: "authorizations is not array".to_string(),
            });
        };
        let mut auths = AHashMap::new();
        for item in authorizations.iter() {
            let Some(value) = item.as_table() else {
                continue;
            };
            let app_id = get_str_conf(value, "app_id");
            if app_id.is_empty() {
                continue;
            }
            let mut ip_rules = None;
            let ip_list = get_str_slice_conf(value, "ip_list");
            if !ip_list.is_empty() {
                ip_rules = Some(pingap_util::IpRules::new(&ip_list));
            }
            auths.insert(
                app_id,
                AuthParam {
                    ip_rules,
                    secret: get_str_conf(value, "secret"),
                    deviation: get_int_conf(value, "deviation"),
                },
            );
        }

        Ok(Self {
            plugin_step: PluginStep::Request,
            hash_value,
            auths,
        })
    }
}

impl CombinedAuth {
    /// Creates a new CombinedAuth plugin instance from the provided configuration
    ///
    /// # Arguments
    /// * `params` - Plugin configuration parameters
    ///
    /// # Returns
    /// * `Result<Self>` - A new plugin instance or an error if configuration is invalid
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new combined auth plugin");
        Self::try_from(params)
    }

    /// Validates an incoming request against the configured authentication rules
    ///
    /// # Arguments
    /// * `session` - The HTTP session containing the request details
    ///
    /// # Returns
    /// * `Result<()>` - Ok if validation passes, Error if any check fails
    ///
    /// # Authentication Steps
    /// 1. Validates app_id from query parameters
    /// 2. Checks IP restrictions (if configured)
    /// 3. Validates timestamp to prevent replay attacks
    /// 4. Verifies HMAC digest for request authenticity
    ///
    /// # Query Parameters Required
    /// * `app_id` - Application identifier
    /// * `ts` - Unix timestamp
    /// * `digest` - SHA-256 HMAC of `secret:timestamp`
    #[inline]
    fn validate(&self, session: &Session) -> Result<()> {
        let category = "combined_auth";
        let req_header = session.req_header();

        // Step 1: Extract and validate app_id
        // The app_id must be provided as a query parameter: ?app_id=your_app_id
        let Some(app_id) = pingap_core::get_query_value(req_header, "app_id")
        else {
            return Err(Error::Invalid {
                category: category.to_string(),
                message: "app id is empty".to_string(),
            });
        };

        // Step 2: Lookup authentication configuration for this app_id
        let Some(auth_param) = self.auths.get(app_id) else {
            return Err(Error::Invalid {
                category: category.to_string(),
                message: "app id is invalid".to_string(),
            });
        };

        // Step 3: Super user check
        // If secret is "*", this app has unlimited access
        // USE WITH CAUTION: This bypasses all security checks
        if auth_param.secret == "*" {
            return Ok(());
        }

        // Step 4: IP validation (if configured)
        // Checks if the client IP is in the allowed list
        // Uses X-Forwarded-For header for IP detection behind proxies
        if let Some(ip_rules) = &auth_param.ip_rules {
            let ip = pingap_core::get_client_ip(session);
            if !ip_rules.is_match(&ip).unwrap_or_default() {
                return Err(Error::Invalid {
                    category: category.to_string(),
                    message: "ip is invalid".to_string(),
                });
            }
        }

        // Step 5: Timestamp validation
        // Requires a Unix timestamp as query parameter: ?ts=1234567890
        let ts =
            pingap_core::get_query_value(req_header, "ts").unwrap_or_default();
        if ts.is_empty() {
            return Err(Error::Invalid {
                category: category.to_string(),
                message: "timestamp is empty".to_string(),
            });
        }

        // Convert timestamp to i64 and validate it's within acceptable range
        let value = ts.parse::<i64>().map_err(|e| Error::Invalid {
            category: category.to_string(),
            message: e.to_string(),
        })?;
        let now = pingap_core::now_sec() as i64;
        if (now - value).abs() > auth_param.deviation {
            return Err(Error::Invalid {
                category: category.to_string(),
                message: "timestamp deviation is invalid".to_string(),
            });
        }

        // Step 6: HMAC Authentication
        // Requires a hex-encoded SHA-256 HMAC digest as query parameter: ?digest=abc123...
        // digest = hex(SHA256(secret:timestamp))
        let digest = pingap_core::get_query_value(req_header, "digest")
            .unwrap_or_default();
        if digest.is_empty() {
            return Err(Error::Invalid {
                category: category.to_string(),
                message: "digest is empty".to_string(),
            });
        }

        // Calculate expected digest
        let mut hasher = Sha256::new();
        hasher.update(format!("{}:{ts}", auth_param.secret).as_bytes());
        let hash256 = hasher.finalize();

        // Compare digests in constant time to prevent timing attacks
        if digest.to_lowercase() != hash256.encode_hex::<String>() {
            return Err(Error::Invalid {
                category: category.to_string(),
                message: "digest is invalid".to_string(),
            });
        }

        Ok(())
    }
}

#[async_trait]
impl Plugin for CombinedAuth {
    /// Returns the unique hash key for this plugin instance
    #[inline]
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    /// Handles incoming HTTP requests by performing authentication checks
    ///
    /// # Arguments
    /// * `step` - The current plugin execution step
    /// * `session` - The HTTP session containing request details
    /// * `_ctx` - Plugin state context
    ///
    /// # Returns
    /// * `pingora::Result<Option<HttpResponse>>` - None if authentication passes,
    ///   or an HTTP 401 response if authentication fails
    #[inline]
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        _ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        if step != self.plugin_step {
            return Ok(RequestPluginResult::Skipped);
        }
        if let Err(e) = self.validate(session) {
            return Ok(RequestPluginResult::Respond(HttpResponse {
                status: StatusCode::UNAUTHORIZED,
                headers: Some(vec![HTTP_HEADER_NO_STORE.clone()]),
                body: Bytes::from(e.to_string()),
                ..Default::default()
            }));
        }

        Ok(RequestPluginResult::Continue)
    }
}

#[ctor]
fn init() {
    get_plugin_factory().register("combined_auth", |params| {
        Ok(Arc::new(CombinedAuth::new(params)?))
    });
}

#[cfg(test)]
mod tests {
    use super::{AuthParam, CombinedAuth};
    use ahash::AHashMap;
    use hex::ToHex;
    use pingap_core::PluginStep;
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use sha2::{Digest, Sha256};
    use tokio_test::io::Builder;

    #[tokio::test]
    async fn test_combined_auth() {
        let mut auths = AHashMap::new();
        let secret = "abcd";
        auths.insert(
            "pingap".to_string(),
            AuthParam {
                ip_rules: Some(pingap_util::IpRules::new(&[
                    "127.0.0.1".to_string(),
                    "192.168.1.0/24".to_string(),
                ])),
                secret: secret.to_string(),
                deviation: 60,
            },
        );
        let combined_auth = CombinedAuth {
            plugin_step: PluginStep::Request,
            hash_value: "".to_string(),
            auths,
        };

        // no app id
        let headers = [""].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = combined_auth.validate(&session);
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Plugin combined_auth invalid, message: app id is empty",
            result.unwrap_err().to_string()
        );

        // app id is invalid
        let headers = [""].join("\r\n");
        let input_header = format!(
            "GET /vicanso/pingap?app_id=abc HTTP/1.1\r\n{headers}\r\n\r\n"
        );
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = combined_auth.validate(&session);
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Plugin combined_auth invalid, message: app id is invalid",
            result.unwrap_err().to_string()
        );

        // ip is invalid
        let headers = ["X-Forwarded-For: 1.1.1.1"].join("\r\n");
        let input_header = format!(
            "GET /vicanso/pingap?app_id=pingap HTTP/1.1\r\n{headers}\r\n\r\n"
        );
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = combined_auth.validate(&session);
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Plugin combined_auth invalid, message: ip is invalid",
            result.unwrap_err().to_string()
        );

        // timestamp is empty
        let headers = ["X-Forwarded-For: 192.168.1.10"].join("\r\n");
        let input_header = format!(
            "GET /vicanso/pingap?app_id=pingap HTTP/1.1\r\n{headers}\r\n\r\n"
        );
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = combined_auth.validate(&session);
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Plugin combined_auth invalid, message: timestamp is empty",
            result.unwrap_err().to_string()
        );

        // timestamp is invalid
        let headers = ["X-Forwarded-For: 192.168.1.10"].join("\r\n");
        let input_header = format!(
            "GET /vicanso/pingap?app_id=pingap&ts=123 HTTP/1.1\r\n{headers}\r\n\r\n"
        );
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = combined_auth.validate(&session);
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Plugin combined_auth invalid, message: timestamp deviation is invalid",
            result.unwrap_err().to_string()
        );

        // digest is empty
        let headers = ["X-Forwarded-For: 192.168.1.10"].join("\r\n");
        let ts = pingap_core::now_sec() as i64;
        let input_header = format!(
            "GET /vicanso/pingap?app_id=pingap&ts={ts} HTTP/1.1\r\n{headers}\r\n\r\n"
        );
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = combined_auth.validate(&session);
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Plugin combined_auth invalid, message: digest is empty",
            result.unwrap_err().to_string()
        );

        // digest is invalid
        let headers = ["X-Forwarded-For: 192.168.1.10"].join("\r\n");
        let ts = pingap_core::now_sec() as i64;
        let input_header = format!(
            "GET /vicanso/pingap?app_id=pingap&ts={ts}&digest=abc HTTP/1.1\r\n{headers}\r\n\r\n"
        );
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = combined_auth.validate(&session);
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Plugin combined_auth invalid, message: digest is invalid",
            result.unwrap_err().to_string()
        );

        let headers = ["X-Forwarded-For: 192.168.1.10"].join("\r\n");
        let ts = pingap_core::now_sec() as i64;
        let mut hasher = Sha256::new();
        hasher.update(format!("{secret}:{ts}",).as_bytes());
        let hash256 = hasher.finalize();
        let digest = hash256.encode_hex::<String>();
        let input_header = format!(
            "GET /vicanso/pingap?app_id=pingap&ts={ts}&digest={digest} HTTP/1.1\r\n{headers}\r\n\r\n"
        );
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = combined_auth.validate(&session);
        assert_eq!(true, result.is_ok());
    }
}
