// Copyright 2024 Tree xie.
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

use super::{get_hash_key, get_step_conf, get_str_conf, Error, Plugin, Result};
use crate::config::{PluginCategory, PluginConf, PluginStep};
use crate::http_extra::{
    HttpResponse, HTTP_HEADER_CONTENT_JSON, HTTP_HEADER_TRANSFER_CHUNKED,
};
use crate::state::{ModifyResponseBody, State};
use crate::util;
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use bytes::Bytes;
use http::StatusCode;
use humantime::parse_duration;
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use substring::Substring;
use tokio::time::sleep;
use tracing::debug;

/// JwtAuth struct holds configuration for JWT authentication and validation.
///
/// This plugin provides JWT-based authentication with the following features:
/// - Token generation endpoint at a configurable path
/// - Support for multiple token locations (header, query param, or cookie)
/// - HMAC-based signatures using HS256 or HS512
/// - Token expiration validation
/// - Protection against timing attacks
///
/// # Token Locations
/// Tokens can be extracted from one of:
/// - HTTP header (typically "Authorization: Bearer <token>")
/// - Query parameter (e.g., "?token=<token>")
/// - Cookie value
///
/// # Security Features
/// - Configurable HMAC algorithms (HS256/HS512)
/// - Optional delay on authentication failures to prevent timing attacks
/// - Automatic expiration checking via "exp" claim
///
/// # Example Configuration
/// ```toml
/// secret = "your-secret-key"
/// header = "Authorization"
/// auth_path = "/login"
/// algorithm = "HS256"
/// delay = "100ms"
/// ```
pub struct JwtAuth {
    /// Plugin execution step (must be Request)
    plugin_step: PluginStep,

    /// Endpoint path for generating new JWT tokens (e.g., "/login")
    /// When this path is accessed, the plugin will sign the response data as a JWT
    auth_path: String,

    /// Secret key used for HMAC signing/verification
    /// This should be kept secure and consistent across all instances
    secret: String,

    /// HTTP header name to extract JWT from (typically "Authorization")
    /// Supports both "Bearer <token>" and raw token formats
    header: Option<String>,

    /// Query parameter name to extract JWT from
    /// Token will be read from ?{query}=<token>
    query: Option<String>,

    /// Cookie name to extract JWT from
    /// Token will be read from the specified cookie value
    cookie: Option<String>,

    /// HMAC algorithm selection: "HS256" (default) or "HS512"
    /// HS512 provides stronger hashing but may be slower
    algorithm: String,

    /// Optional delay on authentication failure
    /// Helps prevent timing attacks by making success/failure responses take similar time
    delay: Option<Duration>,

    /// Template for 401 Unauthorized responses
    /// Used when token is missing, invalid, or expired
    unauthorized_resp: HttpResponse,

    /// Unique identifier for this plugin instance
    /// Used for internal plugin management
    hash_value: String,
}

impl TryFrom<&PluginConf> for JwtAuth {
    type Error = Error;

    /// Attempts to create a JwtAuth instance from plugin configuration
    ///
    /// # Arguments
    /// * `value` - Plugin configuration
    ///
    /// # Returns
    /// * `Result<Self>` - Valid JwtAuth instance or configuration error
    ///
    /// # Errors
    /// * When no token location (header/query/cookie) is specified
    /// * When secret is empty
    /// * When plugin step is not Request
    /// * When delay duration is invalid
    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);
        let header = get_str_conf(value, "header");
        let query = get_str_conf(value, "query");
        let cookie = get_str_conf(value, "cookie");
        if header.is_empty() && query.is_empty() && cookie.is_empty() {
            return Err(Error::Invalid {
                category: PluginCategory::Jwt.to_string(),
                message: "Jwt key or key type is not allowed empty".to_string(),
            });
        }
        let header = if header.is_empty() {
            None
        } else {
            Some(header)
        };
        let query = if query.is_empty() { None } else { Some(query) };
        let cookie = if cookie.is_empty() {
            None
        } else {
            Some(cookie)
        };
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
        let params = Self {
            hash_value,
            plugin_step: get_step_conf(value),
            secret: get_str_conf(value, "secret"),
            auth_path: get_str_conf(value, "auth_path"),
            algorithm: get_str_conf(value, "algorithm"),
            delay,
            header,
            query,
            cookie,
            unauthorized_resp: HttpResponse {
                status: StatusCode::UNAUTHORIZED,
                body: Bytes::from_static(b"Invalid or expired jwt"),
                ..Default::default()
            },
        };

        if params.secret.is_empty() {
            return Err(Error::Invalid {
                category: PluginCategory::Jwt.to_string(),
                message: "Jwt secret is not allowed empty".to_string(),
            });
        }

        if PluginStep::Request != params.plugin_step {
            return Err(Error::Invalid {
                category: PluginCategory::Jwt.to_string(),
                message: "Jwt auth plugin should be executed at request step"
                    .to_string(),
            });
        }

        Ok(params)
    }
}

impl JwtAuth {
    /// Creates a new JwtAuth plugin instance from the provided configuration
    ///
    /// # Arguments
    /// * `params` - Plugin configuration containing JWT settings
    ///
    /// # Returns
    /// * `Result<Self>` - New JwtAuth instance or error if configuration is invalid
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new jwt auth plugin");
        Self::try_from(params)
    }
}

/// Header structure for JWT tokens containing algorithm and type information
#[derive(Debug, Default, Deserialize, Clone, Serialize)]
struct JwtHeader {
    alg: String,
    typ: String,
}

#[async_trait]
impl Plugin for JwtAuth {
    /// Returns unique identifier for this plugin instance
    #[inline]
    fn hash_key(&self) -> String {
        self.hash_value.clone()
    }

    /// Handles incoming requests by validating JWT tokens
    ///
    /// # Arguments
    /// * `step` - Current plugin execution step
    /// * `session` - Current HTTP session
    /// * `_ctx` - Plugin state context
    ///
    /// # Returns
    /// * `pingora::Result<Option<HttpResponse>>` - None if authentication succeeds, or error response if it fails
    #[inline]
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        _ctx: &mut State,
    ) -> pingora::Result<Option<HttpResponse>> {
        if step != self.plugin_step {
            return Ok(None);
        }
        let req_header = session.req_header();
        if req_header.uri.path() == self.auth_path {
            return Ok(None);
        }
        let value = if let Some(key) = &self.header {
            let value =
                util::get_req_header_value(req_header, key).unwrap_or_default();
            let bearer = "Bearer ";
            if value.starts_with(bearer) {
                value.substring(bearer.len(), value.len())
            } else {
                value
            }
        } else if let Some(key) = &self.cookie {
            util::get_cookie_value(req_header, key).unwrap_or_default()
        } else if let Some(key) = &self.query {
            util::get_query_value(req_header, key).unwrap_or_default()
        } else {
            ""
        };
        if value.is_empty() {
            let mut resp = self.unauthorized_resp.clone();
            resp.body = Bytes::from_static(b"Jwt authorization is missing");
            return Ok(Some(resp));
        }
        let arr: Vec<&str> = value.split('.').collect();
        if arr.len() != 3 {
            let mut resp = self.unauthorized_resp.clone();
            resp.body =
                Bytes::from_static(b"Jwt authorization format is invalid");
            return Ok(Some(resp));
        }
        let jwt_header = serde_json::from_slice::<JwtHeader>(
            &URL_SAFE_NO_PAD.decode(arr[0]).unwrap_or_default(),
        )
        .unwrap_or_default();
        let content = format!("{}.{}", arr[0], arr[1]);
        let secret = self.secret.as_bytes();
        let valid = match jwt_header.alg.as_str() {
            "HS512" => {
                let hash = hmac_sha512::HMAC::mac(content.as_bytes(), secret);
                URL_SAFE_NO_PAD.encode(hash) == arr[2]
            },
            _ => {
                let hash = hmac_sha256::HMAC::mac(content.as_bytes(), secret);
                URL_SAFE_NO_PAD.encode(hash) == arr[2]
            },
        };
        if !valid {
            if let Some(d) = self.delay {
                sleep(d).await;
            }
            let mut resp = self.unauthorized_resp.clone();
            resp.body = Bytes::from_static(b"Jwt authorization is invalid");
            return Ok(Some(resp));
        }
        let value: serde_json::Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD.decode(arr[1]).unwrap_or_default(),
        )
        .unwrap_or_default();
        if let Some(exp) = value.get("exp") {
            if exp.as_u64().unwrap_or_default() < util::now().as_secs() {
                let mut resp = self.unauthorized_resp.clone();
                resp.body = Bytes::from_static(b"Jwt authorization is expired");
                return Ok(Some(resp));
            }
        }

        Ok(None)
    }

    /// Handles responses for the token generation endpoint
    ///
    /// # Arguments
    /// * `step` - Current plugin execution step
    /// * `session` - Current HTTP session
    /// * `ctx` - Plugin state context
    /// * `upstream_response` - Response headers from upstream
    ///
    /// # Returns
    /// * `pingora::Result<()>` - Success or error
    #[inline]
    async fn handle_response(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut State,
        upstream_response: &mut ResponseHeader,
    ) -> pingora::Result<()> {
        if step != PluginStep::Response || self.auth_path.is_empty() {
            return Ok(());
        }
        if session.req_header().uri.path() != self.auth_path {
            return Ok(());
        }
        upstream_response.remove_header(&http::header::CONTENT_LENGTH);
        let json = HTTP_HEADER_CONTENT_JSON.clone();
        let _ = upstream_response.insert_header(json.0, json.1);

        // no error
        let _ = upstream_response.insert_header(
            http::header::TRANSFER_ENCODING,
            HTTP_HEADER_TRANSFER_CHUNKED.1.clone(),
        );
        ctx.modify_response_body = Some(Box::new(Sign {
            algorithm: self.algorithm.clone(),
            secret: self.secret.clone(),
        }));

        Ok(())
    }
}

/// Handles JWT token signing for the token generation endpoint
struct Sign {
    secret: String,
    algorithm: String,
}

impl ModifyResponseBody for Sign {
    /// Signs and formats response data into a JWT token
    ///
    /// # Arguments
    /// * `data` - Response payload to be encoded in the JWT
    ///
    /// # Returns
    /// * `Bytes` - JSON response containing the signed JWT token
    fn handle(&self, data: Bytes) -> Bytes {
        let is_hs512 = self.algorithm == "HS512";
        let alg = if is_hs512 { "HS512" } else { "HS256" };
        let header = URL_SAFE_NO_PAD
            .encode(r#"{"alg": ""#.to_owned() + alg + r#"","typ": "JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(data);
        let content = format!("{header}.{payload}");
        let secret = self.secret.as_bytes();
        let sign = if is_hs512 {
            let hash = hmac_sha512::HMAC::mac(content.as_bytes(), secret);
            URL_SAFE_NO_PAD.encode(hash)
        } else {
            let hash = hmac_sha256::HMAC::mac(content.as_bytes(), secret);
            URL_SAFE_NO_PAD.encode(hash)
        };
        let token = format!("{content}.{sign}");
        Bytes::from(r#"{"token": "{}"}"#.replace("{}", &token))
    }
}

#[cfg(test)]
mod tests {
    use super::JwtAuth;
    use crate::config::{PluginConf, PluginStep};
    use crate::plugin::Plugin;
    use crate::state::State;
    use bytes::Bytes;
    use pingora::http::ResponseHeader;
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    /// Tests JWT authentication parameter validation
    #[test]
    fn test_jwt_auth_params() {
        let params = JwtAuth::try_from(
            &toml::from_str::<PluginConf>(
                r###"
secret = "123123"
cookie = "jwt"
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!("jwt", params.cookie.unwrap_or_default());
        assert_eq!("123123", params.secret);

        let result = JwtAuth::try_from(
            &toml::from_str::<PluginConf>(
                r###"
cookie = "jwt"
"###,
            )
            .unwrap(),
        );

        assert_eq!(
            "Plugin jwt invalid, message: Jwt secret is not allowed empty",
            result.err().unwrap().to_string()
        );

        let result = JwtAuth::try_from(
            &toml::from_str::<PluginConf>(
                r###"
secret = "123123"
"###,
            )
            .unwrap(),
        );

        assert_eq!(
            "Plugin jwt invalid, message: Jwt key or key type is not allowed empty",
            result.err().unwrap().to_string()
        );
    }

    /// Tests creation of new JWT auth instances
    #[test]
    fn test_new_jwt() {
        let auth = JwtAuth::new(
            &toml::from_str::<PluginConf>(
                r###"
secret = "123123"
cookie = "jwt"
"###,
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!("jwt", auth.cookie.unwrap());

        let auth = JwtAuth::new(
            &toml::from_str::<PluginConf>(
                r###"
secret = "123123"
cookie = "jwt"
auth_path = "/login"
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!("jwt", auth.cookie.unwrap());
        assert_eq!("/login", auth.auth_path);
    }

    /// Tests JWT token validation functionality
    #[tokio::test]
    async fn test_jwt_auth() {
        let auth = JwtAuth::new(
            &toml::from_str::<PluginConf>(
                r###"
secret = "123123"
header = "Authorization"
"###,
            )
            .unwrap(),
        )
        .unwrap();

        // auth success(hs256)
        let headers = ["Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiIsImFkbWluIjp0cnVlLCJleHAiOjIzNDgwNTUyNjV9.j6sYJ2dCCSxskwPmvHM7WniGCbkT30z2BrjfsuQLFJc"].join("\r\n");
        let input_header = format!("GET / HTTP/1.1\r\n{headers}\r\n\r\n");
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

        // auth success(hs512)
        let headers = ["Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiIsImFkbWluIjp0cnVlLCJleHAiOjIzNDgwNTUyNjV9.HxFVxDd5ZiLsD1dWW1AywWMERhqk0Ck9IsdBHyD_1zap3w-waVOmFq0Yt1fWaYmh8HDtXLN6vlTd0HHYIYEGUw"].join("\r\n");
        let input_header = format!("GET / HTTP/1.1\r\n{headers}\r\n\r\n");
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

        // no auth token
        let headers = [""].join("\r\n");
        let input_header = format!("GET / HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let resp = auth
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut State::default(),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(401, resp.status.as_u16());
        assert_eq!(
            "Jwt authorization is missing",
            std::string::String::from_utf8_lossy(resp.body.as_ref())
        );

        // auth format invalid
        let headers = ["Authorization: Bearer a.b"].join("\r\n");
        let input_header = format!("GET / HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let resp = auth
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut State::default(),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(401, resp.status.as_u16());
        assert_eq!(
            "Jwt authorization format is invalid",
            std::string::String::from_utf8_lossy(resp.body.as_ref())
        );

        let headers = ["Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiIsImFkbWluIjp0cnVlLCJleHAiOjE3MTcwODQ4MDB9.zz7VHuqt9t6UGLNr5RZdfzvqMDEei"].join("\r\n");
        let input_header = format!("GET / HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let resp = auth
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut State::default(),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(401, resp.status.as_u16());
        assert_eq!(
            "Jwt authorization is invalid",
            std::string::String::from_utf8_lossy(resp.body.as_ref())
        );

        // expired
        let headers = ["Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiIsImFkbWluIjp0cnVlLCJleHAiOjE3MTY5MDMyNjV9.PRS-PZafcGsV_rCL8QQfJdOJAvL5fOI_Z14N16JEcng"].join("\r\n");
        let input_header = format!("GET / HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let resp = auth
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut State::default(),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(401, resp.status.as_u16());
        assert_eq!(
            "Jwt authorization is expired",
            std::string::String::from_utf8_lossy(resp.body.as_ref())
        );
    }

    /// Tests JWT token signing functionality
    #[tokio::test]
    async fn test_jwt_sign() {
        let auth = JwtAuth::new(
            &toml::from_str::<PluginConf>(
                r###"
secret = "123123"
header = "Authorization"
auth_path = "/login"
"###,
            )
            .unwrap(),
        )
        .unwrap();

        let headers = [""].join("\r\n");
        let input_header = format!("GET /login HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let mut ctx = State::default();
        let mut upstream_response =
            ResponseHeader::build_no_case(200, None).unwrap();
        auth.handle_response(
            PluginStep::Response,
            &mut session,
            &mut ctx,
            &mut upstream_response,
        )
        .await
        .unwrap();

        assert_eq!(
            r#"ResponseHeader { base: Parts { status: 200, version: HTTP/1.1, headers: {"content-type": "application/json; charset=utf-8", "transfer-encoding": "chunked"} }, header_name_map: None, reason_phrase: None }"#,
            format!("{upstream_response:?}")
        );
        assert_eq!(true, ctx.modify_response_body.is_some());
        if let Some(modify) = ctx.modify_response_body {
            let data = modify.handle(Bytes::from_static(b"Pingap"));
            assert_eq!(
                r#"{"token": "eyJhbGciOiAiSFMyNTYiLCJ0eXAiOiAiSldUIn0.UGluZ2Fw.wRLT2HhM1R-J4rVz3XCWADNIrmeInLtRGQzfJZaz-qI"}"#,
                std::string::String::from_utf8_lossy(&data)
                    .to_string()
                    .as_str()
            );
        }
    }
}
