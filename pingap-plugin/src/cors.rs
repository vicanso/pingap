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
    get_bool_conf, get_hash_key, get_plugin_factory, get_str_conf, Error,
};
use async_trait::async_trait;
use ctor::ctor;
use http::{header, HeaderValue};
use humantime::parse_duration;
use pingap_config::{PluginCategory, PluginConf};
use pingap_core::{
    convert_header_value, Ctx, HttpHeader, HttpResponse, Plugin, PluginStep,
    RequestPluginResult, ResponsePluginResult,
};
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use regex::Regex;
use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

type Result<T, E = Error> = std::result::Result<T, E>;

/// CORS (Cross-Origin Resource Sharing) plugin for handling cross-origin requests
/// Supports both preflight requests and actual CORS requests with configurable rules
pub struct Cors {
    // Determines when plugin executes (Request phase for preflight, Response for actual requests)
    plugin_step: PluginStep,
    // Optional regex for path-based CORS rules (e.g., "^/api" for API endpoints only)
    path: Option<Regex>,
    // Configurable origin - can be "*", specific domain, or dynamic "$http_origin"
    allow_origin: HeaderValue,
    // Pre-computed CORS headers to avoid rebuilding on every request
    // Includes: Allow-Methods, Allow-Headers, Max-Age, Allow-Credentials, Expose-Headers
    headers: Vec<HttpHeader>,
    // Unique identifier for plugin instance, used for caching and identification
    hash_value: String,
}

impl TryFrom<&PluginConf> for Cors {
    type Error = Error;
    /// Converts a plugin configuration into a CORS plugin instance
    ///
    /// # Arguments
    /// * `value` - Plugin configuration containing CORS settings
    ///
    /// # Returns
    /// * `Result<Self>` - Configured CORS plugin or error if configuration is invalid
    ///
    /// # Configuration Options
    /// * `path` - Regex pattern for matching request paths
    /// * `max_age` - Duration for caching preflight results (e.g., "60m")
    /// * `allow_origin` - Allowed origins ("*", domain, or "$http_origin")
    /// * `allow_methods` - Comma-separated list of allowed HTTP methods
    /// * `allow_headers` - Allowed request headers
    /// * `allow_credentials` - Whether to allow credentials (cookies, auth)
    /// * `expose_headers` - Headers accessible to the browser
    fn try_from(value: &PluginConf) -> Result<Self> {
        // Generate unique hash for this configuration
        let hash_value = get_hash_key(value);

        // Parse max-age duration with human-friendly format (e.g., "60m", "24h")
        // Controls browser caching of preflight results
        let max_age = get_str_conf(value, "max_age");
        let max_age = if !max_age.is_empty() {
            parse_duration(&max_age).map_err(|e| Error::Invalid {
                category: PluginCategory::Cors.to_string(),
                message: e.to_string(),
            })?
        } else {
            // Default to 1 hour if not specified
            Duration::from_secs(3600)
        };

        // Compile path regex if specified, used for selective CORS application
        let path = get_str_conf(value, "path");
        let path = if path.is_empty() {
            None
        } else {
            let reg = Regex::new(&path).map_err(|e| Error::Invalid {
                category: PluginCategory::Cors.to_string(),
                message: e.to_string(),
            })?;
            Some(reg)
        };

        // Configure allowed origins
        // "*" - Allow all origins
        // "example.com" - Allow specific domain
        // "$http_origin" - Mirror the requesting origin (dynamic)
        let mut allow_origin = get_str_conf(value, "allow_origin");
        if allow_origin.is_empty() {
            allow_origin = "*".to_string();
        }

        // Configure allowed HTTP methods
        // Important for preflight requests to know which methods are supported
        let mut allow_methods = get_str_conf(value, "allow_methods");
        if allow_methods.is_empty() {
            allow_methods =
                ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"].join(", ");
        };

        // Helper to convert string values to HTTP header values
        let format_header_value = |value: &str| -> Result<HeaderValue> {
            HeaderValue::from_str(value).map_err(|e| Error::Invalid {
                category: PluginCategory::Cors.to_string(),
                message: e.to_string(),
            })
        };

        // Build the set of CORS headers based on configuration
        let mut headers = vec![(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            format_header_value(&allow_methods)?,
        )];

        // Optional: Allow-Headers for custom headers client may send
        let allow_headers = get_str_conf(value, "allow_headers");
        if !allow_headers.is_empty() {
            headers.push((
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                format_header_value(&allow_headers)?,
            ));
        }

        // Add max-age if non-zero (controls preflight caching)
        if !max_age.is_zero() {
            headers.push((
                header::ACCESS_CONTROL_MAX_AGE,
                format_header_value(&max_age.as_secs().to_string())?,
            ));
        }

        // Optional: Allow credentials (cookies, auth headers)
        // Important: Cannot be used with Allow-Origin: *
        let allow_credentials = get_bool_conf(value, "allow_credentials");
        if allow_credentials {
            headers.push((
                header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                format_header_value("true")?,
            ));
        }

        // Optional: Expose-Headers lets client access custom response headers
        let expose_headers = get_str_conf(value, "expose_headers");
        if !expose_headers.is_empty() {
            headers.push((
                header::ACCESS_CONTROL_EXPOSE_HEADERS,
                format_header_value(&expose_headers)?,
            ));
        }

        let cors = Self {
            hash_value,
            plugin_step: PluginStep::Request,
            path,
            allow_origin: format_header_value(&allow_origin)?,
            headers,
        };

        Ok(cors)
    }
}

impl Cors {
    /// Creates a new CORS plugin instance from the given configuration
    ///
    /// # Arguments
    /// * `params` - Plugin configuration parameters
    ///
    /// # Returns
    /// * `Result<Self>` - Configured CORS plugin or error
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new cors plugin");
        Self::try_from(params)
    }

    /// Generates the set of CORS headers for a request/response
    /// Handles dynamic values like $http_origin
    ///
    /// # Arguments
    /// * `session` - Current HTTP session
    /// * `ctx` - Plugin state context
    ///
    /// # Returns
    /// * `Result<Vec<HttpHeader>>` - Collection of CORS headers or error
    #[inline]
    fn get_headers(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> Result<Vec<HttpHeader>> {
        // Convert dynamic values (e.g., $http_origin) to actual values
        let origin = convert_header_value(&self.allow_origin, session, ctx)
            .ok_or(Error::Invalid {
                category: PluginCategory::Cors.to_string(),
                message: "Allow origin is invalid".to_string(),
            })?;
        // Clone pre-computed headers and add dynamic origin
        let mut headers = self.headers.clone();
        headers.push((header::ACCESS_CONTROL_ALLOW_ORIGIN, origin));
        Ok(headers)
    }
}

#[async_trait]
impl Plugin for Cors {
    /// Returns the unique identifier for this plugin instance
    #[inline]
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    /// Handles incoming requests, particularly CORS preflight (OPTIONS) requests
    ///
    /// # Arguments
    /// * `step` - Current plugin execution step
    /// * `session` - Current HTTP session
    /// * `ctx` - Plugin state context
    ///
    /// # Returns
    /// * `pingora::Result<Option<HttpResponse>>` - Response for preflight requests or None
    #[inline]
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        // Early return if not in request phase
        if step != self.plugin_step {
            return Ok(RequestPluginResult::Skipped);
        }

        // Check if request path matches CORS rules
        if let Some(reg) = &self.path {
            if !reg.is_match(session.req_header().uri.path()) {
                return Ok(RequestPluginResult::Skipped);
            }
        }

        // Handle CORS preflight (OPTIONS) requests
        // Preflight happens before actual request to check if it's allowed
        if http::Method::OPTIONS == session.req_header().method {
            let headers = self
                .get_headers(session, ctx)
                .map_err(|e| pingap_core::new_internal_error(400, e))?;
            // Return 204 No Content with CORS headers for preflight
            let mut resp = HttpResponse::no_content();
            resp.headers = Some(headers);
            return Ok(RequestPluginResult::Respond(resp));
        }
        Ok(RequestPluginResult::Continue)
    }

    /// Modifies responses to add appropriate CORS headers for actual (non-preflight) requests
    ///
    /// # Arguments
    /// * `session` - Current HTTP session
    /// * `ctx` - Plugin state context
    /// * `upstream_response` - Response headers to modify
    ///
    /// # Returns
    /// * `pingora::Result<()>` - Success or error
    async fn handle_response(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
        upstream_response: &mut ResponseHeader,
    ) -> pingora::Result<ResponsePluginResult> {
        // Skip if path doesn't match CORS rules
        if let Some(reg) = &self.path {
            if !reg.is_match(session.req_header().uri.path()) {
                return Ok(ResponsePluginResult::Unchanged);
            }
        }

        // Only add CORS headers if request has Origin header
        // (indicates it's a CORS request)
        if session.get_header(header::ORIGIN).is_none() {
            return Ok(ResponsePluginResult::Unchanged);
        }

        // Add all configured CORS headers to the response
        let headers = self
            .get_headers(session, ctx)
            .map_err(|e| pingap_core::new_internal_error(400, e))?;
        for (name, value) in &headers {
            let _ = upstream_response.insert_header(name, value);
        }
        Ok(ResponsePluginResult::Modified)
    }
}

#[ctor]
fn init() {
    get_plugin_factory()
        .register("cors", |params| Ok(Arc::new(Cors::new(params)?)));
}

#[cfg(test)]
mod tests {
    /// Tests CORS plugin configuration parsing
    use super::*;
    use pingap_config::PluginConf;
    use pingap_core::{Ctx, PluginStep, RequestPluginResult};
    use pingora::{http::ResponseHeader, proxy::Session};
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    #[test]
    fn test_cors_params() {
        let params = Cors::try_from(
            &toml::from_str::<PluginConf>(
                r###"
path = "^/api"
allow_methods = "GET"
allow_origin = "$http_origin"
allow_credentials = true
allow_headers = "Content-Type, X-User-Id"
max_age = "60m"
        "###,
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!("request", params.plugin_step.to_string());
        assert_eq!("^/api", params.path.unwrap().to_string());
        assert_eq!("$http_origin", params.allow_origin);
        assert_eq!(
            r#"[("access-control-allow-methods", "GET"), ("access-control-allow-headers", "Content-Type, X-User-Id"), ("access-control-max-age", "3600"), ("access-control-allow-credentials", "true")]"#,
            format!("{:?}", params.headers)
        );
    }
    /// Tests CORS request handling including preflight and actual requests
    #[tokio::test]
    async fn test_cors() {
        let headers = ["X-User: 123", "Origin: https://pingap.io"].join("\r\n");
        let input_header =
            format!("OPTIONS /api/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let cors = Cors::new(
            &toml::from_str::<PluginConf>(
                r###"
path = "^/api"
allow_methods = "GET"
allow_origin = "$http_origin"
allow_credentials = true
allow_headers = "Content-Type, X-User-Id"
expose_headers = "Content-Encoding, Kuma-Revision"
max_age = "60m"
    "###,
            )
            .unwrap(),
        )
        .unwrap();

        let result = cors
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
        assert_eq!(resp.status, http::StatusCode::NO_CONTENT);

        assert_eq!(
            r#"[("access-control-allow-methods", "GET"), ("access-control-allow-headers", "Content-Type, X-User-Id"), ("access-control-max-age", "3600"), ("access-control-allow-credentials", "true"), ("access-control-expose-headers", "Content-Encoding, Kuma-Revision"), ("access-control-allow-origin", "https://pingap.io")]"#,
            format!("{:?}", resp.headers.unwrap())
        );

        let mut header = ResponseHeader::build(200, None).unwrap();

        cors.handle_response(&mut session, &mut Ctx::default(), &mut header)
            .await
            .unwrap();

        assert_eq!(
            r#"{"access-control-allow-methods": "GET", "access-control-allow-headers": "Content-Type, X-User-Id", "access-control-max-age": "3600", "access-control-allow-credentials": "true", "access-control-expose-headers": "Content-Encoding, Kuma-Revision", "access-control-allow-origin": "https://pingap.io"}"#,
            format!("{:?}", header.headers)
        );
    }
}
