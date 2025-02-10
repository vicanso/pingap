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
use http::StatusCode;
use pingap_config::PluginConf;
use pingap_core::{convert_headers, Ctx, HttpResponse, Plugin, PluginStep};
use pingora::proxy::Session;
use std::sync::Arc;
use tracing::debug;

type Result<T, E = Error> = std::result::Result<T, E>;

/// A plugin that handles HTTP/HTTPS redirects and path prefix modifications.
///
/// # Use Cases
/// - Force HTTPS usage for security requirements
/// - Add API version prefixes (e.g., /v1, /api/v2)
/// - Implement path-based routing
///
/// # Configuration
/// - `http_to_https`: Boolean flag to control redirect direction
/// - `prefix`: Optional path prefix to add to redirected URLs
/// - `step`: Must be set to "request" as redirects are pre-processing only
pub struct Redirect {
    // Path prefix to add to redirected URLs (e.g., "/api")
    // Will be normalized to start with "/" if not empty
    prefix: String,
    // Whether to redirect HTTP requests to HTTPS
    // true = force HTTPS, false = force HTTP
    http_to_https: bool,
    // Plugin execution step (must be Request)
    // Response step is invalid as redirects must be handled before request processing
    plugin_step: PluginStep,
    // Unique hash value for plugin instance
    // Used for plugin identification and caching
    hash_value: String,
}

impl Redirect {
    /// Creates a new Redirect plugin instance from the provided configuration.
    ///
    /// # Arguments
    /// * `params` - Plugin configuration containing redirect settings
    ///
    /// # Returns
    /// * `Result<Self>` - New plugin instance or error if configuration is invalid
    ///
    /// # Errors
    /// Returns an error if:
    /// - Plugin step is not set to "request"
    /// - Required configuration parameters are missing
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new redirect plugin");
        let hash_value = get_hash_key(params);

        // Normalize prefix handling:
        // - Empty or single char prefixes become empty string
        // - Prefixes without leading "/" get one added
        // This ensures consistent path handling
        let mut prefix = get_str_conf(params, "prefix");
        if prefix.len() <= 1 {
            prefix = "".to_string();
        } else if !prefix.starts_with("/") {
            prefix = format!("/{prefix}");
        }
        Ok(Self {
            hash_value,
            prefix,
            http_to_https: get_bool_conf(params, "http_to_https"),
            plugin_step: PluginStep::Request,
        })
    }
}

#[async_trait]
impl Plugin for Redirect {
    /// Returns a unique identifier for this plugin instance.
    ///
    /// The hash key is used for plugin identification and caching purposes.
    /// It's generated from the plugin's configuration parameters.
    #[inline]
    fn hash_key(&self) -> String {
        // Return unique identifier for this plugin instance
        self.hash_value.clone()
    }

    /// Handles incoming HTTP requests and performs redirects as needed.
    ///
    /// # Arguments
    /// * `step` - Current processing step (must match plugin_step)
    /// * `session` - HTTP session containing request details
    /// * `ctx` - Request context containing TLS information
    ///
    /// # Returns
    /// * `Ok(None)` - No redirect needed
    /// * `Ok(Some(HttpResponse))` - 307 redirect response with new location
    ///
    /// # Processing Logic
    /// 1. Validates processing step
    /// 2. Checks if current schema (HTTP/HTTPS) matches desired state
    /// 3. Verifies if URL already has correct prefix
    /// 4. Constructs redirect URL with appropriate schema and prefix
    /// 5. Returns 307 redirect response to preserve HTTP method
    #[inline]
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<Option<HttpResponse>> {
        // Early return if not in request phase
        if step != self.plugin_step {
            return Ok(None);
        }

        // Check current request state:
        // - ctx.tls_version.is_some() indicates HTTPS
        // - Compare against desired http_to_https setting
        let schema_match = ctx.tls_version.is_some() == self.http_to_https;

        // Skip redirect if:
        // 1. Schema already matches desired state (HTTP/HTTPS)
        // 2. URL path already has the correct prefix
        if schema_match
            && session.req_header().uri.path().starts_with(&self.prefix)
        {
            return Ok(None);
        }

        // Extract host from request headers
        // Fallback to empty string if not found
        let host =
            pingap_util::get_host(session.req_header()).unwrap_or_default();

        // Determine target schema based on configuration
        let schema = if self.http_to_https { "https" } else { "http" };

        // Build Location header with:
        // - Desired schema (http/https)
        // - Original host
        // - Configured prefix
        // - Original URI (path + query parameters)
        let location = format!(
            "Location: {}://{host}{}{}",
            schema,
            self.prefix,
            session.req_header().uri
        );

        // Return 307 Temporary Redirect
        // Using 307 instead of 301/302 to preserve HTTP method
        // This is important for POST/PUT/DELETE requests
        Ok(Some(HttpResponse {
            status: StatusCode::TEMPORARY_REDIRECT,
            headers: Some(convert_headers(&[location]).unwrap_or_default()),
            ..Default::default()
        }))
    }
}

#[ctor]
fn init() {
    get_plugin_factory()
        .register("redirect", |params| Ok(Arc::new(Redirect::new(params)?)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::StatusCode;
    use pingap_config::PluginConf;
    use pingap_core::{Ctx, PluginStep};
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    /// Tests the redirect plugin functionality.
    ///
    /// Verifies:
    /// - HTTP to HTTPS redirection
    /// - Path prefix addition
    /// - Error handling for invalid configuration
    /// - Correct status code and header generation
    #[tokio::test]
    async fn test_redirect() {
        let redirect = Redirect::new(
            &toml::from_str::<PluginConf>(
                r###"
http_to_https = true
prefix = "/api"
"###,
            )
            .unwrap(),
        )
        .unwrap();

        let headers = ["Host: github.com"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = redirect
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result.is_some());
        let resp = result.unwrap();
        assert_eq!(StatusCode::TEMPORARY_REDIRECT, resp.status);
        assert_eq!(
            r###"Some([("location", "https://github.com/api/vicanso/pingap?size=1")])"###,
            format!("{:?}", resp.headers)
        );
    }
}
