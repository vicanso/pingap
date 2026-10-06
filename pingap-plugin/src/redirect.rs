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

use super::{Error, get_bool_conf, get_hash_key, get_int_conf, get_str_conf};
use async_trait::async_trait;
use http::{HeaderValue, StatusCode, header};
use pingap_config::{PluginCategory, PluginConf};
use pingap_core::{
    Ctx, HttpResponse, Plugin, PluginStep, RequestPluginResult, get_host,
    new_internal_error,
};
use pingora::http::RequestHeader;
use pingora::proxy::Session;
use std::borrow::Cow;
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
/// - `status`: HTTP status code for the redirect (301, 302, 307, 308). Defaults to 307.
/// - `step`: Must be set to "request" as redirects are pre-processing only
pub struct Redirect {
    // Path prefix to add to redirected URLs (e.g., "/api")
    // Will be normalized to start with "/" if not empty
    prefix: String,
    // Whether to redirect HTTP requests to HTTPS
    // true = force HTTPS, false = force HTTP
    http_to_https: bool,
    // HTTP status code for the redirect response
    status: StatusCode,
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
        debug!(
            params = pingap_config::masked_toml(params),
            "new redirect plugin"
        );
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
        // Only a redirect status makes sense; a mistyped one used to turn
        // into a 307 without a word.
        let status = match get_int_conf(params, "status") {
            0 | 307 => StatusCode::TEMPORARY_REDIRECT,
            301 => StatusCode::MOVED_PERMANENTLY,
            302 => StatusCode::FOUND,
            303 => StatusCode::SEE_OTHER,
            308 => StatusCode::PERMANENT_REDIRECT,
            other => {
                return Err(Error::Invalid {
                    category: PluginCategory::Redirect.to_string(),
                    message: format!(
                        "Invalid status({other}), expect 301, 302, 303, 307 or 308"
                    ),
                });
            },
        };
        Ok(Self {
            hash_value,
            prefix,
            http_to_https: get_bool_conf(params, "http_to_https"),
            status,
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
    fn config_key(&self) -> Cow<'_, str> {
        // Return unique identifier for this plugin instance
        Cow::Borrowed(&self.hash_value)
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
    ) -> pingora::Result<RequestPluginResult> {
        // Early return if not in request phase
        if step != self.plugin_step {
            return Ok(RequestPluginResult::Skipped);
        }

        // Only `http_to_https` changes the scheme, and only one way: a
        // request that came over TLS is where it should be. Without the
        // option the scheme is left alone. It used to count as "plain http
        // wanted", so a plugin set up for the prefix alone sent every
        // https request to `http://`, the ones with the prefix included.
        let is_tls = ctx.conn.tls_version.is_some();
        let schema_match = is_tls || !self.http_to_https;

        // Skip redirect if:
        // 1. Schema already matches desired state (HTTP/HTTPS)
        // 2. URL path already has the correct prefix
        if schema_match
            && session.req_header().uri.path().starts_with(&self.prefix)
        {
            return Ok(RequestPluginResult::Skipped);
        }

        // The host to send the client to. A redirect that only adds the
        // prefix stays where the request came in, port included: taking the
        // host alone sent a request for `example.com:8080` to port 80. A
        // change of scheme goes to the default port of the new scheme,
        // since the port of the old one is not where the new one listens.
        let req_header = session.req_header();
        let host = if schema_match {
            request_authority(req_header)
        } else {
            get_host(req_header).unwrap_or_default()
        };

        // The scheme of the request, or https when it is being changed.
        let schema = if is_tls || self.http_to_https {
            "https"
        } else {
            "http"
        };

        // Only a url that is missing the prefix gets it prepended. Getting here
        // with the prefix already in place means the schema is what triggered
        // the redirect, and prepending unconditionally would produce
        // `/api/api/...`. The test matches the skip condition above so the two
        // cannot disagree.
        let prefix = if req_header.uri.path().starts_with(&self.prefix) {
            ""
        } else {
            self.prefix.as_str()
        };
        // Path and query only. The uri of an HTTP/2 request carries scheme
        // and host as well, and written out whole it gave
        // `https://example.comhttps://example.com/path`.
        let path_and_query = req_header
            .uri
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/");

        // Build Location with:
        // - Desired schema (http/https)
        // - Original host
        // - Configured prefix
        // - Original path and query parameters
        // A host the header syntax rejects is the client's mistake.
        let location = HeaderValue::from_str(&format!(
            "{schema}://{host}{prefix}{path_and_query}"
        ))
        .map_err(|e| new_internal_error(400, e))?;

        Ok(RequestPluginResult::Respond(HttpResponse {
            status: self.status,
            headers: Some(vec![(header::LOCATION, location)]),
            ..Default::default()
        }))
    }
}

/// The host of the request as it was sent, with its port: the authority of
/// the uri (HTTP/2), or the `Host` header.
fn request_authority(req_header: &RequestHeader) -> &str {
    if let Some(authority) = req_header.uri.authority() {
        return authority.as_str();
    }
    req_header
        .headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
}

register_plugin!("redirect", Redirect);

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
        let RequestPluginResult::Respond(resp) = result else {
            panic!("result is not Respond");
        };
        assert_eq!(StatusCode::TEMPORARY_REDIRECT, resp.status);
        assert_eq!(
            r###"Some([("location", "https://github.com/api/vicanso/pingap?size=1")])"###,
            format!("{:?}", resp.headers)
        );
    }

    async fn location(
        redirect: &Redirect,
        session: &mut Session,
    ) -> Option<String> {
        let result = redirect
            .handle_request(PluginStep::Request, session, &mut Ctx::default())
            .await
            .unwrap();
        let RequestPluginResult::Respond(resp) = result else {
            return None;
        };
        let headers = resp.headers.unwrap();
        Some(headers[0].1.to_str().unwrap().to_string())
    }

    async fn h1_session(host: &str, path: &str) -> Session {
        let input_header =
            format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        session
    }

    /// Regression: the port of the request was dropped from the redirect.
    /// When only the prefix is added the scheme stays, and so does the port.
    #[tokio::test]
    async fn test_redirect_keeps_the_port() {
        let prefix_only = Redirect::new(
            &toml::from_str::<PluginConf>("prefix = \"/api\"").unwrap(),
        )
        .unwrap();
        let mut session = h1_session("github.com:8080", "/users?size=1").await;
        assert_eq!(
            Some("http://github.com:8080/api/users?size=1".to_string()),
            location(&prefix_only, &mut session).await
        );
        let mut session = h1_session("[::1]:8080", "/users").await;
        assert_eq!(
            Some("http://[::1]:8080/api/users".to_string()),
            location(&prefix_only, &mut session).await
        );
        // Nothing to do once the prefix is there.
        let mut session = h1_session("github.com:8080", "/api/users").await;
        assert_eq!(None, location(&prefix_only, &mut session).await);

        // A change of scheme goes to the default port of the new scheme.
        let to_https = Redirect::new(
            &toml::from_str::<PluginConf>("http_to_https = true").unwrap(),
        )
        .unwrap();
        let mut session = h1_session("github.com:8080", "/users").await;
        assert_eq!(
            Some("https://github.com/users".to_string()),
            location(&to_https, &mut session).await
        );
    }

    /// Regression: the uri of an HTTP/2 request has scheme and host in it,
    /// and the whole of it was appended to the scheme and host of the
    /// redirect.
    #[tokio::test]
    async fn test_redirect_http2_uri() {
        let redirect = Redirect::new(
            &toml::from_str::<PluginConf>(
                "http_to_https = true\nprefix = \"/api\"",
            )
            .unwrap(),
        )
        .unwrap();
        let mut session = h1_session("ignored.example", "/").await;
        session.req_header_mut().set_uri(
            "http://github.com:8080/users?size=1"
                .parse::<http::Uri>()
                .unwrap(),
        );
        assert_eq!(
            Some("https://github.com/api/users?size=1".to_string()),
            location(&redirect, &mut session).await
        );

        let prefix_only = Redirect::new(
            &toml::from_str::<PluginConf>("prefix = \"/api\"").unwrap(),
        )
        .unwrap();
        assert_eq!(
            Some("http://github.com:8080/api/users?size=1".to_string()),
            location(&prefix_only, &mut session).await
        );
    }

    #[test]
    fn test_redirect_rejects_other_statuses() {
        for status in [200, 304, 404, 399] {
            let err = Redirect::new(
                &toml::from_str::<PluginConf>(&format!(
                    "http_to_https = true\nstatus = {status}"
                ))
                .unwrap(),
            )
            .err()
            .unwrap()
            .to_string();
            assert_eq!(
                format!(
                    "Plugin redirect invalid, message: Invalid status({status}), expect 301, 302, 303, 307 or 308"
                ),
                err
            );
        }
    }

    #[tokio::test]
    async fn test_redirect_with_status() {
        for (status_conf, expected_status) in [
            (301, StatusCode::MOVED_PERMANENTLY),
            (302, StatusCode::FOUND),
            (303, StatusCode::SEE_OTHER),
            (307, StatusCode::TEMPORARY_REDIRECT),
            (308, StatusCode::PERMANENT_REDIRECT),
        ] {
            let redirect = Redirect::new(
                &toml::from_str::<PluginConf>(&format!(
                    r###"
http_to_https = true
status = {status_conf}
"###,
                ))
                .unwrap(),
            )
            .unwrap();

            let headers = ["Host: github.com"].join("\r\n");
            let input_header =
                format!("GET /vicanso/pingap HTTP/1.1\r\n{headers}\r\n\r\n");
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
            let RequestPluginResult::Respond(resp) = result else {
                panic!("result is not Respond for status {status_conf}");
            };
            assert_eq!(expected_status, resp.status);
        }
    }

    /// Regression: without `http_to_https` the plugin took plain http for
    /// the scheme it was to enforce. Set up for the prefix alone on an
    /// https server, it redirected every request to `http://`, the ones
    /// that had the prefix already included.
    #[tokio::test]
    async fn test_redirect_prefix_only_keeps_https() {
        let prefix_only = Redirect::new(
            &toml::from_str::<PluginConf>("prefix = \"/api\"").unwrap(),
        )
        .unwrap();
        let over_tls = || {
            let mut ctx = Ctx::default();
            ctx.conn.tls_version = Some("TLSv1.3".into());
            ctx
        };
        let target = async |path: &str, ctx: &mut Ctx| {
            let mut session = h1_session("a.test", path).await;
            let result = prefix_only
                .handle_request(PluginStep::Request, &mut session, ctx)
                .await
                .unwrap();
            match result {
                RequestPluginResult::Respond(resp) => Some(
                    resp.headers.unwrap()[0].1.to_str().unwrap().to_string(),
                ),
                _ => None,
            }
        };

        // Over TLS: the prefix is added, the scheme stays.
        assert_eq!(
            Some("https://a.test/api/users".to_string()),
            target("/users", &mut over_tls()).await
        );
        // With the prefix in place there is nothing to do.
        assert_eq!(None, target("/api/users", &mut over_tls()).await);
        // Plain http, as before.
        assert_eq!(
            Some("http://a.test/api/users".to_string()),
            target("/users", &mut Ctx::default()).await
        );
        assert_eq!(None, target("/api/users", &mut Ctx::default()).await);
    }

    /// Regression: a plain-http request whose path already carries the prefix
    /// used to be redirected to `/api/api/...`.
    #[tokio::test]
    async fn test_redirect_keeps_existing_prefix() {
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
            format!("GET /api/vicanso?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
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
        let RequestPluginResult::Respond(resp) = result else {
            panic!("result is not Respond");
        };
        assert_eq!(
            r###"Some([("location", "https://github.com/api/vicanso?size=1")])"###,
            format!("{:?}", resp.headers)
        );
    }
}
