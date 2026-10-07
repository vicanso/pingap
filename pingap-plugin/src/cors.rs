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
    Error, get_bool_conf, get_hash_key, get_str_conf, get_str_slice_conf,
};
use async_trait::async_trait;
use http::{HeaderValue, header};
use humantime::parse_duration;
use pingap_config::{PluginCategory, PluginConf};
use pingap_core::{
    Ctx, HttpHeader, HttpResponse, Plugin, PluginStep, RequestPluginResult,
    ResponsePluginResult, convert_header_value,
};
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use regex::Regex;
use std::borrow::Cow;
use std::time::Duration;
use tracing::{debug, warn};

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
    // The origins that are let in, when it is a list of them and not the
    // one value of `allow_origin`: a request from one of these has its own
    // origin sent back, one from any other gets no CORS headers at all.
    allow_origins: Vec<OriginRule>,
    // The origin is taken from the request (`$http_origin`, or a list of
    // origins), so the answer differs per origin and caches have to be told
    // with `Vary: Origin`.
    vary_origin: bool,
    // Unique identifier for plugin instance, used for caching and identification
    hash_value: String,
}

/// One entry of `allow_origins`.
enum OriginRule {
    /// An origin as a browser sends it: `https://app.example.com`.
    Exact(String),
    /// `~` and a pattern, which the whole of an origin has to match.
    Pattern(Regex),
}

impl OriginRule {
    /// An entry that is neither an origin nor a pattern is an error: it
    /// would let nobody in, and the page it was meant for would fail with
    /// nothing on this side saying why.
    fn parse(entry: &str) -> std::result::Result<Self, String> {
        let entry = entry.trim();
        if let Some(pattern) = entry.strip_prefix('~') {
            // The whole origin, whether or not the pattern says so with
            // `^` and `$`: one that matched anywhere in it would take
            // `example\.com` for `https://example.com.evil.net` too.
            return Regex::new(&format!("^(?:{pattern})$"))
                .map(Self::Pattern)
                .map_err(|e| format!("allow_origins: {e}"));
        }
        if !is_origin(entry) {
            return Err(format!(
                "allow_origins: {entry:?} is not an origin (scheme://host[:port]), nor a pattern starting with ~"
            ));
        }
        Ok(Self::Exact(entry.to_ascii_lowercase()))
    }
    fn matches(&self, origin: &str) -> bool {
        match self {
            Self::Exact(allowed) => allowed.eq_ignore_ascii_case(origin),
            Self::Pattern(pattern) => pattern.is_match(origin),
        }
    }
}

/// Whether `entry` is an origin as a client sends it: a scheme, a host
/// and, where it is not the default of the scheme, a port.
///
/// For http and https that is what the url of it serializes back to, so
/// that `https://a.test/` and `https://a.test:443` - neither of which a
/// browser ever sends - are told apart from `https://a.test`. Another
/// scheme (`capacitor://localhost`, the page of an app in a web view) has
/// no such form to compare with and is taken by its shape.
fn is_origin(entry: &str) -> bool {
    let Some((scheme, rest)) = entry.split_once("://") else {
        return false;
    };
    if scheme.eq_ignore_ascii_case("http")
        || scheme.eq_ignore_ascii_case("https")
    {
        return url::Url::parse(entry).is_ok_and(|url| {
            url.origin()
                .ascii_serialization()
                .eq_ignore_ascii_case(entry)
        });
    }
    let is_scheme = scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    is_scheme
        && !rest.is_empty()
        && rest.chars().all(|c| {
            c.is_ascii_graphic() && !matches!(c, '/' | '?' | '#' | '@' | '\\')
        })
}

/// The headers of a response that let an origin in.
const ALLOW_HEADERS: [header::HeaderName; 6] = [
    header::ACCESS_CONTROL_ALLOW_ORIGIN,
    header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
    header::ACCESS_CONTROL_ALLOW_METHODS,
    header::ACCESS_CONTROL_ALLOW_HEADERS,
    header::ACCESS_CONTROL_EXPOSE_HEADERS,
    header::ACCESS_CONTROL_MAX_AGE,
];

/// Whether `Vary` already covers `Origin` (or everything).
fn varies_by_origin(headers: &http::HeaderMap) -> bool {
    headers
        .get_all(header::VARY)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .any(|name| name == "*" || name.eq_ignore_ascii_case("origin"))
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
        let invalid = |message: String| Error::Invalid {
            category: PluginCategory::Cors.to_string(),
            message,
        };
        let allow_origins = get_str_slice_conf(value, "allow_origins")
            .iter()
            .map(|entry| OriginRule::parse(entry).map_err(invalid))
            .collect::<Result<Vec<_>>>()?;
        // A list with nothing on it reads as "nobody", and would be taken
        // for no list at all: everybody.
        if allow_origins.is_empty() && value.contains_key("allow_origins") {
            return Err(invalid(
                "allow_origins is empty: list the origins that are let in, or leave it out"
                    .to_string(),
            ));
        }
        if !allow_origins.is_empty() && !allow_origin.is_empty() {
            return Err(invalid(
                "allow_origin and allow_origins are two ways to say who is let in, set one of them"
                    .to_string(),
            ));
        }
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
        // A browser refuses the two together, for a request that carries
        // credentials. Said and not refused here: requests without them
        // do work with it, and configurations that have it are in use.
        if allow_credentials && allow_origins.is_empty() && allow_origin == "*"
        {
            warn!(
                "cors: allow_credentials with allow_origin \"*\" is refused by browsers for requests with credentials, list the origins in allow_origins"
            );
        }
        // The pairing that does work, and for everyone: whatever site the
        // visitor has open is sent back as allowed and may use the
        // visitor's cookies.
        if allow_credentials
            && allow_origins.is_empty()
            && allow_origin == "$http_origin"
        {
            warn!(
                "cors: allow_credentials with allow_origin \"$http_origin\" lets every site act with the visitor's credentials, list the origins in allow_origins"
            );
        }
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
            vary_origin: !allow_origins.is_empty()
                || allow_origin.starts_with('$')
                || allow_origin.starts_with(':'),
            allow_origin: format_header_value(&allow_origin)?,
            allow_origins,
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
        debug!(
            params = pingap_config::masked_toml(params),
            "new cors plugin"
        );
        Self::try_from(params)
    }

    /// The preflight headers: the prebuilt list plus the origin.
    #[inline]
    fn get_headers(&self, origin: HeaderValue) -> Vec<HttpHeader> {
        let mut headers = self.headers.clone();
        headers.push((header::ACCESS_CONTROL_ALLOW_ORIGIN, origin));
        if self.vary_origin {
            headers.push((header::VARY, HeaderValue::from_static("Origin")));
        }
        headers
    }

    /// The `Access-Control-Allow-Origin` value for this request: the
    /// configured one as it is, or, for `$http_origin`, the request's
    /// origin, which is `None` when the request carries none.
    ///
    /// `convert_header_value` only resolves `$`/`:` values and answers
    /// `None` for a literal, which used to be taken as a failure: every
    /// static `allow_origin`, the default `*` included, was refused with a
    /// 400 and only `$http_origin` ever worked.
    #[inline]
    fn resolve_origin(
        &self,
        session: &Session,
        ctx: &Ctx,
    ) -> Option<HeaderValue> {
        // A list of origins: the request's own, when it is one of them.
        if !self.allow_origins.is_empty() {
            let origin = session.get_header(header::ORIGIN)?;
            let text = origin.to_str().ok()?;
            return self
                .allow_origins
                .iter()
                .any(|rule| rule.matches(text))
                .then(|| origin.clone());
        }
        if self.vary_origin {
            convert_header_value(&self.allow_origin, session, ctx)
        } else {
            Some(self.allow_origin.clone())
        }
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
        if let Some(reg) = &self.path
            && !reg.is_match(session.req_header().uri.path())
        {
            return Ok(RequestPluginResult::Skipped);
        }

        // Handle CORS preflight (OPTIONS) requests
        // Preflight happens before actual request to check if it's allowed.
        // A mirrored origin needs an Origin to mirror; without one this is
        // a plain OPTIONS for the upstream.
        if http::Method::OPTIONS == session.req_header().method {
            if let Some(origin) = self.resolve_origin(session, ctx) {
                // Return 204 No Content with CORS headers for preflight
                let mut resp = HttpResponse::no_content();
                resp.headers = Some(self.get_headers(origin));
                return Ok(RequestPluginResult::Respond(resp));
            }
            // From an origin that is not on the list: answered here, with
            // nothing that lets it in. Passed on, it would be the upstream
            // that decides who is let in, and the list would be for show.
            if !self.allow_origins.is_empty()
                && session.get_header(header::ORIGIN).is_some()
            {
                let mut resp = HttpResponse::no_content();
                resp.headers = Some(vec![(
                    header::VARY,
                    HeaderValue::from_static("Origin"),
                )]);
                return Ok(RequestPluginResult::Respond(resp));
            }
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
        if let Some(reg) = &self.path
            && !reg.is_match(session.req_header().uri.path())
        {
            return Ok(ResponsePluginResult::Unchanged);
        }

        // Where the answer goes by the origin, every response says so,
        // the one to a request without an `Origin` and the one to an
        // origin that is not let in as well: kept by a shared cache
        // without it, such a response was replayed to the cross-origin
        // request that came next, which then had no CORS headers.
        // Appended, not inserted: the upstream's own `Vary` must survive.
        let mut result = ResponsePluginResult::Unchanged;
        if self.vary_origin && !varies_by_origin(&upstream_response.headers) {
            let _ = upstream_response.append_header(header::VARY, "Origin");
            result = ResponsePluginResult::Modified;
        }

        // Only add CORS headers if request has Origin header
        // (indicates it's a CORS request)
        if session.get_header(header::ORIGIN).is_none() {
            return Ok(result);
        }

        // Add all configured CORS headers to the response, straight from
        // the prebuilt list rather than through a per-response copy.
        let origin = self.resolve_origin(session, ctx);
        // With a list of origins, who is let in and with what is this
        // plugin's to say and nobody else's: what the upstream itself
        // answered is taken off, for an origin on the list - which gets
        // the plugin's answer in its place, credentials allowed or not as
        // it is set here - and for one that is not. Left on, the list
        // held for the preflight and not for the request that needs
        // none, which the upstream went on allowing.
        if !self.allow_origins.is_empty() {
            for name in ALLOW_HEADERS.iter() {
                if upstream_response.remove_header(name).is_some() {
                    result = ResponsePluginResult::Modified;
                }
            }
        }
        let Some(origin) = origin else {
            return Ok(result);
        };
        for (name, value) in &self.headers {
            let _ = upstream_response.insert_header(name, value);
        }
        let _ = upstream_response
            .insert_header(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        Ok(ResponsePluginResult::Modified)
    }

    /// A 401 or a 429 that another plugin answers with is a response to the
    /// same cross-origin request. Without these headers the browser keeps
    /// it from the page, which sees a failed request and no status.
    #[inline]
    fn handles_plugin_response(&self) -> bool {
        true
    }
}

register_plugin!("cors", Cors);

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
            r#"[("access-control-allow-methods", "GET"), ("access-control-allow-headers", "Content-Type, X-User-Id"), ("access-control-max-age", "3600"), ("access-control-allow-credentials", "true"), ("access-control-expose-headers", "Content-Encoding, Kuma-Revision"), ("access-control-allow-origin", "https://pingap.io"), ("vary", "Origin")]"#,
            format!("{:?}", resp.headers.unwrap())
        );

        // A mirrored origin varies the response, and the upstream's own
        // `Vary` is kept next to it.
        let mut header = ResponseHeader::build(200, None).unwrap();
        header.append_header("Vary", "Accept-Encoding").unwrap();

        cors.handle_response(&mut session, &mut Ctx::default(), &mut header)
            .await
            .unwrap();

        assert_eq!(
            r#"{"vary": "Accept-Encoding", "vary": "Origin", "access-control-allow-methods": "GET", "access-control-allow-headers": "Content-Type, X-User-Id", "access-control-max-age": "3600", "access-control-allow-credentials": "true", "access-control-expose-headers": "Content-Encoding, Kuma-Revision", "access-control-allow-origin": "https://pingap.io"}"#,
            format!("{:?}", header.headers)
        );

        // A fixed origin does not vary.
        let cors = Cors::new(
            &toml::from_str::<PluginConf>("allow_origin = \"https://a.io\"")
                .unwrap(),
        )
        .unwrap();
        let mut header = ResponseHeader::build(200, None).unwrap();
        cors.handle_response(&mut session, &mut Ctx::default(), &mut header)
            .await
            .unwrap();
        assert_eq!(false, header.headers.contains_key("vary"));
        assert_eq!(
            "https://a.io",
            header.headers.get("access-control-allow-origin").unwrap()
        );

        // The default `*` works too (a literal used to be refused), and a
        // preflight without an Origin is left to the upstream when the
        // origin is mirrored.
        let cors =
            Cors::new(&toml::from_str::<PluginConf>("").unwrap()).unwrap();
        let mock_io = Builder::new()
            .read(b"OPTIONS /api HTTP/1.1\r\nOrigin: https://x.io\r\n\r\n")
            .build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = cors
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        let RequestPluginResult::Respond(resp) = result else {
            panic!("a preflight must be answered");
        };
        assert_eq!(
            true,
            format!("{:?}", resp.headers)
                .contains(r#"("access-control-allow-origin", "*")"#)
        );

        let cors = Cors::new(
            &toml::from_str::<PluginConf>("allow_origin = \"$http_origin\"")
                .unwrap(),
        )
        .unwrap();
        let mock_io = Builder::new()
            .read(b"OPTIONS /api HTTP/1.1\r\n\r\n")
            .build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = cors
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result == RequestPluginResult::Continue);
    }

    /// `allow_origins`: the origins on the list are let in by name, any
    /// other gets nothing that lets it in.
    #[tokio::test]
    async fn test_cors_allow_origins() {
        let cors = Cors::new(
            &toml::from_str::<PluginConf>(
                r#"
allow_origins = ["https://app.example.com", "~https://[a-z0-9-]+\\.example\\.org", "http://localhost:3000"]
allow_credentials = true
"#,
            )
            .unwrap(),
        )
        .unwrap();
        // The headers the response of the upstream leaves with.
        let respond = async |origin: Option<&str>| {
            let origin = origin
                .map(|origin| format!("Origin: {origin}\r\n"))
                .unwrap_or_default();
            let input = format!("GET /api HTTP/1.1\r\n{origin}\r\n");
            let mock_io = Builder::new().read(input.as_bytes()).build();
            let mut session = Session::new_h1(Box::new(mock_io));
            session.read_request().await.unwrap();
            let mut header = ResponseHeader::build(200, None).unwrap();
            cors.handle_response(
                &mut session,
                &mut Ctx::default(),
                &mut header,
            )
            .await
            .unwrap();
            let value = |name: &str| {
                header
                    .headers
                    .get(name)
                    .map(|value| value.to_str().unwrap().to_string())
            };
            (value("access-control-allow-origin"), value("vary"))
        };
        let vary = Some("Origin".to_string());
        for origin in [
            "https://app.example.com",
            // In whatever case the scheme and host were written.
            "HTTPS://APP.example.com",
            "https://docs.example.org",
            "http://localhost:3000",
        ] {
            assert_eq!(
                (Some(origin.to_string()), vary.clone()),
                respond(Some(origin)).await,
                "{origin}"
            );
        }
        for origin in [
            "https://evil.example.net",
            "http://app.example.com",
            "https://app.example.com:8443",
            "http://localhost:3001",
            // A pattern is for the whole of an origin.
            "https://docs.example.org.evil.net",
            "https://evil.net/?https://docs.example.org",
            "null",
        ] {
            assert_eq!(
                (None, vary.clone()),
                respond(Some(origin)).await,
                "{origin}"
            );
        }
        // What the upstream answers to let an origin in does not get
        // past the list either.
        let from_upstream = async |origin: &str| {
            let input =
                format!("GET /api HTTP/1.1\r\nOrigin: {origin}\r\n\r\n");
            let mock_io = Builder::new().read(input.as_bytes()).build();
            let mut session = Session::new_h1(Box::new(mock_io));
            session.read_request().await.unwrap();
            let mut header = ResponseHeader::build(200, None).unwrap();
            header
                .insert_header("Access-Control-Allow-Origin", "*")
                .unwrap();
            header
                .insert_header("Access-Control-Allow-Credentials", "true")
                .unwrap();
            header.insert_header("X-Other", "kept").unwrap();
            cors.handle_response(
                &mut session,
                &mut Ctx::default(),
                &mut header,
            )
            .await
            .unwrap();
            let mut names: Vec<String> =
                header.headers.keys().map(|name| name.to_string()).collect();
            names.sort();
            (
                names.join(","),
                header
                    .headers
                    .get("access-control-allow-origin")
                    .map(|value| value.to_str().unwrap().to_string()),
            )
        };
        assert_eq!(
            ("vary,x-other".to_string(), None),
            from_upstream("https://evil.example.net").await
        );
        let (names, allowed) = from_upstream("https://app.example.com").await;
        assert_eq!(Some("https://app.example.com".to_string()), allowed);
        // This plugin allows credentials, so the header is its own.
        assert_eq!(
            true,
            names.contains("access-control-allow-credentials"),
            "{names}"
        );
        // One that does not: the upstream's `true` is not passed on for
        // an origin of the list either.
        let no_credentials = Cors::new(
            &toml::from_str::<PluginConf>(
                "allow_origins = [\"https://app.example.com\"]",
            )
            .unwrap(),
        )
        .unwrap();
        let mock_io = Builder::new()
            .read(
                b"GET /api HTTP/1.1\r\nOrigin: https://app.example.com\r\n\r\n",
            )
            .build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let mut header = ResponseHeader::build(200, None).unwrap();
        header
            .insert_header("Access-Control-Allow-Credentials", "true")
            .unwrap();
        no_credentials
            .handle_response(&mut session, &mut Ctx::default(), &mut header)
            .await
            .unwrap();
        assert_eq!(
            "https://app.example.com",
            header.headers.get("access-control-allow-origin").unwrap()
        );
        assert_eq!(
            false,
            header
                .headers
                .contains_key("access-control-allow-credentials")
        );

        // Regression: a response to a request without an `Origin` did not
        // say that it goes by the origin, and a shared cache replayed it
        // to the cross-origin request that came next.
        assert_eq!((None, vary.clone()), respond(None).await);

        // A preflight from the list is answered with the headers, one from
        // elsewhere without them - and not passed on for the upstream to
        // decide - and an OPTIONS that is no cross-origin request at all is
        // the upstream's.
        let preflight = async |origin: Option<&str>| {
            let origin = origin
                .map(|origin| format!("Origin: {origin}\r\n"))
                .unwrap_or_default();
            let input = format!("OPTIONS /api HTTP/1.1\r\n{origin}\r\n");
            let mock_io = Builder::new().read(input.as_bytes()).build();
            let mut session = Session::new_h1(Box::new(mock_io));
            session.read_request().await.unwrap();
            let result = cors
                .handle_request(
                    PluginStep::Request,
                    &mut session,
                    &mut Ctx::default(),
                )
                .await
                .unwrap();
            match result {
                RequestPluginResult::Respond(resp) => Some((
                    resp.status.as_u16(),
                    format!("{:?}", resp.headers.unwrap_or_default()),
                )),
                _ => None,
            }
        };
        let (status, headers) =
            preflight(Some("https://app.example.com")).await.unwrap();
        assert_eq!(204, status);
        assert_eq!(
            true,
            headers.contains(
                r#"("access-control-allow-origin", "https://app.example.com")"#
            ),
            "{headers}"
        );
        assert_eq!(
            Some((204, r#"[("vary", "Origin")]"#.to_string())),
            preflight(Some("https://evil.example.net")).await
        );
        assert_eq!(None, preflight(None).await);
    }

    #[test]
    fn test_cors_allow_origins_params() {
        let error = |conf: &str| {
            Cors::new(&toml::from_str::<PluginConf>(conf).unwrap())
                .err()
                .unwrap()
                .to_string()
        };
        let prefix = "Plugin cors invalid, message: ";
        for entry in [
            "app.example.com",
            "https://app.example.com/",
            "https://app.example.com:443",
            "capacitor://",
            "capacitor://localhost/path",
            "*",
            "",
        ] {
            assert_eq!(
                format!(
                    "{prefix}allow_origins: {entry:?} is not an origin (scheme://host[:port]), nor a pattern starting with ~"
                ),
                error(&format!("allow_origins = [\"{entry}\"]")),
            );
        }
        assert_eq!(
            true,
            error(r#"allow_origins = ["~https://(unclosed"]"#)
                .starts_with(&format!("{prefix}allow_origins: ")),
        );
        assert_eq!(
            format!(
                "{prefix}allow_origin and allow_origins are two ways to say who is let in, set one of them"
            ),
            error("allow_origin = \"*\"\nallow_origins = [\"https://a.io\"]")
        );
        // A list with nothing on it is not "everybody".
        assert_eq!(
            format!(
                "{prefix}allow_origins is empty: list the origins that are let in, or leave it out"
            ),
            error("allow_origins = []")
        );
        // The page of an app in a web view has an origin of its own.
        for entry in
            ["capacitor://localhost", "ionic://localhost", "app://my.app"]
        {
            assert_eq!(
                true,
                Cors::new(
                    &toml::from_str::<PluginConf>(&format!(
                        "allow_origins = [\"{entry}\"]"
                    ))
                    .unwrap()
                )
                .is_ok(),
                "{entry}"
            );
        }
        // The pairing a browser refuses is said, not refused.
        assert_eq!(
            true,
            Cors::new(
                &toml::from_str::<PluginConf>("allow_credentials = true")
                    .unwrap()
            )
            .is_ok()
        );
    }
}
