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
    Error, get_bool_conf, get_hash_key, get_int_conf, get_str_conf,
    get_str_slice_conf,
};
use async_trait::async_trait;
use http::{HeaderValue, StatusCode, header};
use pingap_config::{PluginCategory, PluginConf};
use pingap_core::{
    Ctx, HttpResponse, Plugin, PluginStep, RequestPluginResult, canonical_path,
    get_host, new_internal_error,
};
use pingora::http::RequestHeader;
use pingora::proxy::Session;
use regex::Regex;
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
    // Where a path that matches is sent, the first rule that matches.
    rules: Vec<Rule>,
    // The name the site goes by: a request for another host is sent to
    // this one. With its port, where the configuration gives one.
    host: Option<String>,
    // Plugin execution step (must be Request)
    // Response step is invalid as redirects must be handled before request processing
    plugin_step: PluginStep,
    // Unique hash value for plugin instance
    // Used for plugin identification and caching
    hash_value: String,
}

/// `<pattern> <target> [status]`: a path the pattern matches is sent to
/// the target.
struct Rule {
    pattern: Regex,
    /// A path, or a whole url. `$1` and `${name}` stand for what the
    /// pattern captured, `$host` and `$scheme` for those of the request.
    target: String,
    /// Whether the target is a whole url, to be the `Location` as it is.
    absolute: bool,
    /// In place of the plugin's `status`, for this rule.
    status: Option<StatusCode>,
}

/// The redirect statuses, and nothing else: a mistyped one used to turn
/// into a 307 without a word.
fn redirect_status(status: i64) -> Option<StatusCode> {
    match status {
        301 => Some(StatusCode::MOVED_PERMANENTLY),
        302 => Some(StatusCode::FOUND),
        303 => Some(StatusCode::SEE_OTHER),
        307 => Some(StatusCode::TEMPORARY_REDIRECT),
        308 => Some(StatusCode::PERMANENT_REDIRECT),
        _ => None,
    }
}

/// `template` with `value` in place of the variable `name` (`$host`).
/// Only where that is the whole name: `$hostname` is another one, and
/// stays for the expansion to take for a group of the pattern.
fn replace_variable(template: &str, name: &str, value: &str) -> String {
    let mut result = String::with_capacity(template.len() + value.len());
    let mut rest = template;
    while let Some(at) = rest.find(name) {
        let after = &rest[at + name.len()..];
        result.push_str(&rest[..at]);
        let is_whole =
            !after.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_');
        result.push_str(if is_whole { value } else { name });
        rest = after;
    }
    result.push_str(rest);
    result
}

impl Rule {
    fn parse(rule: &str) -> std::result::Result<Self, String> {
        let mut parts = rule.split_whitespace();
        let (Some(pattern), Some(target)) = (parts.next(), parts.next()) else {
            return Err(format!(
                "rules: {rule:?} should be \"<pattern> <target> [status]\""
            ));
        };
        let status = match parts.next() {
            None => None,
            Some(status) => Some(
                status
                    .parse::<i64>()
                    .ok()
                    .and_then(redirect_status)
                    .ok_or_else(|| {
                        format!(
                            "rules: invalid status({status}) in {rule:?}, expect 301, 302, 303, 307 or 308"
                        )
                    })?,
            ),
        };
        if parts.next().is_some() {
            return Err(format!(
                "rules: {rule:?} has more than a pattern, a target and a status"
            ));
        }
        // A path, which begins with a slash and so stays behind the host
        // it is put after, or a whole url. A target that began with what
        // the pattern captured - `$1`, for a rule that takes a prefix off -
        // was put straight after the host: `/old@evil.example` went to
        // `http://example.com@evil.example`, which is another site.
        let absolute = ["http://", "https://", "$scheme://"]
            .iter()
            .find_map(|scheme| target.strip_prefix(scheme));
        if absolute.is_none() && !target.starts_with('/') {
            return Err(format!(
                "rules: the target of {rule:?} should be a path that starts with / or an http(s) url"
            ));
        }
        // And in a url, where to is for the rule to say and not for the
        // request: nothing the pattern captured goes into the host. With
        // `https://new.example.com$1`, `/old.evil.example` is a host of
        // somebody else's.
        if let Some(rest) = absolute {
            let authority =
                rest.split(['/', '?', '#']).next().unwrap_or_default();
            if authority.is_empty()
                || replace_variable(authority, "$host", "").contains('$')
            {
                return Err(format!(
                    "rules: the host of the target of {rule:?} should be a name or $host, with a / before what follows it"
                ));
            }
        }
        Ok(Self {
            pattern: Regex::new(pattern)
                .map_err(|e| format!("rules: {rule:?}: {e}"))?,
            target: target.to_string(),
            absolute: absolute.is_some(),
            status,
        })
    }
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
        let invalid = |message: String| Error::Invalid {
            category: PluginCategory::Redirect.to_string(),
            message,
        };
        // Only a redirect status makes sense; a mistyped one used to turn
        // into a 307 without a word.
        let status = match get_int_conf(params, "status") {
            0 => StatusCode::TEMPORARY_REDIRECT,
            other => redirect_status(other).ok_or_else(|| {
                invalid(format!(
                    "Invalid status({other}), expect 301, 302, 303, 307 or 308"
                ))
            })?,
        };
        let rules = get_str_slice_conf(params, "rules")
            .iter()
            .map(|rule| Rule::parse(rule).map_err(invalid))
            .collect::<Result<Vec<_>>>()?;
        // A name, with a port where the site is not on the default one.
        // Nothing of a url around it: the scheme is the request's, or
        // what `http_to_https` makes of it.
        let host = get_str_conf(params, "host");
        let host = if host.is_empty() {
            None
        } else {
            let is_authority =
                host.parse::<http::uri::Authority>().is_ok_and(|authority| {
                    !authority.host().is_empty()
                        && !authority.as_str().contains('@')
                });
            if !is_authority {
                return Err(invalid(format!(
                    "host: {host:?} should be a host name, with a port where it has one"
                )));
            }
            Some(host.to_ascii_lowercase())
        };
        Ok(Self {
            hash_value,
            prefix,
            http_to_https: get_bool_conf(params, "http_to_https"),
            status,
            rules,
            host,
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
        let req_header = session.req_header();
        let path = req_header.uri.path();

        // The scheme of the request, or https when it is being changed.
        let schema = if is_tls || self.http_to_https {
            "https"
        } else {
            "http"
        };
        // The host to send the client to. The name the site goes by,
        // where one is set and the request came for another. Otherwise
        // where the request came in, port included: taking the host alone
        // sent a request for `example.com:8080` to port 80. A change of
        // scheme goes to the default port of the new scheme, since the
        // port of the old one is not where the new one listens.
        let request_host = get_host(req_header).unwrap_or_default();
        let other_host = self.host.as_deref().filter(|canonical| {
            let name = canonical
                .rsplit_once(':')
                .filter(|(_, port)| port.parse::<u16>().is_ok())
                .map_or(*canonical, |(name, _)| name);
            !name.eq_ignore_ascii_case(request_host)
        });
        let host = match (other_host, schema_match) {
            (Some(canonical), _) => canonical,
            (None, true) => request_authority(req_header),
            (None, false) => request_host,
        };

        // The first rule the path matches. The path is the one a location
        // is chosen by, written so that it can go into a url again: what
        // a rule captures of `/old/a%20b` is `a%20b`, and of
        // `/public/../old/x` it is `x`.
        let mut status = self.status;
        let mut location = None;
        let mut moved_to = None;
        if !self.rules.is_empty() {
            let canonical = canonical_path(path);
            for rule in &self.rules {
                let Some(captures) = rule.pattern.captures(&canonical) else {
                    continue;
                };
                // `$host` and `$scheme` first, as the text they stand
                // for: left to the expansion they would be taken for
                // groups of the pattern, which has none of these names.
                let template = replace_variable(
                    &replace_variable(&rule.target, "$scheme", schema),
                    "$host",
                    &host.replace('$', "$$"),
                );
                let mut target = String::with_capacity(template.len() + 16);
                captures.expand(&template, &mut target);
                status = rule.status.unwrap_or(self.status);
                if rule.absolute {
                    location = Some(target);
                } else {
                    moved_to = Some(target);
                }
                break;
            }
        }

        let has_prefix = path.starts_with(&self.prefix);
        // Nothing to send the client anywhere for: the scheme is the one
        // wanted, the host is the site's, the path has its prefix and no
        // rule is for it.
        if location.is_none()
            && moved_to.is_none()
            && schema_match
            && other_host.is_none()
            && has_prefix
        {
            return Ok(RequestPluginResult::Skipped);
        }

        let location = match location {
            // A rule with a whole url: that is the address.
            Some(location) => location,
            None => {
                let query = req_header.uri.query();
                let path_and_query = match moved_to {
                    // The query goes along, unless the rule wrote one.
                    Some(moved_to) => match query {
                        Some(query) if !moved_to.contains('?') => {
                            format!("{moved_to}?{query}")
                        },
                        _ => moved_to,
                    },
                    // Only a url that is missing the prefix gets it
                    // prepended. Getting here with the prefix already in
                    // place means the schema or the host is what
                    // triggered the redirect, and prepending
                    // unconditionally would produce `/api/api/...`.
                    //
                    // Path and query only. The uri of an HTTP/2 request
                    // carries scheme and host as well, and written out
                    // whole it gave
                    // `https://example.comhttps://example.com/path`.
                    None => {
                        let prefix =
                            if has_prefix { "" } else { self.prefix.as_str() };
                        let path_and_query = req_header
                            .uri
                            .path_and_query()
                            .map(|value| value.as_str())
                            .unwrap_or("/");
                        format!("{prefix}{path_and_query}")
                    },
                };
                format!("{schema}://{host}{path_and_query}")
            },
        };
        // A host the header syntax rejects is the client's mistake.
        let location = HeaderValue::from_str(&location)
            .map_err(|e| new_internal_error(400, e))?;

        Ok(RequestPluginResult::Respond(HttpResponse {
            status,
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

    /// `rules`: a path that matches is sent where its rule says, the
    /// first rule that matches.
    #[tokio::test]
    async fn test_redirect_rules() {
        let plugin = Redirect::new(
            &toml::from_str::<PluginConf>(
                r#"
rules = [
    '^/old/(.*)$ /new/$1 301',
    '^/docs/(?<page>[^/]+)$ https://docs.example.com/${page}.html 308',
    '^/search$ /find?from=search',
    '^/go/(.*)$ $scheme://$host/went/$1',
    '^/strip(/.*)$ /kept$1',
    '^/old/never$ /shadowed',
]
status = 302
"#,
            )
            .unwrap(),
        )
        .unwrap();
        let redirect = async |path: &str| {
            let mut session = h1_session("example.com:8080", path).await;
            let result = plugin
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
                    resp.headers.unwrap()[0].1.to_str().unwrap().to_string(),
                )),
                _ => None,
            }
        };
        let to =
            |status: u16, location: &str| Some((status, location.to_string()));
        // A path stays on the scheme, the host and the port it came on,
        // and takes its query along.
        assert_eq!(
            to(301, "http://example.com:8080/new/a/b"),
            redirect("/old/a/b").await
        );
        assert_eq!(
            to(301, "http://example.com:8080/new/a?x=1&y=2"),
            redirect("/old/a?x=1&y=2").await
        );
        // The first rule that matches, not a later one.
        assert_eq!(
            to(301, "http://example.com:8080/new/never"),
            redirect("/old/never").await
        );
        // A whole url is the address as it is, with what the pattern
        // captured under its name.
        assert_eq!(
            to(308, "https://docs.example.com/intro.html"),
            redirect("/docs/intro?lang=en").await
        );
        // A rule without a status takes the plugin's, and one that writes
        // a query keeps its own.
        assert_eq!(
            to(302, "http://example.com:8080/find?from=search"),
            redirect("/search?q=1").await
        );
        assert_eq!(
            to(302, "http://example.com:8080/went/x"),
            redirect("/go/x").await
        );
        // The path as a location is chosen by it, and fit for a url:
        // however it was written, and whatever was encoded in it.
        assert_eq!(
            to(301, "http://example.com:8080/new/x"),
            redirect("/public/../old/x").await
        );
        assert_eq!(
            to(301, "http://example.com:8080/new/a%20b"),
            redirect("/old/a%20b").await
        );
        assert_eq!(
            to(301, "http://example.com:8080/new/%0D%0ASet-Cookie:x"),
            redirect("/old/%0d%0aSet-Cookie:x").await
        );
        // What stays on the same host cannot be made to leave it: the
        // address begins with the scheme and the host, and a doubled
        // slash is one by the time the rule sees the path.
        assert_eq!(
            to(301, "http://example.com:8080/new/evil.example"),
            redirect("/old//evil.example").await
        );
        // What a rule captures cannot become part of the host: the
        // target of a path begins with a slash of its own.
        assert_eq!(
            to(302, "http://example.com:8080/kept/@evil.example"),
            redirect("/strip/@evil.example").await
        );
        // No rule for it: nothing to do.
        assert_eq!(None, redirect("/other").await);
    }

    /// Regression: a target that began with a capture was put straight
    /// after the host, and one that had a capture next to its host let
    /// the request say where to.
    #[test]
    fn test_redirect_target_cannot_name_the_host() {
        let prefix = "Plugin redirect invalid, message: ";
        let error = |rule: &str| {
            Redirect::new(
                &toml::from_str::<PluginConf>(&format!("rules = ['{rule}']"))
                    .unwrap(),
            )
            .err()
            .map(|e| e.to_string())
        };
        for rule in ["^/old(.*)$ $1", "^/old(.*)$ $scheme$1", "^/(.*)$ new/$1"]
        {
            assert_eq!(
                Some(format!(
                    "{prefix}rules: the target of {rule:?} should be a path that starts with / or an http(s) url"
                )),
                error(rule),
            );
        }
        for rule in [
            "^/old(.*)$ https://new.example.com$1",
            "^/old/(.*)$ https://$1/x",
            "^/old/(.*)$ $scheme://$host$1",
            "^/old/(.*)$ https://",
            "^/old/(?<hostname>.*)$ https://$hostname/x",
        ] {
            assert_eq!(
                Some(format!(
                    "{prefix}rules: the host of the target of {rule:?} should be a name or $host, with a / before what follows it"
                )),
                error(rule),
            );
        }
        for rule in [
            "^/old(.*)$ /new$1",
            "^/old/(.*)$ https://new.example.com/$1",
            "^/old/(.*)$ $scheme://$host/$1",
            "^/old/(.*)$ https://new.example.com:8443",
            "^/old/(.*)$ https://$host?from=$1",
        ] {
            assert_eq!(None, error(rule), "{rule}");
        }

        // `$host` is that name and no longer one.
        assert_eq!(
            "a.test/$hostname/a.test",
            replace_variable("$host/$hostname/$host", "$host", "a.test")
        );
        assert_eq!("$hosts", replace_variable("$hosts", "$host", "a.test"));
    }

    /// `host`: a request for another name is sent to the one the site
    /// goes by, together with whatever else is to change.
    #[tokio::test]
    async fn test_redirect_to_the_canonical_host() {
        let new = |conf: &str| {
            Redirect::new(&toml::from_str::<PluginConf>(conf).unwrap()).unwrap()
        };
        let plugin = new("host = \"example.com\"");
        let mut session = h1_session("www.example.com", "/a?b=1").await;
        assert_eq!(
            Some("http://example.com/a?b=1".to_string()),
            location(&plugin, &mut session).await
        );
        // The site's own name, in whatever case and on whatever port.
        for host in ["example.com", "EXAMPLE.com", "example.com:8080"] {
            let mut session = h1_session(host, "/a").await;
            assert_eq!(None, location(&plugin, &mut session).await, "{host}");
        }
        // With the scheme, the prefix and a rule in the same step: one
        // redirect, not three.
        let plugin = new(
            "host = \"example.com:8443\"\nhttp_to_https = true\nprefix = \"/api\"",
        );
        let mut session = h1_session("www.example.com", "/users").await;
        assert_eq!(
            Some("https://example.com:8443/api/users".to_string()),
            location(&plugin, &mut session).await
        );
        let plugin =
            new("host = \"example.com\"\nrules = ['^/old/(.*)$ /new/$1']");
        let mut session = h1_session("www.example.com", "/old/x").await;
        assert_eq!(
            Some("http://example.com/new/x".to_string()),
            location(&plugin, &mut session).await
        );
    }

    #[test]
    fn test_redirect_rules_params() {
        let error = |conf: &str| {
            Redirect::new(&toml::from_str::<PluginConf>(conf).unwrap())
                .err()
                .unwrap()
                .to_string()
        };
        let prefix = "Plugin redirect invalid, message: ";
        for (conf, message) in [
            (
                "rules = ['^/old']",
                r#"rules: "^/old" should be "<pattern> <target> [status]""#,
            ),
            (
                "rules = ['^/old /new 200']",
                r#"rules: invalid status(200) in "^/old /new 200", expect 301, 302, 303, 307 or 308"#,
            ),
            (
                "rules = ['^/old /new 301 extra']",
                r#"rules: "^/old /new 301 extra" has more than a pattern, a target and a status"#,
            ),
            (
                "rules = ['^/old new']",
                r#"rules: the target of "^/old new" should be a path that starts with / or an http(s) url"#,
            ),
            (
                "host = \"https://example.com\"",
                r#"host: "https://example.com" should be a host name, with a port where it has one"#,
            ),
            (
                "host = \"example.com/path\"",
                r#"host: "example.com/path" should be a host name, with a port where it has one"#,
            ),
        ] {
            assert_eq!(format!("{prefix}{message}"), error(conf), "{conf}");
        }
        assert_eq!(
            true,
            error("rules = ['^/(old /new']")
                .starts_with(&format!("{prefix}rules: ")),
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
