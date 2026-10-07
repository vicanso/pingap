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
    Error, get_hash_key, get_int_conf, get_step_conf_in, get_str_conf,
    get_str_slice_conf,
};
use async_trait::async_trait;
use bytes::Bytes;
use http::{Method, StatusCode};
use pingap_config::PluginConf;
use pingap_core::{
    Ctx, HTTP_HEADER_CONTENT_TEXT, HttpResponse, Plugin, PluginStep,
    RequestPluginResult, normalize_path,
};
use pingora::proxy::Session;
use regex::RegexSet;
use std::borrow::Cow;
use std::str::FromStr;
use tracing::debug;

type Result<T, E = Error> = std::result::Result<T, E>;

const CATEGORY: &str = "uri_block";

/// Turns away requests by what they ask for: a path or a query that
/// matches one of the patterns, or a method that is not one of those
/// allowed.
///
/// It is for the requests no application of the site answers and every
/// scanner sends - `/.env`, `/.git/config`, `/wp-login.php`, a query with
/// `../` in it - which until now took a location with a `mock` plugin for
/// each path to keep from the upstream.
pub struct UriBlock {
    /// Patterns for the path, as the location matching reads it: percent
    /// decoded, `.` and `..` resolved, `//` as one slash.
    paths: Option<RegexSet>,
    /// Patterns for the query, as it was sent and as it reads decoded.
    queries: Option<RegexSet>,
    /// The methods that are let through, any when there are none.
    methods: Vec<Method>,
    /// What a request that is turned away is answered with.
    status: StatusCode,
    message: Bytes,
    plugin_step: PluginStep,
    hash_value: String,
}

/// Why a request was turned away.
#[derive(Debug, PartialEq, Clone, Copy)]
enum Blocked {
    Method,
    Path,
    Query,
}

impl TryFrom<&PluginConf> for UriBlock {
    type Error = Error;

    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);
        let invalid = |message: String| Error::Invalid {
            category: CATEGORY.to_string(),
            message,
        };
        let step = get_step_conf_in(
            value,
            CATEGORY,
            PluginStep::Request,
            &[PluginStep::Request],
        )?;
        // All of them looked at in one pass over the text, however many
        // there are.
        let patterns_of = |key: &str| -> Result<Option<RegexSet>> {
            let patterns = get_str_slice_conf(value, key);
            if patterns.is_empty() {
                return Ok(None);
            }
            RegexSet::new(&patterns)
                .map(Some)
                .map_err(|e| invalid(format!("{key}: {e}")))
        };
        let paths = patterns_of("paths")?;
        let queries = patterns_of("queries")?;
        let methods = get_str_slice_conf(value, "methods")
            .iter()
            .map(|method| {
                let name = method.trim().to_ascii_uppercase();
                Method::from_str(&name)
                    .ok()
                    .filter(|_| !name.is_empty())
                    .ok_or_else(|| {
                        invalid(format!("methods: {method:?} is not a method"))
                    })
            })
            .collect::<Result<Vec<_>>>()?;
        if paths.is_none() && queries.is_none() && methods.is_empty() {
            return Err(invalid(
                "one of paths, queries or methods is required".to_string(),
            ));
        }
        // A status that is not an error would tell the client its request
        // went through.
        let status = if value.contains_key("status") {
            u16::try_from(get_int_conf(value, "status"))
                .ok()
                .filter(|status| (400..600).contains(status))
                .and_then(|status| StatusCode::from_u16(status).ok())
                .ok_or_else(|| {
                    invalid("status must be between 400 and 599".to_string())
                })?
        } else {
            StatusCode::FORBIDDEN
        };
        let message = get_str_conf(value, "message");
        let message = if message.is_empty() {
            Bytes::from_static(b"Request is blocked")
        } else {
            Bytes::from(message)
        };

        Ok(Self {
            hash_value,
            paths,
            queries,
            methods,
            status,
            message,
            plugin_step: step,
        })
    }
}

impl UriBlock {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(
            params = pingap_config::masked_toml(params),
            "new uri block plugin"
        );
        Self::try_from(params)
    }

    /// Whether the request is one to turn away, and for what.
    fn blocked(&self, method: &Method, uri: &http::Uri) -> Option<Blocked> {
        if !self.methods.is_empty() && !self.methods.contains(method) {
            return Some(Blocked::Method);
        }
        // The path as it was sent, and the way the location was chosen
        // by, so that what an upstream reads as `/.env` is one however it
        // was written: `/%2eenv`, `/a/../.env`, `//.env`. Both, since
        // upstreams differ in what they make of a path: one that takes
        // `;` for part of a name serves `/admin/..;/x` from under
        // `/admin`, where the other form of it is `/x`.
        if let Some(paths) = &self.paths {
            let path = uri.path();
            if paths.is_match(path) {
                return Some(Blocked::Path);
            }
            if let Cow::Owned(normalized) = normalize_path(path)
                && paths.is_match(&normalized)
            {
                return Some(Blocked::Path);
            }
        }
        if let Some(queries) = &self.queries
            && let Some(query) = uri.query()
        {
            if queries.is_match(query) {
                return Some(Blocked::Query);
            }
            // And as the application will read it. A `+` is a space
            // there, which the percent decoding alone leaves as it is.
            let spaced = query.replace('+', " ");
            let decoded = urlencoding::decode_binary(spaced.as_bytes());
            if let Cow::Owned(decoded) = &decoded
                && queries.is_match(&String::from_utf8_lossy(decoded))
            {
                return Some(Blocked::Query);
            }
            if spaced != query && queries.is_match(&spaced) {
                return Some(Blocked::Query);
            }
        }
        None
    }
}

#[async_trait]
impl Plugin for UriBlock {
    #[inline]
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

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
        let header = session.req_header();
        let Some(reason) = self.blocked(&header.method, &header.uri) else {
            return Ok(RequestPluginResult::Continue);
        };
        debug!(
            category = CATEGORY,
            reason = ?reason,
            path = header.uri.path(),
            "request is blocked"
        );
        Ok(RequestPluginResult::Respond(
            HttpResponse::builder(self.status)
                .header(HTTP_HEADER_CONTENT_TEXT.clone())
                .body(self.message.clone())
                .no_store()
                .finish(),
        ))
    }
}

register_plugin!("uri_block", UriBlock);

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    fn new_plugin(conf: &str) -> Result<UriBlock> {
        UriBlock::new(&toml::from_str::<PluginConf>(conf).unwrap())
    }

    fn blocked(plugin: &UriBlock, method: &str, uri: &str) -> Option<Blocked> {
        plugin.blocked(
            &Method::from_str(method).unwrap(),
            &uri.parse::<http::Uri>().unwrap(),
        )
    }

    #[test]
    fn test_uri_block_paths() {
        let plugin = new_plugin(
            r#"paths = ['\.env$', '^/\.git/', '(?i)^/wp-(login|admin)']"#,
        )
        .unwrap();
        for uri in [
            "/.env",
            "/app/.env",
            "/.git/config",
            "/wp-login.php",
            "/WP-Admin/install.php",
            // However the path is written, it is the one the upstream
            // would read.
            "/%2eenv",
            "/%2Eenv?x=1",
            "/public/../.env",
            "//.git/HEAD",
            "/a/./../.git/HEAD",
        ] {
            assert_eq!(
                Some(Blocked::Path),
                blocked(&plugin, "GET", uri),
                "{uri}"
            );
        }
        for uri in ["/", "/env", "/app/.envoy", "/git/config", "/x?file=.env"] {
            assert_eq!(None, blocked(&plugin, "GET", uri), "{uri}");
        }

        // As it was sent as well: what one upstream reads as `/x`,
        // another serves from under `/admin`.
        let plugin =
            new_plugin(r#"paths = ['^/admin', '%00', ';jsessionid']"#).unwrap();
        for uri in [
            "/admin/users",
            "/admin/..;/x",
            "/public/../admin",
            "/a%00b",
            "/app;jsessionid=1",
        ] {
            assert_eq!(
                Some(Blocked::Path),
                blocked(&plugin, "GET", uri),
                "{uri}"
            );
        }
        assert_eq!(None, blocked(&plugin, "GET", "/public/admin"));
    }

    #[test]
    fn test_uri_block_queries_and_methods() {
        let plugin = new_plugin(
            r#"
queries = ['\.\./', '(?i)union\s+select']
methods = ["get", "HEAD", "Post"]
"#,
        )
        .unwrap();
        for uri in [
            "/download?file=../../etc/passwd",
            // As it reads once decoded.
            "/download?file=..%2F..%2Fetc%2Fpasswd",
            "/download?file=%2e%2e%2fetc",
            "/search?q=1%20UNION%20SELECT%20password",
            "/search?q=1+union+select+password",
        ] {
            assert_eq!(
                Some(Blocked::Query),
                blocked(&plugin, "GET", uri),
                "{uri}"
            );
        }
        for uri in ["/download?file=report.pdf", "/search?q=union", "/x"] {
            assert_eq!(None, blocked(&plugin, "GET", uri), "{uri}");
        }
        // Only the methods that are listed, in whatever case they were.
        assert_eq!(None, blocked(&plugin, "POST", "/x"));
        assert_eq!(None, blocked(&plugin, "HEAD", "/x"));
        for method in ["DELETE", "PUT", "TRACE", "OPTIONS"] {
            assert_eq!(
                Some(Blocked::Method),
                blocked(&plugin, method, "/x"),
                "{method}"
            );
        }
        // No list of them: any method.
        let plugin = new_plugin(r#"paths = ['^/admin']"#).unwrap();
        assert_eq!(None, blocked(&plugin, "DELETE", "/x"));
    }

    #[tokio::test]
    async fn test_uri_block_response() {
        let respond = async |plugin: &UriBlock, step, request: &str| {
            let mock_io = Builder::new().read(request.as_bytes()).build();
            let mut session = Session::new_h1(Box::new(mock_io));
            session.read_request().await.unwrap();
            plugin
                .handle_request(step, &mut session, &mut Ctx::default())
                .await
                .unwrap()
        };
        let plugin = new_plugin(r#"paths = ['\.env$']"#).unwrap();
        let request = "GET /%2eenv HTTP/1.1\r\nHost: a\r\n\r\n";
        let RequestPluginResult::Respond(resp) =
            respond(&plugin, PluginStep::Request, request).await
        else {
            panic!("the request should be blocked");
        };
        assert_eq!(StatusCode::FORBIDDEN, resp.status);
        assert_eq!("Request is blocked", String::from_utf8_lossy(&resp.body));
        // Not at another step than its own, and not what does not match.
        assert_eq!(
            true,
            respond(&plugin, PluginStep::ProxyUpstream, request).await
                == RequestPluginResult::Skipped
        );
        assert_eq!(
            true,
            respond(
                &plugin,
                PluginStep::Request,
                "GET /index.html HTTP/1.1\r\nHost: a\r\n\r\n"
            )
            .await
                == RequestPluginResult::Continue
        );

        let plugin = new_plugin(
            r#"
paths = ['\.env$']
status = 404
message = "Not Found"
"#,
        )
        .unwrap();
        let RequestPluginResult::Respond(resp) =
            respond(&plugin, PluginStep::Request, request).await
        else {
            panic!("the request should be blocked");
        };
        assert_eq!(StatusCode::NOT_FOUND, resp.status);
        assert_eq!("Not Found", String::from_utf8_lossy(&resp.body));
    }

    #[test]
    fn test_uri_block_params() {
        let error = |conf: &str| new_plugin(conf).err().unwrap().to_string();
        let prefix = "Plugin uri_block invalid, message: ";
        assert_eq!(
            format!("{prefix}one of paths, queries or methods is required"),
            error("")
        );
        assert_eq!(
            true,
            error(r#"paths = ['(unclosed']"#)
                .starts_with(&format!("{prefix}paths: ")),
        );
        assert_eq!(
            true,
            error(r#"queries = ['[a-']"#)
                .starts_with(&format!("{prefix}queries: ")),
        );
        assert_eq!(
            format!("{prefix}methods: \"GE T\" is not a method"),
            error(r#"methods = ["GE T"]"#)
        );
        assert_eq!(
            format!("{prefix}methods: \"\" is not a method"),
            error(r#"methods = [""]"#)
        );
        for status in [200, 302, 600] {
            assert_eq!(
                format!("{prefix}status must be between 400 and 599"),
                error(&format!("paths = ['x']\nstatus = {status}"))
            );
        }
        assert_eq!(
            format!("{prefix}Invalid step(response), expect one of: request"),
            error("paths = ['x']\nstep = \"response\"")
        );
    }
}
