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
    DryRun, Error, get_hash_key, get_int_conf, get_step_conf_in, get_str_conf,
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

const SENSITIVE_FILE_PATHS: &[&str] = &[
    r"(?i)(^|/)\.env(\.[^/]*)?$",
    r"(?i)(^|/)\.(git|svn|hg)(/|$)",
    r"(?i)(^|/)\.(htaccess|htpasswd|htgroups|npmrc|yarnrc|pypirc|netrc|dockerenv|DS_Store)$",
    r"(?i)(^|/)\.(aws|ssh)(/|$)",
    r"(?i)(^|/)wp-config\.php(\.bak|\.old|\.save|~)?$",
    r"(?i)(^|/)web\.config$",
    r"(?i)(^|/)(id_rsa|id_ed25519)(\.pub)?$",
    r"(?i)\.(bak|orig|save|swp|swo|sql|dump)$",
];

const SCANNER_PATHS: &[&str] = &[
    r"(?i)(^|/)wp-(login|signup|cron|config)\.php$",
    r"(?i)(^|/)wp-(admin|includes)(/|$)",
    r"(?i)(^|/)xmlrpc\.php$",
    r"(?i)(^|/)wlwmanifest\.xml$",
    r"(?i)(^|/)(phpmyadmin|pma|myadmin)(/|$)",
    r"(?i)(^|/)(phpinfo|adminer)\.php$",
    r"(?i)(^|/)cgi-bin(/|$)",
    r"(?i)(^|/)vendor/phpunit(/|$)",
    r"(?i)(^|/)boaform/admin(/|$)",
    r"(?i)(^|/)HNAP1(/|$)",
];

const PATH_TRAVERSAL_PATHS: &[&str] = &[
    r"(?i)(^|[/\\])\.\.([/\\;]|$)",
    r"(?i)%2e%2e",
    r"(?i)%252e%252e",
    r"(?i)%00",
    r"(?i)(^|/)(etc/passwd|etc/shadow|proc/self/environ|windows/win\.ini)$",
];

const PATH_TRAVERSAL_QUERIES: &[&str] = &[
    r"(?i)(^|[/\\=])\.\.[/\\]",
    r"(?i)%00|\x00",
    r"(?i)(/etc/passwd|/etc/shadow|/proc/self/environ|c:\\windows\\)",
];

const SQLI_XSS_QUERIES: &[&str] = &[
    r"(?i)\bunion(\s+all)?\s+select\b",
    r#"(?i)('\s*or\s+'?\d+'?\s*=\s*'?\d+|"\s*or\s+"?\d+"?\s*=\s*"?\d+)"#,
    r"(?i)\b(sleep|benchmark|waitfor\s+delay|pg_sleep)\s*\(",
    r"(?i)(information_schema|load_file\s*\(|into\s+outfile)",
    r"(?i)<\s*script\b",
    r"(?i)\bjavascript\s*:",
    r"(?i)\bon(error|load|mouseover|click|focus)\s*=",
];

fn extend_unique_patterns(
    dst: &mut Vec<String>,
    patterns: impl IntoIterator<Item = String>,
) {
    for pattern in patterns {
        if !dst.contains(&pattern) {
            dst.push(pattern);
        }
    }
}

struct PresetRules {
    paths: &'static [&'static [&'static str]],
    queries: &'static [&'static [&'static str]],
}

fn preset_rules(name: &str) -> Option<PresetRules> {
    match name {
        "sensitive_files" => Some(PresetRules {
            paths: &[SENSITIVE_FILE_PATHS],
            queries: &[],
        }),
        "scanners" => Some(PresetRules {
            paths: &[SCANNER_PATHS],
            queries: &[],
        }),
        "path_traversal" => Some(PresetRules {
            paths: &[PATH_TRAVERSAL_PATHS],
            queries: &[PATH_TRAVERSAL_QUERIES],
        }),
        "sqli_xss" => Some(PresetRules {
            paths: &[],
            queries: &[SQLI_XSS_QUERIES],
        }),
        "common" => Some(PresetRules {
            paths: &[SENSITIVE_FILE_PATHS, SCANNER_PATHS, PATH_TRAVERSAL_PATHS],
            queries: &[PATH_TRAVERSAL_QUERIES],
        }),
        "all" => Some(PresetRules {
            paths: &[SENSITIVE_FILE_PATHS, SCANNER_PATHS, PATH_TRAVERSAL_PATHS],
            queries: &[PATH_TRAVERSAL_QUERIES, SQLI_XSS_QUERIES],
        }),
        _ => None,
    }
}

fn expand_presets(names: &[String]) -> Result<(Vec<String>, Vec<String>)> {
    let mut path_patterns = Vec::new();
    let mut query_patterns = Vec::new();
    for raw in names {
        let normalized = raw.trim().to_ascii_lowercase();
        let Some(rules) = preset_rules(&normalized) else {
            return Err(Error::Invalid {
                category: CATEGORY.to_string(),
                message: format!(
                    "presets: unknown preset {raw:?}, expect one of: sensitive_files, scanners, path_traversal, sqli_xss, common, all"
                ),
            });
        };
        for group in rules.paths {
            extend_unique_patterns(
                &mut path_patterns,
                group.iter().map(|p| (*p).to_string()),
            );
        }
        for group in rules.queries {
            extend_unique_patterns(
                &mut query_patterns,
                group.iter().map(|p| (*p).to_string()),
            );
        }
    }
    Ok((path_patterns, query_patterns))
}

fn compile_pattern_set(
    key: &str,
    patterns: Vec<String>,
) -> Result<Option<RegexSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    RegexSet::new(&patterns)
        .map(Some)
        .map_err(|e| Error::Invalid {
            category: CATEGORY.to_string(),
            message: format!("{key}: {e}"),
        })
}

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
    /// Requests are let through and the refusal is only logged.
    dry_run: DryRun,
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
        let (mut path_patterns, mut query_patterns) =
            expand_presets(&get_str_slice_conf(value, "presets"))?;
        extend_unique_patterns(
            &mut path_patterns,
            get_str_slice_conf(value, "paths"),
        );
        extend_unique_patterns(
            &mut query_patterns,
            get_str_slice_conf(value, "queries"),
        );
        let paths = compile_pattern_set("paths", path_patterns)?;
        let queries = compile_pattern_set("queries", query_patterns)?;
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
                "one of presets, paths, queries or methods is required"
                    .to_string(),
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
            dry_run: DryRun::new(value),
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
        ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        if step != self.plugin_step {
            return Ok(RequestPluginResult::Skipped);
        }
        let header = session.req_header();
        let Some(reason) = self.blocked(&header.method, &header.uri) else {
            return Ok(RequestPluginResult::Continue);
        };
        if !self.dry_run.is_on() {
            debug!(
                category = CATEGORY,
                reason = ?reason,
                path = header.uri.path(),
                "request is blocked"
            );
        }
        Ok(self.dry_run.refuse(
            CATEGORY,
            session,
            ctx,
            HttpResponse::builder(self.status)
                .header(HTTP_HEADER_CONTENT_TEXT.clone())
                .body(self.message.clone())
                .no_store()
                .finish(),
            |_| format!("{reason:?}").to_lowercase(),
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
    fn test_uri_block_presets() {
        let common = new_plugin(r#"presets = ["common"]"#).unwrap();
        for uri in [
            "/.env",
            "/app/.env.production",
            "/%2eenv",
            "/.git/config",
            "/repo/.svn/entries",
            "/.htaccess",
            "/.aws/credentials",
            "/db/backup.sql",
            "/wp-login.php",
            "/WP-Admin/install.php",
            "/xmlrpc.php",
            "/phpmyadmin/index.php",
            "/cgi-bin/test.cgi",
            "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
            "/public/..%2f..%2fetc/passwd",
            "/static/%2e%2e/secret",
            "/a%00b",
            "/download?file=../../etc/passwd",
            "/download?file=..%2F..%2Fetc%2Fpasswd",
            "/view?path=/etc/passwd",
        ] {
            assert!(
                blocked(&common, "GET", uri).is_some(),
                "{uri} should be blocked by common preset"
            );
        }

        // Known-safe routes must NOT be blocked, especially ACME / OIDC discovery
        // and regular search queries or archives.
        for uri in [
            "/",
            "/index.html",
            "/.well-known/acme-challenge/token123",
            "/.well-known/openid-configuration",
            "/downloads/app.tar.gz",
            "/api/users?q=select+item",
            "/blog/env-guide",
            "/search?q=1+union+select+from+table",
        ] {
            assert_eq!(
                None,
                blocked(&common, "GET", uri),
                "{uri} should not be blocked by common preset"
            );
        }

        // Case-insensitive preset names + sqli_xss coverage via `all` + custom merge.
        let all = new_plugin(
            r#"
presets = [" ALL ", "sensitive_files"]
paths = ['^/private/']
queries = ['\bdebug=1\b']
"#,
        )
        .unwrap();
        for uri in [
            "/search?q=1+UNION+ALL+SELECT+password",
            "/login?user='+or+'1'='1",
            "/item?q=%3Cscript%3Ealert(1)%3C/script%3E",
            "/item?cb=javascript:alert(1)",
            "/item?img=%20onerror=alert(1)",
            "/item?q=sleep(5)",
            "/private/config",
            "/ok?debug=1",
        ] {
            assert!(
                blocked(&all, "GET", uri).is_some(),
                "{uri} should be blocked by all + custom rules"
            );
        }
        assert_eq!(None, blocked(&all, "GET", "/api/users?q=select+item"));

        // Individual preset scopes: sensitive_files, scanners, path_traversal, sqli_xss.
        let sensitive = new_plugin(r#"presets = ["sensitive_files"]"#).unwrap();
        assert_eq!(Some(Blocked::Path), blocked(&sensitive, "GET", "/.env"));
        assert_eq!(None, blocked(&sensitive, "GET", "/wp-login.php"));

        let scanners = new_plugin(r#"presets = ["scanners"]"#).unwrap();
        assert_eq!(
            Some(Blocked::Path),
            blocked(&scanners, "GET", "/wp-login.php")
        );
        assert_eq!(None, blocked(&scanners, "GET", "/.env"));

        let traversal = new_plugin(r#"presets = ["path_traversal"]"#).unwrap();
        assert_eq!(
            Some(Blocked::Query),
            blocked(&traversal, "GET", "/f?p=../../etc/passwd")
        );
        assert_eq!(None, blocked(&traversal, "GET", "/wp-login.php"));

        let sqli = new_plugin(r#"presets = ["sqli_xss"]"#).unwrap();
        assert_eq!(
            Some(Blocked::Query),
            blocked(&sqli, "GET", "/s?q=1+union+select+2")
        );
        assert_eq!(None, blocked(&sqli, "GET", "/.env"));
    }

    #[tokio::test]
    async fn test_uri_block_preset_dry_run() {
        let plugin = new_plugin(
            r#"
presets = ["common"]
dry_run = true
"#,
        )
        .unwrap();
        let request = "GET /.env HTTP/1.1\r\nHost: a\r\n\r\n";
        let mock_io = Builder::new().read(request.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = plugin
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result == RequestPluginResult::Continue);
    }

    #[test]
    fn test_uri_block_params() {
        let error = |conf: &str| new_plugin(conf).err().unwrap().to_string();
        let prefix = "Plugin uri_block invalid, message: ";
        assert_eq!(
            format!(
                "{prefix}one of presets, paths, queries or methods is required"
            ),
            error("")
        );
        assert_eq!(
            format!(
                "{prefix}presets: unknown preset \"unknown\", expect one of: sensitive_files, scanners, path_traversal, sqli_xss, common, all"
            ),
            error(r#"presets = ["unknown"]"#)
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
