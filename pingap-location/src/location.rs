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

use super::regex::RegexCapture;
use ahash::AHashMap;
use arc_swap::ArcSwapOption;
use http::HeaderName;
use http::HeaderValue;
use pingap_config::Hashable;
use pingap_config::LocationConf;
use pingap_core::new_internal_error;
use pingap_core::{
    HttpHeader, canonical_path, convert_headers, has_dot_segments,
    normalize_path, resolve_static_header_value, set_path_and_query,
    strip_root_label,
};
use pingap_core::{
    LocationInstance, MissingPlugin, NamedPlugin, PluginProvider,
};
use pingora::http::RequestHeader;
use pingora::upstreams::peer::PeerOptions;
use regex::Regex;
use snafu::{ResultExt, Snafu};
use std::borrow::Cow;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::time::Duration;
use tracing::{debug, error};

const LOG_TARGET: &str = "pingap::location";

pub type Locations = AHashMap<String, Arc<Location>>;

// Error enum for various location-related errors
#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Invalid error {message}"))]
    Invalid { message: String },
    #[snafu(display("Regex value: {value}, {source}"))]
    Regex { value: String, source: regex::Error },
    #[snafu(display("Too Many Requests, max:{max}"))]
    TooManyRequest { max: i32 },
    #[snafu(display("Request Entity Too Large, max:{max}"))]
    BodyTooLarge { max: usize },
}
type Result<T, E = Error> = std::result::Result<T, E>;

pub struct LocationStats {
    pub processing: i32,
    pub accepted: u64,
}

// PathSelector enum represents different ways to match request paths:
// - Regex: Uses regex pattern matching
// - Prefix: Matches if path starts with prefix
// - Equal: Matches exact path
// - Any: Matches all paths
#[derive(Debug)]
enum PathSelector {
    Regex(RegexCapture),
    Prefix(String),
    Equal(String),
    Any,
}
impl PathSelector {
    /// Creates a new path selector based on the input path string.
    ///
    /// # Arguments
    /// * `path` - The path pattern string to parse
    ///
    /// # Returns
    /// * `Result<PathSelector>` - The parsed path selector or error
    ///
    /// # Path Format
    /// - Empty string: Matches all paths
    /// - Starting with "~": Regex pattern matching
    /// - Starting with "=": Exact path matching  
    /// - Otherwise: Prefix path matching
    ///
    /// A request is matched by its normalized path (see
    /// `pingap_core::normalize_path`), so an exact or prefix path is kept in
    /// that form too: `/%E6%96%87%E6%A1%A3` in the config and in the request are the
    /// same path. A regex is taken as written and sees the normalized path.
    fn new(path: &str) -> Result<Self> {
        let path = path.trim();
        if path.is_empty() {
            return Ok(PathSelector::Any);
        }

        if let Some(re_path) = path.strip_prefix('~') {
            let re = RegexCapture::new(re_path.trim()).context(RegexSnafu {
                value: re_path.trim(),
            })?;
            Ok(PathSelector::Regex(re))
        } else if let Some(eq_path) = path.strip_prefix('=') {
            Ok(PathSelector::Equal(
                normalize_path(eq_path.trim()).into_owned(),
            ))
        } else {
            Ok(PathSelector::Prefix(normalize_path(path).into_owned()))
        }
    }
    #[inline]
    fn is_match(&self, path: &str) -> (bool, Option<AHashMap<String, String>>) {
        match self {
            // For exact path matching, compare path strings directly
            PathSelector::Equal(value) => (value == path, None),
            // For regex path matching, use regex is_match
            PathSelector::Regex(value) => value.captures(path),
            // For prefix path matching, check if path starts with prefix
            PathSelector::Prefix(value) => (path.starts_with(value), None),
            // Empty path selector matches everything
            PathSelector::Any => (true, None),
        }
    }
}

// HostSelector enum represents ways to match request hosts:
// - Regex: Uses regex pattern matching with capture groups
// - Equal: Matches exact hostname
// - Suffix: Matches one-or-more subdomains of a domain (`*.example.com`)
#[derive(Debug)]
enum HostSelector {
    Regex(RegexCapture),
    Equal(String),
    /// Domain without the leading `*.` — e.g. `"example.com"` for `*.example.com`.
    /// Matches `a.example.com` but not the apex `example.com` (same as common
    /// TLS wildcard rules).
    Suffix(String),
}
impl HostSelector {
    /// Creates a new host selector based on the input host string.
    ///
    /// # Arguments
    /// * `host` - The host pattern string to parse
    ///
    /// # Returns
    /// * `Result<HostSelector>` - The parsed host selector or error
    ///
    /// # Host Format
    /// - Empty string: Matches empty host
    /// - Starting with "~": Regex pattern matching with capture groups
    /// - Starting with `*.`: Suffix / subdomain wildcard (`*.example.com`)
    /// - Otherwise: Exact hostname matching
    fn new(host: &str) -> Result<Self> {
        let host = host.trim();
        if let Some(re_host) = host.strip_prefix('~') {
            let re = RegexCapture::new(re_host.trim()).context(RegexSnafu {
                value: re_host.trim(),
            })?;
            Ok(HostSelector::Regex(re))
        } else if let Some(domain) = host.strip_prefix("*.") {
            let domain = domain.trim();
            if domain.is_empty() || domain.contains('*') {
                return Err(Error::Invalid {
                    message: format!("invalid host wildcard pattern: {host}"),
                });
            }
            // The request host is compared without its root label (see
            // `strip_root_label`), so one written here must go as well.
            Ok(HostSelector::Suffix(
                strip_root_label(domain).to_ascii_lowercase(),
            ))
        } else {
            Ok(HostSelector::Equal(
                strip_root_label(host).to_ascii_lowercase(),
            ))
        }
    }
    /// Host matching is case-insensitive (the Host header may vary in
    /// case) and compares in place: the patterns are stored lowercased, so
    /// no lowercased copy of the request host is made per selector.
    #[inline]
    fn is_match(&self, host: &str) -> (bool, Option<AHashMap<String, String>>) {
        match self {
            HostSelector::Equal(value) => {
                (value.eq_ignore_ascii_case(host), None)
            },
            HostSelector::Suffix(domain) => {
                (host_matches_suffix(host, domain), None)
            },
            HostSelector::Regex(value) => value.captures(host),
        }
    }
}

/// `*.example.com` style: `host` is a subdomain of `domain` (lowercase),
/// not the apex itself. Case-insensitive, byte-wise, so a host that is not
/// ASCII cannot be split inside a character.
#[inline]
pub(crate) fn host_matches_suffix(host: &str, domain: &str) -> bool {
    let host = host.as_bytes();
    let Some(dot) = host.len().checked_sub(domain.len() + 1) else {
        return false;
    };
    dot > 0
        && host[dot] == b'.'
        && host[dot + 1..].eq_ignore_ascii_case(domain.as_bytes())
}

/// Classification of a single host pattern for the routing index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostIndexEntry {
    /// Exact host string (already lowercased).
    Exact(String),
    /// Suffix domain without `*.` (already lowercased).
    Suffix(String),
    /// Regex host — cannot be hashed, scanned linearly.
    Regex,
    /// No host restriction — matches every request host.
    Any,
}

// proxy_set_header X-Real-IP $remote_addr;
// proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
// proxy_set_header X-Forwarded-Proto $scheme;
// proxy_set_header X-Forwarded-Host $host;
// proxy_set_header X-Forwarded-Port $server_port;
//
// As nginx has them, and by the same variables: each is what this
// connection has. Behind a proxy that is trusted, the address, scheme and
// port of the client are in `$client_ip`, `$forwarded_proto` and
// `$forwarded_port`, for a location to set with `proxy_set_headers` - as
// they are set by hand in an nginx behind a load balancer.
static DEFAULT_PROXY_SET_HEADERS: LazyLock<Vec<HttpHeader>> =
    LazyLock::new(|| {
        convert_headers(&[
            "x-real-ip:$remote_addr".to_string(),
            "x-forwarded-for:$proxy_add_x_forwarded_for".to_string(),
            "x-forwarded-proto:$scheme".to_string(),
            "x-forwarded-host:$host".to_string(),
            "x-forwarded-port:$server_port".to_string(),
        ])
        .expect("Failed to convert default proxy set headers")
    });

/// A compiled URL rewrite rule with values precomputed at construction so the
/// per-request path (see [`Location::rewrite`]) avoids re-deriving them.
#[derive(Debug)]
struct RegexRewrite {
    /// Regex matched against the request path.
    re: Regex,
    /// Replacement string (may contain `$name` capture references).
    value: String,
    /// Pattern is `.*`: the whole path is replaced, no matching needed.
    match_all: bool,
    /// Regex declares named capture groups worth extracting into `variables`.
    has_named_captures: bool,
    /// The replacement holds a `$`, so request variables may apply to it.
    has_variables: bool,
}

/// Whether two rewritten targets, `path` or `path?query`, are the same
/// path to an upstream however it reads one, with the same query.
fn same_path(a: &str, b: &str) -> bool {
    let split = |target| match str::split_once(target, '?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    };
    let ((path_a, query_a), (path_b, query_b)) = (split(a), split(b));
    query_a == query_b && canonical_path(path_a) == canonical_path(path_b)
}

impl RegexRewrite {
    /// Applies the rule to `path`: the new path, and the groups of the
    /// match it was made from. `None` when the rule does not match.
    ///
    /// One pass over the path: the leftmost match both builds the new path
    /// (what `Regex::replace` does) and keeps its groups, so the named
    /// captures cost no second run of the regex.
    fn apply<'h>(
        &self,
        replacement: &str,
        path: &'h str,
    ) -> Option<(String, Option<regex::Captures<'h>>)> {
        if self.match_all {
            return Some((replacement.to_string(), None));
        }
        let found = self.re.captures(path)?;
        let whole = found.get(0)?;
        let mut new_path =
            String::with_capacity(path.len() + replacement.len());
        new_path.push_str(&path[..whole.start()]);
        found.expand(replacement, &mut new_path);
        new_path.push_str(&path[whole.end()..]);
        Some((new_path, Some(found)))
    }

    /// Parses `"<regex> <replacement>"`. A lone replacement holding `$`
    /// (`"/$1"`) rewrites the whole path; a lone pattern rewrites its
    /// match to nothing. The pattern must compile: a rewrite that did not
    /// used to be silently dropped, leaving the location proxying the
    /// original path.
    fn new(value: &str) -> Result<Self> {
        let mut parts = value.split_whitespace();
        let (pattern, replacement) = match (parts.next(), parts.next()) {
            (Some(only), None) if only.contains('$') => (".*", only),
            (Some(pattern), replacement) => {
                (pattern, replacement.unwrap_or(""))
            },
            (None, _) => (".*", ""),
        };
        if parts.next().is_some() {
            return Err(Error::Invalid {
                message: format!(
                    "rewrite {value:?} is invalid, expected \"<regex> <replacement>\""
                ),
            });
        }
        let re = Regex::new(pattern).context(RegexSnafu { value: pattern })?;
        Ok(Self {
            match_all: re.as_str() == ".*",
            has_named_captures: re.capture_names().flatten().next().is_some(),
            has_variables: replacement.contains('$'),
            re,
            value: replacement.to_string(),
        })
    }
}

/// Substitutes `$name` in `template` with the value of request variable
/// `name`. A `$` naming no variable (`$1`, a regex group) is left for the
/// regex replacement. Borrowed when nothing applied.
fn interpolate_variables<'a>(
    template: &'a str,
    variables: &AHashMap<String, String>,
) -> Cow<'a, str> {
    let bytes = template.as_bytes();
    let mut out: Option<String> = None;
    let mut copied = 0;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'$' {
            i += 1;
            continue;
        }
        let start = i + 1;
        let end = start
            + bytes[start..]
                .iter()
                .take_while(|b| b.is_ascii_alphanumeric() || **b == b'_')
                .count();
        if end > start
            && let Some(value) = variables.get(&template[start..end])
        {
            let out = out.get_or_insert_with(|| {
                String::with_capacity(template.len() + 16)
            });
            out.push_str(&template[copied..i]);
            out.push_str(value);
            copied = end;
        }
        i = end.max(start);
    }
    match out {
        Some(mut out) => {
            out.push_str(&template[copied..]);
            Cow::Owned(out)
        },
        None => Cow::Borrowed(template),
    }
}

/// Parses `["name:value", "name", ...]` match conditions into `(name, value)`
/// pairs, where a missing value means a presence-only check.
fn parse_match_conditions(
    list: &Option<Vec<String>>,
) -> Vec<(String, Option<String>)> {
    list.as_ref()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let item = item.trim();
                    if item.is_empty() {
                        return None;
                    }
                    let cond = match item.split_once(':') {
                        Some((n, v)) => {
                            (n.trim().to_string(), Some(v.trim().to_string()))
                        },
                        None => (item.to_string(), None),
                    };
                    Some(cond)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Returns true if `actual` satisfies `expected`: present with the exact value,
/// or merely present when no value is required.
#[inline]
fn condition_met(actual: Option<&str>, expected: &Option<String>) -> bool {
    match actual {
        Some(a) => expected.as_deref().is_none_or(|v| v == a),
        None => false,
    }
}

/// [`condition_met`] for a query parameter: the value is also taken as
/// the client meant it, with its percent-encoding decoded.
///
/// It used to be compared as it was sent and nothing else. A client that
/// encodes what it may - `?v=a%2Bb` for `a+b`, `%2F` for a slash, any
/// character that is not ASCII - did not match `match_query = ["v:a+b"]`,
/// and went to whatever location came next. A condition that was written
/// in the encoded form to get around that goes on matching: the value as
/// it was sent is compared first.
#[inline]
fn query_condition_met(
    actual: Option<&str>,
    expected: &Option<String>,
) -> bool {
    if condition_met(actual, expected) {
        return true;
    }
    match actual.map(pingap_core::decode_query_value) {
        Some(Cow::Owned(decoded)) => condition_met(Some(&decoded), expected),
        _ => false,
    }
}

/// The plugin instances a location's names resolved to, stamped with the
/// provider version they came from.
struct ResolvedPlugins {
    version: u64,
    plugins: Arc<[NamedPlugin]>,
}

impl std::fmt::Debug for ResolvedPlugins {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> =
            self.plugins.iter().map(|(name, _)| name.as_ref()).collect();
        f.debug_struct("ResolvedPlugins")
            .field("version", &self.version)
            .field("plugins", &names)
            .finish()
    }
}

/// Location represents a routing configuration for handling HTTP requests.
/// It defines rules for matching requests based on paths and hosts, and specifies
/// how these requests should be processed and proxied.
#[derive(Debug)]
pub struct Location {
    /// Unique identifier for this location configuration
    pub name: Arc<str>,

    /// Hash key used for configuration versioning and change detection
    pub key: String,

    /// Target upstream server where requests will be proxied to
    upstream: String,

    /// Compiled path matching rules (regex, prefix, exact or any)
    path_selector: PathSelector,

    /// List of host patterns to match against request Host header
    /// Empty list means match all hosts
    hosts: Vec<HostSelector>,

    /// Optional request-header match conditions. A location matches only when
    /// every condition holds: a `(name, Some(value))` requires that exact
    /// header value, a `(name, None)` requires the header to be present. Empty
    /// (the common case) always matches, so non-conditional locations pay
    /// nothing. Covers headers, query params and cookies.
    header_conditions: Vec<(String, Option<String>)>,
    query_conditions: Vec<(String, Option<String>)>,
    cookie_conditions: Vec<(String, Option<String>)>,

    /// Optional URL rewriting rule consisting of:
    /// - regex pattern to match against request path
    /// - replacement string with optional capture group references
    reg_rewrite: Option<RegexRewrite>,

    /// Headers to set or append on proxied requests
    pub headers: Option<Vec<(HeaderName, HeaderValue, bool)>>,

    /// Additional headers to append to proxied requests
    /// These are added without removing existing headers
    // pub proxy_add_headers: Option<Vec<HttpHeader>>,

    /// Headers to set on proxied requests
    /// These override any existing headers with the same name
    // pub proxy_set_headers: Option<Vec<HttpHeader>>,

    /// Ordered list of plugin names to execute during request/response processing
    pub plugins: Option<Vec<Arc<str>>>,

    /// `plugins` resolved to instances, kept until the plugin provider
    /// reports a new version. Requests share the list instead of looking
    /// every name up again.
    resolved_plugins: ArcSwapOption<ResolvedPlugins>,

    /// Total number of requests accepted by this location
    /// Used for metrics and monitoring
    accepted: AtomicU64,

    /// Number of requests currently being processed
    /// Used for concurrency control
    processing: AtomicI32,

    /// Maximum number of concurrent requests allowed
    /// Zero means unlimited
    max_processing: i32,

    /// Whether to enable gRPC-Web protocol support
    /// When true, handles gRPC-Web requests and converts them to regular gRPC
    grpc_web: bool,

    /// Maximum allowed size of client request body in bytes
    /// Zero means unlimited. Requests exceeding this limit receive 413 error
    client_max_body_size: usize,

    /// Whether to automatically add standard reverse proxy headers like:
    /// X-Forwarded-For, X-Real-IP, X-Forwarded-Proto, etc.
    // pub enable_reverse_proxy_headers: bool,

    /// Maximum window for retries
    pub max_retries: Option<u8>,

    /// Maximum window for retries
    pub max_retry_window: Option<Duration>,

    /// What the requests of this location wait for the upstream, where it
    /// is not what the upstream says for everyone: see
    /// [`Location::apply_timeouts`].
    connection_timeout: Option<Duration>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
}

/// Formats a vector of header strings into internal HttpHeader representation.
///
/// # Arguments
/// * `values` - Optional vector of header strings in "Name: Value" format
///
/// # Returns
/// * `Result<Option<Vec<HttpHeader>>>` - Parsed headers or None if input was None
fn format_headers(
    values: &Option<Vec<String>>,
) -> Result<Option<Vec<HttpHeader>>> {
    if let Some(header_values) = values {
        let arr =
            convert_headers(header_values).map_err(|err| Error::Invalid {
                message: err.to_string(),
            })?;
        Ok(Some(arr))
    } else {
        Ok(None)
    }
}

/// Get the content length from http request header.
fn get_content_length(header: &RequestHeader) -> Option<usize> {
    if let Some(content_length) =
        header.headers.get(http::header::CONTENT_LENGTH)
        && let Ok(size) =
            content_length.to_str().unwrap_or_default().parse::<usize>()
    {
        return Some(size);
    }
    None
}

impl Location {
    /// Puts the timeouts of this location in place of the upstream's, on
    /// the peer of one of its requests.
    ///
    /// The timeouts were the upstream's alone, so an upload path, a long
    /// poll and an ordinary endpoint on one upstream all waited the same.
    /// What a location does not set stays as the upstream has it. A
    /// connection timeout longer than the upstream's limit on connect and
    /// handshake together takes that limit up with it, or it would not be
    /// the time that counts.
    pub fn apply_timeouts(&self, options: &mut PeerOptions) {
        if let Some(timeout) = self.connection_timeout {
            options.connection_timeout = Some(timeout);
            options.total_connection_timeout = options
                .total_connection_timeout
                .map(|total| total.max(timeout));
        }
        if let Some(timeout) = self.read_timeout {
            options.read_timeout = Some(timeout);
        }
        if let Some(timeout) = self.write_timeout {
            options.write_timeout = Some(timeout);
        }
    }
    /// Creates a new Location from configuration
    /// Validates and compiles path/host patterns and other settings
    pub fn new(name: &str, conf: &LocationConf) -> Result<Location> {
        if name.is_empty() {
            return Err(Error::Invalid {
                message: "Name is required".to_string(),
            });
        }
        let key = conf.hash_key();
        let upstream = conf.upstream.clone().unwrap_or_default();
        // rewrite: "^/users/(.*)$ /api/users/$1"
        let reg_rewrite = conf
            .rewrite
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(RegexRewrite::new)
            .transpose()?;

        let hosts = conf
            .host
            .as_deref()
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(HostSelector::new)
            .collect::<Result<Vec<_>>>()?;

        // Parse optional match conditions ("name:value" for an exact value, or
        // "name" for a presence check) on headers, query params and cookies.
        let header_conditions = parse_match_conditions(&conf.match_headers);
        let query_conditions = parse_match_conditions(&conf.match_query);
        let cookie_conditions = parse_match_conditions(&conf.match_cookies);

        let mut headers: Vec<(HeaderName, HeaderValue, bool)> = vec![];
        if conf.enable_reverse_proxy_headers.unwrap_or_default() {
            for (name, value) in DEFAULT_PROXY_SET_HEADERS.iter() {
                headers.push((name.clone(), value.clone(), false));
            }
        }
        // `$hostname` and `$ENV_VAR` values are fixed for the life of the
        // process: resolve them here so the request path only sees the
        // variables that really change per request.
        if let Some(proxy_set_headers) =
            format_headers(&conf.proxy_set_headers)?
        {
            for (name, value) in proxy_set_headers {
                headers.push((name, resolve_static_header_value(value), false));
            }
        }
        if let Some(proxy_add_headers) =
            format_headers(&conf.proxy_add_headers)?
        {
            for (name, value) in proxy_add_headers {
                headers.push((name, resolve_static_header_value(value), true));
            }
        }

        let location = Location {
            name: name.into(),
            key,
            path_selector: PathSelector::new(
                conf.path.as_deref().unwrap_or_default(),
            )?,
            hosts,
            header_conditions,
            query_conditions,
            cookie_conditions,
            upstream,
            reg_rewrite,
            plugins: conf.plugins.as_ref().map(|list| {
                list.iter().map(|name| Arc::from(name.as_str())).collect()
            }),
            resolved_plugins: ArcSwapOption::const_empty(),
            accepted: AtomicU64::new(0),
            processing: AtomicI32::new(0),
            max_processing: conf.max_processing.unwrap_or_default(),
            grpc_web: conf.grpc_web.unwrap_or_default(),
            headers: if headers.is_empty() {
                None
            } else {
                Some(headers)
            },
            // proxy_add_headers: format_headers(&conf.proxy_add_headers)?,
            // proxy_set_headers: format_headers(&conf.proxy_set_headers)?,
            client_max_body_size: conf
                .client_max_body_size
                .unwrap_or_default()
                .as_u64() as usize,
            // enable_reverse_proxy_headers: conf
            //     .enable_reverse_proxy_headers
            //     .unwrap_or_default(),
            max_retries: conf.max_retries,
            max_retry_window: conf.max_retry_window,
            connection_timeout: conf.connection_timeout,
            read_timeout: conf.read_timeout,
            write_timeout: conf.write_timeout,
        };
        debug!(
            target: LOG_TARGET,
            location = format!("{location:?}"),
            "create a new location"
        );

        Ok(location)
    }

    /// Returns whether gRPC-Web protocol support is enabled for this location
    /// The location's plugins, resolved through `provider`. The list is
    /// built on the first request after the location or the plugins were
    /// loaded and shared by every request after that, so the per-request
    /// cost is one atomic load and one reference count. `None` when the
    /// location names no plugins.
    ///
    /// A name the provider does not have resolves to [`MissingPlugin`], so
    /// the location answers 500 instead of serving without that plugin.
    #[inline]
    pub fn plugins_for(
        &self,
        provider: &dyn PluginProvider,
    ) -> Option<Arc<[NamedPlugin]>> {
        let names = self.plugins.as_ref()?;
        let version = provider.version();
        if let Some(resolved) = self.resolved_plugins.load().as_ref()
            && resolved.version == version
        {
            return (!resolved.plugins.is_empty())
                .then(|| resolved.plugins.clone());
        }
        let plugins: Arc<[NamedPlugin]> = names
            .iter()
            .map(|name| {
                let plugin = provider.get(name).unwrap_or_else(|| {
                    // Once per plugin reload, not once per request.
                    error!(
                        target: LOG_TARGET,
                        location = self.name.as_ref(),
                        plugin = name.as_ref(),
                        "plugin is not available, requests of the location are rejected"
                    );
                    Arc::new(MissingPlugin::new(name.clone()))
                });
                (name.clone(), plugin)
            })
            .collect();
        self.resolved_plugins.store(Some(Arc::new(ResolvedPlugins {
            version,
            plugins: plugins.clone(),
        })));
        (!plugins.is_empty()).then_some(plugins)
    }

    /// When enabled, the proxy will handle gRPC-Web requests and convert them to regular gRPC
    #[inline]
    pub fn support_grpc_web(&self) -> bool {
        self.grpc_web
    }

    /// Validates that the request's Content-Length header does not exceed the configured maximum
    ///
    /// # Arguments
    /// * `header` - The HTTP request header to validate
    ///
    /// # Returns
    /// * `Result<()>` - Ok if validation passes, Error::BodyTooLarge if content length exceeds limit
    ///
    /// # Notes
    /// - Returns Ok if client_max_body_size is 0 (unlimited)
    /// - Uses get_content_length() helper to parse the Content-Length header
    #[inline]
    pub fn validate_content_length(
        &self,
        header: &RequestHeader,
    ) -> Result<()> {
        if self.client_max_body_size == 0 {
            return Ok(());
        }
        if get_content_length(header).unwrap_or_default()
            > self.client_max_body_size
        {
            return Err(Error::BodyTooLarge {
                max: self.client_max_body_size,
            });
        }

        Ok(())
    }

    /// Host patterns of this location classified for [`crate::LocationHostIndex`].
    ///
    /// A multi-host location contributes one entry per pattern so it appears in
    /// every relevant bucket. Empty host list → a single [`HostIndexEntry::Any`].
    pub fn host_index_entries(&self) -> Vec<HostIndexEntry> {
        if self.hosts.is_empty() {
            return vec![HostIndexEntry::Any];
        }
        self.hosts
            .iter()
            .map(|selector| match selector {
                HostSelector::Equal(value) => {
                    HostIndexEntry::Exact(value.clone())
                },
                HostSelector::Suffix(domain) => {
                    HostIndexEntry::Suffix(domain.clone())
                },
                HostSelector::Regex(_) => HostIndexEntry::Regex,
            })
            .collect()
    }

    /// Checks if a request matches this location's path and host rules
    /// Returns a tuple containing:
    /// - bool: Whether the request matched both path and host rules
    /// - Option<Vec<(String, String)>>: Any captured variables from regex host matching
    #[inline]
    pub fn match_host_path(
        &self,
        host: &str,
        path: &str,
    ) -> (bool, Option<AHashMap<String, String>>) {
        // Path first: it is the cheaper check and the usual reason not to
        // match.
        let (matched, mut capture_values) = self.path_selector.is_match(path);
        if !matched {
            return (false, None);
        }

        // If no host patterns configured, path match is sufficient
        if self.hosts.is_empty() {
            return (true, capture_values);
        }

        let matched = self.hosts.iter().any(|host_selector| {
            let (matched, captures) = host_selector.is_match(host);
            if let Some(captures) = captures {
                if let Some(values) = capture_values.as_mut() {
                    values.extend(captures);
                } else {
                    capture_values = Some(captures);
                }
            }
            matched
        });

        (matched, capture_values)
    }

    /// Returns true when the request satisfies this location's optional
    /// header / query / cookie match conditions. With none configured this is a
    /// cheap `true`, so non-conditional locations pay nothing.
    #[inline]
    pub fn match_conditions(&self, req_header: &RequestHeader) -> bool {
        self.header_conditions.iter().all(|(name, expected)| {
            condition_met(
                pingap_core::get_req_header_value(req_header, name),
                expected,
            )
        }) && self.query_conditions.iter().all(|(name, expected)| {
            query_condition_met(
                pingap_core::get_query_value(req_header, name),
                expected,
            )
        }) && self.cookie_conditions.iter().all(|(name, expected)| {
            condition_met(
                pingap_core::get_cookie_value(req_header, name),
                expected,
            )
        })
    }

    pub fn stats(&self) -> LocationStats {
        LocationStats {
            processing: self.processing.load(Ordering::Relaxed),
            accepted: self.accepted.load(Ordering::Relaxed),
        }
    }
}

impl LocationInstance for Location {
    fn name(&self) -> &str {
        self.name.as_ref()
    }
    fn has_rewrite(&self) -> bool {
        self.reg_rewrite.is_some()
    }
    fn headers(&self) -> Option<&Vec<(HeaderName, HeaderValue, bool)>> {
        self.headers.as_ref()
    }
    fn client_body_size_limit(&self) -> usize {
        self.client_max_body_size
    }
    fn apply_timeouts(&self, options: &mut PeerOptions) {
        Location::apply_timeouts(self, options);
    }
    fn upstream(&self) -> &str {
        self.upstream.as_ref()
    }
    fn on_response(&self) {
        self.processing.fetch_sub(1, Ordering::Relaxed);
    }
    /// Increments the processing and accepted request counters for this location.
    ///
    /// This method is called when a new request starts being processed by this location.
    /// It performs two atomic operations:
    /// 1. Increments the total accepted requests counter
    /// 2. Increments the currently processing requests counter
    ///
    /// # Returns
    /// * `Result<(u64, i32)>` - A tuple containing:
    ///   - The new total number of accepted requests (u64)
    ///   - The new number of currently processing requests (i32)
    ///
    /// # Errors
    /// Returns `Error::TooManyRequest` if the number of currently processing requests
    /// would exceed the configured `max_processing` limit (when non-zero).
    fn on_request(&self) -> pingora::Result<(u64, i32)> {
        let accepted = self.accepted.fetch_add(1, Ordering::Relaxed) + 1;
        let processing = self.processing.fetch_add(1, Ordering::Relaxed) + 1;
        if self.max_processing != 0 && processing > self.max_processing {
            let err = Error::TooManyRequest {
                max: self.max_processing,
            };
            return Err(new_internal_error(429, err));
        }
        Ok((accepted, processing))
    }
    /// Applies URL rewriting rules if configured for this location.
    ///
    /// This method performs path rewriting based on regex patterns and replacement rules.
    /// It supports variable interpolation from captured values in the host matching.
    ///
    /// # Arguments
    /// * `header` - Mutable reference to the request header containing the URI to rewrite
    /// * `variables` - Optional map of variables captured from host matching that can be interpolated
    ///   into the replacement value
    ///
    /// # Returns
    /// * `bool` - Returns true if the path was rewritten, false if no rewriting was performed
    ///
    /// # Examples
    /// ```
    /// // Configuration example:
    /// // rewrite: "^/users/(.*)$ /api/users/$1"
    /// // This would rewrite "/users/123" to "/api/users/123"
    /// ```
    ///
    /// # Notes
    /// - Preserves query parameters when rewriting the path
    /// - Logs debug information about path rewrites
    /// - Logs errors if the new path cannot be parsed as a valid URI
    #[inline]
    fn rewrite(
        &self,
        header: &mut RequestHeader,
        variables: &mut Option<AHashMap<String, String>>,
    ) -> pingora::Result<bool> {
        let Some(rewrite) = &self.reg_rewrite else {
            return Ok(false);
        };
        // `$name` in the replacement is a request variable (a host capture,
        // a plugin's) before it is a regex group: those are filled in first,
        // and only when the replacement can hold one at all.
        let replacement = match variables.as_ref() {
            Some(vars) if rewrite.has_variables && !vars.is_empty() => {
                interpolate_variables(&rewrite.value, vars)
            },
            _ => Cow::Borrowed(rewrite.value.as_str()),
        };
        let apply = |path| rewrite.apply(replacement.as_ref(), path);

        // The location was chosen by the path as an upstream may read it
        // (`normalize_path`), and the rule has to hold for that reading
        // too: matched against the path as it was sent and nothing else,
        // `/%75sers/x` slipped past `^/users/(.*)$ /acme/$1` to arrive as
        // `/users/x`, and `/users/../other` took the prefix only to leave
        // it one segment later.
        //
        // For nearly every request the two are the same path. Where they
        // are not, the path as sent is still the one to rewrite when it can
        // be: the other reading has lost what it took for syntax, the
        // `%2F` in `group%2Fproject`, `;jsessionid=...`, a second slash.
        // It can be when it has no `.` or `..` segment under any reading,
        // so that it stays below whatever the rule puts in front of it,
        // and when both readings of the result name the same path.
        let sent = header.uri.path();
        let read = canonical_path(sent);
        let (mut new_path, captures) = match &read {
            Cow::Borrowed(_) => match apply(sent) {
                Some(result) => result,
                // no match: nothing to rewrite, and nothing was allocated
                None => return Ok(false),
            },
            Cow::Owned(read) => {
                let as_sent = if has_dot_segments(sent) {
                    None
                } else {
                    apply(sent)
                };
                match (as_sent, apply(read)) {
                    (Some(as_sent), Some(as_read)) => {
                        if same_path(&as_sent.0, &as_read.0) {
                            as_sent
                        } else {
                            as_read
                        }
                    },
                    // A rule written for the spelling itself, `%2F` or a
                    // path parameter.
                    (Some(as_sent), None) => as_sent,
                    (None, Some(as_read)) => as_read,
                    (None, None) => return Ok(false),
                }
            },
        };
        if new_path == sent {
            return Ok(false);
        }

        if rewrite.has_named_captures
            && let Some(captures) = &captures
        {
            for name in rewrite.re.capture_names().flatten() {
                if let Some(match_value) = captures.name(name) {
                    let values = variables.get_or_insert_with(AHashMap::new);
                    values.insert(
                        name.to_string(),
                        match_value.as_str().to_string(),
                    );
                }
            }
        }

        // preserve query parameters, appended in place. A replacement can
        // bring a query of its own (`/search?from=old`): the request's is
        // then added to it with `&`. It used to get a second `?`, which
        // made the request's first parameter part of the last value.
        if let Some(query) = header.uri.query() {
            let has_query = new_path.contains('?');
            if !has_query || !query.is_empty() {
                new_path.reserve(query.len() + 1);
                new_path.push(if has_query { '&' } else { '?' });
                new_path.push_str(query);
            }
        }
        debug!(target: LOG_TARGET, new_path, "rewrite path");

        // set new uri, the host of an HTTP/2 request stays in it. A rule
        // that gives something that is no path fails the request: it used
        // to be logged and the request sent on with the path it came with,
        // past the rewrite that was to put it where it belongs.
        set_path_and_query(header, &new_path).map_err(|e| {
            error!(target: LOG_TARGET, error = %e, location = self.name.as_ref(), "new path parse fail");
            new_internal_error(500, "rewrite gives an invalid path")
        })?;

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytesize::ByteSize;
    use pingap_config::LocationConf;
    use pingora::http::RequestHeader;
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    #[test]
    fn test_format_headers() {
        let headers = format_headers(&Some(vec![
            "Content-Type: application/json".to_string(),
        ]))
        .unwrap();
        assert_eq!(
            r###"Some([("content-type", "application/json")])"###,
            format!("{headers:?}")
        );
    }
    #[test]
    fn test_new_path_selector() {
        let selector = PathSelector::new("").unwrap();
        assert_eq!(true, matches!(selector, PathSelector::Any));

        let selector = PathSelector::new("~/api").unwrap();
        assert_eq!(true, matches!(selector, PathSelector::Regex(_)));

        let selector = PathSelector::new("=/api").unwrap();
        assert_eq!(true, matches!(selector, PathSelector::Equal(_)));

        let selector = PathSelector::new("/api").unwrap();
        assert_eq!(true, matches!(selector, PathSelector::Prefix(_)));
    }
    /// Regression: a host is the same host with its root label written
    /// out. The request side drops it (`get_host`); one written in the
    /// configuration is dropped as well, or it would never match.
    #[test]
    fn test_host_is_matched_without_its_root_label() {
        let location = |host: &str| {
            Location::new(
                "lo",
                &LocationConf {
                    upstream: Some("charts".to_string()),
                    host: Some(host.to_string()),
                    ..Default::default()
                },
            )
            .unwrap()
        };
        // What `get_host` gives for `Host: admin.example.com.`
        let request_host = pingap_core::strip_root_label("admin.example.com.");
        for host in
            ["admin.example.com", "admin.example.com.", "*.example.com."]
        {
            assert_eq!(
                true,
                location(host).match_host_path(request_host, "/").0,
                "{host}"
            );
        }
        assert_eq!(
            false,
            location("other.example.com.")
                .match_host_path(request_host, "/")
                .0
        );
    }

    #[test]
    fn test_location_timeouts_take_the_place_of_the_upstreams() {
        use pingora::upstreams::peer::PeerOptions;
        let of_upstream = || {
            let mut options = PeerOptions::new();
            options.connection_timeout = Some(Duration::from_secs(3));
            options.total_connection_timeout = Some(Duration::from_secs(10));
            options.read_timeout = Some(Duration::from_secs(30));
            options.write_timeout = None;
            options
        };
        let timeouts = |options: &PeerOptions| {
            (
                options.connection_timeout.map(|value| value.as_secs()),
                options
                    .total_connection_timeout
                    .map(|value| value.as_secs()),
                options.read_timeout.map(|value| value.as_secs()),
                options.write_timeout.map(|value| value.as_secs()),
            )
        };
        let apply = |conf: LocationConf| {
            let location = Location::new("lo", &conf).unwrap();
            let mut options = of_upstream();
            location.apply_timeouts(&mut options);
            timeouts(&options)
        };
        let upstream = Some("charts".to_string());

        // Nothing set: the upstream's, as they were.
        assert_eq!(
            (Some(3), Some(10), Some(30), None),
            apply(LocationConf {
                upstream: upstream.clone(),
                ..Default::default()
            })
        );
        // Each on its own, also where the upstream has none.
        assert_eq!(
            (Some(3), Some(10), Some(300), Some(20)),
            apply(LocationConf {
                upstream: upstream.clone(),
                read_timeout: Some(Duration::from_secs(300)),
                write_timeout: Some(Duration::from_secs(20)),
                ..Default::default()
            })
        );
        // A connect shorter than the upstream's leaves its total alone,
        // a longer one takes it along.
        assert_eq!(
            (Some(1), Some(10), Some(30), None),
            apply(LocationConf {
                upstream: upstream.clone(),
                connection_timeout: Some(Duration::from_secs(1)),
                ..Default::default()
            })
        );
        assert_eq!(
            (Some(60), Some(60), Some(30), None),
            apply(LocationConf {
                upstream: upstream.clone(),
                connection_timeout: Some(Duration::from_secs(60)),
                ..Default::default()
            })
        );
    }

    #[test]
    fn test_path_host_select_location() {
        let upstream_name = "charts";

        // no path, no host
        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some(upstream_name.to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(true, lo.match_host_path("pingap", "/api").0);
        assert_eq!(true, lo.match_host_path("", "").0);

        // host
        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some(upstream_name.to_string()),
                host: Some("test.com,pingap".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(true, lo.match_host_path("pingap", "/api").0);
        assert_eq!(true, lo.match_host_path("Pingap", "/api").0); // case-insensitive
        assert_eq!(true, lo.match_host_path("pingap", "").0);
        assert_eq!(false, lo.match_host_path("", "/api").0);

        // wildcard suffix host
        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some(upstream_name.to_string()),
                host: Some("*.example.com".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(true, lo.match_host_path("a.example.com", "/").0);
        assert_eq!(true, lo.match_host_path("api.example.com", "/").0);
        assert_eq!(true, lo.match_host_path("API.Example.COM", "/").0);
        assert_eq!(false, lo.match_host_path("example.com", "/").0);
        assert_eq!(false, lo.match_host_path("evil-example.com", "/").0);
        assert_eq!(false, lo.match_host_path(".example.com", "/").0);
        assert_eq!(false, lo.match_host_path("com", "/").0);
        // a non-ASCII host is compared byte-wise, never split in a char
        assert_eq!(false, lo.match_host_path("ü.example.co", "/").0);
        assert_eq!(true, lo.match_host_path("ü.example.com", "/").0);

        // regex
        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some(upstream_name.to_string()),
                path: Some("~/users".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(true, lo.match_host_path("", "/api/users").0);
        assert_eq!(true, lo.match_host_path("", "/users").0);
        assert_eq!(false, lo.match_host_path("", "/api").0);

        // regex ^/api
        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some(upstream_name.to_string()),
                path: Some("~^/api".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(true, lo.match_host_path("", "/api/users").0);
        assert_eq!(false, lo.match_host_path("", "/users").0);
        assert_eq!(true, lo.match_host_path("", "/api").0);

        // prefix
        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some(upstream_name.to_string()),
                path: Some("/api".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(true, lo.match_host_path("", "/api/users").0);
        assert_eq!(false, lo.match_host_path("", "/users").0);
        assert_eq!(true, lo.match_host_path("", "/api").0);

        // equal
        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some(upstream_name.to_string()),
                path: Some("=/api".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(false, lo.match_host_path("", "/api/users").0);
        assert_eq!(false, lo.match_host_path("", "/users").0);
        assert_eq!(true, lo.match_host_path("", "/api").0);
    }

    #[test]
    fn test_match_host_path_variables() {
        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some("charts".to_string()),
                host: Some("~(?<name>.+).npmtrend.com".to_string()),
                path: Some("~/(?<route>.+)/(.*)".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        let (matched, variables) =
            lo.match_host_path("charts.npmtrend.com", "/users/123");
        assert_eq!(true, matched);
        let variables = variables.unwrap();
        assert_eq!("users", variables.get("route").unwrap());
        assert_eq!("charts", variables.get("name").unwrap());
    }

    #[test]
    fn test_rewrite_path() {
        let upstream_name = "charts";

        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some(upstream_name.to_string()),
                rewrite: Some("^/users/(?<upstream>.*?)/(.*)$ /$2".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        let mut req_header =
            RequestHeader::build("GET", b"/users/rest/me?abc=1", None).unwrap();
        let mut variables = None;
        let matched = lo.rewrite(&mut req_header, &mut variables).unwrap();
        assert_eq!(true, matched);
        assert_eq!(r#"Some({"upstream": "rest"})"#, format!("{:?}", variables));
        assert_eq!("/me?abc=1", req_header.uri.to_string());

        let mut req_header =
            RequestHeader::build("GET", b"/api/me?abc=1", None).unwrap();
        let mut variables = None;
        let matched = lo.rewrite(&mut req_header, &mut variables).unwrap();
        assert_eq!(false, matched);
        assert_eq!(None, variables);
        assert_eq!("/api/me?abc=1", req_header.uri.to_string());
    }

    /// A request is matched by its normalized path, and the paths of the
    /// config are kept in the same form.
    #[test]
    fn test_path_is_matched_in_normalized_form() {
        let new_location = |path: &str| {
            Location::new(
                "lo",
                &LocationConf {
                    upstream: Some("up".to_string()),
                    path: Some(path.to_string()),
                    ..Default::default()
                },
            )
            .unwrap()
        };
        let matches = |lo: &Location, path: &str| {
            lo.match_host_path("", &normalize_path(path)).0
        };

        let lo = new_location("/admin");
        for path in ["/admin/x", "/%61dmin/x", "//admin", "/a/../admin"] {
            assert_eq!(true, matches(&lo, path), "{path}");
        }
        assert_eq!(false, matches(&lo, "/public"));

        // Written with an escape in the config: the same path.
        let lo = new_location("/%E6%96%87%E6%A1%A3/");
        assert_eq!(true, matches(&lo, "/%E6%96%87%E6%A1%A3/menu"));
        assert_eq!(true, matches(&lo, "/文档/menu"));
        let lo = new_location("=/a%20b");
        assert_eq!(true, matches(&lo, "/a%20b"));
        assert_eq!(false, matches(&lo, "/a%20b/c"));

        // A regex sees the normalized path.
        let lo = new_location("~^/admin/(?<id>\\d+)$");
        assert_eq!(true, matches(&lo, "/%61dmin/42"));
        assert_eq!(false, matches(&lo, "/admin/42/x"));
        assert_eq!(true, matches(&lo, "/admin;v=1/42;x"));

        // Regression: a path parameter or a backslash took a request past
        // the location of the path that a servlet container, or IIS, goes
        // on to serve.
        let lo = new_location("/api/admin");
        for path in [
            "/api;v=1/admin/users",
            "/public/..;/api/admin",
            "/api\\admin\\users",
            "/public/..%5capi/admin",
        ] {
            assert_eq!(true, matches(&lo, path), "{path}");
        }
        assert_eq!(false, matches(&lo, "/api;admin"));
        let lo = new_location("=/login");
        assert_eq!(true, matches(&lo, "/login;jsessionid=A1"));
        assert_eq!(false, matches(&lo, "/login;x/more"));
    }

    /// Regression: a rewrite replaced the whole uri with the new path. An
    /// HTTP/2 request has its host there, so the host was gone afterwards:
    /// for the upstream, and for the cache key.
    /// Regression: the rule was matched against the path as it was sent,
    /// while the location had been chosen by the normalized one. An
    /// encoded or roundabout spelling reached the location and went past
    /// its rewrite: with a rule that puts a prefix in front, the upstream
    /// got the path without the prefix, or with a `..` that left it again.
    #[test]
    fn test_rewrite_works_on_the_path_the_location_matched() {
        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some("charts".to_string()),
                path: Some("/users".to_string()),
                rewrite: Some("^/users/(.*)$ /acme/$1".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        let rewritten = |path: &str| {
            let mut header =
                RequestHeader::build("GET", path.as_bytes(), None).unwrap();
            // only what the location matches gets here
            assert_eq!(
                true,
                lo.match_host_path("", &normalize_path(header.uri.path())).0,
                "{path}"
            );
            lo.rewrite(&mut header, &mut None).unwrap();
            header.uri.to_string()
        };
        assert_eq!("/acme/x?a=1", rewritten("/users/x?a=1"));
        // Spelled another way, it is still under the prefix.
        assert_eq!("/acme/x", rewritten("/%75sers/x"));
        assert_eq!("/acme/x", rewritten("//users/./x"));
        assert_eq!("/acme/y", rewritten("/users/../users/y"));
        assert_eq!("/acme/y", rewritten("/users/a/%2e%2e/y"));
        assert_eq!("/acme/y", rewritten("/users;v=1/y"));
        assert_eq!("/acme/x", rewritten("/users%2Fx"));
        assert_eq!("/acme/x", rewritten("/\\users\\x"));
        // A `..` that only shows once `%2F` or `%5C` is read as a
        // separator, or once the parameters of a segment are dropped.
        assert_eq!("/acme/y", rewritten("/users/x%2F..%2Fy"));
        assert_eq!("/acme/y", rewritten("/users/x%5c..%5cy"));
        assert_eq!("/acme/y", rewritten("/users/x/..;a=1/y"));
        assert_eq!("/acme/secret", rewritten("/users/a%2Fb/../../secret"));
        // What has to stay encoded is encoded in what is sent on, and a
        // `?` that was part of the path is not the start of a query.
        assert_eq!("/acme/a%20b", rewritten("/users/a%20b"));
        assert_eq!("/acme/a%3fb?q=1", rewritten("/users/a%3fb?q=1"));
        assert_eq!("/acme/100%25", rewritten("/users/100%25"));
        assert_eq!("/acme/a%20b", rewritten("/%75sers/a%20b"));
        assert_eq!("/acme/a%3Fb?q=1", rewritten("/%75sers/a%3fb?q=1"));
    }

    /// Regression of the fix above: every request the rule matched was
    /// rewritten from the normalized path, which is the path with less in
    /// it. `group%2Fproject` reached the upstream as two segments, a
    /// `;jsessionid` was gone, `https://` in a path had one slash.
    /// A path that hides no `..` is rewritten as it was sent.
    #[test]
    fn test_rewrite_keeps_the_path_as_sent() {
        let location = |rewrite: &str| {
            Location::new(
                "lo",
                &LocationConf {
                    upstream: Some("charts".to_string()),
                    rewrite: Some(rewrite.to_string()),
                    ..Default::default()
                },
            )
            .unwrap()
        };
        let rewritten = |lo: &Location, path: &str| {
            let mut header =
                RequestHeader::build("GET", path.as_bytes(), None).unwrap();
            lo.rewrite(&mut header, &mut None).unwrap();
            header.uri.to_string()
        };

        let strip = location("^/gitlab/(.*)$ /$1");
        for (path, expected) in [
            (
                "/gitlab/api/v4/projects/group%2Fproject",
                "/api/v4/projects/group%2Fproject",
            ),
            ("/gitlab/@scope%2fname", "/@scope%2fname"),
            (
                "/gitlab/login;jsessionid=ABC?next=1",
                "/login;jsessionid=ABC?next=1",
            ),
            ("/gitlab/report%3Bfinal.pdf", "/report%3Bfinal.pdf"),
            (
                "/gitlab/img/https://cdn.example/a.png",
                "/img/https://cdn.example/a.png",
            ),
            ("/gitlab/caf%c3%a9", "/caf%c3%a9"), // spellchecker:disable-line
            // Not when the prefix is spelled so that only the other
            // reading finds it, or when a `..` is in it.
            ("/%67itlab/group%2Fproject", "/group/project"),
            ("/gitlab/a/../group%2Fproject", "/group/project"),
        ] {
            assert_eq!(expected, rewritten(&strip, path), "{path}");
        }

        // A rule written for the spelling itself still finds it.
        let slashes = location("^/files/(.*)%2F(.*)$ /files/$1/$2");
        assert_eq!("/files/a/b", rewritten(&slashes, "/files/a%2Fb"));
        let session = location(";jsessionid=[^/?]*");
        assert_eq!(
            "/app/login?next=1",
            rewritten(&session, "/app/login;jsessionid=ABC?next=1")
        );

        // The two readings of the path give two results: the one of the
        // reading the location was chosen by is sent.
        let split = location("^/users/([^/]+)/(.*)$ /acme/$2?u=$1");
        assert_eq!("/acme/c?u=a", rewritten(&split, "/users/a/c"));
        assert_eq!("/acme/b/c?u=a", rewritten(&split, "/users/a%2Fb/c"));
    }

    /// Regression: a rule whose result is no path was logged, and the
    /// request sent on with the path it came with - past the rewrite.
    #[test]
    fn test_rewrite_that_gives_no_path_fails_the_request() {
        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some("charts".to_string()),
                rewrite: Some("^/bad/(.*)$ /a\u{7f}b/$1".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        let mut header = RequestHeader::build("GET", b"/bad/x", None).unwrap();
        let err = lo.rewrite(&mut header, &mut None).unwrap_err();
        assert_eq!(
            true,
            matches!(err.etype(), pingora::ErrorType::HTTPStatus(500)),
            "{err}"
        );
        assert_eq!("/bad/x", header.uri.path());
        // The rule does not apply: nothing happens.
        let mut header = RequestHeader::build("GET", b"/good/x", None).unwrap();
        assert_eq!(false, lo.rewrite(&mut header, &mut None).unwrap());
    }

    #[test]
    fn test_rewrite_keeps_the_authority() {
        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some("up".to_string()),
                rewrite: Some("^/api/(.*) /$1".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        let mut variables = None;

        let mut h2 = RequestHeader::build("GET", b"/", None).unwrap();
        h2.set_uri(http::Uri::from_static("https://a.test/api/me?abc=1"));
        assert_eq!(true, lo.rewrite(&mut h2, &mut variables).unwrap());
        assert_eq!("https://a.test/me?abc=1", h2.uri.to_string());

        let mut h1 =
            RequestHeader::build("GET", b"/api/me?abc=1", None).unwrap();
        assert_eq!(true, lo.rewrite(&mut h1, &mut variables).unwrap());
        assert_eq!("/me?abc=1", h1.uri.to_string());
    }

    /// Regression: a replacement with a query of its own got the request's
    /// query after a second `?`.
    #[test]
    fn test_rewrite_to_a_path_with_query() {
        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some("up".to_string()),
                rewrite: Some("^/old/(.*) /search?from=old&q=$1".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        let rewritten = |path: &str| {
            let mut header =
                RequestHeader::build("GET", path.as_bytes(), None).unwrap();
            assert_eq!(
                true,
                lo.rewrite(&mut header, &mut None).unwrap(),
                "{path}"
            );
            header.uri.to_string()
        };
        assert_eq!("/search?from=old&q=a", rewritten("/old/a"));
        assert_eq!("/search?from=old&q=a&page=2", rewritten("/old/a?page=2"));
        assert_eq!("/search?from=old&q=a", rewritten("/old/a?"));
    }

    /// The resolved plugin list is shared until the provider reports a new
    /// version, then rebuilt.
    #[test]
    fn test_plugins_for_follows_provider_version() {
        use pingap_core::Plugin;
        use std::sync::atomic::AtomicBool;

        struct NoopPlugin;
        impl Plugin for NoopPlugin {}

        struct Provider {
            version: AtomicU64,
            present: AtomicBool,
        }
        impl PluginProvider for Provider {
            fn get(&self, _name: &str) -> Option<Arc<dyn Plugin>> {
                self.present
                    .load(Ordering::Relaxed)
                    .then(|| Arc::new(NoopPlugin) as Arc<dyn Plugin>)
            }
            fn version(&self) -> u64 {
                self.version.load(Ordering::Relaxed)
            }
        }

        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some("up".to_string()),
                plugins: Some(vec!["a".to_string(), "b".to_string()]),
                ..Default::default()
            },
        )
        .unwrap();
        let provider = Provider {
            version: AtomicU64::new(1),
            present: AtomicBool::new(true),
        };
        let first = lo.plugins_for(&provider).expect("resolved");
        assert_eq!(2, first.len());
        assert_eq!("a", first[0].0.as_ref());

        // Same version: the very same list is handed out again.
        let again = lo.plugins_for(&provider).expect("cached");
        assert_eq!(true, Arc::ptr_eq(&first, &again));

        // The provider changed without saying so: the cache is trusted.
        provider.present.store(false, Ordering::Relaxed);
        assert_eq!(true, lo.plugins_for(&provider).is_some());

        // A new version rebuilds the list. Nothing resolves now, and the
        // names are not dropped: each one is held by a placeholder that
        // fails the request, so the location is never served without them.
        provider.version.store(2, Ordering::Relaxed);
        let missing = lo.plugins_for(&provider).expect("placeholders");
        assert_eq!(2, missing.len());
        assert_eq!("a", missing[0].0.as_ref());
        assert_eq!(false, Arc::ptr_eq(&first, &missing));

        // No plugin names at all: nothing to resolve, nothing cached.
        let bare = Location::new(
            "bare",
            &LocationConf {
                upstream: Some("up".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(true, bare.plugins_for(&provider).is_none());
    }

    /// `$name` in the replacement takes the request variable of that name
    /// (a host capture, a plugin's); `$1` and regex groups are untouched.
    #[test]
    fn test_rewrite_with_variables() {
        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some("charts".to_string()),
                host: Some("~(?<tenant>.+)\\.example\\.com".to_string()),
                rewrite: Some("^/users/(.*)$ /$tenant/$1".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        let (matched, mut variables) =
            lo.match_host_path("acme.example.com", "/users/me");
        assert_eq!(true, matched);
        let mut req_header =
            RequestHeader::build("GET", b"/users/me?x=1", None).unwrap();
        assert_eq!(true, lo.rewrite(&mut req_header, &mut variables).unwrap());
        assert_eq!("/acme/me?x=1", req_header.uri.to_string());

        // Without variables the `$tenant` is left to the regex, which knows
        // no such group and expands it to nothing.
        let mut req_header =
            RequestHeader::build("GET", b"/users/me", None).unwrap();
        assert_eq!(true, lo.rewrite(&mut req_header, &mut None).unwrap());
        assert_eq!("//me", req_header.uri.to_string());

        // A request that does not match the pattern is left alone.
        let mut req_header =
            RequestHeader::build("GET", b"/other?x=1", None).unwrap();
        let mut variables =
            Some(AHashMap::from([("tenant".to_string(), "acme".to_string())]));
        assert_eq!(false, lo.rewrite(&mut req_header, &mut variables).unwrap());
        assert_eq!("/other?x=1", req_header.uri.to_string());
    }

    #[test]
    fn test_interpolate_variables() {
        let vars = AHashMap::from([
            ("tenant".to_string(), "acme".to_string()),
            ("v".to_string(), "2".to_string()),
        ]);
        let interpolate = |template: &str| {
            interpolate_variables(template, &vars).into_owned()
        };
        assert_eq!("/acme/$1", interpolate("/$tenant/$1"));
        assert_eq!("/api/v2/2", interpolate("/api/v$v/$v"));
        // a name that is only a prefix of a longer identifier is not it
        assert_eq!("/$tenants", interpolate("/$tenants"));
        assert_eq!("/$1/$$", interpolate("/$1/$$"));
        assert_eq!("acme", interpolate("$tenant"));
        assert_eq!("$", interpolate("$"));
        assert_eq!(
            true,
            matches!(interpolate_variables("/plain", &vars), Cow::Borrowed(_))
        );
    }

    /// A rewrite that does not parse is an error, not a silently ignored
    /// rule.
    #[test]
    fn test_invalid_rewrite_is_rejected() {
        let build = |rewrite: &str| {
            Location::new(
                "lo",
                &LocationConf {
                    upstream: Some("charts".to_string()),
                    rewrite: Some(rewrite.to_string()),
                    ..Default::default()
                },
            )
            .err()
            .map(|e| e.to_string())
        };
        assert_eq!(
            Some("Regex value: ^/users/(, regex parse error:\n    ^/users/(\n            ^\nerror: unclosed group".to_string()),
            build("^/users/( /")
        );
        assert_eq!(
            Some("Invalid error rewrite \"^/a /b /c\" is invalid, expected \"<regex> <replacement>\"".to_string()),
            build("^/a /b /c")
        );
        // whitespace runs and a blank rule are fine
        assert_eq!(None, build("^/a   /b"));
        assert_eq!(None, build("  "));
    }

    /// A rule whose output equals the input is no rewrite: nothing is set
    /// and no captures are harvested, as before the single-pass version.
    #[test]
    fn test_rewrite_unchanged_path() {
        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some("charts".to_string()),
                rewrite: Some(
                    "^/(?<first>[a-z]+)/(.*)$ /$first/$2".to_string(),
                ),
                ..Default::default()
            },
        )
        .unwrap();
        let mut req_header =
            RequestHeader::build("GET", b"/users/me?x=1", None).unwrap();
        let mut variables = None;
        assert_eq!(false, lo.rewrite(&mut req_header, &mut variables).unwrap());
        assert_eq!(None, variables);
        assert_eq!("/users/me?x=1", req_header.uri.to_string());

        // `$$` is a literal dollar, `$0` the whole match.
        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some("charts".to_string()),
                rewrite: Some("^/old(/.*)$ /new$$$1".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        let mut req_header =
            RequestHeader::build("GET", b"/old/a", None).unwrap();
        assert_eq!(true, lo.rewrite(&mut req_header, &mut None).unwrap());
        assert_eq!("/new$/a", req_header.uri.to_string());
    }

    #[test]
    fn test_rewrite_path_without_named_captures() {
        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some("charts".to_string()),
                rewrite: Some("^/old/(.*)$ /new/$1".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        let mut req_header =
            RequestHeader::build("GET", b"/old/thing?x=1", None).unwrap();
        let mut variables = None;
        let matched = lo.rewrite(&mut req_header, &mut variables).unwrap();
        assert_eq!(true, matched);
        // No named groups -> the second regex pass is skipped, no variables.
        assert_eq!(None, variables);
        assert_eq!("/new/thing?x=1", req_header.uri.to_string());
    }

    /// Regression: `match_query` compared the value of a parameter as it
    /// was sent, so a client that percent-encodes it did not match.
    #[test]
    fn test_match_query_takes_the_value_as_it_is_meant() {
        let location = |conditions: &[&str]| {
            Location::new(
                "lo",
                &LocationConf {
                    upstream: Some("charts".to_string()),
                    path: Some("/".to_string()),
                    match_query: Some(
                        conditions.iter().map(|c| c.to_string()).collect(),
                    ),
                    ..Default::default()
                },
            )
            .unwrap()
        };
        let matches = |lo: &Location, uri: &str| {
            let req =
                RequestHeader::build("GET", uri.as_bytes(), None).unwrap();
            lo.match_conditions(&req)
        };
        let lo = location(&["v:a+b"]);
        assert_eq!(true, matches(&lo, "/?v=a+b"));
        assert_eq!(true, matches(&lo, "/?v=a%2Bb"));
        assert_eq!(true, matches(&lo, "/?x=1&v=a%2bb"));
        // A plus is a plus, and a space is not one.
        assert_eq!(false, matches(&lo, "/?v=a%20b"));
        assert_eq!(false, matches(&lo, "/?v=a%252Bb"));
        assert_eq!(false, matches(&lo, "/?v=a"));
        assert_eq!(false, matches(&lo, "/"));

        // spellchecker:off
        let lo = location(&["path:/a/b", "name:caf\u{e9}", "debug"]);
        assert_eq!(
            true,
            matches(&lo, "/?path=%2Fa%2Fb&name=caf%C3%A9&debug=%31")
        );
        assert_eq!(true, matches(&lo, "/?path=/a/b&name=caf%c3%a9&debug="));
        assert_eq!(
            false,
            matches(&lo, "/?path=%2Fa%2Fc&name=caf%C3%A9&debug=1")
        );
        // What does not decode to text is compared as it came.
        assert_eq!(false, matches(&lo, "/?path=/a/b&name=caf%E9&debug=1"));
        // spellchecker:on

        // A condition written the way the value is sent still holds.
        let lo = location(&["v:a%2Bb"]);
        assert_eq!(true, matches(&lo, "/?v=a%2Bb"));
        assert_eq!(false, matches(&lo, "/?v=a+b"));
    }

    #[test]
    fn test_match_conditions() {
        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some("charts".to_string()),
                path: Some("/".to_string()),
                match_headers: Some(vec![
                    "x-version:2".to_string(),
                    "x-canary".to_string(),
                ]),
                ..Default::default()
            },
        )
        .unwrap();

        // No matching headers -> no match.
        let req = RequestHeader::build("GET", b"/", None).unwrap();
        assert_eq!(false, lo.match_conditions(&req));

        // Only one condition satisfied -> no match.
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("x-version", "2").unwrap();
        assert_eq!(false, lo.match_conditions(&req));

        // Exact value + presence both satisfied -> match.
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("x-version", "2").unwrap();
        req.insert_header("x-canary", "anything").unwrap();
        assert_eq!(true, lo.match_conditions(&req));

        // Wrong value -> no match.
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("x-version", "3").unwrap();
        req.insert_header("x-canary", "y").unwrap();
        assert_eq!(false, lo.match_conditions(&req));

        // A location without conditions matches any request (zero overhead).
        let lo2 = Location::new(
            "lo2",
            &LocationConf {
                upstream: Some("charts".to_string()),
                path: Some("/".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        let req = RequestHeader::build("GET", b"/", None).unwrap();
        assert_eq!(true, lo2.match_conditions(&req));

        // Query-param (exact) and cookie (presence) conditions.
        let lo3 = Location::new(
            "lo3",
            &LocationConf {
                upstream: Some("charts".to_string()),
                path: Some("/".to_string()),
                match_query: Some(vec!["ver:2".to_string()]),
                match_cookies: Some(vec!["session".to_string()]),
                ..Default::default()
            },
        )
        .unwrap();
        // Query value matches and the session cookie is present -> match.
        let mut req = RequestHeader::build("GET", b"/?ver=2", None).unwrap();
        req.insert_header("Cookie", "session=abc").unwrap();
        assert_eq!(true, lo3.match_conditions(&req));
        // Cookie missing -> no match.
        let req = RequestHeader::build("GET", b"/?ver=2", None).unwrap();
        assert_eq!(false, lo3.match_conditions(&req));
        // Wrong query value -> no match.
        let mut req = RequestHeader::build("GET", b"/?ver=3", None).unwrap();
        req.insert_header("Cookie", "session=abc").unwrap();
        assert_eq!(false, lo3.match_conditions(&req));
    }

    #[tokio::test]
    async fn test_get_content_length() {
        let headers = ["Content-Length: 123"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        assert_eq!(get_content_length(session.req_header()), Some(123));
    }

    #[test]
    fn test_validate_content_length() {
        let lo = Location::new(
            "lo",
            &LocationConf {
                client_max_body_size: Some(ByteSize(10)),
                ..Default::default()
            },
        )
        .unwrap();
        let mut req_header =
            RequestHeader::build("GET", b"/users/me?abc=1", None).unwrap();
        assert_eq!(true, lo.validate_content_length(&req_header).is_ok());

        req_header
            .append_header(
                http::header::CONTENT_LENGTH,
                http::HeaderValue::from_str("20").unwrap(),
            )
            .unwrap();
        assert_eq!(
            "Request Entity Too Large, max:10",
            lo.validate_content_length(&req_header)
                .err()
                .unwrap()
                .to_string()
        );
    }
}
