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
use http::HeaderName;
use http::HeaderValue;
use pingap_config::Hashable;
use pingap_config::LocationConf;
use pingap_core::new_internal_error;
use pingap_core::LocationInstance;
use pingap_core::{convert_headers, HttpHeader};
use pingora::http::RequestHeader;
use regex::Regex;
use snafu::{ResultExt, Snafu};
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::Duration;
use tracing::{debug, error};

const LOG_CATEGORY: &str = "location";

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
            Ok(PathSelector::Equal(eq_path.trim().to_string()))
        } else {
            Ok(PathSelector::Prefix(path.to_string()))
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
#[derive(Debug)]
enum HostSelector {
    Regex(RegexCapture),
    Equal(String),
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
    /// - Otherwise: Exact hostname matching
    fn new(host: &str) -> Result<Self> {
        let host = host.trim();
        if let Some(re_host) = host.strip_prefix('~') {
            let re = RegexCapture::new(re_host.trim()).context(RegexSnafu {
                value: re_host.trim(),
            })?;
            Ok(HostSelector::Regex(re))
        } else {
            Ok(HostSelector::Equal(host.to_string()))
        }
    }
    #[inline]
    fn is_match(&self, host: &str) -> (bool, Option<AHashMap<String, String>>) {
        match self {
            HostSelector::Equal(value) => (value == host, None),
            HostSelector::Regex(value) => value.captures(host),
        }
    }
}

// proxy_set_header X-Real-IP $remote_addr;
// proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
// proxy_set_header X-Forwarded-Proto $scheme;
// proxy_set_header X-Forwarded-Host $host;
// proxy_set_header X-Forwarded-Port $server_port;
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

    /// Original path pattern string used for matching requests
    path: String,

    /// Compiled path matching rules (regex, prefix, or exact match)
    path_selector: PathSelector,

    /// List of host patterns to match against request Host header
    /// Empty list means match all hosts
    hosts: Vec<HostSelector>,

    /// Optional URL rewriting rule consisting of:
    /// - regex pattern to match against request path
    /// - replacement string with optional capture group references
    reg_rewrite: Option<(Regex, String)>,

    /// Headers to set or append on proxied requests
    pub headers: Option<Vec<(HeaderName, HeaderValue, bool)>>,

    /// Additional headers to append to proxied requests
    /// These are added without removing existing headers
    // pub proxy_add_headers: Option<Vec<HttpHeader>>,

    /// Headers to set on proxied requests
    /// These override any existing headers with the same name
    // pub proxy_set_headers: Option<Vec<HttpHeader>>,

    /// Ordered list of plugin names to execute during request/response processing
    pub plugins: Option<Vec<String>>,

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
    {
        if let Ok(size) =
            content_length.to_str().unwrap_or_default().parse::<usize>()
        {
            return Some(size);
        }
    }
    None
}

impl Location {
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
        let mut reg_rewrite = None;
        // rewrite: "^/users/(.*)$ /api/users/$1"
        if let Some(value) = &conf.rewrite {
            let mut arr: Vec<&str> = value.split(' ').collect();
            if arr.len() == 1 && arr[0].contains("$") {
                arr.push(arr[0]);
                arr[0] = ".*";
            }

            let value = if arr.len() == 2 { arr[1] } else { "" };
            if let Ok(re) = Regex::new(arr[0]) {
                reg_rewrite = Some((re, value.to_string()));
            }
        }

        let hosts = conf
            .host
            .as_deref()
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(HostSelector::new)
            .collect::<Result<Vec<_>>>()?;

        let path = conf.path.clone().unwrap_or_default();
        let mut headers: Vec<(HeaderName, HeaderValue, bool)> = vec![];
        if conf.enable_reverse_proxy_headers.unwrap_or_default() {
            for (name, value) in DEFAULT_PROXY_SET_HEADERS.iter() {
                headers.push((name.clone(), value.clone(), false));
            }
        }
        if let Some(proxy_set_headers) =
            format_headers(&conf.proxy_set_headers)?
        {
            for (name, value) in proxy_set_headers.iter() {
                headers.push((name.clone(), value.clone(), false));
            }
        }
        if let Some(proxy_add_headers) =
            format_headers(&conf.proxy_add_headers)?
        {
            for (name, value) in proxy_add_headers.iter() {
                headers.push((name.clone(), value.clone(), true));
            }
        }

        let location = Location {
            name: name.into(),
            key,
            path_selector: PathSelector::new(&path)?,
            path,
            hosts,
            upstream,
            reg_rewrite,
            plugins: conf.plugins.clone(),
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
        };
        debug!(
            category = LOG_CATEGORY,
            location = format!("{location:?}"),
            "create a new location"
        );

        Ok(location)
    }

    /// Returns whether gRPC-Web protocol support is enabled for this location
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
        // Check host matching against configured host patterns
        // let mut variables: Vec<(String, String)> = vec![];

        // First check path matching if a path pattern is configured
        let mut capture_values = None;
        if !self.path.is_empty() {
            let (matched, captures) = self.path_selector.is_match(path);
            if !matched {
                return (false, None);
            }
            capture_values = captures;
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
    fn headers(&self) -> Option<&Vec<(HeaderName, HeaderValue, bool)>> {
        self.headers.as_ref()
    }
    fn client_body_size_limit(&self) -> usize {
        self.client_max_body_size
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
        mut variables: Option<AHashMap<String, String>>,
    ) -> (bool, Option<AHashMap<String, String>>) {
        let Some((re, value)) = &self.reg_rewrite else {
            return (false, variables);
        };

        let mut replace_value = value.to_string();

        if let Some(vars) = &variables {
            for (k, v) in vars.iter() {
                replace_value = replace_value.replace(k, v);
            }
        }

        let path = header.uri.path();

        let mut new_path = if re.to_string() == ".*" {
            replace_value
        } else {
            re.replace(path, replace_value).to_string()
        };

        if path == new_path {
            return (false, variables);
        }

        if let Some(captures) = re.captures(path) {
            for name in re.capture_names().flatten() {
                if let Some(match_value) = captures.name(name) {
                    let values = variables.get_or_insert_with(AHashMap::new);
                    values.insert(
                        name.to_string(),
                        match_value.as_str().to_string(),
                    );
                }
            }
        }

        // preserve query parameters
        if let Some(query) = header.uri.query() {
            new_path = format!("{new_path}?{query}");
        }
        debug!(category = LOG_CATEGORY, new_path, "rewrite path");

        // set new uri
        if let Err(e) =
            new_path.parse::<http::Uri>().map(|uri| header.set_uri(uri))
        {
            error!(category = LOG_CATEGORY, error = %e, location = self.name.as_ref(), "new path parse fail");
        }

        (true, variables)
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
        assert_eq!(true, lo.match_host_path("pingap", "").0);
        assert_eq!(false, lo.match_host_path("", "/api").0);

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
        let (matched, variables) = lo.rewrite(&mut req_header, None);
        assert_eq!(true, matched);
        assert_eq!(r#"Some({"upstream": "rest"})"#, format!("{:?}", variables));
        assert_eq!("/me?abc=1", req_header.uri.to_string());

        let mut req_header =
            RequestHeader::build("GET", b"/api/me?abc=1", None).unwrap();
        let (matched, variables) = lo.rewrite(&mut req_header, None);
        assert_eq!(false, matched);
        assert_eq!(None, variables);
        assert_eq!("/api/me?abc=1", req_header.uri.to_string());
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
