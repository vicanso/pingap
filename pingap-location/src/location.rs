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
use arc_swap::ArcSwap;
use once_cell::sync::Lazy;
use pingap_config::LocationConf;
use pingap_core::{HttpHeader, convert_headers};
use pingora::http::RequestHeader;
use regex::Regex;
use snafu::{ResultExt, Snafu};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use substring::Substring;
use tracing::{debug, error};

const LOG_CATEGORY: &str = "location";

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

#[derive(Debug)]
struct RegexPath {
    value: Regex,
}

#[derive(Debug)]
struct PrefixPath {
    value: String,
}

#[derive(Debug)]
struct EqualPath {
    value: String,
}

// PathSelector enum represents different ways to match request paths:
// - RegexPath: Uses regex pattern matching
// - PrefixPath: Matches if path starts with prefix
// - EqualPath: Matches exact path
// - Empty: Matches all paths
#[derive(Debug)]
enum PathSelector {
    RegexPath(RegexPath),
    PrefixPath(PrefixPath),
    EqualPath(EqualPath),
    Empty,
}
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
fn new_path_selector(path: &str) -> Result<PathSelector> {
    let path = path.trim();
    if path.is_empty() {
        return Ok(PathSelector::Empty);
    }
    let first = path.chars().next().unwrap_or_default();
    let last = path.substring(1, path.len()).trim();
    let se = match first {
        '~' => {
            let re = Regex::new(last).context(RegexSnafu {
                value: last.to_string(),
            })?;
            PathSelector::RegexPath(RegexPath { value: re })
        },
        '=' => PathSelector::EqualPath(EqualPath {
            value: last.to_string(),
        }),
        _ => {
            // trim
            PathSelector::PrefixPath(PrefixPath {
                value: path.to_string(),
            })
        },
    };

    Ok(se)
}

#[derive(Debug)]
struct RegexHost {
    value: RegexCapture,
}

#[derive(Debug)]
struct EqualHost {
    value: String,
}

// HostSelector enum represents ways to match request hosts:
// - RegexHost: Uses regex pattern matching with capture groups
// - EqualHost: Matches exact hostname
#[derive(Debug)]
enum HostSelector {
    RegexHost(RegexHost),
    EqualHost(EqualHost),
}

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
fn new_host_selector(host: &str) -> Result<HostSelector> {
    let host = host.trim();
    if host.is_empty() {
        return Ok(HostSelector::EqualHost(EqualHost {
            value: host.to_string(),
        }));
    }
    let first = host.chars().next().unwrap_or_default();
    let last = host.substring(1, host.len()).trim();
    let se = match first {
        '~' => {
            let re = RegexCapture::new(last).context(RegexSnafu {
                value: last.to_string(),
            })?;
            HostSelector::RegexHost(RegexHost { value: re })
        },
        _ => {
            // trim
            HostSelector::EqualHost(EqualHost {
                value: host.to_string(),
            })
        },
    };

    Ok(se)
}

/// Location represents a routing configuration for handling HTTP requests.
/// It defines rules for matching requests based on paths and hosts, and specifies
/// how these requests should be processed and proxied.
#[derive(Debug)]
pub struct Location {
    /// Unique identifier for this location configuration
    pub name: String,

    /// Hash key used for configuration versioning and change detection
    pub key: String,

    /// Target upstream server where requests will be proxied to
    pub upstream: String,

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

    /// Additional headers to append to proxied requests
    /// These are added without removing existing headers
    pub proxy_add_headers: Option<Vec<HttpHeader>>,

    /// Headers to set on proxied requests
    /// These override any existing headers with the same name
    pub proxy_set_headers: Option<Vec<HttpHeader>>,

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
    pub enable_reverse_proxy_headers: bool,
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
            let arr: Vec<&str> = value.split(' ').collect();
            let value = if arr.len() == 2 { arr[1] } else { "" };
            if let Ok(re) = Regex::new(arr[0]) {
                reg_rewrite = Some((re, value.to_string()));
            }
        }
        let mut hosts = vec![];
        for item in conf.host.clone().unwrap_or_default().split(',') {
            let host = item.trim().to_string();
            if host.is_empty() {
                continue;
            }
            hosts.push(new_host_selector(&host)?);
        }

        let path = conf.path.clone().unwrap_or_default();

        let location = Location {
            name: name.to_string(),
            key,
            path_selector: new_path_selector(&path)?,
            path,
            hosts,
            upstream,
            reg_rewrite,
            plugins: conf.plugins.clone(),
            accepted: AtomicU64::new(0),
            processing: AtomicI32::new(0),
            max_processing: conf.max_processing.unwrap_or_default(),
            grpc_web: conf.grpc_web.unwrap_or_default(),
            proxy_add_headers: format_headers(&conf.proxy_add_headers)?,
            proxy_set_headers: format_headers(&conf.proxy_set_headers)?,
            client_max_body_size: conf
                .client_max_body_size
                .unwrap_or_default()
                .as_u64() as usize,
            enable_reverse_proxy_headers: conf
                .enable_reverse_proxy_headers
                .unwrap_or_default(),
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

    /// Sets the maximum allowed size of the client request body.
    /// If the size in a request exceeds the configured value, the 413 (Request Entity Too Large) error
    /// is returned to the client.
    #[inline]
    pub fn client_body_size_limit(&self, payload_size: usize) -> Result<()> {
        if self.client_max_body_size == 0 {
            return Ok(());
        }
        if payload_size > self.client_max_body_size {
            return Err(Error::BodyTooLarge {
                max: self.client_max_body_size,
            });
        }
        Ok(())
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
    #[inline]
    pub fn add_processing(&self) -> Result<(u64, i32)> {
        let accepted = self.accepted.fetch_add(1, Ordering::Relaxed) + 1;
        let processing = self.processing.fetch_add(1, Ordering::Relaxed) + 1;
        if self.max_processing != 0 && processing > self.max_processing {
            return Err(Error::TooManyRequest {
                max: self.max_processing,
            });
        }
        Ok((accepted, processing))
    }

    /// Decrements the processing request counter for this location.
    ///
    /// This method is called when a request finishes being processed.
    /// It performs an atomic decrement of the currently processing requests counter.
    #[inline]
    pub fn sub_processing(&self) {
        self.processing.fetch_sub(1, Ordering::Relaxed);
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
    ) -> (bool, Option<Vec<(String, String)>>) {
        // First check path matching if a path pattern is configured
        if !self.path.is_empty() {
            let matched = match &self.path_selector {
                // For exact path matching, compare path strings directly
                PathSelector::EqualPath(EqualPath { value }) => value == path,
                // For regex path matching, use regex is_match
                PathSelector::RegexPath(RegexPath { value }) => {
                    value.is_match(path)
                },
                // For prefix path matching, check if path starts with prefix
                PathSelector::PrefixPath(PrefixPath { value }) => {
                    path.starts_with(value)
                },
                // Empty path selector matches everything
                PathSelector::Empty => true,
            };
            // If path doesn't match, return false early
            if !matched {
                return (false, None);
            }
        }

        // If no host patterns configured, path match is sufficient
        if self.hosts.is_empty() {
            return (true, None);
        }

        // Check host matching against configured host patterns
        let mut variables = None;
        let matched = self.hosts.iter().any(|item| match item {
            // For regex host matching:
            // - Attempt to capture variables from host string
            // - Store captures in variables if match successful
            HostSelector::RegexHost(RegexHost { value }) => {
                let (matched, value) = value.captures(host);
                if matched {
                    variables = value;
                }
                matched
            },
            // For exact host matching:
            // - Empty host pattern matches everything
            // - Otherwise compare host strings directly
            HostSelector::EqualHost(EqualHost { value }) => {
                if value.is_empty() {
                    return true;
                }
                value == host
            },
        });

        // Return whether both path and host matched, along with any captured variables
        (matched, variables)
    }

    /// Applies URL rewriting rules if configured for this location.
    ///
    /// This method performs path rewriting based on regex patterns and replacement rules.
    /// It supports variable interpolation from captured values in the host matching.
    ///
    /// # Arguments
    /// * `header` - Mutable reference to the request header containing the URI to rewrite
    /// * `variables` - Optional map of variables captured from host matching that can be interpolated
    ///                into the replacement value
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
    pub fn rewrite(
        &self,
        header: &mut RequestHeader,
        variables: Option<&AHashMap<String, String>>,
    ) -> bool {
        if let Some((re, value)) = &self.reg_rewrite {
            let mut replace_value = value.to_string();
            // replace variables for rewrite value
            if let Some(variables) = variables {
                for (k, v) in variables.iter() {
                    replace_value = replace_value.replace(k, v);
                }
            }
            let path = header.uri.path();
            let mut new_path = re.replace(path, replace_value).to_string();
            if path == new_path {
                return false;
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
                error!(category = LOG_CATEGORY, error = %e, location = self.name, "new path parse fail");
            }
            return true;
        }
        false
    }
}

type Locations = AHashMap<String, Arc<Location>>;
static LOCATION_MAP: Lazy<ArcSwap<Locations>> =
    Lazy::new(|| ArcSwap::from_pointee(AHashMap::new()));

/// Gets a location configuration by name from the global location map.
///
/// # Arguments
/// * `name` - Name of the location to retrieve
///
/// # Returns
/// * `Option<Arc<Location>>` - The location if found, None otherwise
pub fn get_location(name: &str) -> Option<Arc<Location>> {
    if name.is_empty() {
        return None;
    }
    LOCATION_MAP.load().get(name).cloned()
}

/// Gets a map of current request processing counts for all locations.
///
/// # Returns
/// * `HashMap<String, i32>` - Map of location names to their current processing counts
pub fn get_locations_processing() -> HashMap<String, i32> {
    let mut processing = HashMap::new();
    LOCATION_MAP.load().iter().for_each(|(k, v)| {
        processing.insert(k.to_string(), v.processing.load(Ordering::Relaxed));
    });
    processing
}

/// Initializes or updates the global location configurations
/// Returns list of location names that were updated
pub fn try_init_locations(
    location_configs: &HashMap<String, LocationConf>,
) -> Result<Vec<String>> {
    let mut locations = AHashMap::new();
    let mut updated_locations = vec![];
    for (name, conf) in location_configs.iter() {
        if let Some(found) = get_location(name) {
            if found.key == conf.hash_key() {
                locations.insert(name.to_string(), found);
                continue;
            }
        }
        updated_locations.push(name.clone());
        let lo = Location::new(name, conf)?;
        locations.insert(name.to_string(), Arc::new(lo));
    }
    LOCATION_MAP.store(Arc::new(locations));
    Ok(updated_locations)
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
        let selector = new_path_selector("").unwrap();
        assert_eq!(true, matches!(selector, PathSelector::Empty));

        let selector = new_path_selector("~/api").unwrap();
        assert_eq!(true, matches!(selector, PathSelector::RegexPath(_)));

        let selector = new_path_selector("=/api").unwrap();
        assert_eq!(true, matches!(selector, PathSelector::EqualPath(_)));

        let selector = new_path_selector("/api").unwrap();
        assert_eq!(true, matches!(selector, PathSelector::PrefixPath(_)));
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
    fn test_rewrite_path() {
        let upstream_name = "charts";

        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some(upstream_name.to_string()),
                rewrite: Some("^/users/(.*)$ /$1".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        let mut req_header =
            RequestHeader::build("GET", b"/users/me?abc=1", None).unwrap();
        assert_eq!(true, lo.rewrite(&mut req_header, None));
        assert_eq!("/me?abc=1", req_header.uri.to_string());

        let mut req_header =
            RequestHeader::build("GET", b"/api/me?abc=1", None).unwrap();
        assert_eq!(false, lo.rewrite(&mut req_header, None));
        assert_eq!("/api/me?abc=1", req_header.uri.to_string());
    }

    #[test]
    fn test_client_body_size_limit() {
        let upstream_name = "charts";

        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some(upstream_name.to_string()),
                rewrite: Some("^/users/(.*)$ /$1".to_string()),
                plugins: Some(vec!["test:mock".to_string()]),
                client_max_body_size: Some(ByteSize(10)),
                ..Default::default()
            },
        )
        .unwrap();

        let result = lo.client_body_size_limit(2);
        assert_eq!(true, result.is_ok());

        let result = lo.client_body_size_limit(20);
        assert_eq!(
            "Request Entity Too Large, max:10",
            result.err().unwrap().to_string()
        );
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
    fn test_location_processing() {
        let lo = Location::new(
            "lo",
            &LocationConf {
                ..Default::default()
            },
        )
        .unwrap();
        let value = lo.add_processing().unwrap();
        assert_eq!(1, value.0);
        assert_eq!(1, value.1);

        lo.sub_processing();
        assert_eq!(1, lo.accepted.load(Ordering::Relaxed));
        assert_eq!(0, lo.processing.load(Ordering::Relaxed));
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
