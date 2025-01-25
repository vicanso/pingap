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

use crate::config::{LocationConf, PluginStep};
use crate::http_extra::{convert_header_value, convert_headers, HttpHeader};
use crate::plugin::get_plugin;
use crate::state::State;
use crate::util::{self, get_content_length};
use ahash::AHashMap;
use arc_swap::ArcSwap;
use http::{HeaderName, HeaderValue};
use once_cell::sync::Lazy;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::proxy::Session;
use regex::Regex;
use snafu::{ResultExt, Snafu};
use std::collections::HashMap;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::Arc;
use substring::Substring;
use tracing::{debug, error};

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
                value: path.trim().to_string(),
            })
        },
    };

    Ok(se)
}

#[derive(Debug)]
struct RegexHost {
    value: util::RegexCapture,
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
            let re = util::RegexCapture::new(last).context(RegexSnafu {
                value: last.to_string(),
            })?;
            HostSelector::RegexHost(RegexHost { value: re })
        },
        _ => {
            // trim
            HostSelector::EqualHost(EqualHost {
                value: host.trim().to_string(),
            })
        },
    };

    Ok(se)
}

// proxy_set_header X-Real-IP $remote_addr;
// proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
// proxy_set_header X-Forwarded-Proto $scheme;
// proxy_set_header X-Forwarded-Host $host;
// proxy_set_header X-Forwarded-Port $server_port;

static DEFAULT_PROXY_SET_HEADERS: Lazy<Vec<HttpHeader>> = Lazy::new(|| {
    convert_headers(&[
        "X-Real-IP:$remote_addr".to_string(),
        "X-Forwarded-For:$proxy_add_x_forwarded_for".to_string(),
        "X-Forwarded-Proto:$scheme".to_string(),
        "X-Forwarded-Host:$host".to_string(),
        "X-Forwarded-Port:$server_port".to_string(),
    ])
    .unwrap()
});

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
    proxy_add_headers: Option<Vec<HttpHeader>>,

    /// Headers to set on proxied requests
    /// These override any existing headers with the same name
    proxy_set_headers: Option<Vec<HttpHeader>>,

    /// Ordered list of plugin names to execute during request/response processing
    plugins: Option<Vec<String>>,

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
    enable_reverse_proxy_headers: bool,
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
        debug!("create a new location, {location:?}");

        Ok(location)
    }
    #[inline]
    pub fn enable_grpc(&self) -> bool {
        self.grpc_web
    }
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
    /// Add processing and accepted count of location.
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
    /// Sub processing count of location.
    #[inline]
    pub fn sub_processing(&self) {
        self.processing.fetch_sub(1, Ordering::Relaxed);
    }
    /// Checks if a request matches this location's path and host rules
    /// Returns (matched, variables) where variables contains any regex captures
    #[inline]
    pub fn matched(
        &self,
        host: &str,
        path: &str,
    ) -> (bool, Option<Vec<(String, String)>>) {
        if !self.path.is_empty() {
            let matched = match &self.path_selector {
                PathSelector::EqualPath(EqualPath { value }) => value == path,
                PathSelector::RegexPath(RegexPath { value }) => {
                    value.is_match(path)
                },
                PathSelector::PrefixPath(PrefixPath { value }) => {
                    path.starts_with(value)
                },
                PathSelector::Empty => true,
            };
            if !matched {
                return (false, None);
            }
        }

        if self.hosts.is_empty() {
            return (true, None);
        }

        let mut variables = None;
        let matched = self.hosts.iter().any(|item| match item {
            HostSelector::RegexHost(RegexHost { value }) => {
                let (matched, value) = value.captures(host);
                if matched {
                    variables = value;
                }
                matched
            },
            HostSelector::EqualHost(EqualHost { value }) => value == host,
        });
        (matched, variables)
    }
    /// Sets the maximum allowed size of the client request body.
    /// If the size in a request exceeds the configured value, the 413 (Request Entity Too Large) error
    /// is returned to the client.
    #[inline]
    pub fn client_body_size_limit(&self, ctx: &State) -> Result<()> {
        if self.client_max_body_size == 0 {
            return Ok(());
        }
        if ctx.payload_size > self.client_max_body_size {
            return Err(Error::BodyTooLarge {
                max: self.client_max_body_size,
            });
        }
        Ok(())
    }
    /// Applies URL rewriting rules if configured
    /// Returns true if rewriting was performed
    #[inline]
    pub fn rewrite(
        &self,
        header: &mut RequestHeader,
        variables: Option<&AHashMap<String, String>>,
    ) -> bool {
        if let Some((re, value)) = &self.reg_rewrite {
            let mut replae_value = value.to_string();
            if let Some(variables) = variables {
                for (k, v) in variables.iter() {
                    replae_value = replae_value.replace(k, v);
                }
            }
            let path = header.uri.path();
            let mut new_path = re.replace(path, replae_value).to_string();
            if path == new_path {
                return false;
            }
            if let Some(query) = header.uri.query() {
                new_path = format!("{new_path}?{query}");
            }
            debug!(new_path, "rewrite path");
            if let Err(e) =
                new_path.parse::<http::Uri>().map(|uri| header.set_uri(uri))
            {
                error!(
                    error = e.to_string(),
                    location = self.name,
                    "new path parse fail"
                );
            }
            return true;
        }
        false
    }
    /// Sets or appends proxy-related headers before forwarding request
    /// Handles both default reverse proxy headers and custom configured headers
    #[inline]
    pub fn set_append_proxy_headers(
        &self,
        session: &Session,
        ctx: &State,
        header: &mut RequestHeader,
    ) {
        // Helper closure to avoid code duplication
        let mut set_header = |k: &HeaderName, v: &HeaderValue, append: bool| {
            let value = convert_header_value(v, session, ctx)
                .unwrap_or_else(|| v.clone());
            // v validate for HeaderValue, so always no error
            if append {
                let _ = header.append_header(k, value);
            } else {
                let _ = header.insert_header(k, value);
            };
        };

        // Set default reverse proxy headers if enabled
        if self.enable_reverse_proxy_headers {
            DEFAULT_PROXY_SET_HEADERS
                .iter()
                .for_each(|(k, v)| set_header(k, v, false));
        }

        // Set custom proxy headers
        if let Some(arr) = &self.proxy_set_headers {
            arr.iter().for_each(|(k, v)| set_header(k, v, false));
        }

        // Append custom proxy headers
        if let Some(arr) = &self.proxy_add_headers {
            arr.iter().for_each(|(k, v)| set_header(k, v, true));
        }
    }
    /// Executes request plugins in the configured chain
    /// Returns true if a plugin handled the request completely
    #[inline]
    pub async fn handle_request_plugin(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut State,
    ) -> pingora::Result<bool> {
        let Some(plugins) = self.plugins.as_ref() else {
            return Ok(false);
        };

        for name in plugins.iter() {
            if let Some(plugin) = get_plugin(name) {
                debug!(name, step = step.to_string(), "handle request plugin");
                let result = plugin.handle_request(step, session, ctx).await?;
                if let Some(resp) = result {
                    // ignore http response status >= 900
                    if resp.status.as_u16() < 900 {
                        ctx.status = Some(resp.status);
                        resp.send(session).await?;
                    }
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
    /// Run response plugins,
    #[inline]
    pub async fn handle_response_plugin(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut State,
        upstream_response: &mut ResponseHeader,
    ) -> pingora::Result<()> {
        let Some(plugins) = self.plugins.as_ref() else {
            return Ok(());
        };
        for name in plugins.iter() {
            if let Some(plugin) = get_plugin(name) {
                debug!(name, step = step.to_string(), "handle response plugin");
                plugin
                    .handle_response(step, session, ctx, upstream_response)
                    .await?;
            }
        }
        Ok(())
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
    confs: &HashMap<String, LocationConf>,
) -> Result<Vec<String>> {
    let mut locations = AHashMap::new();
    let mut updated_locations = vec![];
    for (name, conf) in confs.iter() {
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
    use super::{
        format_headers, new_path_selector, Location, PathSelector,
        DEFAULT_PROXY_SET_HEADERS,
    };
    use crate::config::{LocationConf, PluginStep};
    use crate::http_extra::convert_header_value;
    use crate::plugin::initialize_test_plugins;
    use crate::state::State;
    use bytesize::ByteSize;
    use http::Method;
    use pingora::http::{RequestHeader, ResponseHeader};
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    #[tokio::test]
    async fn test_set_reverse_proxy_headers() {
        let headers = [
            "X-Forwarded-For:192.168.1.1".to_string(),
            "Host: pingap.io".to_string(),
        ]
        .join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let ctx = State {
            remote_addr: Some("1.1.1.1".to_string()),
            server_port: Some(443),
            tls_version: Some("TLSv1.3".to_string()),
            ..Default::default()
        };
        let mut values = vec![];
        DEFAULT_PROXY_SET_HEADERS.iter().for_each(|(k, v)| {
            if let Some(value) = convert_header_value(v, &session, &ctx) {
                values.push(format!("{k}:{}", value.to_str().unwrap()));
            }
        });
        assert_eq!(
            r###"["x-real-ip:1.1.1.1", "x-forwarded-for:192.168.1.1, 1.1.1.1", "x-forwarded-proto:https", "x-forwarded-host:pingap.io", "x-forwarded-port:443"]"###,
            format!("{values:?}")
        );
    }

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
        assert_eq!(true, lo.matched("pingap", "/api").0);
        assert_eq!(true, lo.matched("", "").0);

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
        assert_eq!(true, lo.matched("pingap", "/api").0);
        assert_eq!(true, lo.matched("pingap", "").0);
        assert_eq!(false, lo.matched("", "/api").0);

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
        assert_eq!(true, lo.matched("", "/api/users").0);
        assert_eq!(true, lo.matched("", "/users").0);
        assert_eq!(false, lo.matched("", "/api").0);

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
        assert_eq!(true, lo.matched("", "/api/users").0);
        assert_eq!(false, lo.matched("", "/users").0);
        assert_eq!(true, lo.matched("", "/api").0);

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
        assert_eq!(true, lo.matched("", "/api/users").0);
        assert_eq!(false, lo.matched("", "/users").0);
        assert_eq!(true, lo.matched("", "/api").0);

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
        assert_eq!(false, lo.matched("", "/api/users").0);
        assert_eq!(false, lo.matched("", "/users").0);
        assert_eq!(true, lo.matched("", "/api").0);
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

    #[tokio::test]
    async fn test_insert_header() {
        let upstream_name = "charts";

        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some(upstream_name.to_string()),
                rewrite: Some("^/users/(.*)$ /$1".to_string()),
                proxy_set_headers: Some(vec![
                    "Cache-Control: no-store".to_string()
                ]),
                proxy_add_headers: Some(vec!["X-User: pingap".to_string()]),
                ..Default::default()
            },
        )
        .unwrap();

        let headers = [""].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let mut req_header =
            RequestHeader::build_no_case(Method::GET, b"", None).unwrap();
        lo.set_append_proxy_headers(
            &session,
            &State::default(),
            &mut req_header,
        );
        assert_eq!(
            r###"RequestHeader { base: Parts { method: GET, uri: , version: HTTP/1.1, headers: {"cache-control": "no-store", "x-user": "pingap"} }, header_name_map: None, raw_path_fallback: [], send_end_stream: true }"###,
            format!("{req_header:?}")
        );
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

        let result = lo.client_body_size_limit(&State {
            payload_size: 2,
            ..Default::default()
        });
        assert_eq!(true, result.is_ok());

        let result = lo.client_body_size_limit(&State {
            payload_size: 20,
            ..Default::default()
        });
        assert_eq!(
            "Request Entity Too Large, max:10",
            result.err().unwrap().to_string()
        );
    }

    #[tokio::test]
    async fn test_exec_proxy_plugins() {
        initialize_test_plugins();
        let upstream_name = "charts";

        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some(upstream_name.to_string()),
                rewrite: Some("^/users/(.*)$ /$1".to_string()),
                plugins: Some(vec!["test:mock".to_string()]),
                ..Default::default()
            },
        )
        .unwrap();

        let headers = [""].join("\r\n");
        let input_header = format!("GET /mock HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = lo
            .handle_request_plugin(
                PluginStep::Request,
                &mut session,
                &mut State {
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(true, result);

        let headers = [""].join("\r\n");
        let input_header = format!("GET /stats HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let result = lo
            .handle_request_plugin(
                PluginStep::Request,
                &mut session,
                &mut State::default(),
            )
            .await
            .unwrap();
        assert_eq!(false, result);
    }

    #[tokio::test]
    async fn test_exec_response_plugins() {
        initialize_test_plugins();
        let upstream_name = "charts";

        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some(upstream_name.to_string()),
                rewrite: Some("^/users/(.*)$ /$1".to_string()),
                plugins: Some(vec!["test:add_headers".to_string()]),
                ..Default::default()
            },
        )
        .unwrap();

        let headers = [""].join("\r\n");
        let input_header = format!("GET /mock HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let mut upstream_response =
            ResponseHeader::build(200, Some(4)).unwrap();
        upstream_response
            .append_header("Content-Type", "application/json")
            .unwrap();
        upstream_response.append_header("X-Server", "abc").unwrap();

        lo.handle_response_plugin(
            PluginStep::Response,
            &mut session,
            &mut State::default(),
            &mut upstream_response,
        )
        .await
        .unwrap();

        assert_eq!(
            r###"{"x-service": "1", "x-service": "2", "x-server": "abc", "x-response-id": "123"}"###,
            format!("{:?}", upstream_response.headers)
        );
    }
}
