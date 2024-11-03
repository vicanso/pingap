// Copyright 2024 Tree xie.
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
use crate::util;
use ahash::AHashMap;
use arc_swap::ArcSwap;
use once_cell::sync::Lazy;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::proxy::Session;
use regex::Regex;
use snafu::{ResultExt, Snafu};
use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicI32, AtomicU64};
use std::sync::Arc;
use substring::Substring;
use tracing::{debug, error};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Invalid error {message}"))]
    Invalid { message: String },
    #[snafu(display("Regex value: {value}, {source}"))]
    Regex { value: String, source: regex::Error },
}
type Result<T, E = Error> = std::result::Result<T, E>;

struct RegexPath {
    value: Regex,
}
struct PrefixPath {
    value: String,
}
struct EqualPath {
    value: String,
}

enum PathSelector {
    RegexPath(RegexPath),
    PrefixPath(PrefixPath),
    EqualPath(EqualPath),
    Empty,
}
/// New a path selector, regex, prefix or equal selector
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
    value: Regex,
}

#[derive(Debug)]
struct EqualHost {
    value: String,
}

#[derive(Debug)]
enum HostSelector {
    RegexHost(RegexHost),
    EqualHost(EqualHost),
}

/// New a host selector, regex or  equal selector
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
            let re = Regex::new(last).context(RegexSnafu {
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

pub struct Location {
    pub name: String,
    pub key: String,
    path: String,
    path_selector: PathSelector,
    hosts: Vec<HostSelector>,
    reg_rewrite: Option<(Regex, String)>,
    proxy_add_headers: Option<Vec<HttpHeader>>,
    proxy_set_headers: Option<Vec<HttpHeader>>,
    plugins: Option<Vec<String>>,
    pub accepted: AtomicU64,
    pub processing: AtomicI32,
    pub upstream: String,
    client_max_body_size: usize,
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "name:{} ", self.name)?;
        write!(f, "path:{} ", self.path)?;
        write!(f, "hosts:{:?} ", self.hosts)?;
        write!(f, "reg_rewrite:{:?} ", self.reg_rewrite)?;
        write!(f, "proxy_set_headers:{:?} ", self.proxy_set_headers)?;
        write!(f, "proxy_add_headers:{:?} ", self.proxy_add_headers)?;
        write!(f, "plugins:{:?} ", self.plugins)?;
        write!(f, "upstream:{}", self.upstream)
    }
}

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
    /// Create a location from config.
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
        // sort hosts regexp --> equal
        hosts.sort_by_key(|host| match host {
            HostSelector::RegexHost(RegexHost { value }) => {
                1000 + value.to_string().len()
            },
            HostSelector::EqualHost(EqualHost { value }) => value.len(),
        });
        hosts.reverse();

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
            proxy_add_headers: format_headers(&conf.proxy_add_headers)?,
            proxy_set_headers: format_headers(&conf.proxy_set_headers)?,
            client_max_body_size: conf
                .client_max_body_size
                .unwrap_or_default()
                .as_u64() as usize,
        };
        debug!(location = location.to_string(), "create a new location");

        Ok(location)
    }
    /// Return `true` if the host and path match location.
    #[inline]
    pub fn matched(&self, host: &str, path: &str) -> bool {
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
                return false;
            }
        }

        if self.hosts.is_empty() {
            return true;
        }

        self.hosts.iter().any(|item| match item {
            HostSelector::RegexHost(RegexHost { value }) => {
                let (matched, _) =
                    util::regex_capture(value, host).unwrap_or_default();
                matched
            },
            HostSelector::EqualHost(EqualHost { value }) => value == host,
        })
    }
    /// Sets the maximum allowed size of the client request body.
    /// If the size in a request exceeds the configured value, the 413 (Request Entity Too Large) error
    /// is returned to the client.
    #[inline]
    pub fn client_body_size_limit(
        &self,
        header: Option<&RequestHeader>,
        ctx: &State,
    ) -> pingora::Result<()> {
        if self.client_max_body_size == 0 {
            return Ok(());
        }
        if let Some(header) = header {
            if util::get_content_length(header).unwrap_or_default()
                > self.client_max_body_size
            {
                return Err(util::new_internal_error(
                    413,
                    "Request Entity Too Large".to_string(),
                ));
            }
        }
        if ctx.payload_size > self.client_max_body_size {
            return Err(util::new_internal_error(
                413,
                "Request Entity Too Large".to_string(),
            ));
        }
        Ok(())
    }
    /// Rewrite the path by the rule and returns true.
    /// If the rule is not exists, returns false.
    #[inline]
    pub fn rewrite(&self, header: &mut RequestHeader) -> bool {
        if let Some((re, value)) = &self.reg_rewrite {
            let path = header.uri.path();
            let mut new_path = re.replace(path, value).to_string();
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
    /// Set or append the headers before proxy the request to upstream.
    #[inline]
    pub fn set_append_proxy_headers(
        &self,
        session: &Session,
        ctx: &State,
        header: &mut RequestHeader,
    ) {
        if let Some(arr) = &self.proxy_set_headers {
            for (k, v) in arr {
                if let Some(v) = convert_header_value(v, session, ctx) {
                    // v validate for HeaderValue, so always no error
                    let _ = header.insert_header(k, v);
                } else {
                    // v validate for HeaderValue, so always no error
                    let _ = header.insert_header(k, v);
                }
            }
        }
        if let Some(arr) = &self.proxy_add_headers {
            for (k, v) in arr {
                if let Some(v) = convert_header_value(v, session, ctx) {
                    // v validate for HeaderValue, so always no error
                    let _ = header.append_header(k, v);
                } else {
                    // v validate for HeaderValue, so always no error
                    let _ = header.append_header(k, v);
                }
            }
        }
    }
    /// Run request plugins, if return Ok(true), the request will be done.
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
                    // ingore http response status >= 900
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

pub fn get_location(name: &str) -> Option<Arc<Location>> {
    if name.is_empty() {
        return None;
    }
    LOCATION_MAP.load().get(name).cloned()
}

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
    use super::{format_headers, new_path_selector, Location, PathSelector};
    use crate::config::{LocationConf, PluginStep};
    use crate::plugin::initialize_test_plugins;
    use crate::state::State;
    use bytesize::ByteSize;
    use http::Method;
    use pingora::http::{RequestHeader, ResponseHeader};
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
        assert_eq!(true, lo.matched("pingap", "/api"));
        assert_eq!(true, lo.matched("", ""));

        assert_eq!("name:lo path: hosts:[] reg_rewrite:None proxy_set_headers:None proxy_add_headers:None plugins:None upstream:charts", lo.to_string());

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
        assert_eq!(true, lo.matched("pingap", "/api"));
        assert_eq!(true, lo.matched("pingap", ""));
        assert_eq!(false, lo.matched("", "/api"));

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
        assert_eq!(true, lo.matched("", "/api/users"));
        assert_eq!(true, lo.matched("", "/users"));
        assert_eq!(false, lo.matched("", "/api"));

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
        assert_eq!(true, lo.matched("", "/api/users"));
        assert_eq!(false, lo.matched("", "/users"));
        assert_eq!(true, lo.matched("", "/api"));

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
        assert_eq!(true, lo.matched("", "/api/users"));
        assert_eq!(false, lo.matched("", "/users"));
        assert_eq!(true, lo.matched("", "/api"));

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
        assert_eq!(false, lo.matched("", "/api/users"));
        assert_eq!(false, lo.matched("", "/users"));
        assert_eq!(true, lo.matched("", "/api"));
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
        assert_eq!(true, lo.rewrite(&mut req_header));
        assert_eq!("/me?abc=1", req_header.uri.to_string());

        let mut req_header =
            RequestHeader::build("GET", b"/api/me?abc=1", None).unwrap();
        assert_eq!(false, lo.rewrite(&mut req_header));
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

        let mut req_header =
            RequestHeader::build("GET", b"/users/v1/me", None).unwrap();
        req_header
            .insert_header(http::header::CONTENT_LENGTH, "1")
            .unwrap();
        let result =
            lo.client_body_size_limit(Some(&req_header), &State::default());
        assert_eq!(true, result.is_ok());

        req_header
            .insert_header(http::header::CONTENT_LENGTH, "1024")
            .unwrap();
        let result =
            lo.client_body_size_limit(Some(&req_header), &State::default());
        assert_eq!(
            " HTTPStatus context: Request Entity Too Large cause:  InternalError",
            result.err().unwrap().to_string()
        );

        let result = lo.client_body_size_limit(
            None,
            &State {
                payload_size: 2,
                ..Default::default()
            },
        );
        assert_eq!(true, result.is_ok());

        let result = lo.client_body_size_limit(
            None,
            &State {
                payload_size: 20,
                ..Default::default()
            },
        );
        assert_eq!(
            " HTTPStatus context: Request Entity Too Large cause:  InternalError",
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
