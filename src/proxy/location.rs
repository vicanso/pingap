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

use super::upstream::new_empty_upstream;
use super::Upstream;
use crate::config::{LocationConf, PluginStep};
use crate::http_extra::{convert_headers, HttpHeader};
use crate::plugin::{get_proxy_plugin, get_response_plugin};
use crate::state::State;
use log::{debug, error};
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::proxy::Session;
use regex::Regex;
use snafu::{ResultExt, Snafu};
use std::fmt;
use std::sync::atomic::{AtomicI32, AtomicU64};
use std::sync::Arc;
use substring::Substring;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Invalid error {message}"))]
    Invalid { message: String },
    #[snafu(display("Regex {source}, {value}"))]
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
        }
        '=' => PathSelector::EqualPath(EqualPath {
            value: last.to_string(),
        }),
        _ => {
            // trim
            PathSelector::PrefixPath(PrefixPath {
                value: path.trim().to_string(),
            })
        }
    };

    Ok(se)
}

pub struct Location {
    pub name: String,
    path: String,
    path_selector: PathSelector,
    hosts: Vec<String>,
    reg_rewrite: Option<(Regex, String)>,
    proxy_add_headers: Option<Vec<HttpHeader>>,
    proxy_set_headers: Option<Vec<HttpHeader>>,
    plugins: Option<Vec<String>>,
    pub accepted: AtomicU64,
    pub processing: AtomicI32,
    pub upstream: Arc<Upstream>,
    pub client_max_body_size: usize,
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
        write!(f, "upstream:{}", self.upstream.name)
    }
}

fn format_headers(values: &Option<Vec<String>>) -> Result<Option<Vec<HttpHeader>>> {
    if let Some(header_values) = values {
        let arr = convert_headers(header_values).map_err(|err| Error::Invalid {
            message: err.to_string(),
        })?;
        Ok(Some(arr))
    } else {
        Ok(None)
    }
}

impl Location {
    /// Create a location from config.
    pub fn new(name: &str, conf: &LocationConf, upstreams: Vec<Arc<Upstream>>) -> Result<Location> {
        let upstream = conf.upstream.clone().unwrap_or_default();
        let up = if upstream.is_empty() {
            Arc::new(new_empty_upstream())
        } else {
            upstreams
                .iter()
                .find(|item| item.name == upstream)
                .ok_or(Error::Invalid {
                    message: format!("Upstream({upstream}) not found"),
                })?
                .clone()
        };
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
            if !host.is_empty() {
                hosts.push(host);
            }
        }

        let path = conf.path.clone().unwrap_or_default();

        let lo = Location {
            name: name.to_string(),
            path_selector: new_path_selector(&path)?,
            path,
            hosts,
            upstream: up,
            reg_rewrite,
            plugins: conf.plugins.clone(),
            accepted: AtomicU64::new(0),
            processing: AtomicI32::new(0),
            proxy_add_headers: format_headers(&conf.proxy_add_headers)?,
            proxy_set_headers: format_headers(&conf.proxy_set_headers)?,
            client_max_body_size: conf.client_max_body_size.unwrap_or_default().as_u64() as usize,
        };
        debug!("Location {lo}");

        Ok(lo)
    }
    /// Return `true` if the host and path match location.
    #[inline]
    pub fn matched(&self, host: &str, path: &str) -> bool {
        if !self.path.is_empty() {
            let matched = match &self.path_selector {
                PathSelector::EqualPath(EqualPath { value }) => value == path,
                PathSelector::RegexPath(RegexPath { value }) => value.is_match(path),
                PathSelector::PrefixPath(PrefixPath { value }) => path.starts_with(value),
                PathSelector::Empty => true,
            };
            if !matched {
                return false;
            }
        }

        if self.hosts.is_empty() {
            return true;
        }

        self.hosts.iter().any(|item| item == host)
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
            debug!("New path:{new_path}");
            if let Err(e) = new_path.parse::<http::Uri>().map(|uri| header.set_uri(uri)) {
                error!("Location:{}, new path parse error:{e:?}", self.name);
            }
            return true;
        }
        false
    }
    /// Set or append the headers before proxy the request to upstream.
    #[inline]
    pub fn set_append_proxy_headers(&self, header: &mut RequestHeader) {
        if let Some(arr) = &self.proxy_set_headers {
            for (k, v) in arr {
                // v validate for HeaderValue, so always no error
                let _ = header.insert_header(k, v);
            }
        }
        if let Some(arr) = &self.proxy_add_headers {
            for (k, v) in arr {
                // v validate for HeaderValue, so always no error
                let _ = header.append_header(k, v);
            }
        }
    }
    /// Execute all proxy plugins. If one plugin return true,
    /// that means http request processing is complete.
    #[inline]
    pub async fn exec_proxy_plugins(
        &self,
        session: &mut Session,
        ctx: &mut State,
        step: PluginStep,
    ) -> pingora::Result<bool> {
        if let Some(plugins) = &self.plugins {
            for name in plugins.iter() {
                if let Some(plugin) = get_proxy_plugin(name) {
                    if plugin.step() != step {
                        continue;
                    }
                    debug!("Run proxy plugin {name}");
                    let result = plugin.handle(session, ctx).await?;
                    if let Some(resp) = result {
                        // ingore http response status >= 900
                        if resp.status.as_u16() < 900 {
                            ctx.status = Some(resp.status);
                            ctx.response_body_size = resp.send(session).await?;
                        }
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }
    /// Execute all response plugins.
    #[inline]
    pub fn exec_response_plugins(
        &self,
        session: &mut Session,
        ctx: &mut State,
        upstream_response: &mut ResponseHeader,
        step: PluginStep,
    ) {
        if let Some(plugins) = &self.plugins {
            for name in plugins.iter() {
                if let Some(plugin) = get_response_plugin(name) {
                    if plugin.step() != step {
                        continue;
                    }
                    debug!("Run response plugin {name}");
                    plugin.handle(session, ctx, upstream_response);
                }
            }
        }
    }

    /// Get the connected count of upstream
    pub fn upstream_connected(&self) -> Option<u32> {
        self.upstream.connected()
    }
}

#[cfg(test)]
mod tests {
    use super::{format_headers, new_path_selector, Location, PathSelector};
    use crate::config::{LocationConf, PluginStep, UpstreamConf};
    use crate::plugin::initialize_test_plugins;
    use crate::proxy::Upstream;
    use crate::state::State;
    use http::Method;
    use pingora::http::{RequestHeader, ResponseHeader};
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use std::sync::Arc;
    use tokio_test::io::Builder;

    #[test]
    fn test_format_headers() {
        let headers =
            format_headers(&Some(vec!["Content-Type: application/json".to_string()])).unwrap();
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
        let upstream = Arc::new(
            Upstream::new(
                upstream_name,
                &UpstreamConf {
                    addrs: vec!["127.0.0.1".to_string()],
                    ..Default::default()
                },
            )
            .unwrap(),
        );

        // no path, no host
        let lo = Location::new(
            "",
            &LocationConf {
                upstream: Some(upstream_name.to_string()),
                ..Default::default()
            },
            vec![upstream.clone()],
        )
        .unwrap();
        assert_eq!(true, lo.matched("pingap", "/api"));
        assert_eq!(true, lo.matched("", ""));

        assert_eq!("name: path: hosts:[] reg_rewrite:None proxy_set_headers:None proxy_add_headers:None plugins:None upstream:charts", lo.to_string());

        // host
        let lo = Location::new(
            "",
            &LocationConf {
                upstream: Some(upstream_name.to_string()),
                host: Some("test.com,pingap".to_string()),
                ..Default::default()
            },
            vec![upstream.clone()],
        )
        .unwrap();
        assert_eq!(true, lo.matched("pingap", "/api"));
        assert_eq!(true, lo.matched("pingap", ""));
        assert_eq!(false, lo.matched("", "/api"));

        // regex
        let lo = Location::new(
            "",
            &LocationConf {
                upstream: Some(upstream_name.to_string()),
                path: Some("~/users".to_string()),
                ..Default::default()
            },
            vec![upstream.clone()],
        )
        .unwrap();
        assert_eq!(true, lo.matched("", "/api/users"));
        assert_eq!(true, lo.matched("", "/users"));
        assert_eq!(false, lo.matched("", "/api"));

        // regex ^/api
        let lo = Location::new(
            "",
            &LocationConf {
                upstream: Some(upstream_name.to_string()),
                path: Some("~^/api".to_string()),
                ..Default::default()
            },
            vec![upstream.clone()],
        )
        .unwrap();
        assert_eq!(true, lo.matched("", "/api/users"));
        assert_eq!(false, lo.matched("", "/users"));
        assert_eq!(true, lo.matched("", "/api"));

        // prefix
        let lo = Location::new(
            "",
            &LocationConf {
                upstream: Some(upstream_name.to_string()),
                path: Some("/api".to_string()),
                ..Default::default()
            },
            vec![upstream.clone()],
        )
        .unwrap();
        assert_eq!(true, lo.matched("", "/api/users"));
        assert_eq!(false, lo.matched("", "/users"));
        assert_eq!(true, lo.matched("", "/api"));

        // equal
        let lo = Location::new(
            "",
            &LocationConf {
                upstream: Some(upstream_name.to_string()),
                path: Some("=/api".to_string()),
                ..Default::default()
            },
            vec![upstream.clone()],
        )
        .unwrap();
        assert_eq!(false, lo.matched("", "/api/users"));
        assert_eq!(false, lo.matched("", "/users"));
        assert_eq!(true, lo.matched("", "/api"));
    }

    #[test]
    fn test_rewrite_path() {
        let upstream_name = "charts";
        let upstream = Arc::new(
            Upstream::new(
                upstream_name,
                &UpstreamConf {
                    addrs: vec!["127.0.0.1".to_string()],
                    ..Default::default()
                },
            )
            .unwrap(),
        );

        let lo = Location::new(
            "",
            &LocationConf {
                upstream: Some(upstream_name.to_string()),
                rewrite: Some("^/users/(.*)$ /$1".to_string()),
                ..Default::default()
            },
            vec![upstream.clone()],
        )
        .unwrap();
        let mut req_header = RequestHeader::build("GET", b"/users/me?abc=1", None).unwrap();
        assert_eq!(true, lo.rewrite(&mut req_header));
        assert_eq!("/me?abc=1", req_header.uri.to_string());

        let mut req_header = RequestHeader::build("GET", b"/api/me?abc=1", None).unwrap();
        assert_eq!(false, lo.rewrite(&mut req_header));
        assert_eq!("/api/me?abc=1", req_header.uri.to_string());
    }

    #[test]
    fn test_insert_header() {
        let upstream_name = "charts";
        let upstream = Arc::new(
            Upstream::new(
                upstream_name,
                &UpstreamConf {
                    addrs: vec!["127.0.0.1".to_string()],
                    ..Default::default()
                },
            )
            .unwrap(),
        );

        let lo = Location::new(
            "",
            &LocationConf {
                upstream: Some(upstream_name.to_string()),
                rewrite: Some("^/users/(.*)$ /$1".to_string()),
                proxy_set_headers: Some(vec!["Cache-Control: no-store".to_string()]),
                proxy_add_headers: Some(vec!["X-User: pingap".to_string()]),
                ..Default::default()
            },
            vec![upstream.clone()],
        )
        .unwrap();

        let mut req_header = RequestHeader::build_no_case(Method::GET, b"", None).unwrap();
        lo.set_append_proxy_headers(&mut req_header);
        assert_eq!(
            r###"RequestHeader { base: Parts { method: GET, uri: , version: HTTP/1.1, headers: {"cache-control": "no-store", "x-user": "pingap"} }, header_name_map: None, raw_path_fallback: [] }"###,
            format!("{req_header:?}")
        );
    }

    #[tokio::test]
    async fn test_exec_proxy_plugins() {
        initialize_test_plugins();
        let upstream_name = "charts";
        let upstream = Arc::new(
            Upstream::new(
                upstream_name,
                &UpstreamConf {
                    addrs: vec!["127.0.0.1".to_string()],
                    ..Default::default()
                },
            )
            .unwrap(),
        );

        let lo = Location::new(
            "",
            &LocationConf {
                upstream: Some(upstream_name.to_string()),
                rewrite: Some("^/users/(.*)$ /$1".to_string()),
                plugins: Some(vec!["test:mock".to_string()]),
                ..Default::default()
            },
            vec![upstream.clone()],
        )
        .unwrap();

        let headers = [""].join("\r\n");
        let input_header = format!("GET /mock HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = lo
            .exec_proxy_plugins(&mut session, &mut State::default(), PluginStep::Request)
            .await
            .unwrap();
        assert_eq!(true, result);

        let headers = [""].join("\r\n");
        let input_header = format!("GET /stats HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let result = lo
            .exec_proxy_plugins(&mut session, &mut State::default(), PluginStep::Request)
            .await
            .unwrap();
        assert_eq!(false, result);
    }

    #[tokio::test]
    async fn test_exec_response_plugins() {
        initialize_test_plugins();
        let upstream_name = "charts";
        let upstream = Arc::new(
            Upstream::new(
                upstream_name,
                &UpstreamConf {
                    addrs: vec!["127.0.0.1".to_string()],
                    ..Default::default()
                },
            )
            .unwrap(),
        );

        let lo = Location::new(
            "",
            &LocationConf {
                upstream: Some(upstream_name.to_string()),
                rewrite: Some("^/users/(.*)$ /$1".to_string()),
                plugins: Some(vec!["test:add_headers".to_string()]),
                ..Default::default()
            },
            vec![upstream.clone()],
        )
        .unwrap();

        let headers = [""].join("\r\n");
        let input_header = format!("GET /mock HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let mut upstream_response = ResponseHeader::build(200, Some(4)).unwrap();
        upstream_response
            .append_header("Content-Type", "application/json")
            .unwrap();
        upstream_response.append_header("X-Server", "abc").unwrap();

        lo.exec_response_plugins(
            &mut session,
            &mut State::default(),
            &mut upstream_response,
            PluginStep::UpstreamResponse,
        );

        assert_eq!(
            r###"{"x-service": "1", "x-service": "2", "x-server": "abc", "x-response-id": "123"}"###,
            format!("{:?}", upstream_response.headers)
        );
    }
}
