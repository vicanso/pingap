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
use crate::config::{LocationConf, ProxyPluginStep};
use crate::http_extra::{convert_headers, HttpHeader};
use crate::plugin::get_proxy_plugin;
use crate::state::State;
use log::debug;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::proxy::Session;
use regex::Regex;
use snafu::{ResultExt, Snafu};
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
    headers: Option<Vec<HttpHeader>>,
    proxy_headers: Option<Vec<HttpHeader>>,
    proxy_plugins: Option<Vec<String>>,
    pub upstream: Arc<Upstream>,
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

        Ok(Location {
            name: name.to_string(),
            path_selector: new_path_selector(&path)?,
            path,
            hosts,
            upstream: up,
            reg_rewrite,
            headers: format_headers(&conf.headers)?,
            proxy_headers: format_headers(&conf.proxy_headers)?,
            proxy_plugins: conf.proxy_plugins.clone(),
        })
    }
    /// Returns `true` if the host and path match location.
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
    /// Rewrites the path by the rule and returns the new path.
    /// If the rule is not exists, returns `None`.
    #[inline]
    pub fn rewrite(&self, path: &str) -> Option<String> {
        if let Some((re, value)) = &self.reg_rewrite {
            return Some(re.replace(path, value).to_string());
        }
        None
    }
    /// Inserts the headers before proxy the request to upstream.
    #[inline]
    pub fn insert_proxy_headers(&self, header: &mut RequestHeader) {
        if let Some(arr) = &self.proxy_headers {
            for (k, v) in arr {
                // v validate for HeaderValue, so always no error
                let _ = header.insert_header(k, v);
            }
        }
    }
    /// Inserts the header to response before sends to downstream.
    #[inline]
    pub fn insert_headers(&self, header: &mut ResponseHeader) {
        if let Some(arr) = &self.headers {
            for (k, v) in arr {
                // v validate for HeaderValue, so always no error
                let _ = header.insert_header(k, v);
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
        step: ProxyPluginStep,
    ) -> pingora::Result<bool> {
        if let Some(plugins) = &self.proxy_plugins {
            for name in plugins.iter() {
                if let Some(plugin) = get_proxy_plugin(name) {
                    if plugin.step() != step {
                        continue;
                    }
                    debug!("Run plugin {name}");
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
}

#[cfg(test)]
mod tests {
    use super::{format_headers, new_path_selector, Location, PathSelector};
    use crate::config::{LocationConf, UpstreamConf};
    use crate::proxy::Upstream;
    use http::{Method, StatusCode};
    use pingora::http::{RequestHeader, ResponseHeader};
    use pretty_assertions::assert_eq;
    use std::sync::Arc;

    #[test]
    fn test_format_headers() {
        let headers = format_headers(&Some(vec!["Content-Type: application/json".to_string()]))
            .unwrap()
            .unwrap();
        assert_eq!(
            r###"[("content-type", "application/json")]"###,
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
        assert_eq!("/me?abc=1", lo.rewrite("/users/me?abc=1").unwrap());
        assert_eq!("/api/me", lo.rewrite("/api/me").unwrap());
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
                proxy_headers: Some(vec!["Cache-Control: no-store".to_string()]),
                headers: Some(vec!["X-Response-Id: pig".to_string()]),
                ..Default::default()
            },
            vec![upstream.clone()],
        )
        .unwrap();

        let mut req_header = RequestHeader::build_no_case(Method::GET, b"", None).unwrap();
        lo.insert_proxy_headers(&mut req_header);
        assert_eq!(
            r###"RequestHeader { base: Parts { method: GET, uri: , version: HTTP/1.1, headers: {"cache-control": "no-store"} }, header_name_map: None, raw_path_fallback: [] }"###,
            format!("{req_header:?}")
        );

        let mut resp_header = ResponseHeader::build_no_case(StatusCode::OK, None).unwrap();
        lo.insert_headers(&mut resp_header);
        assert_eq!(
            r###"ResponseHeader { base: Parts { status: 200, version: HTTP/1.1, headers: {"x-response-id": "pig"} }, header_name_map: None, reason_phrase: None }"###,
            format!("{resp_header:?}")
        );
    }
}
