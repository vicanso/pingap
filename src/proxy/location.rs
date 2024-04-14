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

use super::Upstream;
use crate::config::LocationConf;
use crate::http_extra::{convert_headers, HttpHeader};
use crate::plugin::get_proxy_plugin;
use crate::state::State;
use http::header::HeaderValue;
use once_cell::sync::Lazy;
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

static ZSTD_ENCODING: Lazy<HeaderValue> = Lazy::new(|| "zstd".try_into().unwrap());
static BR_ENCODING: Lazy<HeaderValue> = Lazy::new(|| "br".try_into().unwrap());
static GZIP_ENCODING: Lazy<HeaderValue> = Lazy::new(|| "gzip".try_into().unwrap());

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
    if path.is_empty() {
        return Ok(PathSelector::Empty);
    }
    let se = if path.starts_with('~') {
        // remove ~ and trim
        let path = path.substring(1, path.len()).trim();
        let re = Regex::new(path).context(RegexSnafu {
            value: path.to_string(),
        })?;
        PathSelector::RegexPath(RegexPath { value: re })
    } else if path.starts_with('=') {
        // remove = and trim
        let path = path.substring(1, path.len()).trim();
        PathSelector::EqualPath(EqualPath {
            value: path.to_string(),
        })
    } else {
        // trim
        PathSelector::PrefixPath(PrefixPath {
            value: path.trim().to_string(),
        })
    };
    Ok(se)
}

pub struct Location {
    path: String,
    path_selector: PathSelector,
    hosts: Vec<String>,
    reg_rewrite: Option<(Regex, String)>,
    headers: Option<Vec<HttpHeader>>,
    proxy_headers: Option<Vec<HttpHeader>>,
    gzip_level: u32,
    br_level: u32,
    zstd_level: u32,
    proxy_plugins: Option<Vec<String>>,
    pub support_compression: bool,
    pub upstream: Arc<Upstream>,
    pub upstream_name: String,
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
    pub fn new(
        _name: &str,
        conf: &LocationConf,
        upstreams: Vec<Arc<Upstream>>,
    ) -> Result<Location> {
        let up = upstreams
            .iter()
            .find(|item| item.name == conf.upstream)
            .ok_or(Error::Invalid {
                message: format!("Upstream({}) not found", conf.upstream),
            })?;
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

        let gzip_level = conf.gzip_level.unwrap_or_default();
        let br_level = conf.br_level.unwrap_or_default();
        let zstd_level = conf.zstd_level.unwrap_or_default();
        let support_compression = gzip_level + br_level + zstd_level > 0;
        let path = conf.path.clone().unwrap_or_default();

        Ok(Location {
            upstream_name: conf.upstream.clone(),
            path_selector: new_path_selector(&path)?,
            path,
            hosts,
            upstream: up.clone(),
            reg_rewrite,
            headers: format_headers(&conf.headers)?,
            proxy_headers: format_headers(&conf.proxy_headers)?,
            gzip_level,
            proxy_plugins: conf.proxy_plugins.clone(),
            br_level,
            zstd_level,
            support_compression,
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
    /// Modify accpet encoding for choose compression
    #[inline]
    pub fn modify_accept_encoding(&self, header: &mut RequestHeader) -> Option<u32> {
        if !self.support_compression {
            return None;
        }
        // TODO wait for the feature
        // pingora_cor:compression:decide_action
        // TODO: support to configure preferred encoding
        if let Some(accept_encoding) = header.headers.get(http::header::ACCEPT_ENCODING) {
            let accept_encoding = accept_encoding.to_str().unwrap_or_default();
            if accept_encoding.is_empty() {
                return None;
            }
            // zstd first
            return if self.zstd_level > 0 && accept_encoding.contains("zstd") {
                let _ = header.insert_header(http::header::ACCEPT_ENCODING, ZSTD_ENCODING.clone());
                Some(self.zstd_level)
            } else if self.br_level > 0 && accept_encoding.contains("br") {
                let _ = header.insert_header(http::header::ACCEPT_ENCODING, BR_ENCODING.clone());
                Some(self.br_level)
            } else if self.gzip_level > 0 && accept_encoding.contains("gzip") {
                let _ = header.insert_header(http::header::ACCEPT_ENCODING, GZIP_ENCODING.clone());
                Some(self.gzip_level)
            } else {
                None
            };
        }
        None
    }
    #[inline]
    pub async fn exec_proxy_plugins(
        &self,
        session: &mut Session,
        ctx: &mut State,
    ) -> pingora::Result<bool> {
        if let Some(plugins) = &self.proxy_plugins {
            for name in plugins.iter() {
                if let Some(plugin) = get_proxy_plugin(name) {
                    let done = plugin.handle(session, ctx).await?;
                    if done {
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
                upstream: upstream_name.to_string(),
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
                upstream: upstream_name.to_string(),
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
                upstream: upstream_name.to_string(),
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
                upstream: upstream_name.to_string(),
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
                upstream: upstream_name.to_string(),
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
                upstream: upstream_name.to_string(),
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
                upstream: upstream_name.to_string(),
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
                upstream: upstream_name.to_string(),
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
            r###"ResponseHeader { base: Parts { status: 200, version: HTTP/1.1, headers: {"x-response-id": "pig"} }, header_name_map: None }"###,
            format!("{resp_header:?}")
        );
    }

    #[test]
    fn test_modify_accept_encoding() {
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
                upstream: upstream_name.to_string(),
                gzip_level: Some(1),
                br_level: Some(2),
                zstd_level: Some(3),
                ..Default::default()
            },
            vec![upstream.clone()],
        )
        .unwrap();
        let mut req_header = RequestHeader::build_no_case(Method::GET, b"", None).unwrap();
        let result = lo.modify_accept_encoding(&mut req_header);
        assert_eq!(true, result.is_none());

        let key = "Accept-Encoding";
        req_header
            .insert_header(key, "gzip, deflate, br, zstd")
            .unwrap();
        let result = lo.modify_accept_encoding(&mut req_header);
        assert_eq!("zstd", req_header.headers.get(key).unwrap());
        assert_eq!(3, result.unwrap());

        req_header.insert_header(key, "gzip, deflate, br").unwrap();
        let result = lo.modify_accept_encoding(&mut req_header);
        assert_eq!("br", req_header.headers.get(key).unwrap());
        assert_eq!(2, result.unwrap());

        req_header.insert_header(key, "gzip, deflate").unwrap();
        let result = lo.modify_accept_encoding(&mut req_header);
        assert_eq!("gzip", req_header.headers.get(key).unwrap());
        assert_eq!(1, result.unwrap());
    }
}
