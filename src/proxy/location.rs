use super::Upstream;
use crate::{config::LocationConf, utils};
use bytes::Bytes;
use http::HeaderValue;
use regex::Regex;
use snafu::{ResultExt, Snafu};
use std::sync::Arc;
use substring::Substring;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Invalid error {message}"))]
    Invalid { message: String },
    #[snafu(display("Invalid header value {source}, {value}"))]
    InvalidHeaderValue {
        value: String,
        source: http::header::InvalidHeaderValue,
    },
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
    if path.is_empty() {
        return Ok(PathSelector::Empty);
    }
    let se = if path.starts_with('~') {
        let re = Regex::new(path.substring(1, path.len())).context(RegexSnafu {
            value: path.to_string(),
        })?;
        PathSelector::RegexPath(RegexPath { value: re })
    } else if path.starts_with('=') {
        PathSelector::EqualPath(EqualPath {
            value: path.substring(1, path.len()).to_string(),
        })
    } else {
        PathSelector::PrefixPath(PrefixPath {
            value: path.to_string(),
        })
    };
    Ok(se)
}

pub struct Location {
    // name: String,
    path: String,
    path_selector: PathSelector,
    host: String,
    reg_rewrite: Option<(Regex, String)>,
    // TODO better performance for http header
    headers: Option<Vec<(Bytes, Bytes)>>,
    proxy_headers: Option<Vec<(Bytes, Bytes)>>,
    pub upstream: Arc<Upstream>,
}

fn convert_headers(values: &Option<Vec<String>>) -> Result<Option<Vec<(Bytes, Bytes)>>> {
    if let Some(header_values) = values {
        let mut arr = vec![];
        for item in header_values {
            if let Some([k, v]) = utils::split_to_two_trim(item, ":") {
                let _ =
                    HeaderValue::from_str(&v).context(InvalidHeaderValueSnafu { value: v.clone() });
                arr.push((Bytes::from(k), Bytes::from(v)));
            }
        }
        Ok(Some(arr))
    } else {
        Ok(None)
    }
}

impl Location {
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

        let path = conf.path.clone().unwrap_or_default();
        Ok(Location {
            // name: conf.name.clone(),
            path_selector: new_path_selector(&path)?,
            path,
            host: conf.host.clone().unwrap_or_default(),
            upstream: up.clone(),
            reg_rewrite,
            headers: convert_headers(&conf.headers)?,
            proxy_headers: convert_headers(&conf.proxy_headers)?,
        })
    }
    #[inline]
    pub fn matched(&self, path: &str, host: &str) -> bool {
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

        if !self.host.is_empty() && host != self.host {
            return false;
        }
        true
    }
    #[inline]
    pub fn rewrite(&self, path: &str) -> Option<String> {
        if let Some((re, value)) = &self.reg_rewrite {
            return Some(re.replace(path, value).to_string());
        }
        None
    }
    #[inline]
    pub fn get_proxy_headers(&self) -> Option<Vec<(Bytes, Bytes)>> {
        self.proxy_headers.clone()
    }
    #[inline]
    pub fn get_header(&self) -> Option<Vec<(Bytes, Bytes)>> {
        self.headers.clone()
    }
}
