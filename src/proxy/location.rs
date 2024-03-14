use super::Upstream;
use crate::config::LocationConf;
use bytes::Bytes;
use http::HeaderValue;
use regex::Regex;
use snafu::{ResultExt, Snafu};
use std::sync::Arc;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Invalid error {message}"))]
    Invalid { message: String },
    #[snafu(display("Invalid header value {source}, {value}"))]
    InvalidHeaderValue {
        value: String,
        source: http::header::InvalidHeaderValue,
    },
}
type Result<T, E = Error> = std::result::Result<T, E>;

pub struct Location {
    // name: String,
    path: String,
    host: String,
    reg_rewrite: Option<(Regex, String)>,
    proxy_headers: Option<Vec<(Bytes, Bytes)>>,
    pub upstream: Arc<Upstream>,
}

fn convert_headers(values: &Option<Vec<String>>) -> Result<Option<Vec<(Bytes, Bytes)>>> {
    if let Some(header_values) = values {
        let mut arr = vec![];
        for item in header_values {
            let values: Vec<&str> = item.split(':').collect();
            if values.len() < 2 {
                continue;
            }
            let k = Bytes::from(values[0].to_string());
            let _ = HeaderValue::from_str(values[1]).context(InvalidHeaderValueSnafu {
                value: values[1].to_string(),
            })?;
            let v = Bytes::from(values[1].to_string());
            arr.push((k, v))
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
        let proxy_headers = convert_headers(&conf.proxy_headers)?;
        Ok(Location {
            // name: conf.name.clone(),
            path: conf.path.clone().unwrap_or_default(),
            host: conf.host.clone().unwrap_or_default(),
            upstream: up.clone(),
            reg_rewrite,
            proxy_headers,
        })
    }
    #[inline]
    pub fn matched(&self, path: &str, host: &str) -> bool {
        if !self.path.is_empty() && !path.starts_with(&self.path) {
            return false;
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
    pub fn get_proxy_headers(&self) -> Option<Vec<(Bytes, Bytes)>> {
        self.proxy_headers.clone()
    }
}
