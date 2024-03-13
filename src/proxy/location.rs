use super::Upstream;
use regex::Regex;
use serde::Deserialize;
use snafu::Snafu;
use std::sync::Arc;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Invalid error {message}"))]
    Invalid { message: String },
}
type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Default, Deserialize, Clone)]
pub struct LocationConf {
    pub name: String,
    pub path: Option<String>,
    pub host: Option<String>,
    pub rewrite: Option<String>,
    pub upstream: String,
}

pub struct Location {
    // name: String,
    path: String,
    host: String,
    reg_rewrite: Option<(Regex, String)>,
    pub upstream: Arc<Upstream>,
}

impl Location {
    pub fn new(conf: &LocationConf, upstreams: Vec<Arc<Upstream>>) -> Result<Location> {
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
        Ok(Location {
            // name: conf.name.clone(),
            path: conf.path.clone().unwrap_or_default(),
            host: conf.host.clone().unwrap_or_default(),
            upstream: up.clone(),
            reg_rewrite,
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
}
