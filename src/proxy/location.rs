use super::Upstream;
use crate::error::{Error, Result};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct LocationConf {
    pub name: String,
    pub path: String,
    pub host: String,
    pub upstream: String,
    // TODO: location filter by host
}

pub struct Location {
    name: String,
    path: String,
    host: String,
    pub upstream: Arc<Upstream>,
}

impl Location {
    pub fn new(conf: LocationConf, upstreams: Vec<Arc<Upstream>>) -> Result<Location> {
        let up = upstreams
            .iter()
            .find(|item| item.name == conf.upstream)
            .ok_or(Error::Invalid {
                category: "location".to_string(),
                message: "Upstream not found".to_string(),
            })?;
        Ok(Location {
            name: conf.name.clone(),
            path: conf.path.clone(),
            host: conf.host.clone(),
            upstream: up.clone(),
        })
    }
    pub fn matched(&self, path: &str, host: &str) -> bool {
        if !self.path.is_empty() && !path.starts_with(&self.path) {
            return false;
        }
        if !self.host.is_empty() && host != self.host {
            return false;
        }
        true
    }
}
