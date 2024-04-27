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

use super::{Error, Result};
use crate::util;
use base64::{engine::general_purpose::STANDARD, Engine};
use http::HeaderValue;
use once_cell::sync::OnceCell;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::collections::HashMap;
use std::net::ToSocketAddrs;
use std::time::Duration;
use url::Url;

pub const CATEGORY_UPSTREAM: &str = "upstream";
pub const CATEGORY_LOCATION: &str = "location";
pub const CATEGORY_SERVER: &str = "server";
pub const CATEGORY_PROXY_PLUGIN: &str = "proxy_plugin";

#[derive(PartialEq, Debug, Default, Deserialize_repr, Clone, Serialize_repr)]
#[repr(u8)]
pub enum ProxyPluginCategory {
    #[default]
    Stats,
    Limit,
    Compression,
    Admin,
    Directory,
    Mock,
    RequestId,
    IpLimit,
    KeyAuth,
    BasicAuth,
    Cache,
    RedirectHttps,
}

#[derive(PartialEq, Debug, Default, Deserialize_repr, Clone, Copy, Serialize_repr)]
#[repr(u8)]
pub enum ProxyPluginStep {
    #[default]
    RequestFilter,
    ProxyUpstreamFilter,
}

#[derive(Debug, Default, Deserialize, Clone, Serialize)]
pub struct ProxyPluginConf {
    pub value: Option<String>,
    pub category: ProxyPluginCategory,
    pub step: Option<ProxyPluginStep>,
    pub remark: Option<String>,
}

#[derive(Debug, Default, Deserialize, Clone, Serialize)]
pub struct UpstreamConf {
    pub addrs: Vec<String>,
    pub algo: Option<String>,
    pub sni: Option<String>,
    pub verify_cert: Option<bool>,
    pub health_check: Option<String>,
    pub ipv4_only: Option<bool>,
    pub alpn: Option<String>,
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub connection_timeout: Option<Duration>,
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub total_connection_timeout: Option<Duration>,
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub read_timeout: Option<Duration>,
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub idle_timeout: Option<Duration>,
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub write_timeout: Option<Duration>,
    pub remark: Option<String>,
}
impl UpstreamConf {
    pub fn validate(&self, name: &str) -> Result<()> {
        if self.addrs.is_empty() {
            return Err(Error::Invalid {
                message: "Upstream addrs is empty".to_string(),
            });
        }
        // validate upstream addr
        for addr in self.addrs.iter() {
            let arr: Vec<_> = addr.split(' ').collect();
            let _ = arr[0]
                .parse::<std::net::SocketAddr>()
                .map_err(|e| Error::AddrParse {
                    source: e,
                    addr: format!("{}(upstream:{name})", arr[0]),
                });
        }
        // validate health check
        let health_check = self.health_check.clone().unwrap_or_default();
        if !health_check.is_empty() {
            let _ = Url::parse(&health_check).map_err(|e| Error::UrlParse {
                source: e,
                url: health_check,
            })?;
        }

        Ok(())
    }
}

#[derive(Debug, Default, Deserialize, Clone, Serialize)]
pub struct LocationConf {
    pub upstream: Option<String>,
    pub path: Option<String>,
    pub host: Option<String>,
    pub proxy_headers: Option<Vec<String>>,
    pub headers: Option<Vec<String>>,
    pub rewrite: Option<String>,
    pub weight: Option<u16>,
    pub proxy_plugins: Option<Vec<String>>,
    pub remark: Option<String>,
}

impl LocationConf {
    /// Validate the options of location config.
    fn validate(&self, name: &str, upstream_names: &[String]) -> Result<()> {
        // validate header for http
        let validate = |headers: &Option<Vec<String>>| -> Result<()> {
            if let Some(headers) = headers {
                for header in headers.iter() {
                    let arr = header.split_once(':').map(|(k, v)| (k.trim(), v.trim()));
                    if arr.is_none() {
                        return Err(Error::Invalid {
                            message: format!("{header} is invalid header(location:{name})"),
                        });
                    }
                    HeaderValue::from_str(arr.unwrap().1).map_err(|err| Error::Invalid {
                        message: format!("{}(location:{name})", err),
                    })?;
                }
            }
            Ok(())
        };

        let upstream = self.upstream.clone().unwrap_or_default();
        if !upstream.is_empty() && !upstream_names.contains(&upstream) {
            return Err(Error::Invalid {
                message: format!("{upstream} upstream is not found(location:{name})"),
            });
        }
        validate(&self.proxy_headers)?;
        validate(&self.headers)?;

        if let Some(value) = &self.rewrite {
            let arr: Vec<&str> = value.split(' ').collect();
            let _ = Regex::new(arr[0]).map_err(|e| Error::Regex { source: e })?;
        }

        Ok(())
    }

    pub fn get_weight(&self) -> u16 {
        if let Some(weight) = self.weight {
            return weight;
        }
        // path starts with
        // = 1024
        // prefix(default) 512
        // ~ 256
        // host exist 128
        let mut weight: u16 = 0;
        if let Some(path) = &self.path {
            if path.starts_with('=') {
                weight += 1024;
            } else if path.starts_with('~') {
                weight += 256;
            } else {
                weight += 512;
            }
            weight += path.len().min(64) as u16;
        };
        if self.host.is_some() {
            weight += 128;
        }
        weight
    }
}

#[derive(Debug, Default, Deserialize, Clone, Serialize)]

pub struct ServerConf {
    pub addr: String,
    pub access_log: Option<String>,
    pub locations: Option<Vec<String>>,
    pub threads: Option<usize>,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub lets_encrypt: Option<String>,
    pub enabled_h2: Option<bool>,
    pub remark: Option<String>,
}

impl ServerConf {
    /// Validate the options of server config.
    fn validate(&self, name: &str, location_names: &[String]) -> Result<()> {
        let _ = self.addr.to_socket_addrs().map_err(|e| Error::Io {
            source: e,
            file: self.addr.clone(),
        })?;
        if let Some(locations) = &self.locations {
            for item in locations {
                if !location_names.contains(item) {
                    return Err(Error::Invalid {
                        message: format!("{item} location is not found(server:{name})"),
                    });
                }
            }
        }
        if let Some(value) = &self.tls_key {
            if !util::is_pem(value) {
                let _ = STANDARD
                    .decode(value)
                    .map_err(|e| Error::Base64Decode { source: e })?;
            }
        }
        if let Some(value) = &self.tls_cert {
            if !util::is_pem(value) {
                let _ = STANDARD
                    .decode(value)
                    .map_err(|e| Error::Base64Decode { source: e })?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct PingapConf {
    pub name: Option<String>,
    pub upstreams: HashMap<String, UpstreamConf>,
    pub locations: HashMap<String, LocationConf>,
    pub servers: HashMap<String, ServerConf>,
    pub proxy_plugins: HashMap<String, ProxyPluginConf>,
    pub error_template: String,
    pub pid_file: Option<String>,
    pub upgrade_sock: Option<String>,
    pub user: Option<String>,
    pub group: Option<String>,
    pub threads: Option<usize>,
    pub work_stealing: Option<bool>,
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub grace_period: Option<Duration>,
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub graceful_shutdown_timeout: Option<Duration>,
    pub upstream_keepalive_pool_size: Option<usize>,
    pub webhook: Option<String>,
    pub webhook_type: Option<String>,
    pub log_level: Option<String>,
    pub sentry: Option<String>,
    pub pyroscope: Option<String>,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
struct Description {
    name: String,
    data: String,
}

impl PingapConf {
    /// Validate the options of pinggap config.
    pub fn validate(&self) -> Result<()> {
        let mut upstream_names = vec![];
        for (name, upstream) in self.upstreams.iter() {
            upstream.validate(name)?;
            upstream_names.push(name.to_string());
        }
        let mut location_names = vec![];
        for (name, location) in self.locations.iter() {
            location.validate(name, &upstream_names)?;
            location_names.push(name.to_string());
        }
        for (name, server) in self.servers.iter() {
            server.validate(name, &location_names)?;
        }
        Ok(())
    }
    pub fn hash(&self) -> Result<String> {
        let data = toml::to_string_pretty(self).map_err(|e| Error::Ser { source: e })?;
        let mut lines: Vec<&str> = data.split('\n').collect();
        lines.sort();
        let hash = crc32fast::hash(lines.join("\n").as_bytes());
        Ok(format!("{:X}", hash))
    }
    pub fn remove(&mut self, category: &str, name: &str) -> Result<()> {
        match category {
            CATEGORY_UPSTREAM => {
                let upstreams: Vec<String> = self
                    .locations
                    .values()
                    .map(|lo| lo.upstream.clone().unwrap_or_default())
                    .collect();
                if upstreams.contains(&name.to_string()) {
                    return Err(Error::Invalid {
                        message: format!("Upstream({name}) is in use"),
                    });
                }

                self.upstreams.remove(name);
            }
            CATEGORY_LOCATION => {
                for server in self.servers.values() {
                    if server
                        .locations
                        .clone()
                        .unwrap_or_default()
                        .contains(&name.to_string())
                    {
                        return Err(Error::Invalid {
                            message: format!("Location({name}) is in use"),
                        });
                    }
                }
                self.locations.remove(name);
            }
            CATEGORY_SERVER => {
                self.servers.remove(name);
            }
            CATEGORY_PROXY_PLUGIN => {
                let mut all_plugins = vec![];
                for lo in self.locations.values() {
                    if let Some(plguins) = &lo.proxy_plugins {
                        all_plugins.extend(plguins.clone());
                    }
                }
                if all_plugins.contains(&name.to_string()) {
                    return Err(Error::Invalid {
                        message: format!("Proxy plugin({name}) is in use"),
                    });
                }
                self.proxy_plugins.remove(name);
            }
            _ => {}
        };
        Ok(())
    }
    fn descriptions(&self) -> Vec<Description> {
        let mut value = self.clone();
        let mut descriptions = vec![];
        for (name, data) in value.servers.iter() {
            descriptions.push(Description {
                name: format!("server:{name}"),
                data: toml::to_string_pretty(data).unwrap_or_default(),
            });
        }
        for (name, data) in value.locations.iter() {
            descriptions.push(Description {
                name: format!("location:{name}"),
                data: toml::to_string_pretty(data).unwrap_or_default(),
            });
        }
        for (name, data) in value.upstreams.iter() {
            descriptions.push(Description {
                name: format!("upstream:{name}"),
                data: toml::to_string_pretty(data).unwrap_or_default(),
            });
        }
        for (name, data) in value.proxy_plugins.iter() {
            descriptions.push(Description {
                name: format!("proxy_plugin:{name}"),
                data: toml::to_string_pretty(data).unwrap_or_default(),
            });
        }
        value.servers = HashMap::new();
        value.locations = HashMap::new();
        value.upstreams = HashMap::new();
        value.proxy_plugins = HashMap::new();
        descriptions.push(Description {
            name: "basic".to_string(),
            data: toml::to_string_pretty(&value).unwrap_or_default(),
        });
        descriptions.sort_by_key(|d| d.name.clone());
        descriptions
    }
    pub fn diff(&self, other: PingapConf) -> Vec<String> {
        let current_descriptions = self.descriptions();
        let new_descriptions = other.descriptions();
        let mut diff_result = vec![];

        // remove item
        let mut exists_remove = false;
        for item in current_descriptions.iter() {
            let mut found = false;
            for new_item in new_descriptions.iter() {
                if item.name == new_item.name {
                    found = true;
                    exists_remove = true;
                }
            }
            if !found {
                diff_result.push(format!("--{}", item.name));
            }
        }
        if exists_remove {
            diff_result.push("\n".to_string());
        }

        // add item
        let mut exists_add = false;
        for new_item in new_descriptions.iter() {
            let mut found = false;
            for item in current_descriptions.iter() {
                if item.name == new_item.name {
                    found = true;
                    exists_add = true;
                }
            }
            if !found {
                diff_result.push(format!("++{}", new_item.name));
            }
        }
        if exists_add {
            diff_result.push("\n".to_string());
        }

        for item in current_descriptions.iter() {
            for new_item in new_descriptions.iter() {
                if item.name != new_item.name {
                    continue;
                }
                let mut item_diff_result = vec![];
                for diff in diff::lines(&item.data, &new_item.data) {
                    match diff {
                        diff::Result::Left(l) => item_diff_result.push(format!("-{}", l)),
                        diff::Result::Right(r) => item_diff_result.push(format!("+{}", r)),
                        _ => {}
                    };
                }
                if !item_diff_result.is_empty() {
                    diff_result.push(item.name.clone());
                    diff_result.extend(item_diff_result);
                    diff_result.push("\n".to_string());
                }
            }
        }

        diff_result
    }
}

static CONFIG_PATH: OnceCell<String> = OnceCell::new();
pub fn set_config_path(conf_path: &str) {
    CONFIG_PATH.get_or_init(|| conf_path.to_string());
}

static CURRENT_CONFIG: OnceCell<PingapConf> = OnceCell::new();
pub fn set_current_config(value: &PingapConf) {
    CURRENT_CONFIG.get_or_init(|| value.clone());
}

pub fn get_current_config() -> PingapConf {
    if let Some(value) = CURRENT_CONFIG.get() {
        value.clone()
    } else {
        PingapConf::default()
    }
}

pub fn get_config_path() -> String {
    CONFIG_PATH.get_or_init(|| "".to_string()).to_owned()
}

static CONFIG_HASH: OnceCell<String> = OnceCell::new();
/// Sets pingap running config's crc hash
pub fn set_config_hash(version: &str) {
    CONFIG_HASH.get_or_init(|| version.to_string());
}

static APP_NAME: OnceCell<String> = OnceCell::new();
/// Sets app name
pub fn set_app_name(name: &str) {
    APP_NAME.get_or_init(|| name.to_string());
}
pub fn get_app_name() -> String {
    if let Some(name) = APP_NAME.get() {
        name.to_string()
    } else {
        "Pingap".to_string()
    }
}

/// Returns current running pingap's config crc hash
pub fn get_config_hash() -> String {
    if let Some(value) = CONFIG_HASH.get() {
        value.to_string()
    } else {
        "".to_string()
    }
}
