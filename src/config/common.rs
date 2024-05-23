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
use crate::plugin::parse_plugins;
use crate::proxy::Parser;
use crate::util;
use base64::{engine::general_purpose::STANDARD, Engine};
use http::{HeaderName, HeaderValue};
use once_cell::sync::OnceCell;
use regex::Regex;
use serde::{Deserialize, Serialize, Serializer};
use std::net::ToSocketAddrs;
use std::time::Duration;
use std::{collections::HashMap, str::FromStr};
use strum::EnumString;
use toml::{map::Map, Value};
use url::Url;

pub const CATEGORY_UPSTREAM: &str = "upstream";
pub const CATEGORY_LOCATION: &str = "location";
pub const CATEGORY_SERVER: &str = "server";
pub const CATEGORY_PLUGIN: &str = "plugin";

#[derive(PartialEq, Debug, Default, Clone, EnumString, strum::Display)]
#[strum(serialize_all = "snake_case")]
pub enum PluginCategory {
    #[default]
    Stats,
    Limit,
    Compression,
    Admin,
    Directory,
    Mock,
    RequestId,
    IpRestriction,
    KeyAuth,
    BasicAuth,
    Cache,
    Redirect,
    Ping,
    ResponseHeaders,
    RefererRestriction,
}

impl Serialize for PluginCategory {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().as_ref())
    }
}

impl<'de> Deserialize<'de> for PluginCategory {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value: String = serde::Deserialize::deserialize(deserializer)?;
        let category = PluginCategory::from_str(&value).unwrap_or(PluginCategory::default());

        Ok(category)
    }
}

#[derive(PartialEq, Debug, Default, Clone, Copy, EnumString, strum::Display)]
#[strum(serialize_all = "snake_case")]
pub enum PluginStep {
    #[default]
    Request,
    ProxyUpstream,
    UpstreamResponse,
}

impl Serialize for PluginStep {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().as_ref())
    }
}

impl<'de> Deserialize<'de> for PluginStep {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value: String = serde::Deserialize::deserialize(deserializer)?;
        let category = PluginStep::from_str(&value).unwrap_or(PluginStep::default());

        Ok(category)
    }
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
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub tcp_idle: Option<Duration>,
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub tcp_interval: Option<Duration>,
    pub tcp_probe_count: Option<usize>,
    pub tcp_recv_buf: Option<usize>,
    pub remark: Option<String>,
}
impl UpstreamConf {
    /// Validate the options of upstream config.
    pub fn validate(&self, name: &str) -> Result<()> {
        if self.addrs.is_empty() {
            return Err(Error::Invalid {
                message: "upstream addrs is empty".to_string(),
            });
        }
        // validate upstream addr
        for addr in self.addrs.iter() {
            let arr: Vec<_> = addr.split(' ').collect();
            let mut addr = arr[0].to_string();
            if !addr.contains(':') {
                addr = format!("{addr}:80");
            }
            let _ = addr.to_socket_addrs().map_err(|e| Error::Io {
                source: e,
                file: format!("{}(upstream:{name})", arr[0]),
            })?;
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
    pub proxy_set_headers: Option<Vec<String>>,
    pub proxy_add_headers: Option<Vec<String>>,
    pub rewrite: Option<String>,
    pub weight: Option<u16>,
    pub plugins: Option<Vec<String>>,
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
                            message: format!("Header {header} is invalid(location:{name})"),
                        });
                    }
                    let (header_name, header_value) = arr.unwrap();
                    HeaderName::from_bytes(header_name.as_bytes()).map_err(|err| {
                        Error::Invalid {
                            message: format!(
                                "Header name({header_name}) is invalid, {err}(location:{name})"
                            ),
                        }
                    })?;
                    HeaderValue::from_str(header_value).map_err(|err| Error::Invalid {
                        message: format!(
                            "Header value({header_value}) is invalid, {err}(location:{name})"
                        ),
                    })?;
                }
            }
            Ok(())
        };

        let upstream = self.upstream.clone().unwrap_or_default();
        if !upstream.is_empty() && !upstream_names.contains(&upstream) {
            return Err(Error::Invalid {
                message: format!("upstream({upstream}) is not found(location:{name})"),
            });
        }
        validate(&self.proxy_add_headers)?;
        validate(&self.proxy_set_headers)?;

        if let Some(value) = &self.rewrite {
            let arr: Vec<&str> = value.split(' ').collect();
            let _ = Regex::new(arr[0]).map_err(|e| Error::Regex { source: e })?;
        }

        Ok(())
    }
    /// Get weight of location.
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
        for addr in self.addr.split(',') {
            let _ = addr.to_socket_addrs().map_err(|e| Error::Io {
                source: e,
                file: self.addr.clone(),
            })?;
        }
        if let Some(locations) = &self.locations {
            for item in locations {
                if !location_names.contains(item) {
                    return Err(Error::Invalid {
                        message: format!("location({item}) is not found(server:{name})"),
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
        if let Some(access_log) = &self.access_log {
            let logger = Parser::from(access_log.as_str());
            if logger.tags.is_empty() {
                return Err(Error::Invalid {
                    message: "Access log format is invalid".to_string(),
                });
            }
        }

        Ok(())
    }
}
#[derive(Debug, Default, Deserialize, Clone, Serialize)]
pub struct BasicConf {
    pub name: Option<String>,
    pub error_template: Option<String>,
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
    pub webhook_notifications: Option<Vec<String>>,
    pub log_level: Option<String>,
    pub log_capacity: Option<usize>,
    pub sentry: Option<String>,
    pub pyroscope: Option<String>,
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub auto_restart_check_interval: Option<Duration>,
    pub cache_max_size: Option<usize>,
}

#[derive(Deserialize, Debug, Serialize)]
struct TomlConfig {
    basic: Option<BasicConf>,
    servers: Option<Map<String, Value>>,
    upstreams: Option<Map<String, Value>>,
    locations: Option<Map<String, Value>>,
    plugins: Option<Map<String, Value>>,
}

fn format_toml(value: &Value) -> String {
    if let Some(value) = value.as_table() {
        value.to_string()
    } else {
        "".to_string()
    }
}

pub type PluginConf = Map<String, Value>;

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct PingapConf {
    pub basic: BasicConf,
    pub upstreams: HashMap<String, UpstreamConf>,
    pub locations: HashMap<String, LocationConf>,
    pub servers: HashMap<String, ServerConf>,
    pub plugins: HashMap<String, PluginConf>,
}

impl PingapConf {
    pub fn get_toml(&self, category: &str) -> Result<(String, String)> {
        let ping_conf = toml::to_string_pretty(self).map_err(|e| Error::Ser { source: e })?;
        let mut data: TomlConfig =
            toml::from_str(&ping_conf).map_err(|e| Error::De { source: e })?;
        let result = match category {
            CATEGORY_SERVER => {
                let mut m = Map::new();
                let _ = m.insert(
                    "servers".to_string(),
                    toml::Value::Table(data.servers.unwrap_or_default()),
                );
                let value = toml::to_string_pretty(&m).map_err(|e| Error::Ser { source: e })?;
                ("/servers.toml".to_string(), value)
            }
            CATEGORY_LOCATION => {
                let mut m = Map::new();
                let _ = m.insert(
                    "locations".to_string(),
                    toml::Value::Table(data.locations.unwrap_or_default()),
                );
                let value = toml::to_string_pretty(&m).map_err(|e| Error::Ser { source: e })?;
                ("/locations.toml".to_string(), value)
            }
            CATEGORY_UPSTREAM => {
                let mut m = Map::new();
                let _ = m.insert(
                    "upstreams".to_string(),
                    toml::Value::Table(data.upstreams.unwrap_or_default()),
                );
                let value = toml::to_string_pretty(&m).map_err(|e| Error::Ser { source: e })?;
                ("/upstreams.toml".to_string(), value)
            }
            CATEGORY_PLUGIN => {
                let mut m = Map::new();
                let _ = m.insert(
                    "plugins".to_string(),
                    toml::Value::Table(data.plugins.unwrap_or_default()),
                );
                let value = toml::to_string_pretty(&m).map_err(|e| Error::Ser { source: e })?;
                ("/plugins.toml".to_string(), value)
            }
            _ => {
                data.servers = None;
                data.locations = None;
                data.upstreams = None;
                data.plugins = None;
                let value = toml::to_string_pretty(&data).map_err(|e| Error::Ser { source: e })?;
                ("/basic.toml".to_string(), value)
            }
        };
        Ok(result)
    }
}

impl TryFrom<&[u8]> for PingapConf {
    type Error = Error;
    fn try_from(data: &[u8]) -> Result<Self, self::Error> {
        let data: TomlConfig = toml::from_str(
            std::string::String::from_utf8_lossy(data)
                .to_string()
                .as_str(),
        )
        .map_err(|e| Error::De { source: e })?;

        let mut conf = PingapConf {
            basic: data.basic.unwrap_or_default(),
            ..Default::default()
        };
        for (name, value) in data.upstreams.unwrap_or_default() {
            let upstream: UpstreamConf = toml::from_str(format_toml(&value).as_str())
                .map_err(|e| Error::De { source: e })?;
            conf.upstreams.insert(name, upstream);
        }
        for (name, value) in data.locations.unwrap_or_default() {
            let location: LocationConf = toml::from_str(format_toml(&value).as_str())
                .map_err(|e| Error::De { source: e })?;
            conf.locations.insert(name, location);
        }
        for (name, value) in data.servers.unwrap_or_default() {
            let server: ServerConf = toml::from_str(format_toml(&value).as_str())
                .map_err(|e| Error::De { source: e })?;
            conf.servers.insert(name, server);
        }
        for (name, value) in data.plugins.unwrap_or_default() {
            let plugin: PluginConf = toml::from_str(format_toml(&value).as_str())
                .map_err(|e| Error::De { source: e })?;
            conf.plugins.insert(name, plugin);
        }

        Ok(conf)
    }
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
        for (name, plugin) in self.plugins.iter() {
            parse_plugins(vec![(name.to_string(), plugin.clone())]).map_err(|e| {
                Error::Invalid {
                    message: e.to_string(),
                }
            })?;
        }
        Ok(())
    }
    /// Generate the content hash of config.
    pub fn hash(&self) -> Result<String> {
        let data = toml::to_string_pretty(self).map_err(|e| Error::Ser { source: e })?;
        let mut lines: Vec<&str> = data.split('\n').collect();
        lines.sort();
        let hash = crc32fast::hash(lines.join("\n").as_bytes());
        Ok(format!("{:X}", hash))
    }
    /// Remove the config by name.
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
            CATEGORY_PLUGIN => {
                let mut all_plugins = vec![];
                for lo in self.locations.values() {
                    if let Some(plguins) = &lo.plugins {
                        all_plugins.extend(plguins.clone());
                    }
                }
                if all_plugins.contains(&name.to_string()) {
                    return Err(Error::Invalid {
                        message: format!("Proxy plugin({name}) is in use"),
                    });
                }
                self.plugins.remove(name);
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
        for (name, data) in value.plugins.iter() {
            descriptions.push(Description {
                name: format!("plugin:{name}"),
                data: toml::to_string_pretty(data).unwrap_or_default(),
            });
        }
        value.servers = HashMap::new();
        value.locations = HashMap::new();
        value.upstreams = HashMap::new();
        value.plugins = HashMap::new();
        descriptions.push(Description {
            name: "basic".to_string(),
            data: toml::to_string_pretty(&value).unwrap_or_default(),
        });
        descriptions.sort_by_key(|d| d.name.clone());
        descriptions
    }
    /// Get the different content of two config.
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
                }
            }
            if !found {
                exists_remove = true;
                diff_result.push(format!("--{}", item.name));
            }
        }
        if exists_remove {
            diff_result.push("".to_string());
        }

        // add item
        let mut exists_add = false;
        for new_item in new_descriptions.iter() {
            let mut found = false;
            for item in current_descriptions.iter() {
                if item.name == new_item.name {
                    found = true;
                }
            }
            if !found {
                exists_add = true;
                diff_result.push(format!("++{}", new_item.name));
            }
        }
        if exists_add {
            diff_result.push("".to_string());
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
/// Set config path.
pub fn set_config_path(conf_path: &str) {
    CONFIG_PATH.get_or_init(|| conf_path.to_string());
}
/// Get config path
pub fn get_config_path() -> String {
    if let Some(value) = CONFIG_PATH.get() {
        value.to_string()
    } else {
        "".to_string()
    }
}

static CURRENT_CONFIG: OnceCell<PingapConf> = OnceCell::new();
/// Set current config of pingap.
pub fn set_current_config(value: &PingapConf) {
    CURRENT_CONFIG.get_or_init(|| value.clone());
}

/// Get the running pingap config.
pub fn get_current_config() -> PingapConf {
    if let Some(value) = CURRENT_CONFIG.get() {
        value.clone()
    } else {
        PingapConf::default()
    }
}

static CONFIG_HASH: OnceCell<String> = OnceCell::new();
/// Sets pingap running config's crc hash
pub fn set_config_hash(version: &str) {
    CONFIG_HASH.get_or_init(|| version.to_string());
}

static DEFAULT_APP_NAME: &str = "Pingap";

static APP_NAME: OnceCell<String> = OnceCell::new();
/// Sets app name
pub fn set_app_name(name: &str) {
    APP_NAME.get_or_init(|| {
        if name.is_empty() {
            DEFAULT_APP_NAME.to_string()
        } else {
            name.to_string()
        }
    });
}
pub fn get_app_name() -> String {
    if let Some(name) = APP_NAME.get() {
        name.to_string()
    } else {
        DEFAULT_APP_NAME.to_string()
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

#[cfg(test)]
mod tests {
    use super::{
        LocationConf, PingapConf, PluginCategory, ServerConf, UpstreamConf, CATEGORY_LOCATION,
        CATEGORY_PLUGIN, CATEGORY_SERVER, CATEGORY_UPSTREAM,
    };
    use pretty_assertions::assert_eq;
    use serde::{Deserialize, Serialize};

    #[test]
    fn test_plugin_category_serde() {
        #[derive(Deserialize, Serialize)]
        struct TmpPluginCategory {
            category: PluginCategory,
        }
        let tmp = TmpPluginCategory {
            category: PluginCategory::RequestId,
        };
        let data = serde_json::to_string(&tmp).unwrap();
        assert_eq!(r#"{"category":"request_id"}"#, data);

        let tmp: TmpPluginCategory = serde_json::from_str(&data).unwrap();
        assert_eq!(PluginCategory::RequestId, tmp.category);
    }

    #[test]
    fn test_upstream_conf() {
        let mut conf = UpstreamConf::default();

        let result = conf.validate("test");
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Invalid error upstream addrs is empty",
            result.expect_err("").to_string()
        );

        conf.addrs = vec!["127.0.0.1".to_string(), "github".to_string()];
        let result = conf.validate("test");
        assert_eq!(true, result.is_err());
        assert_eq!(
            true,
            result
                .expect_err("")
                .to_string()
                .contains("Io error failed to lookup address information")
        );

        conf.addrs = vec!["127.0.0.1".to_string(), "github.com".to_string()];
        conf.health_check = Some("http:///".to_string());
        let result = conf.validate("test");
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Url parse error empty host, http:///",
            result.expect_err("").to_string()
        );

        conf.health_check = Some("http://github.com/".to_string());
        let result = conf.validate("test");
        assert_eq!(true, result.is_ok());
    }

    #[test]
    fn test_location_conf() {
        let mut conf = LocationConf::default();
        let upstream_names = vec!["upstream1".to_string()];

        conf.upstream = Some("upstream2".to_string());
        let result = conf.validate("lo", &upstream_names);
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Invalid error upstream(upstream2) is not found(location:lo)",
            result.expect_err("").to_string()
        );

        conf.upstream = Some("upstream1".to_string());
        conf.proxy_set_headers = Some(vec!["X-Request-Id".to_string()]);
        let result = conf.validate("lo", &upstream_names);
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Invalid error Header X-Request-Id is invalid(location:lo)",
            result.expect_err("").to_string()
        );

        conf.proxy_set_headers = Some(vec!["请求:响应".to_string()]);
        let result = conf.validate("lo", &upstream_names);
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Invalid error Header name(请求) is invalid, invalid HTTP header name(location:lo)",
            result.expect_err("").to_string()
        );

        conf.proxy_set_headers = Some(vec!["X-Request-Id: abcd".to_string()]);
        let result = conf.validate("lo", &upstream_names);
        assert_eq!(true, result.is_ok());

        conf.rewrite = Some(r"foo(bar".to_string());
        let result = conf.validate("lo", &upstream_names);
        assert_eq!(true, result.is_err());
        assert_eq!(
            true,
            result
                .expect_err("")
                .to_string()
                .starts_with("Regex error regex parse error")
        );

        conf.rewrite = Some(r"^/api /".to_string());
        let result = conf.validate("lo", &upstream_names);
        assert_eq!(true, result.is_ok());
    }

    #[test]
    fn test_location_get_wegiht() {
        let mut conf = LocationConf {
            weight: Some(2048),
            ..Default::default()
        };

        assert_eq!(2048, conf.get_weight());

        conf.weight = None;
        conf.path = Some("=/api".to_string());
        assert_eq!(1029, conf.get_weight());

        conf.path = Some("~/api".to_string());
        assert_eq!(261, conf.get_weight());

        conf.path = Some("/api".to_string());
        assert_eq!(516, conf.get_weight());

        conf.path = None;
        conf.host = Some("github.com".to_string());
        assert_eq!(128, conf.get_weight());
    }

    #[test]
    fn test_server_conf() {
        let mut conf = ServerConf::default();
        let location_names = vec!["lo".to_string()];

        let result = conf.validate("test", &location_names);
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Io error invalid socket address, ",
            result.expect_err("").to_string()
        );

        conf.addr = "127.0.0.1:3001".to_string();
        conf.locations = Some(vec!["lo1".to_string()]);
        let result = conf.validate("test", &location_names);
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Invalid error location(lo1) is not found(server:test)",
            result.expect_err("").to_string()
        );

        conf.locations = Some(vec!["lo".to_string()]);
        conf.tls_key = Some("ab".to_string());
        let result = conf.validate("test", &location_names);
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Base64 decode error Invalid padding",
            result.expect_err("").to_string()
        );

        conf.tls_key = Some("YWJj".to_string());
        conf.tls_cert = Some("YWJj".to_string());
        let result = conf.validate("test", &location_names);
        assert_eq!(true, result.is_ok());
    }

    #[test]
    fn test_pingap_conf() {
        let toml_data = include_bytes!("../../conf/pingap.toml");
        let conf = PingapConf::try_from(toml_data.to_vec().as_slice()).unwrap();

        let (key, data) = conf.get_toml(CATEGORY_SERVER).unwrap();
        assert_eq!("/servers.toml", key);
        assert_eq!(
            r###"[servers.test]
access_log = "tiny"
addr = "0.0.0.0:6188"
locations = ["lo"]
"###,
            data
        );

        let (key, data) = conf.get_toml(CATEGORY_LOCATION).unwrap();
        assert_eq!("/locations.toml", key);
        assert_eq!(
            r###"[locations.lo]
host = ""
path = "/"
plugins = [
    "pingap:requestId",
    "pingap:stats",
]
proxy_add_headers = ["name:value"]
proxy_set_headers = ["name:value"]
rewrite = ""
upstream = "charts"
"###,
            data
        );

        let (key, data) = conf.get_toml(CATEGORY_UPSTREAM).unwrap();
        assert_eq!("/upstreams.toml", key);
        assert_eq!(
            r###"[upstreams.charts]
addrs = ["127.0.0.1:5000"]
algo = "hash:cookie"
connection_timeout = "10s"
health_check = "http://charts/ping?connection_timeout=3s&pingap"
idle_timeout = "2m"
read_timeout = "10s"
total_connection_timeout = "30s"
write_timeout = "10s"

[upstreams.diving]
addrs = ["127.0.0.1:5001"]
"###,
            data
        );

        let (key, data) = conf.get_toml(CATEGORY_PLUGIN).unwrap();
        assert_eq!("/plugins.toml", key);
        assert_eq!(
            r###"[plugins.stats]
category = "stats"
value = "/stats"
"###,
            data
        );

        let (key, data) = conf.get_toml("").unwrap();
        assert_eq!("/basic.toml", key);
        assert_eq!(
            r###"[basic]
error_template = ""
pid_file = "/tmp/pingap.pid"
upgrade_sock = "/tmp/pingap_upgrade.sock"
threads = 1
work_stealing = true
grace_period = "3m"
graceful_shutdown_timeout = "10s"
log_level = "info"
"###,
            data
        );

        assert_eq!("6DFE695D", conf.hash().unwrap());
    }

    #[test]
    fn test_pingap_diff() {
        let toml_data = include_bytes!("../../conf/pingap.toml");
        let conf = PingapConf::try_from(toml_data.to_vec().as_slice()).unwrap();

        let mut other = conf.clone();
        other.servers.insert(
            "github".to_string(),
            ServerConf {
                addr: "127.0.0.1:5123".to_string(),
                ..Default::default()
            },
        );

        other.remove(CATEGORY_UPSTREAM, "diving").unwrap();
        other.basic.threads = Some(5);

        let value = conf.diff(other);

        assert_eq!(
            r###"--upstream:diving

++server:github

basic
-threads = 1
+threads = 5

"###,
            value.join("\n")
        );
    }
}
