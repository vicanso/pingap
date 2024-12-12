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
use crate::discovery::{is_static_discovery, DNS_DISCOVERY};
use crate::plugin::parse_plugins;
use crate::proxy::Parser;
use crate::util::{self, aes_decrypt, base64_decode};
use arc_swap::ArcSwap;
use bytesize::ByteSize;
use http::{HeaderName, HeaderValue};
use once_cell::sync::Lazy;
use once_cell::sync::OnceCell;
use regex::Regex;
use serde::{Deserialize, Serialize, Serializer};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::Cursor;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Duration;
use std::{collections::HashMap, str::FromStr};
use strum::EnumString;
use toml::Table;
use toml::{map::Map, Value};
use url::Url;

pub const CATEGORY_BASIC: &str = "basic";
pub const CATEGORY_SERVER: &str = "server";
pub const CATEGORY_LOCATION: &str = "location";
pub const CATEGORY_UPSTREAM: &str = "upstream";
pub const CATEGORY_PLUGIN: &str = "plugin";
pub const CATEGORY_CERTIFICATE: &str = "certificate";
pub const CATEGORY_STORAGE: &str = "storage";

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
    CombinedAuth,
    Jwt,
    Cache,
    Redirect,
    Ping,
    ResponseHeaders,
    RefererRestriction,
    UaRestriction,
    Csrf,
    Cors,
    AcceptEncoding,
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
        let category = PluginCategory::from_str(&value)
            .unwrap_or(PluginCategory::default());

        Ok(category)
    }
}

#[derive(
    PartialEq, Debug, Default, Clone, Copy, EnumString, strum::Display,
)]
#[strum(serialize_all = "snake_case")]
pub enum PluginStep {
    EarlyRequest,
    #[default]
    Request,
    ProxyUpstream,
    Response,
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
        let category =
            PluginStep::from_str(&value).unwrap_or(PluginStep::default());

        Ok(category)
    }
}

/// Convert pem to [u8]
fn convert_pem(value: &str) -> Result<Vec<u8>> {
    let buf = if util::is_pem(value) {
        value.as_bytes().to_vec()
    } else {
        base64_decode(value).map_err(|e| Error::Base64Decode { source: e })?
    };
    Ok(buf)
}

#[derive(Debug, Default, Deserialize, Clone, Serialize, Hash)]
pub struct CertificateConf {
    pub domains: Option<String>,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub tls_chain: Option<String>,
    pub is_default: Option<bool>,
    pub acme: Option<String>,
    pub remark: Option<String>,
}

fn validate_cert(value: &str) -> Result<()> {
    let buf = convert_pem(value)?;
    let mut key = Cursor::new(&buf);
    let mut err = None;
    let success = rustls_pemfile::certs(&mut key).all(|item| {
        if let Err(e) = &item {
            err = Some(Error::Invalid {
                message: e.to_string(),
            });
            return false;
        }
        true
    });
    if !success && err.is_some() {
        return Err(err.unwrap_or(Error::Invalid {
            message: "Invalid certitificate".to_string(),
        }));
    }
    Ok(())
}

impl CertificateConf {
    /// Get hash key of certificate config
    pub fn hash_key(&self) -> String {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
    /// Validate the options of certificate config.
    pub fn validate(&self) -> Result<()> {
        // convert private key
        if let Some(value) = &self.tls_key {
            let buf = convert_pem(value)?;
            let mut key = Cursor::new(buf);
            let _ = rustls_pemfile::private_key(&mut key).map_err(|e| {
                Error::Invalid {
                    message: e.to_string(),
                }
            })?;
        }
        // convert certificate
        if let Some(value) = &self.tls_cert {
            validate_cert(value)?;
        }
        // convert certificate chain
        if let Some(value) = &self.tls_chain {
            validate_cert(value)?;
        }
        Ok(())
    }
}

#[derive(Debug, Default, Deserialize, Clone, Serialize, Hash)]
pub struct UpstreamConf {
    pub addrs: Vec<String>,
    pub discovery: Option<String>,
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub update_frequency: Option<Duration>,
    pub algo: Option<String>,
    pub sni: Option<String>,
    pub verify_cert: Option<bool>,
    pub health_check: Option<String>,
    pub ipv4_only: Option<bool>,
    pub enable_tracer: Option<bool>,
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
    pub tcp_recv_buf: Option<ByteSize>,
    pub tcp_fast_open: Option<bool>,
    pub includes: Option<Vec<String>>,
    pub remark: Option<String>,
}
impl UpstreamConf {
    /// Get hash key of upstream config
    pub fn hash_key(&self) -> String {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
    pub fn guess_discovery(&self) -> String {
        if let Some(discovery) = &self.discovery {
            return discovery.to_string();
        }
        let exists_name_addr = self.addrs.iter().any(|item| {
            let host = if let Some((item, _)) = item.split_once(':') {
                item.to_string()
            } else {
                item.to_string()
            };
            host.parse::<std::net::IpAddr>().is_err()
        });
        if exists_name_addr {
            return DNS_DISCOVERY.to_string();
        }
        "".to_string()
    }
    /// Validate the options of upstream config.
    /// 1. The address list can't be empty, and can be converted to socket addr.
    /// 2. The health check url can be parsed to Url if it exists.
    pub fn validate(&self, name: &str) -> Result<()> {
        if self.addrs.is_empty() {
            return Err(Error::Invalid {
                message: "upstream addrs is empty".to_string(),
            });
        }
        // only validate upstream addr for static discovery
        if is_static_discovery(&self.guess_discovery()) {
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
        }
        // validate health check
        let health_check = self.health_check.clone().unwrap_or_default();
        if !health_check.is_empty() {
            let _ = Url::parse(&health_check).map_err(|e| Error::UrlParse {
                source: e,
                url: health_check,
            })?;
        }
        let max_tcp_probe_count = 16;
        if self.tcp_probe_count.unwrap_or_default() > max_tcp_probe_count {
            return Err(Error::Invalid {
                message: format!(
                    "tcp probe count should be <= {max_tcp_probe_count}"
                ),
            });
        }

        Ok(())
    }
}

#[derive(Debug, Default, Deserialize, Clone, Serialize, Hash)]
pub struct LocationConf {
    pub upstream: Option<String>,
    pub path: Option<String>,
    pub host: Option<String>,
    pub proxy_set_headers: Option<Vec<String>>,
    pub proxy_add_headers: Option<Vec<String>>,
    pub rewrite: Option<String>,
    pub weight: Option<u16>,
    pub plugins: Option<Vec<String>>,
    pub client_max_body_size: Option<ByteSize>,
    pub max_processing: Option<i32>,
    pub includes: Option<Vec<String>>,
    pub grpc_web: Option<bool>,
    pub remark: Option<String>,
}

impl LocationConf {
    /// Get hash key of location config
    pub fn hash_key(&self) -> String {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
    /// Validate the options of location config.
    /// 1. Convert add and set headers to (HeaderName, HeaderValue).
    /// 2. Parse rewrite path to regexp if it exists.
    fn validate(&self, name: &str, upstream_names: &[String]) -> Result<()> {
        // validate header for http
        let validate = |headers: &Option<Vec<String>>| -> Result<()> {
            if let Some(headers) = headers {
                for header in headers.iter() {
                    let arr = header
                        .split_once(':')
                        .map(|(k, v)| (k.trim(), v.trim()));
                    if arr.is_none() {
                        return Err(Error::Invalid {
                            message: format!(
                                "header {header} is invalid(location:{name})"
                            ),
                        });
                    }
                    let (header_name, header_value) = arr.unwrap();
                    HeaderName::from_bytes(header_name.as_bytes()).map_err(|err| Error::Invalid {
                        message: format!("header name({header_name}) is invalid, error: {err}(location:{name})"),
                    })?;
                    HeaderValue::from_str(header_value).map_err(|err| Error::Invalid {
                        message: format!("header value({header_value}) is invalid, error: {err}(location:{name})"),
                    })?;
                }
            }
            Ok(())
        };

        let upstream = self.upstream.clone().unwrap_or_default();
        if !upstream.is_empty() && !upstream_names.contains(&upstream) {
            return Err(Error::Invalid {
                message: format!(
                    "upstream({upstream}) is not found(location:{name})"
                ),
            });
        }
        validate(&self.proxy_add_headers)?;
        validate(&self.proxy_set_headers)?;

        if let Some(value) = &self.rewrite {
            let arr: Vec<&str> = value.split(' ').collect();
            let _ =
                Regex::new(arr[0]).map_err(|e| Error::Regex { source: e })?;
        }

        Ok(())
    }
    /// Get weight of location, which is calculated from the domain name, path and path length
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
        let path = self.path.clone().unwrap_or("".to_string());
        if path.len() > 1 {
            if path.starts_with('=') {
                weight += 1024;
            } else if path.starts_with('~') {
                weight += 256;
            } else {
                weight += 512;
            }
            weight += path.len().min(64) as u16;
        };
        if !self.host.clone().unwrap_or_default().is_empty() {
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
    pub tls_cipher_list: Option<String>,
    pub tls_ciphersuites: Option<String>,
    pub tls_min_version: Option<String>,
    pub tls_max_version: Option<String>,
    pub global_certificates: Option<bool>,
    pub enabled_h2: Option<bool>,
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub tcp_idle: Option<Duration>,
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub tcp_interval: Option<Duration>,
    pub tcp_probe_count: Option<usize>,
    pub tcp_fastopen: Option<usize>,
    pub prometheus_metrics: Option<String>,
    pub otlp_exporter: Option<String>,
    pub includes: Option<Vec<String>>,
    pub modules: Option<Vec<String>>,
    pub remark: Option<String>,
}

impl ServerConf {
    /// Validate the options of server config.
    /// 1. Parse listen addr to socket addr.
    /// 2. Check the locations are exists.
    /// 3. Parse access log layout success.
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
                        message: format!(
                            "location({item}) is not found(server:{name})"
                        ),
                    });
                }
            }
        }

        if let Some(access_log) = &self.access_log {
            let logger = Parser::from(access_log.as_str());
            if logger.tags.is_empty() {
                return Err(Error::Invalid {
                    message: "access log format is invalid".to_string(),
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
    pub log_buffered_size: Option<ByteSize>,
    pub log_format_json: Option<bool>,
    pub sentry: Option<String>,
    pub pyroscope: Option<String>,
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub auto_restart_check_interval: Option<Duration>,
    pub cache_directory: Option<String>,
    pub cache_max_size: Option<ByteSize>,
}

impl BasicConf {
    pub fn get_pid_file(&self) -> String {
        if let Some(pid_file) = &self.pid_file {
            pid_file.clone()
        } else {
            format!("/run/{}.pid", util::get_pkg_name())
        }
    }
}

#[derive(Debug, Default, Deserialize, Clone, Serialize)]
pub struct StorageConf {
    pub category: String,
    pub value: String,
    pub secret: Option<String>,
    pub remark: Option<String>,
}

#[derive(Deserialize, Debug, Serialize)]
struct TomlConfig {
    basic: Option<BasicConf>,
    servers: Option<Map<String, Value>>,
    upstreams: Option<Map<String, Value>>,
    locations: Option<Map<String, Value>>,
    plugins: Option<Map<String, Value>>,
    certificates: Option<Map<String, Value>>,
    storages: Option<Map<String, Value>>,
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
    pub certificates: HashMap<String, CertificateConf>,
    pub storages: HashMap<String, StorageConf>,
}

impl PingapConf {
    pub fn get_toml(
        &self,
        category: &str,
        name: Option<&str>,
    ) -> Result<(String, String)> {
        let ping_conf = toml::to_string_pretty(self)
            .map_err(|e| Error::Ser { source: e })?;
        let data: TomlConfig =
            toml::from_str(&ping_conf).map_err(|e| Error::De { source: e })?;

        let filter_values = |mut values: Map<String, Value>| {
            let name = name.unwrap_or_default();
            if name.is_empty() {
                return values;
            }
            let remove_keys: Vec<_> = values
                .keys()
                .filter(|key| *key != name)
                .map(|key| key.to_string())
                .collect();
            for key in remove_keys {
                values.remove(&key);
            }
            values
        };
        let get_path = |key: &str| {
            let name = name.unwrap_or_default();
            if key == CATEGORY_BASIC || name.is_empty() {
                return format!("/{key}.toml");
            }
            format!("/{key}/{name}.toml")
        };

        let (key, value) = match category {
            CATEGORY_SERVER => {
                ("servers", filter_values(data.servers.unwrap_or_default()))
            },
            CATEGORY_LOCATION => (
                "locations",
                filter_values(data.locations.unwrap_or_default()),
            ),
            CATEGORY_UPSTREAM => (
                "upstreams",
                filter_values(data.upstreams.unwrap_or_default()),
            ),
            CATEGORY_PLUGIN => {
                ("plugins", filter_values(data.plugins.unwrap_or_default()))
            },
            CATEGORY_CERTIFICATE => (
                "certificates",
                filter_values(data.certificates.unwrap_or_default()),
            ),
            CATEGORY_STORAGE => {
                ("storages", filter_values(data.storages.unwrap_or_default()))
            },
            _ => {
                let value = toml::to_string(&data.basic.unwrap_or_default())
                    .map_err(|e| Error::Ser { source: e })?;
                let m: Map<String, Value> = toml::from_str(&value)
                    .map_err(|e| Error::De { source: e })?;
                ("basic", m)
            },
        };
        let path = get_path(key);
        if value.is_empty() {
            return Ok((path, "".to_string()));
        }

        let mut m = Map::new();
        let _ = m.insert(key.to_string(), toml::Value::Table(value));
        let value =
            toml::to_string_pretty(&m).map_err(|e| Error::Ser { source: e })?;
        Ok((path, value))
    }
    pub fn get_storage_value(&self, name: &str) -> Result<String> {
        for (key, item) in self.storages.iter() {
            if key != name {
                continue;
            }

            if let Some(key) = &item.secret {
                return aes_decrypt(key, &item.value).map_err(|e| {
                    Error::Invalid {
                        message: e.to_string(),
                    }
                });
            }
            return Ok(item.value.clone());
        }
        Ok("".to_string())
    }
}

fn convert_include_toml(
    data: &HashMap<String, String>,
    replace_includes: bool,
    mut value: Value,
) -> String {
    let Some(m) = value.as_table_mut() else {
        return "".to_string();
    };
    if !replace_includes {
        return m.to_string();
    }
    if let Some(includes) = m.remove("includes") {
        if let Some(includes) = get_include_toml(data, includes) {
            if let Ok(includes) = toml::from_str::<Table>(&includes) {
                for (key, value) in includes.iter() {
                    m.insert(key.to_string(), value.clone());
                }
            }
        }
    }
    m.to_string()
}

fn get_include_toml(
    data: &HashMap<String, String>,
    includes: Value,
) -> Option<String> {
    let values = includes.as_array()?;
    let arr: Vec<String> = values
        .iter()
        .map(|item| {
            let key = item.as_str().unwrap_or_default();
            if let Some(value) = data.get(key) {
                value.clone()
            } else {
                "".to_string()
            }
        })
        .collect();
    Some(arr.join("\n"))
}

fn convert_pingap_config(
    data: &[u8],
    replace_includes: bool,
) -> Result<PingapConf, Error> {
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
    let mut includes = HashMap::new();
    for (name, value) in data.storages.unwrap_or_default() {
        let toml = format_toml(&value);
        let storage: StorageConf = toml::from_str(toml.as_str())
            .map_err(|e| Error::De { source: e })?;
        includes.insert(name.clone(), storage.value.clone());
        conf.storages.insert(name, storage);
    }

    for (name, value) in data.upstreams.unwrap_or_default() {
        let toml = convert_include_toml(&includes, replace_includes, value);

        let upstream: UpstreamConf = toml::from_str(toml.as_str())
            .map_err(|e| Error::De { source: e })?;
        conf.upstreams.insert(name, upstream);
    }
    for (name, value) in data.locations.unwrap_or_default() {
        let toml = convert_include_toml(&includes, replace_includes, value);

        let location: LocationConf = toml::from_str(toml.as_str())
            .map_err(|e| Error::De { source: e })?;
        conf.locations.insert(name, location);
    }
    for (name, value) in data.servers.unwrap_or_default() {
        let toml = convert_include_toml(&includes, replace_includes, value);

        let server: ServerConf = toml::from_str(toml.as_str())
            .map_err(|e| Error::De { source: e })?;
        conf.servers.insert(name, server);
    }
    for (name, value) in data.plugins.unwrap_or_default() {
        let plugin: PluginConf = toml::from_str(format_toml(&value).as_str())
            .map_err(|e| Error::De { source: e })?;
        conf.plugins.insert(name, plugin);
    }

    for (name, value) in data.certificates.unwrap_or_default() {
        let certificate: CertificateConf =
            toml::from_str(format_toml(&value).as_str())
                .map_err(|e| Error::De { source: e })?;
        conf.certificates.insert(name, certificate);
    }

    Ok(conf)
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
struct Description {
    category: String,
    name: String,
    data: String,
}

impl PingapConf {
    pub fn new(data: &[u8], replace_includes: bool) -> Result<Self> {
        convert_pingap_config(data, replace_includes)
    }
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
        let mut listen_addr_list = vec![];
        for (name, server) in self.servers.iter() {
            for addr in server.addr.split(',') {
                if listen_addr_list.contains(&addr.to_string()) {
                    return Err(Error::Invalid {
                        message: format!("{addr} is inused by other server"),
                    });
                }
                listen_addr_list.push(addr.to_string());
            }
            server.validate(name, &location_names)?;
        }
        for (name, plugin) in self.plugins.iter() {
            parse_plugins(vec![(name.to_string(), plugin.clone())]).map_err(
                |e| Error::Invalid {
                    message: e.to_string(),
                },
            )?;
        }
        for (_, certificate) in self.certificates.iter() {
            certificate.validate()?;
        }
        let ping_conf = toml::to_string_pretty(self)
            .map_err(|e| Error::Ser { source: e })?;
        convert_pingap_config(ping_conf.as_bytes(), true)?;
        Ok(())
    }
    /// Generate the content hash of config.
    pub fn hash(&self) -> Result<String> {
        let mut lines = vec![];
        for desc in self.descriptions() {
            lines.push(desc.category);
            lines.push(desc.name);
            lines.push(desc.data);
        }
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
                        message: format!("upstream({name}) is in used"),
                    });
                }

                self.upstreams.remove(name);
            },
            CATEGORY_LOCATION => {
                for server in self.servers.values() {
                    if server
                        .locations
                        .clone()
                        .unwrap_or_default()
                        .contains(&name.to_string())
                    {
                        return Err(Error::Invalid {
                            message: format!("location({name}) is in used"),
                        });
                    }
                }
                self.locations.remove(name);
            },
            CATEGORY_SERVER => {
                self.servers.remove(name);
            },
            CATEGORY_PLUGIN => {
                let mut all_plugins = vec![];
                for lo in self.locations.values() {
                    if let Some(plguins) = &lo.plugins {
                        all_plugins.extend(plguins.clone());
                    }
                }
                if all_plugins.contains(&name.to_string()) {
                    return Err(Error::Invalid {
                        message: format!("proxy plugin({name}) is in used"),
                    });
                }
                self.plugins.remove(name);
            },
            CATEGORY_CERTIFICATE => {
                self.certificates.remove(name);
            },
            _ => {},
        };
        Ok(())
    }
    fn descriptions(&self) -> Vec<Description> {
        let mut value = self.clone();
        let mut descriptions = vec![];
        for (name, data) in value.servers.iter() {
            descriptions.push(Description {
                category: CATEGORY_SERVER.to_string(),
                name: format!("server:{name}"),
                data: toml::to_string_pretty(data).unwrap_or_default(),
            });
        }
        for (name, data) in value.locations.iter() {
            descriptions.push(Description {
                category: CATEGORY_LOCATION.to_string(),
                name: format!("location:{name}"),
                data: toml::to_string_pretty(data).unwrap_or_default(),
            });
        }
        for (name, data) in value.upstreams.iter() {
            descriptions.push(Description {
                category: CATEGORY_UPSTREAM.to_string(),
                name: format!("upstream:{name}"),
                data: toml::to_string_pretty(data).unwrap_or_default(),
            });
        }
        for (name, data) in value.plugins.iter() {
            descriptions.push(Description {
                category: CATEGORY_PLUGIN.to_string(),
                name: format!("plugin:{name}"),
                data: toml::to_string_pretty(data).unwrap_or_default(),
            });
        }
        for (name, data) in value.certificates.iter() {
            descriptions.push(Description {
                category: CATEGORY_CERTIFICATE.to_string(),
                name: format!("certificate:{name}"),
                data: toml::to_string_pretty(data).unwrap_or_default(),
            });
        }
        for (name, data) in value.storages.iter() {
            descriptions.push(Description {
                category: CATEGORY_STORAGE.to_string(),
                name: format!("storage:{name}"),
                data: toml::to_string_pretty(data).unwrap_or_default(),
            });
        }
        value.servers = HashMap::new();
        value.locations = HashMap::new();
        value.upstreams = HashMap::new();
        value.plugins = HashMap::new();
        value.certificates = HashMap::new();
        value.storages = HashMap::new();
        descriptions.push(Description {
            category: CATEGORY_BASIC.to_string(),
            name: CATEGORY_BASIC.to_string(),
            data: toml::to_string_pretty(&value).unwrap_or_default(),
        });
        descriptions.sort_by_key(|d| d.name.clone());
        descriptions
    }
    /// Get the different content of two config.
    pub fn diff(&self, other: &PingapConf) -> (Vec<String>, Vec<String>) {
        let mut category_list = vec![];

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
                category_list.push(item.category.clone());
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
                category_list.push(new_item.category.clone());
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
                        diff::Result::Left(l) => {
                            item_diff_result.push(format!("-{}", l))
                        },
                        diff::Result::Right(r) => {
                            item_diff_result.push(format!("+{}", r))
                        },
                        _ => {},
                    };
                }
                if !item_diff_result.is_empty() {
                    diff_result.push(item.name.clone());
                    diff_result.extend(item_diff_result);
                    diff_result.push("\n".to_string());
                    category_list.push(item.category.clone());
                }
            }
        }

        (category_list, diff_result)
    }
}

static CURRENT_CONFIG: Lazy<ArcSwap<PingapConf>> =
    Lazy::new(|| ArcSwap::from_pointee(PingapConf::default()));
/// Set current config of pingap.
pub fn set_current_config(value: &PingapConf) {
    CURRENT_CONFIG.store(Arc::new(value.clone()));
}

/// Get the running pingap config.
pub fn get_current_config() -> Arc<PingapConf> {
    CURRENT_CONFIG.load().clone()
}

static DEFAULT_APP_NAME: &str = "Pingap";

static APP_NAME: OnceCell<String> = OnceCell::new();
/// Set app name, it only can set once
pub fn set_app_name(name: &str) {
    APP_NAME.get_or_init(|| {
        if name.is_empty() {
            DEFAULT_APP_NAME.to_string()
        } else {
            name.to_string()
        }
    });
}

/// Get app name
pub fn get_app_name() -> String {
    if let Some(name) = APP_NAME.get() {
        name.to_string()
    } else {
        DEFAULT_APP_NAME.to_string()
    }
}

/// Get current running pingap's config crc hash
pub fn get_config_hash() -> String {
    get_current_config().hash().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{
        get_app_name, get_config_hash, set_app_name, set_current_config,
        validate_cert, BasicConf, CertificateConf, PluginStep,
    };
    use super::{
        LocationConf, PingapConf, PluginCategory, ServerConf, UpstreamConf,
        CATEGORY_LOCATION, CATEGORY_PLUGIN, CATEGORY_SERVER, CATEGORY_UPSTREAM,
    };
    use crate::util::base64_encode;
    use pretty_assertions::assert_eq;
    use serde::{Deserialize, Serialize};
    use std::str::FromStr;

    #[test]
    fn test_plugin_step() {
        let step = PluginStep::from_str("early_request").unwrap();
        assert_eq!(step, PluginStep::EarlyRequest);

        assert_eq!("early_request", step.to_string());
    }

    #[test]
    fn test_validate_cert() {
        let pem = r#"-----BEGIN CERTIFICATE-----
MIIEljCCAv6gAwIBAgIQeYUdeFj3gpzhQes3aGaMZTANBgkqhkiG9w0BAQsFADCB
pTEeMBwGA1UEChMVbWtjZXJ0IGRldmVsb3BtZW50IENBMT0wOwYDVQQLDDR4aWVz
aHV6aG91QHhpZXNodXpob3VzLU1hY0Jvb2stQWlyLmxvY2FsICjosKLmoJHmtLIp
MUQwQgYDVQQDDDtta2NlcnQgeGllc2h1emhvdUB4aWVzaHV6aG91cy1NYWNCb29r
LUFpci5sb2NhbCAo6LCi5qCR5rSyKTAeFw0yMzA5MjQxMzA1MjdaFw0yNTEyMjQx
MzA1MjdaMGgxJzAlBgNVBAoTHm1rY2VydCBkZXZlbG9wbWVudCBjZXJ0aWZpY2F0
ZTE9MDsGA1UECww0eGllc2h1emhvdUB4aWVzaHV6aG91cy1NYWNCb29rLUFpci5s
b2NhbCAo6LCi5qCR5rSyKTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
ALuJ8lYEj9uf4iE9hguASq7re87Np+zJc2x/eqr1cR/SgXRStBsjxqI7i3xwMRqX
AuhAnM6ktlGuqidl7D9y6AN/UchqgX8AetslRJTpCcEDfL/q24zy0MqOS0FlYEgh
s4PIjWsSNoglBDeaIdUpN9cM/64IkAAtHndNt2p2vPfjrPeixLjese096SKEnZM/
xBdWF491hx06IyzjtWKqLm9OUmYZB9d/gDGnDsKpqClw8m95opKD4TBHAoE//WvI
m1mZnjNTNR27vVbmnc57d2Lx2Ib2eqJG5zMsP2hPBoqS8CKEwMRFLHAcclNkI67U
kcSEGaWgr15QGHJPN/FtjDsCAwEAAaN+MHwwDgYDVR0PAQH/BAQDAgWgMBMGA1Ud
JQQMMAoGCCsGAQUFBwMBMB8GA1UdIwQYMBaAFJo0y9bYUM/OuenDjsJ1RyHJfL3n
MDQGA1UdEQQtMCuCBm1lLmRldoIJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAA
AAAAAAABMA0GCSqGSIb3DQEBCwUAA4IBgQAlQbow3+4UyQx+E+J0RwmHBltU6i+K
soFfza6FWRfAbTyv+4KEWl2mx51IfHhJHYZvsZqPqGWxm5UvBecskegDExFMNFVm
O5QixydQzHHY2krmBwmDZ6Ao88oW/qw4xmMUhzKAZbsqeQyE/uiUdyI4pfDcduLB
rol31g9OFsgwZrZr0d1ZiezeYEhemnSlh9xRZW3veKx9axgFttzCMmWdpGTCvnav
ZVc3rB+KBMjdCwsS37zmrNm9syCjW1O5a1qphwuMpqSnDHBgKWNpbsgqyZM0oyOc
9Bkja+BV5wFO+4zH5WtestcrNMeoQ83a5lI0m42u/bUEJ/T/5BQBSFidNuvS7Ylw
IZpXa00xvlnm1BOHOfRI4Ehlfa5jmfcdnrGkQLGjiyygQtKcc7rOXGK+mSeyxwhs
sIARwslSQd4q0dbYTPKvvUHxTYiCv78vQBAsE15T2GGS80pAFDBW9vOf3upANvOf
EHjKf0Dweb4ppL4ddgeAKU5V0qn76K2fFaE=
-----END CERTIFICATE-----"#;
        let result = validate_cert(pem);
        assert_eq!(true, result.is_ok());

        let value = base64_encode(pem);
        let result = validate_cert(&value);
        assert_eq!(true, result.is_ok());
    }

    #[test]
    fn test_app_name() {
        assert_eq!("Pingap", get_app_name());
        set_app_name("Pingap-X");
        assert_eq!("Pingap-X", get_app_name());
    }

    #[test]
    fn test_current_config() {
        let conf = PingapConf {
            basic: BasicConf {
                name: Some("Pingap-X".to_string()),
                threads: Some(5),
                ..Default::default()
            },
            ..Default::default()
        };
        set_current_config(&conf);
        assert_eq!("B7B8046B", get_config_hash());
    }

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
        conf.discovery = Some("common".to_string());
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
            "Invalid error header X-Request-Id is invalid(location:lo)",
            result.expect_err("").to_string()
        );

        conf.proxy_set_headers = Some(vec!["请求:响应".to_string()]);
        let result = conf.validate("lo", &upstream_names);
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Invalid error header name(请求) is invalid, error: invalid HTTP header name(location:lo)",
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

        conf.host = Some("".to_string());
        assert_eq!(0, conf.get_weight());
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
        let result = conf.validate("test", &location_names);
        assert_eq!(true, result.is_ok());
    }

    #[test]
    fn test_certificate_conf() {
        let pem = r#"-----BEGIN CERTIFICATE-----
MIIEljCCAv6gAwIBAgIQeYUdeFj3gpzhQes3aGaMZTANBgkqhkiG9w0BAQsFADCB
pTEeMBwGA1UEChMVbWtjZXJ0IGRldmVsb3BtZW50IENBMT0wOwYDVQQLDDR4aWVz
aHV6aG91QHhpZXNodXpob3VzLU1hY0Jvb2stQWlyLmxvY2FsICjosKLmoJHmtLIp
MUQwQgYDVQQDDDtta2NlcnQgeGllc2h1emhvdUB4aWVzaHV6aG91cy1NYWNCb29r
LUFpci5sb2NhbCAo6LCi5qCR5rSyKTAeFw0yMzA5MjQxMzA1MjdaFw0yNTEyMjQx
MzA1MjdaMGgxJzAlBgNVBAoTHm1rY2VydCBkZXZlbG9wbWVudCBjZXJ0aWZpY2F0
ZTE9MDsGA1UECww0eGllc2h1emhvdUB4aWVzaHV6aG91cy1NYWNCb29rLUFpci5s
b2NhbCAo6LCi5qCR5rSyKTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
ALuJ8lYEj9uf4iE9hguASq7re87Np+zJc2x/eqr1cR/SgXRStBsjxqI7i3xwMRqX
AuhAnM6ktlGuqidl7D9y6AN/UchqgX8AetslRJTpCcEDfL/q24zy0MqOS0FlYEgh
s4PIjWsSNoglBDeaIdUpN9cM/64IkAAtHndNt2p2vPfjrPeixLjese096SKEnZM/
xBdWF491hx06IyzjtWKqLm9OUmYZB9d/gDGnDsKpqClw8m95opKD4TBHAoE//WvI
m1mZnjNTNR27vVbmnc57d2Lx2Ib2eqJG5zMsP2hPBoqS8CKEwMRFLHAcclNkI67U
kcSEGaWgr15QGHJPN/FtjDsCAwEAAaN+MHwwDgYDVR0PAQH/BAQDAgWgMBMGA1Ud
JQQMMAoGCCsGAQUFBwMBMB8GA1UdIwQYMBaAFJo0y9bYUM/OuenDjsJ1RyHJfL3n
MDQGA1UdEQQtMCuCBm1lLmRldoIJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAA
AAAAAAABMA0GCSqGSIb3DQEBCwUAA4IBgQAlQbow3+4UyQx+E+J0RwmHBltU6i+K
soFfza6FWRfAbTyv+4KEWl2mx51IfHhJHYZvsZqPqGWxm5UvBecskegDExFMNFVm
O5QixydQzHHY2krmBwmDZ6Ao88oW/qw4xmMUhzKAZbsqeQyE/uiUdyI4pfDcduLB
rol31g9OFsgwZrZr0d1ZiezeYEhemnSlh9xRZW3veKx9axgFttzCMmWdpGTCvnav
ZVc3rB+KBMjdCwsS37zmrNm9syCjW1O5a1qphwuMpqSnDHBgKWNpbsgqyZM0oyOc
9Bkja+BV5wFO+4zH5WtestcrNMeoQ83a5lI0m42u/bUEJ/T/5BQBSFidNuvS7Ylw
IZpXa00xvlnm1BOHOfRI4Ehlfa5jmfcdnrGkQLGjiyygQtKcc7rOXGK+mSeyxwhs
sIARwslSQd4q0dbYTPKvvUHxTYiCv78vQBAsE15T2GGS80pAFDBW9vOf3upANvOf
EHjKf0Dweb4ppL4ddgeAKU5V0qn76K2fFaE=
-----END CERTIFICATE-----"#;
        let key = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7ifJWBI/bn+Ih
PYYLgEqu63vOzafsyXNsf3qq9XEf0oF0UrQbI8aiO4t8cDEalwLoQJzOpLZRrqon
Zew/cugDf1HIaoF/AHrbJUSU6QnBA3y/6tuM8tDKjktBZWBIIbODyI1rEjaIJQQ3
miHVKTfXDP+uCJAALR53Tbdqdrz346z3osS43rHtPekihJ2TP8QXVhePdYcdOiMs
47Viqi5vTlJmGQfXf4Axpw7CqagpcPJveaKSg+EwRwKBP/1ryJtZmZ4zUzUdu71W
5p3Oe3di8diG9nqiRuczLD9oTwaKkvAihMDERSxwHHJTZCOu1JHEhBmloK9eUBhy
TzfxbYw7AgMBAAECggEALjed0FMJfO+XE+gMm9L/FMKV3W5TXwh6eJemDHG2ckg3
fQpQtouHjT2tb3par5ndro0V19tBzzmDV3hH048m3I3JAuI0ja75l/5EO4p+y+Fn
IgjoGIFSsUiGBVTNeJlNm0GWkHeJlt3Af09t3RFuYIIklKgpjNGRu4ccl5ExmslF
WHv7/1dwzeJCi8iOY2gJZz6N7qHD95VkgVyDj/EtLltONAtIGVdorgq70CYmtwSM
9XgXszqOTtSJxle+UBmeQTL4ZkUR0W+h6JSpcTn0P9c3fiNDrHSKFZbbpAhO/wHd
Ab4IK8IksVyg+tem3m5W9QiXn3WbgcvjJTi83Y3syQKBgQD5IsaSbqwEG3ruttQe
yfMeq9NUGVfmj7qkj2JiF4niqXwTpvoaSq/5gM/p7lAtSMzhCKtlekP8VLuwx8ih
n4hJAr8pGfyu/9IUghXsvP2DXsCKyypbhzY/F2m4WNIjtyLmed62Nt1PwWWUlo9Q
igHI6pieT45vJTBICsRyqC/a/wKBgQDAtLXUsCABQDTPHdy/M/dHZA/QQ/xU8NOs
ul5UMJCkSfFNk7b2etQG/iLlMSNup3bY3OPvaCGwwEy/gZ31tTSymgooXQMFxJ7G
1S/DF45yKD6xJEmAUhwz/Hzor1cM95g78UpZFCEVMnEmkBNb9pmrXRLDuWb0vLE6
B6YgiEP6xQKBgBOXuooVjg2co6RWWIQ7WZVV6f65J4KIVyNN62zPcRaUQZ/CB/U9
Xm1+xdsd1Mxa51HjPqdyYBpeB4y1iX+8bhlfz+zJkGeq0riuKk895aoJL5c6txAP
qCJ6EuReh9grNOFvQCaQVgNJsFVpKcgpsk48tNfuZcMz54Ii5qQlue29AoGAA2Sr
Nv2K8rqws1zxQCSoHAe1B5PK46wB7i6x7oWUZnAu4ZDSTfDHvv/GmYaN+yrTuunY
0aRhw3z/XPfpUiRIs0RnHWLV5MobiaDDYIoPpg7zW6cp7CqF+JxfjrFXtRC/C38q
MftawcbLm0Q6MwpallvjMrMXDwQrkrwDvtrnZ4kCgYEA0oSvmSK5ADD0nqYFdaro
K+hM90AVD1xmU7mxy3EDPwzjK1wZTj7u0fvcAtZJztIfL+lmVpkvK8KDLQ9wCWE7
SGToOzVHYX7VazxioA9nhNne9kaixvnIUg3iowAz07J7o6EU8tfYsnHxsvjlIkBU
ai02RHnemmqJaNepfmCdyec=
-----END PRIVATE KEY-----"#;
        let conf = CertificateConf {
            tls_cert: Some(pem.to_string()),
            tls_key: Some(key.to_string()),
            ..Default::default()
        };
        let result = conf.validate();
        assert_eq!(true, result.is_ok());

        assert_eq!("488642d0e54f33b6", conf.hash_key());
    }

    #[test]
    fn test_pingap_conf() {
        let toml_data = include_bytes!("../../conf/pingap.toml");
        let conf =
            PingapConf::new(toml_data.to_vec().as_slice(), false).unwrap();
        let full_conf =
            PingapConf::new(toml_data.to_vec().as_slice(), true).unwrap();

        let (key, data) = conf.get_toml(CATEGORY_SERVER, None).unwrap();
        assert_eq!("/servers.toml", key);
        assert_eq!(
            r###"[servers.test]
access_log = "tiny"
addr = "0.0.0.0:6188"
enabled_h2 = false
global_certificates = false
locations = ["lo"]
prometheus_metrics = ""
tcp_idle = "2m"
tcp_interval = "1m"
tcp_probe_count = 9
threads = 1
tls_cipher_list = ""
tls_ciphersuites = ""
tls_max_version = ""
tls_min_version = ""
"###,
            data
        );

        let (key, data) = conf.get_toml(CATEGORY_LOCATION, None).unwrap();
        assert_eq!("/locations.toml", key);
        assert_eq!(
            r###"[locations.lo]
client_max_body_size = "1000.0 KB"
host = ""
includes = ["proxySetHeader"]
path = "/"
plugins = [
    "pingap:requestId",
    "stats",
]
proxy_add_headers = ["name:value"]
rewrite = ""
upstream = "charts"
weight = 1024
"###,
            data
        );

        let (_, data) = full_conf.get_toml(CATEGORY_LOCATION, None).unwrap();
        assert_eq!(
            r###"[locations.lo]
client_max_body_size = "1000.0 KB"
host = ""
path = "/"
plugins = [
    "pingap:requestId",
    "stats",
]
proxy_add_headers = ["name:value"]
proxy_set_headers = ["name:value"]
rewrite = ""
upstream = "charts"
weight = 1024
"###,
            data
        );

        let (key, data) = conf.get_toml(CATEGORY_UPSTREAM, None).unwrap();
        assert_eq!("/upstreams.toml", key);
        assert_eq!(
            r###"[upstreams.charts]
addrs = ["127.0.0.1:5000"]
algo = "hash:cookie"
alpn = "h1"
connection_timeout = "10s"
discovery = ""
enable_tracer = false
health_check = "http://charts/ping?connection_timeout=3s&pingap"
idle_timeout = "2m"
ipv4_only = false
read_timeout = "10s"
sni = ""
tcp_fast_open = true
tcp_idle = "2m"
tcp_interval = "1m"
tcp_probe_count = 9
tcp_recv_buf = "4.0 KB"
total_connection_timeout = "30s"
update_frequency = "1m"
verify_cert = true
write_timeout = "10s"

[upstreams.diving]
addrs = ["127.0.0.1:5001"]
"###,
            data
        );

        let (key, data) = conf.get_toml(CATEGORY_PLUGIN, None).unwrap();
        assert_eq!("/plugins.toml", key);
        assert_eq!(
            r###"[plugins.stats]
category = "stats"
value = "/stats"
"###,
            data
        );

        let (key, data) = conf.get_toml("", None).unwrap();
        assert_eq!("/basic.toml", key);
        assert_eq!(
            r###"[basic]
auto_restart_check_interval = "1m"
cache_directory = ""
cache_max_size = "100.0 MB"
error_template = ""
grace_period = "3m"
graceful_shutdown_timeout = "10s"
log_format_json = false
log_level = "info"
name = "pingap"
pid_file = "/run/pingap.pid"
sentry = ""
threads = 1
upgrade_sock = "/tmp/pingap_upgrade.sock"
work_stealing = true
"###,
            data
        );

        let auth_token = conf.get_storage_value("authToken").unwrap();
        assert_eq!("47.107.66.241", auth_token);
    }

    #[test]
    fn test_pingap_diff() {
        let toml_data = include_bytes!("../../conf/pingap.toml");
        let conf =
            PingapConf::new(toml_data.to_vec().as_slice(), false).unwrap();

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

        let value = conf.diff(&other);

        assert_eq!(
            r###"--upstream:diving

++server:github

basic
-threads = 1
+threads = 5

"###,
            value.1.join("\n")
        );
    }

    #[test]
    fn test_config_remove() {
        let toml_data = include_bytes!("../../conf/pingap.toml");
        let mut conf =
            PingapConf::new(toml_data.to_vec().as_slice(), false).unwrap();

        let result = conf.remove("plugin", "stats");
        assert_eq!(
            "Invalid error proxy plugin(stats) is in used",
            result.err().unwrap().to_string()
        );

        let result = conf.remove("upstream", "charts");
        assert_eq!(
            "Invalid error upstream(charts) is in used",
            result.err().unwrap().to_string()
        );

        let result = conf.remove("location", "lo");
        assert_eq!(
            "Invalid error location(lo) is in used",
            result.err().unwrap().to_string()
        );

        let result = conf.remove("server", "test");
        assert_eq!(true, result.is_ok());

        let result = conf.remove("location", "lo");
        assert_eq!(true, result.is_ok());

        let result = conf.remove("upstream", "charts");
        assert_eq!(true, result.is_ok());

        let result = conf.remove("plugin", "stats");
        assert_eq!(true, result.is_ok());
    }
}
