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

use crate::util;
use base64::{engine::general_purpose::STANDARD, Engine};
use glob::glob;
use http::HeaderValue;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use snafu::{ensure, ResultExt, Snafu};
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;
use toml::{map::Map, Value};
use url::Url;

pub const CATEGORY_UPSTREAM: &str = "upstream";
pub const CATEGORY_LOCATION: &str = "location";
pub const CATEGORY_SERVER: &str = "server";
pub const CATEGORY_PROXY_PLUGIN: &str = "proxy_plugin";

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("{message}"))]
    Invalid { message: String },
    #[snafu(display("Glob pattern error {source}, {path}"))]
    Pattern {
        source: glob::PatternError,
        path: String,
    },
    #[snafu(display("Glob error {source}"))]
    Glob { source: glob::GlobError },
    #[snafu(display("Io error {source}, {file}"))]
    Io {
        source: std::io::Error,
        file: String,
    },
    #[snafu(display("Toml de error {source}"))]
    De { source: toml::de::Error },
    #[snafu(display("Toml ser error {source}"))]
    Ser { source: toml::ser::Error },
    #[snafu(display("Url parse error {source}, {url}"))]
    UrlParse {
        source: url::ParseError,
        url: String,
    },
    #[snafu(display("Addr parse error {source}, {addr}"))]
    AddrParse {
        source: std::net::AddrParseError,
        addr: String,
    },
    #[snafu(display("base64 decode error {source}"))]
    Base64Decode { source: base64::DecodeError },
}
type Result<T, E = Error> = std::result::Result<T, E>;

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
    pub value: String,
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
                .context(AddrParseSnafu {
                    addr: format!("{}(upstream:{name})", arr[0]),
                });
        }
        // validate health check
        let health_check = self.health_check.clone().unwrap_or_default();
        if !health_check.is_empty() {
            let _ = Url::parse(&health_check).context(UrlParseSnafu { url: health_check })?;
        }

        Ok(())
    }
}

#[derive(Debug, Default, Deserialize, Clone, Serialize)]
pub struct LocationConf {
    pub upstream: String,
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
        validate(&self.proxy_headers)?;
        validate(&self.headers)?;
        if !upstream_names.contains(&self.upstream) {
            return Err(Error::Invalid {
                message: format!("{} upstream is not found(location:{name})", self.upstream),
            });
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
    pub remark: Option<String>,
}

impl ServerConf {
    /// Validate the options of server config.
    fn validate(&self, name: &str, location_names: &[String]) -> Result<()> {
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
            let _ = STANDARD.decode(value).context(Base64DecodeSnafu)?;
        }
        if let Some(value) = &self.tls_cert {
            let _ = STANDARD.decode(value).context(Base64DecodeSnafu)?;
        }

        Ok(())
    }
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct PingapConf {
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
    pub created_at: Option<String>,
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
        let data = toml::to_string_pretty(self).context(SerSnafu)?;
        let mut lines: Vec<&str> = data.split('\n').collect();
        lines.sort();
        let hash = crc32fast::hash(lines.join("\n").as_bytes());
        Ok(format!("{:X}", hash))
    }
}

#[derive(Deserialize, Debug, Serialize)]
struct TomlConfig {
    servers: Option<Map<String, Value>>,
    upstreams: Option<Map<String, Value>>,
    locations: Option<Map<String, Value>>,
    proxy_plugins: Option<Map<String, Value>>,
    error_template: Option<String>,
    pid_file: Option<String>,
    upgrade_sock: Option<String>,
    user: Option<String>,
    group: Option<String>,
    threads: Option<usize>,
    work_stealing: Option<bool>,
    created_at: Option<String>,
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
}

fn format_toml(value: &Value) -> String {
    if let Some(value) = value.as_table() {
        value.to_string()
    } else {
        "".to_string()
    }
}

/// Save the confog to path.
///
/// Validate the config before save.
pub fn save_config(path: &str, conf: &mut PingapConf, category: &str) -> Result<()> {
    conf.validate()?;
    conf.created_at = Some(chrono::Local::now().to_rfc3339());

    let mut filepath = util::resolve_path(path);
    let ping_conf = toml::to_string_pretty(&conf).context(SerSnafu)?;
    if Path::new(&filepath).is_file() {
        return std::fs::write(&filepath, ping_conf).context(IoSnafu { file: filepath });
    }
    // file path is dir
    let mut data: TomlConfig = toml::from_str(&ping_conf).context(DeSnafu)?;
    let conf = match category {
        CATEGORY_SERVER => {
            filepath = format!("{filepath}/servers.toml");
            let mut m = Map::new();
            let _ = m.insert(
                "servers".to_string(),
                toml::Value::Table(data.servers.unwrap_or_default()),
            );
            toml::to_string_pretty(&m).context(SerSnafu)?
        }
        CATEGORY_LOCATION => {
            filepath = format!("{filepath}/locations.toml");
            let mut m = Map::new();
            let _ = m.insert(
                "locations".to_string(),
                toml::Value::Table(data.locations.unwrap_or_default()),
            );
            toml::to_string_pretty(&m).context(SerSnafu)?
        }
        CATEGORY_UPSTREAM => {
            filepath = format!("{filepath}/upstreams.toml");
            let mut m = Map::new();
            let _ = m.insert(
                "upstreams".to_string(),
                toml::Value::Table(data.upstreams.unwrap_or_default()),
            );
            toml::to_string_pretty(&m).context(SerSnafu)?
        }
        CATEGORY_PROXY_PLUGIN => {
            filepath = format!("{filepath}/proxy_plugins.toml");
            let mut m = Map::new();
            let _ = m.insert(
                "proxy_plugins".to_string(),
                toml::Value::Table(data.proxy_plugins.unwrap_or_default()),
            );
            toml::to_string_pretty(&m).context(SerSnafu)?
        }
        _ => {
            filepath = format!("{filepath}/basic.toml");
            data.servers = None;
            data.locations = None;
            data.upstreams = None;
            toml::to_string_pretty(&data).context(SerSnafu)?
        }
    };
    std::fs::write(&filepath, conf).context(IoSnafu { file: filepath })
}

/// Load the config from path.
pub fn load_config(path: &str, admin: bool) -> Result<PingapConf> {
    let filepath = util::resolve_path(path);
    ensure!(
        !filepath.is_empty(),
        InvalidSnafu {
            message: "Config path is empty".to_string()
        }
    );

    if admin && !Path::new(&filepath).exists() {
        return Ok(PingapConf::default());
    }

    let mut data = vec![];
    if Path::new(&filepath).is_dir() {
        for entry in
            glob(&format!("{filepath}/**/*.toml")).context(PatternSnafu { path: filepath })?
        {
            let f = entry.context(GlobSnafu)?;
            let mut buf = std::fs::read(&f).context(IoSnafu {
                file: f.to_string_lossy().to_string(),
            })?;
            data.append(&mut buf);
            data.push(0x0a);
        }
    } else {
        let mut buf = std::fs::read(&filepath).context(IoSnafu { file: filepath })?;
        data.append(&mut buf);
    }
    let data: TomlConfig = toml::from_str(
        std::string::String::from_utf8_lossy(&data)
            .to_string()
            .as_str(),
    )
    .context(DeSnafu)?;
    let threads = if let Some(threads) = data.threads {
        if threads > 0 {
            Some(threads)
        } else {
            Some(num_cpus::get())
        }
    } else {
        None
    };
    let mut conf = PingapConf {
        error_template: data.error_template.unwrap_or_default(),
        pid_file: data.pid_file,
        upgrade_sock: data.upgrade_sock,
        user: data.user,
        group: data.group,
        threads,
        work_stealing: data.work_stealing,
        created_at: data.created_at,
        grace_period: data.grace_period,
        graceful_shutdown_timeout: data.graceful_shutdown_timeout,
        upstream_keepalive_pool_size: data.upstream_keepalive_pool_size,
        webhook: data.webhook,
        webhook_type: data.webhook_type,
        log_level: data.log_level,
        sentry: data.sentry,
        ..Default::default()
    };
    for (name, value) in data.upstreams.unwrap_or_default() {
        let upstream: UpstreamConf =
            toml::from_str(format_toml(&value).as_str()).context(DeSnafu)?;
        conf.upstreams.insert(name, upstream);
    }
    for (name, value) in data.locations.unwrap_or_default() {
        let location: LocationConf =
            toml::from_str(format_toml(&value).as_str()).context(DeSnafu)?;
        conf.locations.insert(name, location);
    }
    for (name, value) in data.servers.unwrap_or_default() {
        let server: ServerConf = toml::from_str(format_toml(&value).as_str()).context(DeSnafu)?;
        conf.servers.insert(name, server);
    }
    for (name, value) in data.proxy_plugins.unwrap_or_default() {
        let plugin: ProxyPluginConf =
            toml::from_str(format_toml(&value).as_str()).context(DeSnafu)?;
        conf.proxy_plugins.insert(name, plugin);
    }

    Ok(conf)
}
