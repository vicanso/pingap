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

use super::{ConfigStorage, Error, Result};
use super::{LocationConf, PingapConf, ProxyPluginConf, ServerConf, UpstreamConf};
use super::{CATEGORY_LOCATION, CATEGORY_PROXY_PLUGIN, CATEGORY_SERVER, CATEGORY_UPSTREAM};
use crate::util;
use glob::glob;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;
use toml::{map::Map, Value};

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

fn format_toml(value: &Value) -> String {
    if let Some(value) = value.as_table() {
        value.to_string()
    } else {
        "".to_string()
    }
}

pub struct FileStorage {
    path: String,
}
impl FileStorage {
    pub fn new(path: &str) -> Result<Self> {
        let filepath = util::resolve_path(path);
        if filepath.is_empty() {
            return Err(Error::Invalid {
                message: "Config path is empty".to_string(),
            });
        }

        Ok(Self { path: filepath })
    }
}

impl ConfigStorage for FileStorage {
    fn load_config(&self, admin: bool) -> Result<PingapConf> {
        let filepath = self.path.clone();
        if admin && !Path::new(&filepath).exists() {
            return Ok(PingapConf::default());
        }

        let mut data = vec![];
        if Path::new(&filepath).is_dir() {
            for entry in glob(&format!("{filepath}/**/*.toml")).map_err(|e| Error::Pattern {
                source: e,
                path: filepath,
            })? {
                let f = entry.map_err(|e| Error::Glob { source: e })?;
                let mut buf = std::fs::read(&f).map_err(|e| Error::Io {
                    source: e,
                    file: f.to_string_lossy().to_string(),
                })?;
                data.append(&mut buf);
                data.push(0x0a);
            }
        } else {
            let mut buf = std::fs::read(&filepath).map_err(|e| Error::Io {
                source: e,
                file: filepath,
            })?;
            data.append(&mut buf);
        }
        let data: TomlConfig = toml::from_str(
            std::string::String::from_utf8_lossy(&data)
                .to_string()
                .as_str(),
        )
        .map_err(|e| Error::De { source: e })?;
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
            grace_period: data.grace_period,
            graceful_shutdown_timeout: data.graceful_shutdown_timeout,
            upstream_keepalive_pool_size: data.upstream_keepalive_pool_size,
            webhook: data.webhook,
            webhook_type: data.webhook_type,
            log_level: data.log_level,
            sentry: data.sentry,
            pyroscope: data.pyroscope,
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
        for (name, value) in data.proxy_plugins.unwrap_or_default() {
            let plugin: ProxyPluginConf = toml::from_str(format_toml(&value).as_str())
                .map_err(|e| Error::De { source: e })?;
            conf.proxy_plugins.insert(name, plugin);
        }

        Ok(conf)
    }
    fn save_config(&self, conf: &PingapConf, category: &str) -> Result<()> {
        let mut filepath = self.path.clone();
        conf.validate()?;

        let ping_conf = toml::to_string_pretty(&conf).map_err(|e| Error::Ser { source: e })?;
        if Path::new(&filepath).is_file() {
            return std::fs::write(&filepath, ping_conf).map_err(|e| Error::Io {
                source: e,
                file: filepath,
            });
        }
        // file path is dir
        let mut data: TomlConfig =
            toml::from_str(&ping_conf).map_err(|e| Error::De { source: e })?;
        let conf = match category {
            CATEGORY_SERVER => {
                filepath = format!("{filepath}/servers.toml");
                let mut m = Map::new();
                let _ = m.insert(
                    "servers".to_string(),
                    toml::Value::Table(data.servers.unwrap_or_default()),
                );
                toml::to_string_pretty(&m).map_err(|e| Error::Ser { source: e })?
            }
            CATEGORY_LOCATION => {
                filepath = format!("{filepath}/locations.toml");
                let mut m = Map::new();
                let _ = m.insert(
                    "locations".to_string(),
                    toml::Value::Table(data.locations.unwrap_or_default()),
                );
                toml::to_string_pretty(&m).map_err(|e| Error::Ser { source: e })?
            }
            CATEGORY_UPSTREAM => {
                filepath = format!("{filepath}/upstreams.toml");
                let mut m = Map::new();
                let _ = m.insert(
                    "upstreams".to_string(),
                    toml::Value::Table(data.upstreams.unwrap_or_default()),
                );
                toml::to_string_pretty(&m).map_err(|e| Error::Ser { source: e })?
            }
            CATEGORY_PROXY_PLUGIN => {
                filepath = format!("{filepath}/proxy_plugins.toml");
                let mut m = Map::new();
                let _ = m.insert(
                    "proxy_plugins".to_string(),
                    toml::Value::Table(data.proxy_plugins.unwrap_or_default()),
                );
                toml::to_string_pretty(&m).map_err(|e| Error::Ser { source: e })?
            }
            _ => {
                filepath = format!("{filepath}/basic.toml");
                data.servers = None;
                data.locations = None;
                data.upstreams = None;
                data.proxy_plugins = None;
                toml::to_string_pretty(&data).map_err(|e| Error::Ser { source: e })?
            }
        };
        std::fs::write(&filepath, conf).map_err(|e| Error::Io {
            source: e,
            file: filepath,
        })
    }
}
