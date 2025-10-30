// Copyright 2024-2025 Tree xie.
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

use crate::process::get_admin_addr;
use ahash::AHashMap;
use arc_swap::ArcSwap;
use once_cell::sync::Lazy;
use pingap_config::PluginConf;
use pingap_core::{Plugin, PluginProvider, PluginStep, Plugins};
use pingap_plugin::get_plugin_factory;
use pingap_proxy::ServerConf;
use pingap_util::base64_encode;
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{error, info};

mod admin;
mod stats;

/// UUID for the admin server plugin, generated at runtime
pub static ADMIN_SERVER_PLUGIN: &str = "pingap:admin";

static LOG_TARGET: &str = "main::plugin";

#[derive(Debug, PartialEq, Deserialize, Serialize, Default)]
struct AdminPluginParams {
    max_age: Option<String>,
}

/// Parses admin plugin configuration from an address string.
///
/// # Arguments
/// * `addr` - The address string to parse in URL format
///
/// # Returns
/// A tuple containing:
/// - ServerConf: The server configuration
/// - String: The plugin name
/// - PluginConf: The plugin configuration
///
/// # Errors
/// Returns Error::Invalid if URL parsing fails
pub fn parse_admin_plugin(
    addr: &str,
) -> Result<(ServerConf, String, PluginConf)> {
    let info = url::Url::from_str(&format!("http://{addr}")).map_err(|e| {
        Error::Invalid {
            category: "url".to_string(),
            message: e.to_string(),
        }
    })?;
    let mut addr = info.host_str().unwrap_or_default().to_string();
    addr = format!("{addr}:{}", info.port().unwrap_or(80));

    let mut authorization = "".to_string();
    if !info.username().is_empty() {
        authorization = urlencoding::decode(info.username())
            .unwrap_or_default()
            .to_string();
        // if not base64 string
        if let Some(pass) = info.password() {
            authorization = base64_encode(format!("{authorization}:{pass}"));
        }
    }
    let mut path = info.path().to_string();
    if path.is_empty() {
        path = "/".to_string();
    }
    let params: AdminPluginParams =
        serde_qs::from_str(info.query().unwrap_or_default())
            .unwrap_or_default();
    let max_age = params.max_age.unwrap_or("2d".to_string());

    let data = format!(
        r#"
    category = "admin"
    path = "{path}"
    authorizations = [
        "{authorization}"
    ]
    max_age = "{max_age}"
    remark = "Admin serve"
    "#,
    );
    Ok((
        ServerConf {
            name: "pingap:admin".to_string(),
            admin: true,
            addr,
            ..Default::default()
        },
        ADMIN_SERVER_PLUGIN.to_string(),
        toml::from_str::<PluginConf>(&data).unwrap_or_default(),
    ))
}

/// Error types for plugin operations
#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Plugin {category} invalid, message: {message}"))]
    Invalid { category: String, message: String },
}
type Result<T, E = Error> = std::result::Result<T, E>;

/// Generates a unique hash key for a plugin configuration to detect changes.
///
/// # Arguments
/// * `conf` - The plugin configuration to hash
///
/// # Returns
/// A string containing the CRC32 hash of the sorted configuration key-value pairs
pub(crate) fn get_hash_key(conf: &PluginConf) -> String {
    let mut keys: Vec<String> =
        conf.keys().map(|item| item.to_string()).collect();
    keys.sort();
    let mut lines = vec![];
    for key in keys {
        let value = if let Some(value) = conf.get(&key) {
            value.to_string()
        } else {
            "".to_string()
        };
        lines.push(format!("{key}:{value}"));
    }
    let hash = crc32fast::hash(lines.join("\n").as_bytes());
    format!("{hash:X}")
}

/// Returns a list of built-in plugins with their default configurations.
///
/// Includes plugins for:
/// - Compression (gzip, br, zstd)
/// - Ping health check
/// - Stats reporting
/// - Request ID generation
/// - Accept-Encoding adjustment
pub fn get_builtin_proxy_plugins() -> Vec<(String, PluginConf)> {
    vec![
        // default level, gzip:6 br:6 zstd:3
        (
            "pingap:compression".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "compression"
gzip_level = 6
br_level = 6
zstd_level = 6
remark = "Compression for http, support zstd:6, br:6, gzip:6"
"###,
            )
            .unwrap_or_default(),
        ),
        (
            "pingap:compressionUpstream".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "compression"
gzip_level = 6
br_level = 6
zstd_level = 6 
mode = "upstream"
remark = "Compression for upstream response, support zstd:6, br:6, gzip:6"
"###,
            )
            .unwrap_or_default(),
        ),
        (
            "pingap:ping".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "ping"
path = "/ping"
remark = "Ping pong"
"###,
            )
            .unwrap_or_default(),
        ),
        (
            "pingap:stats".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "stats"
path = "/stats"
remark = "Get stats of server"
"###,
            )
            .unwrap_or_default(),
        ),
        (
            "pingap:requestId".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "request_id"
remark = "Generate a request id for service"
"###,
            )
            .unwrap_or_default(),
        ),
        (
            "pingap:acceptEncodingAdjustment".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "accept_encoding"
encodings = "zstd, br, gzip"
only_one_encoding = true
remark = "Adjust the accept encoding order and choose one encoding"
"###,
            )
            .unwrap_or_default(),
        ),
    ]
}

struct Provider {
    plugins: ArcSwap<Plugins>,
}

impl Provider {
    fn store(&self, data: Plugins) {
        self.plugins.store(Arc::new(data));
    }
}

static PLUGIN_PROVIDER: Lazy<Arc<Provider>> = Lazy::new(|| {
    Arc::new(Provider {
        plugins: ArcSwap::from_pointee(AHashMap::new()),
    })
});

impl PluginProvider for Provider {
    fn get(&self, name: &str) -> Option<Arc<dyn Plugin>> {
        self.plugins.load().get(name).cloned()
    }
}

pub fn new_plugin_provider() -> Arc<dyn PluginProvider> {
    PLUGIN_PROVIDER.clone()
}

/// Parses plugin configurations and instantiates plugin instances.
///
/// # Arguments
/// * `configs` - Vector of (name, config) tuples for plugins to initialize
///
/// # Returns
/// HashMap mapping plugin names to initialized plugin instances
///
/// # Errors
/// Returns Error if plugin initialization fails
pub fn parse_plugins(
    configs: Vec<(String, PluginConf)>,
) -> (Plugins, Vec<Error>) {
    let mut plugins: Plugins = AHashMap::new();
    let mut errors: Vec<Error> = vec![];
    for (name, conf) in configs.iter() {
        let name = name.to_string();
        let category = if let Some(value) = conf.get("category") {
            value.as_str().unwrap_or_default().to_string()
        } else {
            "".to_string()
        };
        if category.is_empty() {
            errors.push(Error::Invalid {
                category: "".to_string(),
                message: format!("category of {name} can not be empty"),
            });
            continue;
        }

        match get_plugin_factory().create(conf) {
            Ok(plugin) => {
                plugins.insert(name.clone(), plugin.clone());
            },
            Err(e) => {
                errors.push(Error::Invalid {
                    category,
                    message: format!("create plugin {name} failed, {e}"),
                });
            },
        }
    }

    // let plugin =
    //     get_plugin_factory()
    //         .create(conf)
    //         .map_err(|e| Error::Invalid {
    //             category,
    //             message: format!("create plugin {name} failed, {}", e),
    //         })?;
    // plugins.insert(name.clone(), plugin.clone());
    // }

    (plugins, errors)
}

/// Initializes or updates plugins based on configuration.
///
/// # Arguments
/// * `plugins` - HashMap of plugin names to configurations
///
/// # Returns
/// Vector of plugin names that were created or updated
///
/// # Errors
/// Returns Error if plugin initialization fails
pub fn try_init_plugins(
    plugins: &HashMap<String, PluginConf>,
) -> (Vec<String>, String) {
    let mut plugin_configs: Vec<(String, PluginConf)> = plugins
        .iter()
        .map(|(name, value)| (name.to_string(), value.clone()))
        .collect();

    // add admin plugin
    let mut errors = vec![];
    if let Some(addr) = &get_admin_addr() {
        match parse_admin_plugin(addr) {
            Ok((_, name, proxy_plugin_info)) => {
                plugin_configs.push((name, proxy_plugin_info));
            },
            Err(e) => {
                errors.push(e);
            },
        }
    }

    plugin_configs.extend(get_builtin_proxy_plugins());

    let mut updated_plugins = vec![];
    let mut plugins = AHashMap::new();
    let plugin_configs: Vec<(String, PluginConf)> = plugin_configs
        .into_iter()
        .filter(|(name, conf)| {
            let conf_hash_key = get_hash_key(conf);
            let mut exists = false;
            if let Some(plugin) = PLUGIN_PROVIDER.get(name) {
                exists = true;
                // exists plugin with same config
                if plugin.config_key() == conf_hash_key {
                    plugins.insert(name.to_string(), plugin);
                    return false;
                }
            }
            let step = get_step_conf(conf, PluginStep::Request).to_string();
            let category = if let Some(value) = conf.get("category") {
                value.as_str().unwrap_or_default().to_string()
            } else {
                "".to_string()
            };
            if exists {
                info!(target: LOG_TARGET, name, step, category, "plugin will be reloaded");
            } else {
                info!(target: LOG_TARGET, name, step, category, "plugin will be created");
            }
            updated_plugins.push(name.to_string());
            true
        })
        .collect();
    let (new_plugins, new_errors) = parse_plugins(plugin_configs);
    plugins.extend(new_plugins);
    errors.extend(new_errors);
    PLUGIN_PROVIDER.store(plugins);
    let error = if !errors.is_empty() {
        let error = errors
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join(";");
        error!(target: LOG_TARGET, error, "parse plugins failed");
        error
    } else {
        "".to_string()
    };

    (updated_plugins, error)
}

/// Helper functions for accessing plugin configuration values
pub(crate) fn get_str_conf(value: &PluginConf, key: &str) -> String {
    if let Some(value) = value.get(key) {
        value.as_str().unwrap_or_default().to_string()
    } else {
        "".to_string()
    }
}

pub(crate) fn get_int_conf(value: &PluginConf, key: &str) -> i64 {
    if let Some(value) = value.get(key) {
        value.as_integer().unwrap_or_default()
    } else {
        0
    }
}

pub(crate) fn get_str_slice_conf(value: &PluginConf, key: &str) -> Vec<String> {
    if let Some(value) = value.get(key) {
        if let Some(values) = value.as_array() {
            return values
                .iter()
                .map(|item| item.as_str().unwrap_or_default().to_string())
                .collect();
        }
    }
    vec![]
}

pub(crate) fn get_step_conf(
    value: &PluginConf,
    default_value: PluginStep,
) -> PluginStep {
    let step = get_str_conf(value, "step");
    if step.is_empty() {
        return default_value;
    }

    PluginStep::from_str(step.as_str()).unwrap_or(default_value)
}

#[test]
pub fn initialize_test_plugins() {
    let plugins = HashMap::from([
        (
            "test:mock".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "mock"
path = "/mock"
status = 999
data = "abc"
"###,
            )
            .unwrap(),
        ),
        (
            "test:add_headers".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "response_headers"
step = "response"
add_headers = [
"X-Service:1",
"X-Service:2",
]
set_headers = [
"X-Response-Id:123"
]
remove_headers = [
"Content-Type"
]
"###,
            )
            .unwrap(),
        ),
    ]);
    let (_, error) = try_init_plugins(&plugins);
    assert!(error.is_empty());
}
