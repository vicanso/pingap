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

use crate::config::{PluginCategory, PluginConf, PluginStep};
use crate::http_extra::HttpResponse;
use crate::proxy::ServerConf;
use crate::state::{get_admin_addr, State};
use crate::util::{self, base64_encode};
use ahash::AHashMap;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use once_cell::sync::Lazy;
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use snafu::Snafu;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use tracing::info;

mod accept_encoding;
mod admin;
mod basic_auth;
mod cache;
mod combined_auth;
mod compression;
mod cors;
mod csrf;
mod directory;
mod ip_restriction;
mod jwt;
mod key_auth;
mod limit;
mod mock;
mod ping;
mod redirect;
mod referer_restriction;
mod request_id;
mod response_headers;
mod stats;
mod sub_filter;
mod ua_restriction;

/// UUID for the admin server plugin, generated at runtime
pub static ADMIN_SERVER_PLUGIN: Lazy<String> =
    Lazy::new(|| uuid::Uuid::now_v7().to_string());

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
    let query = util::convert_query_map(info.query().unwrap_or_default());
    let max_age = if let Some(value) = query.get("max_age") {
        value.to_string()
    } else {
        "2d".to_string()
    };

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
        ADMIN_SERVER_PLUGIN.clone(),
        toml::from_str::<PluginConf>(&data).unwrap(),
    ))
}

/// Error types for plugin operations
#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Plugin {category} invalid, message: {message}"))]
    Invalid { category: String, message: String },
    #[snafu(display("Plugin {category}, exceed limit {value}/{max}"))]
    Exceed {
        category: String,
        max: isize,
        value: isize,
    },
    #[snafu(display("Plugin {category}, base64 decode error {source}"))]
    Base64Decode {
        category: String,
        source: base64::DecodeError,
    },
    #[snafu(display("Plugin {category}, base64 decode error {source}"))]
    ParseDuration {
        category: String,
        source: humantime::DurationError,
    },
    #[snafu(display("Plugin {category}, regex error {source}"))]
    Regex {
        category: String,
        source: Box<fancy_regex::Error>,
    },
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
    format!("{:X}", hash)
}

/// Core trait that defines the interface all plugins must implement.
///
/// Plugins can handle both requests and responses at different processing steps.
/// The default implementations do nothing and return Ok.
#[async_trait]
pub trait Plugin: Sync + Send {
    fn hash_key(&self) -> String {
        "".to_string()
    }
    async fn handle_request(
        &self,
        _step: PluginStep,
        _session: &mut Session,
        _ctx: &mut State,
    ) -> pingora::Result<Option<HttpResponse>> {
        Ok(None)
    }
    async fn handle_response(
        &self,
        _step: PluginStep,
        _session: &mut Session,
        _ctx: &mut State,
        _upstream_response: &mut ResponseHeader,
    ) -> pingora::Result<()> {
        Ok(())
    }
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
step = "early_request"
category = "compression"
gzip_level = 6
br_level = 6
zstd_level = 6
remark = "Compression for http, support zstd:3, br:6, gzip:6"
"###,
            )
            .unwrap(),
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
            .unwrap(),
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
            .unwrap(),
        ),
        (
            "pingap:requestId".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "request_id"
remark = "Generate a request id for service"
"###,
            )
            .unwrap(),
        ),
        (
            "pingap:acceptEncodingAdjustment".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "accept_encoding"
encodings = "zstd, br, gzip"
only_one_encoding = true
remark = "Adjust the accept encoding order and choose one econding"
"###,
            )
            .unwrap(),
        ),
    ]
}

/// Global storage for all active plugins
type Plugins = AHashMap<String, Arc<dyn Plugin>>;
static PLUGINS: Lazy<ArcSwap<Plugins>> =
    Lazy::new(|| ArcSwap::from_pointee(AHashMap::new()));

/// Parses plugin configurations and instantiates plugin instances.
///
/// # Arguments
/// * `confs` - Vector of (name, config) tuples for plugins to initialize
///
/// # Returns
/// HashMap mapping plugin names to initialized plugin instances
///
/// # Errors
/// Returns Error if plugin initialization fails
pub fn parse_plugins(confs: Vec<(String, PluginConf)>) -> Result<Plugins> {
    let mut plguins: Plugins = AHashMap::new();
    for (name, conf) in confs.iter() {
        let name = name.to_string();
        let category = conf.get("category");
        if category.is_none() {
            return Err(Error::Invalid {
                category: "".to_string(),
                message: "Category can not be empty".to_string(),
            });
        }
        let category = PluginCategory::from_str(
            category.unwrap().as_str().unwrap_or_default(),
        )
        .unwrap_or_default();
        match category {
            PluginCategory::Limit => {
                let l = limit::Limiter::new(conf)?;
                plguins.insert(name, Arc::new(l));
            },
            PluginCategory::Compression => {
                let c = compression::Compression::new(conf)?;
                plguins.insert(name, Arc::new(c));
            },
            PluginCategory::Stats => {
                let s = stats::Stats::new(conf)?;
                plguins.insert(name, Arc::new(s));
            },
            PluginCategory::Admin => {
                let a = admin::AdminServe::new(conf)?;
                plguins.insert(name, Arc::new(a));
            },
            PluginCategory::Directory => {
                let d = directory::Directory::new(conf)?;
                plguins.insert(name, Arc::new(d));
            },
            PluginCategory::Mock => {
                let m = mock::MockResponse::new(conf)?;
                plguins.insert(name, Arc::new(m));
            },
            PluginCategory::RequestId => {
                let r = request_id::RequestId::new(conf)?;
                plguins.insert(name, Arc::new(r));
            },
            PluginCategory::IpRestriction => {
                let l = ip_restriction::IpRestriction::new(conf)?;
                plguins.insert(name, Arc::new(l));
            },
            PluginCategory::KeyAuth => {
                let k = key_auth::KeyAuth::new(conf)?;
                plguins.insert(name, Arc::new(k));
            },
            PluginCategory::BasicAuth => {
                let b = basic_auth::BasicAuth::new(conf)?;
                plguins.insert(name, Arc::new(b));
            },
            PluginCategory::CombinedAuth => {
                let c = combined_auth::CombinedAuth::new(conf)?;
                plguins.insert(name, Arc::new(c));
            },
            PluginCategory::Cache => {
                let c = cache::Cache::new(conf)?;
                plguins.insert(name, Arc::new(c));
            },
            PluginCategory::Redirect => {
                let r = redirect::Redirect::new(conf)?;
                plguins.insert(name, Arc::new(r));
            },
            PluginCategory::Ping => {
                let p = ping::Ping::new(conf)?;
                plguins.insert(name, Arc::new(p));
            },
            PluginCategory::ResponseHeaders => {
                let r = response_headers::ResponseHeaders::new(conf)?;
                plguins.insert(name, Arc::new(r));
            },
            PluginCategory::RefererRestriction => {
                let r = referer_restriction::RefererRestriction::new(conf)?;
                plguins.insert(name, Arc::new(r));
            },
            PluginCategory::UaRestriction => {
                let u = ua_restriction::UaRestriction::new(conf)?;
                plguins.insert(name, Arc::new(u));
            },
            PluginCategory::Csrf => {
                let c = csrf::Csrf::new(conf)?;
                plguins.insert(name, Arc::new(c));
            },
            PluginCategory::Jwt => {
                let auth = jwt::JwtAuth::new(conf)?;
                plguins.insert(name.clone(), Arc::new(auth));
            },
            PluginCategory::Cors => {
                let cors = cors::Cors::new(conf)?;
                plguins.insert(name.clone(), Arc::new(cors));
            },
            PluginCategory::AcceptEncoding => {
                let accept_encoding =
                    accept_encoding::AcceptEncoding::new(conf)?;
                plguins.insert(name.clone(), Arc::new(accept_encoding));
            },
            PluginCategory::SubFilter => {
                let s = sub_filter::SubFilter::new(conf)?;
                plguins.insert(name.clone(), Arc::new(s));
            },
        };
    }

    Ok(plguins)
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
) -> Result<Vec<String>> {
    let mut plugin_confs: Vec<(String, PluginConf)> = plugins
        .iter()
        .map(|(name, value)| (name.to_string(), value.clone()))
        .collect();

    // add admin plugin
    if let Some(addr) = &get_admin_addr() {
        let (_, name, proxy_plugin_info) = parse_admin_plugin(addr)?;
        plugin_confs.push((name, proxy_plugin_info));
    }

    plugin_confs.extend(get_builtin_proxy_plugins());

    let mut updated_plugins = vec![];
    let mut plugins = AHashMap::new();
    let plugin_confs: Vec<(String, PluginConf)> = plugin_confs
        .into_iter()
        .filter(|(name, conf)| {
            let conf_hash_key = get_hash_key(conf);
            let mut exists = false;
            if let Some(plugin) = get_plugin(name) {
                exists = true;
                // exists plugin with same config
                if plugin.hash_key() == conf_hash_key {
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
                info!(name, step, category, "plugin will be reloaded");
            } else {
                info!(name, step, category, "plugin will be created");
            }
            updated_plugins.push(name.to_string());
            true
        })
        .collect();
    plugins.extend(parse_plugins(plugin_confs)?);
    PLUGINS.store(Arc::new(plugins));

    Ok(updated_plugins)
}

pub fn get_plugin(name: &str) -> Option<Arc<dyn Plugin>> {
    PLUGINS.load().get(name).cloned()
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

pub(crate) fn get_bool_conf(value: &PluginConf, key: &str) -> bool {
    if let Some(value) = value.get(key) {
        value.as_bool().unwrap_or_default()
    } else {
        false
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
    try_init_plugins(&plugins).unwrap();
}
