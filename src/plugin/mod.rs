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

use crate::config::{PluginCategory, PluginConf, PluginStep};
use crate::http_extra::HttpResponse;
use crate::proxy::ServerConf;
use crate::state::{get_admin_addr, State};
use ahash::AHashMap;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use bytes::Bytes;
use once_cell::sync::Lazy;
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use snafu::Snafu;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use tracing::info;

mod admin;
mod basic_auth;
mod cache;
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

pub static ADMIN_SERVER_PLUGIN: Lazy<String> =
    Lazy::new(|| uuid::Uuid::new_v4().to_string());

pub fn parse_admin_plugin(addr: &str) -> (ServerConf, String, PluginConf) {
    let arr: Vec<&str> = addr.split('@').collect();
    let mut addr = arr[0].to_string();
    let mut authorization = "".to_string();
    if arr.len() >= 2 {
        authorization = arr[0].trim().to_string();
        addr = arr[1].trim().to_string();
    }
    let data = format!(
        r#"
    category = "admin"
    path = "/"
    authorizations = [
        "{}"
    ]
    remark = "Admin serve"
    "#,
        authorization
    );
    (
        ServerConf {
            name: "pingap:admin".to_string(),
            admin: true,
            addr,
            ..Default::default()
        },
        ADMIN_SERVER_PLUGIN.clone(),
        toml::from_str::<PluginConf>(&data).unwrap(),
    )
}

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
}
type Result<T, E = Error> = std::result::Result<T, E>;
#[async_trait]
pub trait Plugin: Sync + Send {
    fn category(&self) -> PluginCategory;
    fn step(&self) -> String;
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
    ) -> pingora::Result<Option<Bytes>> {
        Ok(None)
    }
}

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
    ]
}

type Plugins = AHashMap<String, Arc<dyn Plugin>>;
static PLUGINS: Lazy<ArcSwap<Plugins>> =
    Lazy::new(|| ArcSwap::from_pointee(AHashMap::new()));
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
        };
    }

    Ok(plguins)
}

pub fn try_init_plugins(plugins: &HashMap<String, PluginConf>) -> Result<()> {
    let mut plugin_confs: Vec<(String, PluginConf)> = plugins
        .iter()
        .map(|(name, value)| (name.to_string(), value.clone()))
        .collect();

    // add admin plugin
    if let Some(addr) = &get_admin_addr() {
        let (_, name, proxy_plugin_info) = parse_admin_plugin(addr);
        plugin_confs.push((name, proxy_plugin_info));
    }

    plugin_confs.extend(get_builtin_proxy_plugins());
    let plugins = parse_plugins(plugin_confs.to_vec())?;
    PLUGINS.store(Arc::new(plugins));

    Ok(())
}

pub fn get_plugin(name: &str) -> Option<Arc<dyn Plugin>> {
    PLUGINS.load().get(name).cloned()
}

pub fn list_plugins_summary() {
    for (name, plugin) in PLUGINS.load().iter() {
        info!(
            name,
            category = plugin.category().to_string(),
            step = plugin.step(),
        );
    }
}

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

pub(crate) fn get_step_conf(value: &PluginConf) -> PluginStep {
    PluginStep::from_str(get_str_conf(value, "step").as_str())
        .unwrap_or_default()
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
