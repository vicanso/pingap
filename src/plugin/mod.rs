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
use crate::state::State;
use async_trait::async_trait;
use once_cell::sync::OnceCell;
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use snafu::Snafu;
use std::collections::HashMap;
use std::num::ParseIntError;

mod admin;
mod basic_auth;
mod cache;
mod compression;
mod directory;
mod ip_limit;
mod key_auth;
mod limit;
mod mock;
mod ping;
mod redirect_https;
mod request_id;
mod response_headers;
mod stats;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Invalid {message}"))]
    Invalid { message: String },
    #[snafu(display("Parse int {source}"))]
    ParseInt { source: ParseIntError },
    #[snafu(display("Exceed limit {value}/{max}"))]
    Exceed { max: isize, value: isize },
    #[snafu(display("Json parse error {source}"))]
    Json { source: serde_json::Error },
    #[snafu(display("Base64 decode error {source}"))]
    Base64Decode { source: base64::DecodeError },
}
type Result<T, E = Error> = std::result::Result<T, E>;

#[async_trait]
pub trait ProxyPlugin: Sync + Send {
    fn category(&self) -> PluginCategory;
    fn step(&self) -> PluginStep;
    async fn handle(
        &self,
        _session: &mut Session,
        _ctx: &mut State,
    ) -> pingora::Result<Option<HttpResponse>> {
        Ok(None)
    }
}

pub trait ResponsePlugin: Sync + Send {
    fn category(&self) -> PluginCategory;
    fn step(&self) -> PluginStep;
    fn handle(
        &self,
        _session: &mut Session,
        _ctx: &mut State,
        _upstream_response: &mut ResponseHeader,
    ) {
    }
}

pub fn get_builtin_proxy_plugins() -> Vec<(String, PluginConf)> {
    vec![
        // default level, gzip:6 br:6 zstd:3
        (
            "pingap:compression".to_string(),
            PluginConf {
                value: Some("6 6 3".to_string()),
                category: PluginCategory::Compression,
                remark: Some("Compression for http, support zstd:3, br:6, gzip:6".to_string()),
                step: None,
            },
        ),
        (
            "pingap:ping".to_string(),
            PluginConf {
                value: Some("/ping".to_string()),
                category: PluginCategory::Ping,
                remark: Some("Ping pong".to_string()),
                step: None,
            },
        ),
        (
            "pingap:stats".to_string(),
            PluginConf {
                value: Some("/stats".to_string()),
                category: PluginCategory::Stats,
                remark: Some("Get stats of server".to_string()),
                step: None,
            },
        ),
        (
            "pingap:requestId".to_string(),
            PluginConf {
                category: PluginCategory::RequestId,
                remark: Some("Generate a request id for service".to_string()),
                value: None,
                step: None,
            },
        ),
    ]
}

type Plugins = (
    HashMap<String, Box<dyn ProxyPlugin>>,
    HashMap<String, Box<dyn ResponsePlugin>>,
);

static PLUGINS: OnceCell<Plugins> = OnceCell::new();

pub fn init_proxy_plugins(confs: Vec<(String, PluginConf)>) -> Result<()> {
    PLUGINS.get_or_try_init(|| {
        let mut proxy_plugins: HashMap<String, Box<dyn ProxyPlugin>> = HashMap::new();
        let mut response_plugins: HashMap<String, Box<dyn ResponsePlugin>> = HashMap::new();
        let data = &mut confs.clone();
        data.extend(get_builtin_proxy_plugins());
        for (name, conf) in data {
            let name = name.to_string();
            let step = conf.step.unwrap_or_default();
            let value = conf.value.clone().unwrap_or_default();
            match conf.category {
                PluginCategory::Limit => {
                    let l = limit::Limiter::new(&value, step)?;
                    proxy_plugins.insert(name, Box::new(l));
                }
                PluginCategory::Compression => {
                    let c = compression::Compression::new(&value, step)?;
                    proxy_plugins.insert(name, Box::new(c));
                }
                PluginCategory::Stats => {
                    let s = stats::Stats::new(&value, step)?;
                    proxy_plugins.insert(name, Box::new(s));
                }
                PluginCategory::Admin => {
                    let a = admin::AdminServe::new(&value, step)?;
                    proxy_plugins.insert(name, Box::new(a));
                }
                PluginCategory::Directory => {
                    let d = directory::Directory::new(&value, step)?;
                    proxy_plugins.insert(name, Box::new(d));
                }
                PluginCategory::Mock => {
                    let m = mock::MockResponse::new(&value, step)?;
                    proxy_plugins.insert(name, Box::new(m));
                }
                PluginCategory::RequestId => {
                    let r = request_id::RequestId::new(&value, step)?;
                    proxy_plugins.insert(name, Box::new(r));
                }
                PluginCategory::IpLimit => {
                    let l = ip_limit::IpLimit::new(&value, step)?;
                    proxy_plugins.insert(name, Box::new(l));
                }
                PluginCategory::KeyAuth => {
                    let k = key_auth::KeyAuth::new(&value, step)?;
                    proxy_plugins.insert(name, Box::new(k));
                }
                PluginCategory::BasicAuth => {
                    let b = basic_auth::BasicAuth::new(&value, step)?;
                    proxy_plugins.insert(name, Box::new(b));
                }
                PluginCategory::Cache => {
                    let c = cache::Cache::new(&value, step)?;
                    proxy_plugins.insert(name, Box::new(c));
                }
                PluginCategory::RedirectHttps => {
                    let r = redirect_https::RedirectHttps::new(&value, step)?;
                    proxy_plugins.insert(name, Box::new(r));
                }
                PluginCategory::Ping => {
                    let p = ping::Ping::new(&value, step)?;
                    proxy_plugins.insert(name, Box::new(p));
                }
                PluginCategory::ResponseHeaders => {
                    let r = response_headers::ResponseHeaders::new(&value, step)?;
                    response_plugins.insert(name, Box::new(r));
                }
            };
        }

        Ok((proxy_plugins, response_plugins))
    })?;
    Ok(())
}

pub fn get_proxy_plugin(name: &str) -> Option<&dyn ProxyPlugin> {
    if let Some((proxy_plugins, _)) = PLUGINS.get() {
        if let Some(plugin) = proxy_plugins.get(name) {
            return Some(plugin.as_ref());
        }
    }
    None
}

pub fn get_response_plugin(name: &str) -> Option<&dyn ResponsePlugin> {
    if let Some((_, response_plugins)) = PLUGINS.get() {
        if let Some(plugin) = response_plugins.get(name) {
            return Some(plugin.as_ref());
        }
    }
    None
}

pub fn list_plugins() -> Option<&'static Plugins> {
    PLUGINS.get()
}
