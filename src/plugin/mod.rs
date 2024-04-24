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

use crate::config::{ProxyPluginCategory, ProxyPluginConf, ProxyPluginStep};
use crate::state::State;
use async_trait::async_trait;
use once_cell::sync::OnceCell;
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
mod redirect_https;
mod request_id;
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
}
type Result<T, E = Error> = std::result::Result<T, E>;

#[async_trait]
pub trait ProxyPlugin: Sync + Send {
    fn category(&self) -> ProxyPluginCategory;
    fn step(&self) -> ProxyPluginStep;
    async fn handle(&self, _session: &mut Session, _ctx: &mut State) -> pingora::Result<bool> {
        Ok(false)
    }
}

pub fn get_builtin_proxy_plugins() -> Vec<(String, ProxyPluginConf)> {
    vec![
        // default level, gzip:6 br:6 zstd:3
        (
            "pingap:compression".to_string(),
            ProxyPluginConf {
                value: Some("6 6 3".to_string()),
                category: ProxyPluginCategory::Compression,
                remark: Some("Compression for http, support zstd:3, br:6, gzip:6".to_string()),
                step: None,
            },
        ),
        (
            "pingap:stats".to_string(),
            ProxyPluginConf {
                value: Some("/stats".to_string()),
                category: ProxyPluginCategory::Stats,
                remark: Some("Get stats of server".to_string()),
                step: None,
            },
        ),
        (
            "pingap:requestId".to_string(),
            ProxyPluginConf {
                category: ProxyPluginCategory::RequestId,
                remark: Some("Generate a request id for service".to_string()),
                value: None,
                step: None,
            },
        ),
    ]
}

static PROXY_PLUGINS: OnceCell<HashMap<String, Box<dyn ProxyPlugin>>> = OnceCell::new();

pub fn init_proxy_plugins(confs: Vec<(String, ProxyPluginConf)>) -> Result<()> {
    PROXY_PLUGINS.get_or_try_init(|| {
        let mut plguins: HashMap<String, Box<dyn ProxyPlugin>> = HashMap::new();
        let data = &mut confs.clone();
        data.extend(get_builtin_proxy_plugins());
        for (name, conf) in data {
            let name = name.to_string();
            let step = conf.step.unwrap_or_default();
            let value = conf.value.clone().unwrap_or_default();
            match conf.category {
                ProxyPluginCategory::Limit => {
                    let l = limit::Limiter::new(&value, step)?;
                    plguins.insert(name, Box::new(l));
                }
                ProxyPluginCategory::Compression => {
                    let c = compression::Compression::new(&value, step)?;
                    plguins.insert(name, Box::new(c));
                }
                ProxyPluginCategory::Stats => {
                    let s = stats::Stats::new(&value, step)?;
                    plguins.insert(name, Box::new(s));
                }
                ProxyPluginCategory::Admin => {
                    let a = admin::AdminServe::new(&value, step)?;
                    plguins.insert(name, Box::new(a));
                }
                ProxyPluginCategory::Directory => {
                    let d = directory::Directory::new(&value, step)?;
                    plguins.insert(name, Box::new(d));
                }
                ProxyPluginCategory::Mock => {
                    let m = mock::MockResponse::new(&value, step)?;
                    plguins.insert(name, Box::new(m));
                }
                ProxyPluginCategory::RequestId => {
                    let r = request_id::RequestId::new(&value, step)?;
                    plguins.insert(name, Box::new(r));
                }
                ProxyPluginCategory::IpLimit => {
                    let l = ip_limit::IpLimit::new(&value, step)?;
                    plguins.insert(name, Box::new(l));
                }
                ProxyPluginCategory::KeyAuth => {
                    let k = key_auth::KeyAuth::new(&value, step)?;
                    plguins.insert(name, Box::new(k));
                }
                ProxyPluginCategory::BasicAuth => {
                    let b = basic_auth::BasicAuth::new(&value, step)?;
                    plguins.insert(name, Box::new(b));
                }
                ProxyPluginCategory::Cache => {
                    let c = cache::Cache::new(&value, step)?;
                    plguins.insert(name, Box::new(c));
                }
                ProxyPluginCategory::RedirectHttps => {
                    let r = redirect_https::RedirectHttps::new(&value, step)?;
                    plguins.insert(name, Box::new(r));
                }
            };
        }

        Ok(plguins)
    })?;
    Ok(())
}

pub fn get_proxy_plugin(name: &str) -> Option<&dyn ProxyPlugin> {
    if let Some(plugins) = PROXY_PLUGINS.get() {
        if let Some(plugin) = plugins.get(name) {
            return Some(plugin.as_ref());
        }
    }
    None
}
