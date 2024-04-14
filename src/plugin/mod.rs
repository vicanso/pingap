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

use crate::state::State;
use async_trait::async_trait;
use once_cell::sync::OnceCell;
use pingora::proxy::Session;
use snafu::Snafu;
use std::collections::HashMap;
use std::num::ParseIntError;

mod admin;
mod compression;
mod limit;
mod stats;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Invalid {message}"))]
    Invalid { message: String },
    #[snafu(display("Parse int {source}"))]
    ParseInt { source: ParseIntError },
    #[snafu(display("Exceed limit {value}/{max}"))]
    Exceed { max: isize, value: isize },
}
type Result<T, E = Error> = std::result::Result<T, E>;

#[async_trait]
pub trait ProxyPlugin: Sync + Send {
    async fn handle(&self, _session: &mut Session, _ctx: &mut State) -> pingora::Result<bool> {
        Ok(false)
    }
}

#[derive(PartialEq, Clone, Debug)]
pub enum ProxyPluginCategory {
    Limit,
    Compression,
    Stats,
    Admin,
}

#[derive(Clone, Debug)]
pub struct ProxyPluginConf {
    pub name: String,
    pub value: String,
    pub category: ProxyPluginCategory,
    pub remark: String,
}

pub fn get_builtin_proxy_plguins() -> Vec<ProxyPluginConf> {
    vec![
        // default level, gzip:6 br:6 zstd:3
        ProxyPluginConf {
            name: "Pingap:compression".to_string(),
            value: "6 6 3".to_string(),
            category: ProxyPluginCategory::Compression,
            remark: "Compression for http, support zstd:3, br:6, gzip:6".to_string(),
        },
        ProxyPluginConf {
            name: "Pingap:stats".to_string(),
            value: "/stats".to_string(),
            category: ProxyPluginCategory::Stats,
            remark: "Get stats of server".to_string(),
        },
    ]
}

static PROXY_PLUGINS: OnceCell<HashMap<String, Box<dyn ProxyPlugin>>> = OnceCell::new();

pub fn init_proxy_plguins(confs: Vec<ProxyPluginConf>) -> Result<()> {
    PROXY_PLUGINS.get_or_try_init(|| {
        let mut plguins: HashMap<String, Box<dyn ProxyPlugin>> = HashMap::new();
        let data = &mut confs.clone();
        data.extend(get_builtin_proxy_plguins());
        for conf in data {
            let name = conf.name.clone();
            match conf.category {
                ProxyPluginCategory::Limit => {
                    let l = limit::Limiter::new(&conf.value)?;
                    plguins.insert(name, Box::new(l));
                }
                ProxyPluginCategory::Compression => {
                    let c = compression::Compression::new(&conf.value)?;
                    plguins.insert(name, Box::new(c));
                }
                ProxyPluginCategory::Stats => {
                    let s = stats::Stats::new(&conf.value)?;
                    plguins.insert(name, Box::new(s));
                }
                ProxyPluginCategory::Admin => {
                    let a = admin::AdminServe::new(&conf.value)?;
                    plguins.insert(name, Box::new(a));
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
