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

use std::collections::HashMap;

use crate::state::State;
use async_trait::async_trait;
use once_cell::sync::OnceCell;
use pingora::proxy::Session;
use snafu::Snafu;
use std::num::ParseIntError;

mod limit;

pub use limit::Limiter;

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

#[derive(PartialEq, Debug)]
pub enum ProxyPluginCategory {
    Limit,
}

pub struct ProxyPluginConf {
    pub name: String,
    pub value: String,
    pub category: ProxyPluginCategory,
}

static PROXY_PLUGINS: OnceCell<HashMap<String, Box<dyn ProxyPlugin>>> = OnceCell::new();

pub fn init_proxy_plguins(confs: Vec<ProxyPluginConf>) -> Result<()> {
    PROXY_PLUGINS.get_or_try_init(|| {
        let mut plguins: HashMap<String, Box<dyn ProxyPlugin>> = HashMap::new();
        for conf in confs {
            match conf.category {
                ProxyPluginCategory::Limit => {
                    let l = Limiter::new(&conf.value)?;
                    plguins.insert(conf.name, Box::new(l));
                }
                _ => {
                    return Err(Error::Invalid {
                        message: format!("Invalid cateogry({:?})", conf.category),
                    })
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
