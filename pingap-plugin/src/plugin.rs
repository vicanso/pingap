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

use super::{Error, get_str_conf};
use dashmap::DashMap;
use pingap_config::PluginConf;
use pingap_core::Plugin;
use std::sync::Arc;
use std::sync::LazyLock;

type Result<T, E = Error> = std::result::Result<T, E>;

type NewPlugin = dyn Fn(&PluginConf) -> Result<Arc<dyn Plugin>> + Send + Sync;

/// Plugin factory for managing plugin creation and registration
pub struct PluginFactory {
    plugins: DashMap<String, Arc<NewPlugin>>,
}

impl PluginFactory {
    pub fn new() -> Self {
        Self {
            plugins: DashMap::new(),
        }
    }

    pub fn supported_plugins(&self) -> Vec<String> {
        let mut plugins = self
            .plugins
            .iter()
            .map(|item| item.key().clone())
            .collect::<Vec<String>>();
        plugins.sort();
        plugins
    }

    /// Register a new plugin creator function
    pub fn register<F>(&self, category: &str, creator: F)
    where
        F: Fn(&PluginConf) -> Result<Arc<dyn Plugin>> + Send + Sync + 'static,
    {
        self.plugins.insert(category.to_string(), Arc::new(creator));
    }

    /// Create a new plugin instance by name
    pub fn create(&self, conf: &PluginConf) -> Result<Arc<dyn Plugin>> {
        let category = get_str_conf(conf, "category");
        if category.is_empty() {
            return Err(Error::NotFound {
                category: "unknown".to_string(),
            });
        }

        self.plugins
            .get(&category)
            .ok_or(Error::NotFound {
                category: category.to_string(),
            })
            .and_then(|creator| creator(conf))
    }
}

impl Default for PluginFactory {
    fn default() -> Self {
        Self::new()
    }
}

static PLUGIN_FACTORY: LazyLock<PluginFactory> =
    LazyLock::new(PluginFactory::new);

pub fn get_plugin_factory() -> &'static PluginFactory {
    &PLUGIN_FACTORY
}
