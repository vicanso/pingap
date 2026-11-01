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
use dashmap::mapref::entry::Entry;
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

    /// Register a new plugin creator function.
    ///
    /// A category that is empty, or already in the factory, is an error and
    /// the creator already there is left as it is. Register before the first
    /// [`Self::create`] of that category.
    pub fn register<F>(&self, category: &str, creator: F) -> Result<()>
    where
        F: Fn(&PluginConf) -> Result<Arc<dyn Plugin>> + Send + Sync + 'static,
    {
        if category.is_empty() {
            return Err(Error::Invalid {
                category: "unknown".to_string(),
                message: "category is empty".to_string(),
            });
        }
        // `entry` holds the shard, so two registrations of one new name
        // cannot both pass and the second insert over the first.
        match self.plugins.entry(category.to_string()) {
            Entry::Occupied(_) => Err(Error::Invalid {
                category: category.to_string(),
                message: "category is already registered".to_string(),
            }),
            Entry::Vacant(slot) => {
                slot.insert(Arc::new(creator));
                Ok(())
            },
        }
    }

    /// Create a new plugin instance by name
    pub fn create(&self, conf: &PluginConf) -> Result<Arc<dyn Plugin>> {
        let category = get_str_conf(conf, "category");
        if category.is_empty() {
            return Err(Error::NotFound {
                category: "unknown".to_string(),
            });
        }

        let creator = self
            .plugins
            .get(&category)
            .map(|creator| creator.value().clone())
            .ok_or(Error::NotFound {
                category: category.to_string(),
            })?;
        crate::build_plugin(&category, || creator(conf))
    }
}

impl Default for PluginFactory {
    fn default() -> Self {
        Self::new()
    }
}

static PLUGIN_FACTORY: LazyLock<PluginFactory> = LazyLock::new(|| {
    let factory = PluginFactory::new();
    crate::register_builtin_plugins(&factory);
    factory
});

/// The factory the plugins are created by, with every plugin of this crate
/// in it from the first time it is asked for. Plugins from elsewhere
/// (`image_optim`, the ones of the `pingap` binary) are added by who has
/// them, before the factory is asked to create one.
pub fn get_plugin_factory() -> &'static PluginFactory {
    &PLUGIN_FACTORY
}

#[cfg(test)]
mod tests {
    use super::PluginFactory;
    use super::{Error, Result};
    use pingap_config::PluginConf;
    use pingap_core::Plugin;
    use pretty_assertions::assert_eq;
    use std::sync::Arc;

    fn failing(
        message: &'static str,
    ) -> impl Fn(&PluginConf) -> Result<Arc<dyn Plugin>> + Send + Sync {
        move |_conf| {
            Err(Error::Invalid {
                category: "probe".to_string(),
                message: message.to_string(),
            })
        }
    }

    /// A second registration does not replace the creator. The factory
    /// here is a new one: the process-wide factory is what the other tests
    /// list, and an extra name there would change that list.
    #[test]
    fn test_register_refuses_an_empty_or_taken_category() {
        let factory = PluginFactory::new();
        match factory.register("", failing("empty")) {
            Ok(()) => panic!("an empty category is not a plugin"),
            Err(err) => assert_eq!(
                "Plugin unknown invalid, message: category is empty",
                err.to_string()
            ),
        }
        match factory.register("probe", failing("first")) {
            Ok(()) => {},
            Err(err) => panic!("a new category registers: {err}"),
        }
        match factory.register("probe", failing("second")) {
            Ok(()) => panic!("a category is registered once"),
            Err(err) => assert_eq!(
                "Plugin probe invalid, message: category is already registered",
                err.to_string()
            ),
        }
        let mut conf = PluginConf::new();
        conf.insert(
            "category".to_string(),
            toml::Value::String("probe".to_string()),
        );
        match factory.create(&conf) {
            Ok(_) => panic!("the first creator fails on purpose"),
            Err(err) => assert_eq!(
                "Plugin probe invalid, message: first",
                err.to_string()
            ),
        }
    }
}
