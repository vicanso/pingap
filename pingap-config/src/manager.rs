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

use crate::PingapConfig;
use crate::convert_pingap_config;
use crate::etcd_storage::EtcdStorage;
use crate::file_storage::{FileStorage, is_config_dir};
use crate::memory_storage::MemoryStorage;
use crate::storage::{History, Storage};
use crate::{Category, Error, Observer};
use arc_swap::ArcSwap;
use pingap_util::resolve_path;
use serde::{Deserialize, Deserializer, Serialize, de::DeserializeOwned};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use toml::{Value, map::Map};

type Result<T, E = Error> = std::result::Result<T, E>;

pub fn format_category(category: &Category) -> &str {
    match category {
        Category::Basic => "basic",
        Category::Server => "servers",
        Category::Location => "locations",
        Category::Upstream => "upstreams",
        Category::Plugin => "plugins",
        Category::Certificate => "certificates",
        Category::Storage => "storages",
    }
}

fn to_string_pretty<T>(value: &T) -> Result<String>
where
    T: serde::ser::Serialize + ?Sized,
{
    toml::to_string_pretty(value).map_err(|e| Error::Ser { source: e })
}

#[derive(Deserialize, Debug, Serialize)]
pub struct PingapTomlConfig {
    pub basic: Option<Value>,
    pub servers: Option<Map<String, Value>>,
    pub upstreams: Option<Map<String, Value>>,
    pub locations: Option<Map<String, Value>>,
    pub plugins: Option<Map<String, Value>>,
    pub certificates: Option<Map<String, Value>>,
    pub storages: Option<Map<String, Value>>,
}

fn format_item_toml_config(
    value: Option<Value>,
    category: &Category,
    name: &str,
) -> Result<String> {
    if let Some(value) = value {
        let mut wrapper = Map::new();
        if name.is_empty() {
            wrapper.insert(format_category(category).to_string(), value);
        } else {
            let mut inner = Map::new();
            inner.insert(name.to_string(), value);
            wrapper.insert(
                format_category(category).to_string(),
                Value::Table(inner),
            );
        }

        to_string_pretty(&wrapper)
    } else {
        Ok("".to_string())
    }
}

impl PingapTomlConfig {
    pub fn to_toml(&self) -> Result<String> {
        to_string_pretty(self)
    }
    pub fn to_pingap_config(
        &self,
        replace_include: bool,
    ) -> Result<PingapConfig> {
        let value = self.to_toml()?;
        convert_pingap_config(value.as_bytes(), replace_include)
    }

    fn get_toml(&self, category: &Category, name: &str) -> Result<String> {
        let value = self.get(category, name);
        format_item_toml_config(value, category, name)
    }
    fn get_category_toml(&self, category: &Category) -> Result<String> {
        let wrapper = |value: Option<Value>| {
            if let Some(value) = value {
                let mut wrapper = Map::new();
                wrapper.insert(format_category(category).to_string(), value);
                to_string_pretty(&wrapper)
            } else {
                Ok("".to_string())
            }
        };
        match category {
            Category::Basic => wrapper(self.basic.clone()),
            Category::Server => wrapper(self.servers.clone().map(Value::Table)),
            Category::Location => {
                wrapper(self.locations.clone().map(Value::Table))
            },
            Category::Upstream => {
                wrapper(self.upstreams.clone().map(Value::Table))
            },
            Category::Plugin => wrapper(self.plugins.clone().map(Value::Table)),
            Category::Certificate => {
                wrapper(self.certificates.clone().map(Value::Table))
            },
            Category::Storage => {
                wrapper(self.storages.clone().map(Value::Table))
            },
        }
    }
    fn update(&mut self, category: &Category, name: &str, value: Value) {
        let name = name.to_string();
        match category {
            Category::Basic => {
                self.basic = Some(value);
            },
            Category::Server => {
                self.servers.get_or_insert_default().insert(name, value);
            },
            Category::Location => {
                self.locations.get_or_insert_default().insert(name, value);
            },
            Category::Upstream => {
                self.upstreams.get_or_insert_default().insert(name, value);
            },
            Category::Plugin => {
                self.plugins.get_or_insert_default().insert(name, value);
            },
            Category::Certificate => {
                self.certificates
                    .get_or_insert_default()
                    .insert(name, value);
            },
            Category::Storage => {
                self.storages.get_or_insert_default().insert(name, value);
            },
        };
    }
    fn get(&self, category: &Category, name: &str) -> Option<Value> {
        match category {
            Category::Basic => self.basic.clone(),
            Category::Server => self
                .servers
                .as_ref()
                .and_then(|servers| servers.get(name).cloned()),
            Category::Location => self
                .locations
                .as_ref()
                .and_then(|locations| locations.get(name).cloned()),
            Category::Upstream => self
                .upstreams
                .as_ref()
                .and_then(|upstreams| upstreams.get(name).cloned()),
            Category::Plugin => self
                .plugins
                .as_ref()
                .and_then(|plugins| plugins.get(name).cloned()),
            Category::Certificate => self
                .certificates
                .as_ref()
                .and_then(|certificates| certificates.get(name).cloned()),
            Category::Storage => self
                .storages
                .as_ref()
                .and_then(|storages| storages.get(name).cloned()),
        }
    }
    fn delete(&mut self, category: &Category, name: &str) {
        match category {
            Category::Basic => self.basic = None,
            Category::Server => {
                self.servers.get_or_insert_default().remove(name);
            },
            Category::Location => {
                self.locations.get_or_insert_default().remove(name);
            },
            Category::Upstream => {
                self.upstreams.get_or_insert_default().remove(name);
            },
            Category::Plugin => {
                self.plugins.get_or_insert_default().remove(name);
            },
            Category::Certificate => {
                self.certificates.get_or_insert_default().remove(name);
            },
            Category::Storage => {
                self.storages.get_or_insert_default().remove(name);
            },
        };
    }
}

#[derive(PartialEq, Clone, Debug)]
pub enum ConfigMode {
    /// single mode (e.g., pingap.toml)
    Single,
    /// multi by type (e.g., servers.toml, locations.toml)
    MultiByType,
    /// multi by item (e.g., servers/web.toml)
    MultiByItem,
}

static SINGLE_KEY: &str = "pingap.toml";

fn bool_from_str<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Option<&str> = Deserialize::deserialize(deserializer)?;
    match s {
        Some("false") => Ok(false),
        _ => Ok(true),
    }
}

#[derive(Deserialize, Default, Debug)]
struct ConfigManagerParams {
    #[serde(default, deserialize_with = "bool_from_str")]
    separation: bool,
    #[serde(default)]
    enable_history: bool,
}

pub fn new_file_config_manager(path: &str) -> Result<ConfigManager> {
    let (file, query) = path.split_once('?').unwrap_or((path, ""));
    let file = resolve_path(file);
    let filepath = Path::new(&file);
    let (mode, enable_history) = if is_config_dir(filepath) {
        let params: ConfigManagerParams =
            serde_qs::from_str(query).map_err(|e| Error::Invalid {
                message: e.to_string(),
            })?;
        if params.separation {
            (ConfigMode::MultiByItem, params.enable_history)
        } else {
            (ConfigMode::MultiByType, false)
        }
    } else {
        (ConfigMode::Single, false)
    };

    let mut storage = FileStorage::new(&file)?;
    if enable_history {
        storage.with_history_path(&format!("{file}-history"))?;
    }
    Ok(ConfigManager::new(Arc::new(storage), mode))
}

/// Creates a config manager backed by an in-memory config.
///
/// `data` is the whole configuration as toml — the same layout a single config
/// file would have. Used by the command line quick start, which synthesizes the
/// config from arguments instead of reading it from disk. `path`, when given,
/// receives every write so an ACME issued certificate survives a restart.
pub fn new_memory_config_manager(
    data: &str,
    path: Option<PathBuf>,
) -> ConfigManager {
    let mut storage = MemoryStorage::new(data);
    if let Some(path) = path {
        storage = storage.with_path(path);
    }
    ConfigManager::new(Arc::new(storage), ConfigMode::Single)
}

pub fn new_etcd_config_manager(path: &str) -> Result<ConfigManager> {
    let storage = EtcdStorage::new(path)?;
    Ok(ConfigManager::new(
        Arc::new(storage),
        ConfigMode::MultiByItem,
    ))
}

pub struct ConfigManager {
    storage: Arc<dyn Storage>,
    mode: ConfigMode,
    current_config: ArcSwap<PingapConfig>,
    // Serializes read-modify-write config mutations (update/delete/save_all)
    // so concurrent admin/ACME writes to the same storage file cannot clobber
    // each other's changes.
    write_lock: tokio::sync::Mutex<()>,
}

impl ConfigManager {
    pub fn new(storage: Arc<dyn Storage>, mode: ConfigMode) -> Self {
        Self {
            storage,
            mode,
            current_config: ArcSwap::from_pointee(PingapConfig::default()),
            write_lock: tokio::sync::Mutex::new(()),
        }
    }
    pub fn support_observer(&self) -> bool {
        self.storage.support_observer()
    }
    pub async fn observe(&self) -> Result<Observer> {
        self.storage.observe().await
    }

    pub fn get_current_config(&self) -> Arc<PingapConfig> {
        self.current_config.load().clone()
    }
    pub fn set_current_config(&self, config: PingapConfig) {
        // Keep the global trusted-proxy set in sync with the active config so
        // client-IP resolution (X-Forwarded-For handling) is applied on both
        // boot and every reload without a separate wiring point.
        pingap_core::set_trusted_proxies(&config.basic.trusted_proxies);
        self.current_config.store(Arc::new(config));
    }

    /// get storage key
    fn get_key(&self, category: &Category, name: &str) -> Result<String> {
        // Config item names are single path segments, so a path separator (or
        // NUL) can only come from an attacker crafting a traversal such as
        // `../../etc/foo`. Reject those before the name is joined onto the
        // storage directory: without a separator the name stays one path
        // component and cannot climb out of the category directory.
        if name.contains('/') || name.contains('\\') || name.contains('\0') {
            return Err(Error::Invalid {
                message: format!("invalid config name: {name:?}"),
            });
        }
        let key = match self.mode {
            ConfigMode::Single => SINGLE_KEY.to_string(),
            ConfigMode::MultiByType => {
                format!("{}.toml", format_category(category))
            },
            ConfigMode::MultiByItem => {
                if *category == Category::Basic {
                    format!("{}.toml", format_category(category))
                } else {
                    format!("{}/{}.toml", format_category(category), name)
                }
            },
        };
        Ok(key)
    }

    pub async fn load_all(&self) -> Result<PingapTomlConfig> {
        let data = self.storage.fetch("").await?;
        toml::from_str(&data).map_err(|e| Error::De { source: e })
    }

    /// Whether `key` is a file this `ConfigMode` itself writes.
    ///
    /// Reads accept any layout the loader can glob, but every write -
    /// `get`/`update`/`delete`, the admin panel, the ACME certificate save -
    /// only ever addresses these canonical names. A file outside this set is
    /// therefore configuration the write path cannot see or maintain: `get`
    /// misses it (an ACME certificate defined there was silently never
    /// saved), and a category write puts a second copy of its tables next to
    /// it, after which the concatenated document stops parsing with a
    /// `duplicate key` whose line number matches no individual file.
    fn is_canonical_key(&self, key: &str) -> bool {
        const CATEGORIES: [Category; 7] = [
            Category::Basic,
            Category::Server,
            Category::Location,
            Category::Upstream,
            Category::Plugin,
            Category::Certificate,
            Category::Storage,
        ];
        match self.mode {
            ConfigMode::Single => true,
            // One `<category>.toml` per category, all at the top level.
            ConfigMode::MultiByType => CATEGORIES.iter().any(|category| {
                key == format!("{}.toml", format_category(category))
            }),
            // `basic.toml` at the top level, everything else as one
            // `<category>/<name>.toml` per item.
            ConfigMode::MultiByItem => {
                if key == "basic.toml" {
                    return true;
                }
                let Some((dir, name)) = key.split_once('/') else {
                    return false;
                };
                !name.contains('/')
                    && CATEGORIES.iter().any(|category| {
                        *category != Category::Basic
                            && dir == format_category(category)
                    })
            },
        }
    }

    /// Config files the current mode would never have written itself: another
    /// mode's layout (`pingap.toml` from the days the directory did not exist
    /// yet, `certificates.toml` in a by item directory) or a hand combined
    /// file holding several categories. The loader reads them all the same,
    /// which is exactly the trap - everything works until the first write.
    async fn stale_layout_keys(&self) -> Result<Vec<String>> {
        // Everything lives in the one file the user pointed at, so there is
        // no directory around it to hold a competing layout.
        if self.mode == ConfigMode::Single {
            return Ok(vec![]);
        }
        let keys = self.storage.list_keys("").await?;
        Ok(keys
            .into_iter()
            .filter(|key| !self.is_canonical_key(key))
            .collect())
    }

    /// Rewrites the configuration in canonical form and retires the files the
    /// current mode would never have written itself - another mode's leftovers
    /// or hand combined files.
    ///
    /// Call this once, before the first read, and never after a write. The
    /// admin panel edits a single entry through [`ConfigManager::update`],
    /// which only holds that entry and so cannot safely clean up a file
    /// containing all the others - it is that write which turns a directory
    /// carrying one non-canonical file into a directory carrying two copies
    /// of its tables. Doing the migration up front is also the last moment
    /// the directory still parses.
    ///
    /// Returns a description of every retired file. An empty vec means there
    /// was nothing to migrate, which is the normal case and costs one
    /// directory listing.
    pub async fn migrate_layout(&self) -> Result<Vec<String>> {
        let stale = self.stale_layout_keys().await?;
        if stale.is_empty() {
            return Ok(vec![]);
        }
        let config = match self.load_all().await {
            Ok(config) => config,
            Err(e) => {
                // Both layouts are already present, so the concatenated
                // document no longer parses and there is nothing to migrate
                // from. Which copy of a table should win is not ours to guess,
                // so name the files and let the operator merge them.
                return Err(Error::Invalid {
                    message: format!(
                        "config directory holds more than one layout and no longer parses ({e}); files written by the previous layout: {}. Merge what is still needed into the current layout and remove them.",
                        stale.join(", ")
                    ),
                });
            },
        };
        // Write the new layout before retiring the old one: interrupted the
        // other way round, the configuration would be gone.
        self.save_all(&config).await?;
        let mut retired = Vec::with_capacity(stale.len());
        for key in stale {
            retired.push(self.storage.retire(&key).await?);
        }
        Ok(retired)
    }
    pub async fn save_all(&self, config: &PingapTomlConfig) -> Result<()> {
        let _guard = self.write_lock.lock().await;
        match self.mode {
            ConfigMode::Single => {
                self.storage
                    .save(
                        &self.get_key(&Category::Basic, "")?,
                        &to_string_pretty(config)?,
                    )
                    .await?;
            },
            ConfigMode::MultiByType => {
                for category in [
                    Category::Basic,
                    Category::Server,
                    Category::Location,
                    Category::Upstream,
                    Category::Plugin,
                    Category::Certificate,
                    Category::Storage,
                ]
                .iter()
                {
                    let value = config.get_category_toml(category)?;
                    self.storage
                        .save(&self.get_key(category, "")?, &value)
                        .await?;
                }
            },
            ConfigMode::MultiByItem => {
                let basic_config = config.get_toml(&Category::Basic, "")?;
                self.storage
                    .save(&self.get_key(&Category::Basic, "")?, &basic_config)
                    .await?;

                for (category, value) in [
                    (Category::Server, config.servers.clone()),
                    (Category::Location, config.locations.clone()),
                    (Category::Upstream, config.upstreams.clone()),
                    (Category::Plugin, config.plugins.clone()),
                    (Category::Certificate, config.certificates.clone()),
                    (Category::Storage, config.storages.clone()),
                ] {
                    let Some(value) = value else {
                        continue;
                    };
                    for name in value.keys() {
                        let value = config.get_toml(&category, name)?;
                        self.storage
                            .save(&self.get_key(&category, name)?, &value)
                            .await?;
                    }
                }
            },
        }

        Ok(())
    }
    pub async fn update<T: Serialize + Send + Sync>(
        &self,
        category: Category,
        name: &str,
        value: &T,
    ) -> Result<()> {
        let _guard = self.write_lock.lock().await;
        let key = self.get_key(&category, name)?;
        let value = toml::to_string_pretty(value)
            .map_err(|e| Error::Ser { source: e })?;
        // update by item
        if self.mode == ConfigMode::MultiByItem {
            let value: Value =
                toml::from_str(&value).map_err(|e| Error::De { source: e })?;
            let value = format_item_toml_config(Some(value), &category, name)?;
            return self.storage.save(&key, &value).await;
        }
        // load all config
        let mut config = self.load_all().await?;
        let value: Value =
            toml::from_str(&value).map_err(|e| Error::De { source: e })?;
        config.update(&category, name, value);
        // update by type
        let value = if self.mode == ConfigMode::MultiByType {
            config.get_category_toml(&category)?
        } else {
            to_string_pretty(&config)?
        };

        self.storage.save(&key, &value).await?;
        Ok(())
    }
    pub async fn get<T: DeserializeOwned + Send>(
        &self,
        category: Category,
        name: &str,
    ) -> Result<Option<T>> {
        let key = self.get_key(&category, name)?;
        let data = self.storage.fetch(&key).await?;
        let config: PingapTomlConfig =
            toml::from_str(&data).map_err(|e| Error::De { source: e })?;

        if let Some(value) = config.get(&category, name) {
            let value = to_string_pretty(&value)?;
            let value =
                toml::from_str(&value).map_err(|e| Error::De { source: e })?;
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }
    pub async fn delete(&self, category: Category, name: &str) -> Result<()> {
        let _guard = self.write_lock.lock().await;
        let key = self.get_key(&category, name)?;

        let mut current_config = (*self.get_current_config()).clone();
        current_config.remove(category.to_string().as_str(), name)?;

        if self.mode == ConfigMode::MultiByItem {
            return self.storage.delete(&key).await;
        }
        let mut config = self.load_all().await?;
        config.delete(&category, name);
        let value = if self.mode == ConfigMode::MultiByType {
            config.get_category_toml(&category)?
        } else {
            to_string_pretty(&config)?
        };
        self.storage.save(&key, &value).await
    }
    pub fn support_history(&self) -> bool {
        self.storage.support_history()
    }
    pub async fn history(
        &self,
        category: Category,
        name: &str,
    ) -> Result<Option<Vec<History>>> {
        if !self.storage.support_history() {
            return Ok(None);
        }
        let key = self.get_key(&category, name)?;
        self.storage.fetch_history(&key).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nanoid::nanoid;
    use pretty_assertions::assert_eq;

    fn new_pingap_config() -> PingapTomlConfig {
        let basic_config = r#"auto_restart_check_interval = "1s"
        name = "pingap"
        pid_file = "/tmp/pingap.pid"
        "#;

        let server_config = r#"[server1]
        addr = "127.0.0.1:8080"
        locations = ["location1"]
        threads = 1
        
        [server2]
        addr = "127.0.0.1:8081"
        locations = ["location2"]
        threads = 2
        "#;

        let upstream_config = r#"[upstream1]
        addrs = ["127.0.0.1:7080"]
        
        [upstream2]
        addrs = ["127.0.0.1:7081"]
        "#;

        let location_config = r#"[location1]
        upstream = "upstream1"
        
        [location2]
        upstream = "upstream2"
        "#;

        let plugin_config = r#"[plugin1]
        value = "/plugin1"
        category = "plugin1"
        
        [plugin2]
        value = "/plugin2"
        category = "plugin2"
        "#;

        let certificate_config = r#"[certificate1]
        cert = "/certificate1"
        key = "/key1"
        
        [certificate2]
        cert = "/certificate2"
        key = "/key2"
        "#;
        let storage_config = r#"[storage1]
        value = "/storage1"
        category = "storage1"
        
        [storage2]
        value = "/storage2"
        category = "storage2"
        "#;

        PingapTomlConfig {
            basic: Some(toml::from_str(basic_config).unwrap()),
            servers: Some(toml::from_str(server_config).unwrap()),
            upstreams: Some(toml::from_str(upstream_config).unwrap()),
            locations: Some(toml::from_str(location_config).unwrap()),
            plugins: Some(toml::from_str(plugin_config).unwrap()),
            certificates: Some(toml::from_str(certificate_config).unwrap()),
            storages: Some(toml::from_str(storage_config).unwrap()),
        }
    }

    async fn test_config_manger(manager: ConfigManager, mode: ConfigMode) {
        assert_eq!(true, mode == manager.mode);

        let config = new_pingap_config();

        manager.save_all(&config).await.unwrap();

        // get all data from file
        let data = manager.storage.fetch("").await.unwrap();
        let new_config = toml::from_str::<PingapTomlConfig>(&data).unwrap();

        assert_eq!(toml::to_string(&config), toml::to_string(&new_config));

        let current_config = manager.load_all().await.unwrap();
        assert_eq!(
            toml::to_string(&config).unwrap(),
            toml::to_string(&current_config).unwrap()
        );

        // ----- basic config test start ----- //
        // get basic config
        let value: Value =
            manager.get(Category::Basic, "").await.unwrap().unwrap();
        assert_eq!(
            r#"auto_restart_check_interval = "1s"
name = "pingap"
pid_file = "/tmp/pingap.pid"
"#,
            toml::to_string(&value).unwrap()
        );
        // update basic config
        let new_basic_config: Value = toml::from_str(
            r#"auto_restart_check_interval = "2s"
name = "pingap2"
pid_file = "/tmp/pingap2.pid"
"#,
        )
        .unwrap();
        manager
            .update(Category::Basic, "", &new_basic_config)
            .await
            .unwrap();
        // get new basic config
        let value: Value =
            manager.get(Category::Basic, "").await.unwrap().unwrap();
        assert_eq!(
            toml::to_string(&new_basic_config).unwrap(),
            toml::to_string(&value).unwrap()
        );
        // ----- basic config test end ----- //

        // ----- server config test start ----- //
        // get server config
        let value: Value = manager
            .get(Category::Server, "server1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            r#"addr = "127.0.0.1:8080"
locations = ["location1"]
threads = 1
"#,
            toml::to_string(&value).unwrap()
        );
        // update server config
        let new_server_config: Value = toml::from_str(
            r#"addr = "192.186.1.1:8080"
locations = ["location1"]
threads = 1
"#,
        )
        .unwrap();
        manager
            .update(Category::Server, "server2", &new_server_config)
            .await
            .unwrap();
        // get new server config
        let value: Value = manager
            .get(Category::Server, "server2")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            toml::to_string(&new_server_config).unwrap(),
            toml::to_string(&value).unwrap()
        );
        // ----- server config test end ----- //

        // ----- upstream config test start ----- //
        // get upstream config
        let value: Value = manager
            .get(Category::Upstream, "upstream2")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            r#"addrs = ["127.0.0.1:7081"]
"#,
            toml::to_string(&value).unwrap()
        );
        // update upstream config
        let new_upstream_config: Value = toml::from_str(
            r#"addrs = ["192.168.1.1:7081"]
"#,
        )
        .unwrap();
        manager
            .update(Category::Upstream, "upstream2", &new_upstream_config)
            .await
            .unwrap();

        // get new upstream config
        let value: Value = manager
            .get(Category::Upstream, "upstream2")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            toml::to_string(&new_upstream_config).unwrap(),
            toml::to_string(&value).unwrap()
        );

        // ----- upstream config test end ----- //

        // ----- location config test start ----- //
        // get location config
        let value: Value = manager
            .get(Category::Location, "location2")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            r#"upstream = "upstream2"
"#,
            toml::to_string(&value).unwrap()
        );

        // update location config
        let new_location_config: Value = toml::from_str(
            r#"upstream = "upstream22"
"#,
        )
        .unwrap();
        manager
            .update(Category::Location, "location2", &new_location_config)
            .await
            .unwrap();

        // get new location config
        let value: Value = manager
            .get(Category::Location, "location2")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            toml::to_string(&new_location_config).unwrap(),
            toml::to_string(&value).unwrap()
        );

        // ----- location config test end ----- //

        // ----- plugin config test start ----- //
        // get plugin config
        let value: Value = manager
            .get(Category::Plugin, "plugin2")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            r#"category = "plugin2"
value = "/plugin2"
"#,
            toml::to_string(&value).unwrap()
        );

        // update plugin config
        let new_plugin_config: Value = toml::from_str(
            r#"category = "plugin22"
value = "/plugin22"
"#,
        )
        .unwrap();
        manager
            .update(Category::Plugin, "plugin2", &new_plugin_config)
            .await
            .unwrap();
        // get new plugin config
        let value: Value = manager
            .get(Category::Plugin, "plugin2")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            toml::to_string(&new_plugin_config).unwrap(),
            toml::to_string(&value).unwrap()
        );

        // ----- plugin config test end ----- //

        // ----- certificate config test start ----- //
        // get certificate config
        let value: Value = manager
            .get(Category::Certificate, "certificate2")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            r#"cert = "/certificate2"
key = "/key2"
"#,
            toml::to_string(&value).unwrap()
        );

        // update certificate config
        let new_certificate_config: Value = toml::from_str(
            r#"cert = "/certificate22"
key = "/key22"
"#,
        )
        .unwrap();
        manager
            .update(
                Category::Certificate,
                "certificate2",
                &new_certificate_config,
            )
            .await
            .unwrap();
        // get new certificate config
        let value: Value = manager
            .get(Category::Certificate, "certificate2")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            toml::to_string(&new_certificate_config).unwrap(),
            toml::to_string(&value).unwrap()
        );
        // ----- certificate config test end ----- //

        // ----- storage config test start ----- //
        // get storage config
        let value: Value = manager
            .get(Category::Storage, "storage2")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            r#"category = "storage2"
value = "/storage2"
"#,
            toml::to_string(&value).unwrap()
        );
        // update storage config
        let new_storage_config: Value = toml::from_str(
            r#"category = "storage22"
value = "/storage22"
"#,
        )
        .unwrap();
        manager
            .update(Category::Storage, "storage2", &new_storage_config)
            .await
            .unwrap();
        // get new storage config
        let value: Value = manager
            .get(Category::Storage, "storage2")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            toml::to_string(&new_storage_config).unwrap(),
            toml::to_string(&value).unwrap()
        );
        // ----- storage config test end ----- //

        // ----- delete config test start ----- //

        // delete basic config
        manager.delete(Category::Basic, "").await.unwrap();
        let basic_config: Option<Value> =
            manager.get(Category::Basic, "").await.unwrap();
        assert_eq!(None, basic_config);

        // delete server config
        manager.delete(Category::Server, "server1").await.unwrap();
        let server_config: Option<Value> =
            manager.get(Category::Server, "server1").await.unwrap();
        assert_eq!(None, server_config);

        // delete location config
        manager
            .delete(Category::Location, "location1")
            .await
            .unwrap();
        let location_config: Option<Value> =
            manager.get(Category::Location, "location1").await.unwrap();
        assert_eq!(None, location_config);

        // delete upstream config
        manager
            .delete(Category::Upstream, "upstream1")
            .await
            .unwrap();
        let upstream_config: Option<Value> =
            manager.get(Category::Upstream, "upstream1").await.unwrap();
        assert_eq!(None, upstream_config);

        // delete plugin config
        manager.delete(Category::Plugin, "plugin1").await.unwrap();
        let plugin_config: Option<Value> =
            manager.get(Category::Plugin, "plugin1").await.unwrap();
        assert_eq!(None, plugin_config);

        // delete certificate config
        manager
            .delete(Category::Certificate, "certificate1")
            .await
            .unwrap();
        let certificate_config: Option<Value> = manager
            .get(Category::Certificate, "certificate1")
            .await
            .unwrap();
        assert_eq!(None, certificate_config);

        // delete storage config
        manager.delete(Category::Storage, "storage1").await.unwrap();
        let storage_config: Option<Value> =
            manager.get(Category::Storage, "storage1").await.unwrap();
        assert_eq!(None, storage_config);

        let current_config = manager.load_all().await.unwrap();
        assert_eq!(
            r#"[servers.server2]
addr = "192.186.1.1:8080"
locations = ["location1"]
threads = 1

[upstreams.upstream2]
addrs = ["192.168.1.1:7081"]

[locations.location2]
upstream = "upstream22"

[plugins.plugin2]
category = "plugin22"
value = "/plugin22"

[certificates.certificate2]
cert = "/certificate22"
key = "/key22"

[storages.storage2]
category = "storage22"
value = "/storage22"
"#,
            toml::to_string(&current_config).unwrap()
        );

        // ----- delete config test end ----- //
    }

    #[tokio::test]
    async fn test_single_config_manger() {
        let file = tempfile::NamedTempFile::with_suffix(".toml").unwrap();

        let manager =
            new_file_config_manager(&file.path().to_string_lossy()).unwrap();
        test_config_manger(manager, ConfigMode::Single).await;
    }

    #[tokio::test]
    async fn test_multi_by_type_config_manger() {
        let file = tempfile::TempDir::new().unwrap();

        let manager =
            new_file_config_manager(&file.path().to_string_lossy()).unwrap();
        test_config_manger(manager, ConfigMode::MultiByType).await;
    }

    #[tokio::test]
    async fn test_multi_by_item_config_manger() {
        let file = tempfile::TempDir::new().unwrap();

        let manager = new_file_config_manager(&format!(
            "{}?separation",
            file.path().to_string_lossy()
        ))
        .unwrap();
        test_config_manger(manager, ConfigMode::MultiByItem).await;
    }

    #[tokio::test]
    async fn test_etcd_config_manger() {
        let url = format!(
            "etcd://127.0.0.1:2379/{}?timeout=10s&connect_timeout=5s",
            nanoid!(16)
        );
        let manager = new_etcd_config_manager(&url).unwrap();
        test_config_manger(manager, ConfigMode::MultiByItem).await;
    }

    #[tokio::test]
    async fn test_config_name_rejects_path_traversal() {
        let dir = tempfile::TempDir::new().unwrap();
        let manager = new_file_config_manager(&format!(
            "{}?separation",
            dir.path().to_string_lossy()
        ))
        .unwrap();
        let value: toml::Value =
            toml::from_str(r#"addrs = ["127.0.0.1:7080"]"#).unwrap();

        // A name with a path separator (or NUL) must be rejected so it cannot
        // escape the storage directory via traversal.
        for name in ["../../evil", "..\\evil", "a/b", "x\0y"] {
            assert_eq!(
                true,
                manager
                    .update(Category::Upstream, name, &value)
                    .await
                    .is_err(),
                "update must reject {name:?}"
            );
            assert_eq!(
                true,
                manager.delete(Category::Upstream, name).await.is_err(),
                "delete must reject {name:?}"
            );
            assert_eq!(
                true,
                manager
                    .get::<toml::Value>(Category::Upstream, name)
                    .await
                    .is_err(),
                "get must reject {name:?}"
            );
        }

        // Nothing escaped the storage directory.
        assert_eq!(
            false,
            dir.path().parent().unwrap().join("evil.toml").exists()
        );

        // A dotted-but-safe name (e.g. a certificate domain) is still accepted.
        assert_eq!(
            true,
            manager
                .update(Category::Upstream, "example.com", &value)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_mode_of_a_path_that_does_not_exist_yet() {
        let dir = tempfile::TempDir::new().unwrap();

        // A directory pingap is asked to manage before it has been created has
        // to be treated as a directory, or the very first run writes a layout
        // no later run would produce.
        for (path, expected) in [
            ("conf", ConfigMode::MultiByType),
            ("nested/conf", ConfigMode::MultiByType),
            // An extension the loader understands means a single config file.
            ("pingap.toml", ConfigMode::Single),
            ("pingap.hcl", ConfigMode::Single),
            ("pingap.kdl", ConfigMode::Single),
        ] {
            let target = dir.path().join(path);
            assert_eq!(false, target.exists(), "{path} must not exist yet");
            let manager =
                new_file_config_manager(&target.to_string_lossy()).unwrap();
            assert_eq!(expected, manager.mode, "{path}");
        }

        // And `separation` is honoured rather than silently dropped.
        let manager = new_file_config_manager(&format!(
            "{}?separation=true",
            dir.path().join("fresh").to_string_lossy()
        ))
        .unwrap();
        assert_eq!(ConfigMode::MultiByItem, manager.mode);

        // Writing it produces the separated layout, not a `pingap.toml` that
        // the next run would then have to migrate away.
        manager.save_all(&new_pingap_config()).await.unwrap();
        assert_eq!(true, dir.path().join("fresh/basic.toml").exists());
        assert_eq!(false, dir.path().join("fresh").join(SINGLE_KEY).exists());
    }

    #[tokio::test]
    async fn test_single_config_file_is_not_created_as_a_directory() {
        let dir = tempfile::TempDir::new().unwrap();
        let target = dir.path().join("pingap.toml");

        let manager =
            new_file_config_manager(&target.to_string_lossy()).unwrap();
        assert_eq!(ConfigMode::Single, manager.mode);

        // Reading a config file that has not been written yet is empty, not an
        // error.
        let config = manager.load_all().await.unwrap();
        assert_eq!(true, config.basic.is_none());

        manager.save_all(&new_pingap_config()).await.unwrap();

        // The whole point: the key resolves to the file itself. Resolving it
        // underneath the path instead turned `pingap.toml` into a directory
        // holding a second `pingap.toml`.
        assert_eq!(true, target.is_file());
        assert_eq!(false, target.join(SINGLE_KEY).exists());

        let config = manager.load_all().await.unwrap();
        assert_eq!(true, config.basic.is_some());
    }

    /// Config written by a `Single` mode run, which is what pingap falls back
    /// to when the directory it was pointed at did not exist yet.
    const SINGLE_LAYOUT: &str = r#"
[basic]
name = "pingap"

[upstreams.demo]
addrs = ["127.0.0.1:7080"]
"#;

    #[tokio::test]
    async fn test_migrate_single_layout_to_by_item() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join(SINGLE_KEY), SINGLE_LAYOUT).unwrap();

        let manager = new_file_config_manager(&format!(
            "{}?separation=true",
            dir.path().to_string_lossy()
        ))
        .unwrap();

        let retired = manager.migrate_layout().await.unwrap();
        assert_eq!(1, retired.len(), "{retired:?}");
        assert_eq!(true, retired[0].contains(SINGLE_KEY), "{retired:?}");

        // The single file is out of the way and the by item layout replaced it.
        assert_eq!(false, dir.path().join(SINGLE_KEY).exists());
        assert_eq!(true, dir.path().join("basic.toml").exists());
        assert_eq!(true, dir.path().join("upstreams/demo.toml").exists());

        // Without history the bytes stay one rename away.
        assert_eq!(true, dir.path().join("pingap.toml.bak").exists());

        // And the configuration itself survived the move intact.
        let config = manager.load_all().await.unwrap();
        let config = config.to_pingap_config(true).unwrap();
        assert_eq!(Some("pingap".to_string()), config.basic.name);
        assert_eq!(1, config.upstreams.len());

        // Re-running is a no-op, so a restart does not keep rewriting.
        assert_eq!(true, manager.migrate_layout().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_migrate_by_type_layout_to_by_item() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("basic.toml"), "[basic]\n").unwrap();
        std::fs::write(
            dir.path().join("upstreams.toml"),
            "[upstreams.demo]\naddrs = [\"127.0.0.1:7080\"]\n",
        )
        .unwrap();

        let manager = new_file_config_manager(&format!(
            "{}?separation=true",
            dir.path().to_string_lossy()
        ))
        .unwrap();

        let retired = manager.migrate_layout().await.unwrap();
        assert_eq!(1, retired.len(), "{retired:?}");
        assert_eq!(true, retired[0].contains("upstreams.toml"), "{retired:?}");

        // `basic.toml` is shared by both multi modes, so it must be left alone.
        assert_eq!(true, dir.path().join("basic.toml").exists());
        assert_eq!(false, dir.path().join("upstreams.toml").exists());
        assert_eq!(true, dir.path().join("upstreams/demo.toml").exists());
    }

    #[tokio::test]
    async fn test_migrate_by_item_layout_to_by_type() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("upstreams")).unwrap();
        std::fs::write(
            dir.path().join("upstreams/demo.toml"),
            "[upstreams.demo]\naddrs = [\"127.0.0.1:7080\"]\n",
        )
        .unwrap();

        // No `separation`, so this run wants one file per category.
        let manager =
            new_file_config_manager(&dir.path().to_string_lossy()).unwrap();

        let retired = manager.migrate_layout().await.unwrap();
        assert_eq!(1, retired.len(), "{retired:?}");
        assert_eq!(
            true,
            retired[0].contains("upstreams/demo.toml"),
            "{retired:?}"
        );
        assert_eq!(false, dir.path().join("upstreams/demo.toml").exists());
        assert_eq!(true, dir.path().join("upstreams.toml").exists());
    }

    #[tokio::test]
    async fn test_migrate_keeps_retired_config_in_history() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join(SINGLE_KEY), SINGLE_LAYOUT).unwrap();

        let manager = new_file_config_manager(&format!(
            "{}?separation=true&enable_history=true",
            dir.path().to_string_lossy()
        ))
        .unwrap();

        let retired = manager.migrate_layout().await.unwrap();
        assert_eq!(1, retired.len(), "{retired:?}");
        assert_eq!(true, retired[0].contains("history"), "{retired:?}");

        // History holds the bytes, so no `.bak` is needed next to the config.
        assert_eq!(false, dir.path().join("pingap.toml.bak").exists());
        let history = std::fs::read_dir(format!(
            "{}-history",
            dir.path().to_string_lossy()
        ))
        .unwrap()
        .count();
        assert_eq!(1, history);
    }

    #[tokio::test]
    async fn test_migrate_reports_a_directory_that_already_holds_two_layouts() {
        let dir = tempfile::TempDir::new().unwrap();
        // What a directory looks like once an `update` wrote the second layout
        // next to the first: two `[basic]` tables, so the concatenation of
        // every toml file no longer parses.
        std::fs::write(dir.path().join(SINGLE_KEY), SINGLE_LAYOUT).unwrap();
        std::fs::write(dir.path().join("basic.toml"), "[basic]\n").unwrap();

        let manager = new_file_config_manager(&format!(
            "{}?separation=true",
            dir.path().to_string_lossy()
        ))
        .unwrap();

        let message = manager.migrate_layout().await.unwrap_err().to_string();
        // The operator gets the file to look at, not a line number from a
        // buffer that exists only in memory.
        assert_eq!(true, message.contains(SINGLE_KEY), "{message}");
        assert_eq!(true, message.contains("more than one layout"), "{message}");

        // Nothing was touched, so merging by hand is still possible.
        assert_eq!(true, dir.path().join(SINGLE_KEY).exists());
        assert_eq!(true, dir.path().join("basic.toml").exists());
    }

    /// The layout behind issue #213: a directory holding one combined file
    /// with every section in it. The loader globs all toml files so this
    /// starts up and serves fine - but `get`/`update` address categories by
    /// their canonical files, so an ACME issued certificate was looked up as
    /// `certificates.toml`/`certificates/<name>.toml`, found nothing, and was
    /// silently dropped; every cycle then re-issued from scratch until the
    /// CA's duplicate-certificate rate limit cut it off.
    const COMBINED_LAYOUT: &str = r#"
[basic]
name = "pingap"

[certificates.panel]
domains = "example.com"
acme = "lets_encrypt"

[upstreams.demo]
addrs = ["127.0.0.1:7080"]
"#;

    #[tokio::test]
    async fn test_migrate_normalizes_a_combined_file() {
        for query in ["", "?separation=true"] {
            let dir = tempfile::TempDir::new().unwrap();
            // Any file name that is not a canonical one.
            std::fs::write(dir.path().join("my-proxy.toml"), COMBINED_LAYOUT)
                .unwrap();
            let manager = new_file_config_manager(&format!(
                "{}{query}",
                dir.path().to_string_lossy()
            ))
            .unwrap();

            // Before the migration the certificate cannot be addressed - this
            // miss is what used to lose the issued certificate.
            let cert: Option<toml::Value> =
                manager.get(Category::Certificate, "panel").await.unwrap();
            assert_eq!(true, cert.is_none(), "{query}");

            let retired = manager.migrate_layout().await.unwrap();
            assert_eq!(1, retired.len(), "{query}: {retired:?}");
            assert_eq!(
                true,
                retired[0].contains("my-proxy.toml"),
                "{query}: {retired:?}"
            );

            // Now every write path can find it.
            let cert: Option<toml::Value> =
                manager.get(Category::Certificate, "panel").await.unwrap();
            assert_eq!(true, cert.is_some(), "{query}");

            // And the ACME save itself round-trips: update the certificate,
            // reload, and the stored value is visible to the loader.
            let mut cert = cert.unwrap();
            cert.as_table_mut().unwrap().insert(
                "tls_cert".to_string(),
                toml::Value::String("PEM".to_string()),
            );
            manager
                .update(Category::Certificate, "panel", &cert)
                .await
                .unwrap();
            let config = manager.load_all().await.unwrap();
            let value = config.get(&Category::Certificate, "panel").unwrap();
            assert_eq!(
                "PEM",
                value.get("tls_cert").and_then(|v| v.as_str()).unwrap(),
                "{query}"
            );
            // The rest of the combined file survived the normalization.
            assert_eq!(
                true,
                config.get(&Category::Upstream, "demo").is_some(),
                "{query}"
            );
            assert_eq!(true, config.basic.is_some(), "{query}");

            // Re-running is a no-op.
            assert_eq!(
                true,
                manager.migrate_layout().await.unwrap().is_empty(),
                "{query}"
            );
        }
    }

    #[tokio::test]
    async fn test_migrate_normalizes_a_stray_nested_file() {
        let dir = tempfile::TempDir::new().unwrap();
        // A nested path no mode writes: loaded by the recursive glob, but
        // unreachable for every write.
        std::fs::create_dir_all(dir.path().join("sites")).unwrap();
        std::fs::write(
            dir.path().join("sites/demo.toml"),
            "[upstreams.demo]\naddrs = [\"127.0.0.1:7080\"]\n",
        )
        .unwrap();

        let manager = new_file_config_manager(&format!(
            "{}?separation=true",
            dir.path().to_string_lossy()
        ))
        .unwrap();
        let retired = manager.migrate_layout().await.unwrap();
        assert_eq!(1, retired.len(), "{retired:?}");
        assert_eq!(false, dir.path().join("sites/demo.toml").exists());
        assert_eq!(true, dir.path().join("upstreams/demo.toml").exists());
    }

    #[tokio::test]
    async fn test_migrate_is_noop_for_a_clean_directory() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("basic.toml"), "[basic]\n").unwrap();

        let manager = new_file_config_manager(&format!(
            "{}?separation=true",
            dir.path().to_string_lossy()
        ))
        .unwrap();
        assert_eq!(true, manager.migrate_layout().await.unwrap().is_empty());

        // A single config file has no directory to hold a second layout.
        let file = tempfile::NamedTempFile::with_suffix(".toml").unwrap();
        std::fs::write(file.path(), SINGLE_LAYOUT).unwrap();
        let manager =
            new_file_config_manager(&file.path().to_string_lossy()).unwrap();
        assert_eq!(true, manager.migrate_layout().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_concurrent_update_no_lost_write() {
        let file = tempfile::NamedTempFile::with_suffix(".toml").unwrap();
        // A plain `.toml` file is Single mode: every upstream lives in one
        // file, so concurrent read-modify-write updates would clobber each
        // other without the manager's write lock.
        let manager = Arc::new(
            new_file_config_manager(&file.path().to_string_lossy()).unwrap(),
        );
        let value: toml::Value =
            toml::from_str(r#"addrs = ["127.0.0.1:7080"]"#).unwrap();

        let mut handles = Vec::new();
        for i in 0..12 {
            let manager = manager.clone();
            let value = value.clone();
            handles.push(tokio::spawn(async move {
                manager
                    .update(Category::Upstream, &format!("up{i}"), &value)
                    .await
                    .unwrap();
            }));
        }
        for handle in handles {
            handle.await.unwrap();
        }

        // Every concurrently-written upstream must have survived.
        let config = manager.load_all().await.unwrap();
        let upstreams = config.upstreams.unwrap_or_default();
        for i in 0..12 {
            assert_eq!(
                true,
                upstreams.contains_key(format!("up{i}").as_str()),
                "upstream up{i} was lost to a concurrent write"
            );
        }
    }
}
