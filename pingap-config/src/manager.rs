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

use crate::convert_pingap_config;
use crate::etcd_storage::EtcdStorage;
use crate::file_storage::FileStorage;
use crate::storage::Storage;
use crate::PingapConfig;
use crate::{Category, Error, Observer};
use arc_swap::ArcSwap;
use pingap_util::resolve_path;
use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize};
use std::path::Path;
use std::sync::Arc;
use toml::{map::Map, Value};

type Result<T, E = Error> = std::result::Result<T, E>;

fn format_category(category: &Category) -> &str {
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
    let s: &str = Deserialize::deserialize(deserializer)?;
    // if s is "false", return false, otherwise return true
    match s {
        "false" => Ok(false),
        _ => Ok(true),
    }
}

#[derive(Deserialize, Default, Debug)]
struct ConfigManagerParams {
    #[serde(default, deserialize_with = "bool_from_str")]
    separation: bool,
}

pub fn new_file_config_manager(path: &str) -> Result<ConfigManager> {
    let (file, query) = path.split_once('?').unwrap_or((path, ""));
    let file = resolve_path(file);
    let filepath = Path::new(&file);
    let mode = if filepath.is_dir() {
        let params: ConfigManagerParams =
            serde_qs::from_str(query).map_err(|e| Error::Invalid {
                message: e.to_string(),
            })?;
        if params.separation {
            ConfigMode::MultiByItem
        } else {
            ConfigMode::MultiByType
        }
    } else {
        ConfigMode::Single
    };

    let storage = FileStorage::new(&file)?;
    Ok(ConfigManager::new(Arc::new(storage), mode))
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
}

impl ConfigManager {
    pub fn new(storage: Arc<dyn Storage>, mode: ConfigMode) -> Self {
        Self {
            storage,
            mode,
            current_config: ArcSwap::from_pointee(PingapConfig::default()),
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
        self.current_config.store(Arc::new(config));
    }

    /// get storage key
    fn get_key(&self, category: &Category, name: &str) -> String {
        match self.mode {
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
        }
    }

    pub async fn load_all(&self) -> Result<PingapTomlConfig> {
        let data = self.storage.fetch("").await?;
        toml::from_str(&data).map_err(|e| Error::De { source: e })
    }
    pub async fn save_all(&self, config: &PingapTomlConfig) -> Result<()> {
        match self.mode {
            ConfigMode::Single => {
                self.storage
                    .save(
                        &self.get_key(&Category::Basic, ""),
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
                        .save(&self.get_key(category, ""), &value)
                        .await?;
                }
            },
            ConfigMode::MultiByItem => {
                let basic_config = config.get_toml(&Category::Basic, "")?;
                self.storage
                    .save(&self.get_key(&Category::Basic, ""), &basic_config)
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
                            .save(&self.get_key(&category, name), &value)
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
        let key = self.get_key(&category, name);
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
        let key = self.get_key(&category, name);
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
        let key = self.get_key(&category, name);

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
}
