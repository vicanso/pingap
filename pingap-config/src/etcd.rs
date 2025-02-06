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

use super::{ConfigStorage, Error, LoadConfigOptions, Result};
use super::{Observer, PingapConf};
use async_trait::async_trait;
use etcd_client::{Client, ConnectOptions, GetOptions, WatchOptions};
use humantime::parse_duration;
use substring::Substring;

pub struct EtcdStorage {
    // Base path for all config entries in etcd
    path: String,
    // List of etcd server addresses
    addrs: Vec<String>,
    // Connection options (timeout, auth, etc)
    options: ConnectOptions,
    // Whether to separate config entries by category/name
    separation: bool,
}

pub const ETCD_PROTOCOL: &str = "etcd://";

impl EtcdStorage {
    /// Create a new etcd storage for config.
    /// Connection url format: etcd://host1:port1,host2:port2/pingap?timeout=10s&connect_timeout=5s&user=**&password=**
    pub fn new(value: &str) -> Result<Self> {
        let mut hosts = "".to_string();
        let mut path = "".to_string();
        let mut query = "".to_string();
        if let Some((value1, value2)) = value
            .substring(ETCD_PROTOCOL.len(), value.len())
            .split_once('/')
        {
            hosts = value1.to_string();
            let arr: Vec<&str> = value2.split('?').collect();
            path = format!("/{}", arr[0]);
            if arr.len() == 2 {
                query = arr[1].to_string();
            }
        }

        let addrs: Vec<String> =
            hosts.split(',').map(|item| item.to_string()).collect();
        let mut user = "".to_string();
        let mut password = "".to_string();
        let mut options = ConnectOptions::default();
        let mut separation = false;
        for (key, value) in pingap_util::convert_query_map(&query) {
            match key.as_str() {
                "user" => user = value,
                "password" => password = value,
                "timeout" => {
                    if let Ok(d) = parse_duration(&value) {
                        options = options.with_timeout(d);
                    }
                },
                "connect_timeout" => {
                    if let Ok(d) = parse_duration(&value) {
                        options = options.with_connect_timeout(d);
                    }
                },
                "separation" => {
                    separation = true;
                },
                _ => {},
            }
        }

        if !user.is_empty() && !password.is_empty() {
            options = options.with_user(user, password);
        };
        Ok(Self {
            addrs,
            options,
            path,
            separation,
        })
    }
    /// Connect to etcd server.
    async fn connect(&self) -> Result<Client> {
        Client::connect(&self.addrs, Some(self.options.clone()))
            .await
            .map_err(|e| Error::Etcd { source: e })
    }
}

#[async_trait]
impl ConfigStorage for EtcdStorage {
    /// Load config from etcd by fetching all keys under the base path
    async fn load_config(&self, opts: LoadConfigOptions) -> Result<PingapConf> {
        let mut c = self.connect().await?;
        let replace_include = opts.replace_include;
        let mut opts = GetOptions::new();
        opts = opts.with_prefix();
        let arr = c
            .get(self.path.as_bytes(), Some(opts))
            .await
            .map_err(|e| Error::Etcd { source: e })?
            .take_kvs();
        let mut buffer = vec![];
        for item in arr {
            buffer.extend(item.value());
            buffer.push(0x0a);
        }
        PingapConf::new(buffer.as_slice(), replace_include)
    }
    /// Save config to etcd, optionally separating by category/name
    /// If separation is enabled and name is provided, saves individual sections
    /// Otherwise saves the entire category as one entry
    async fn save_config(
        &self,
        conf: &PingapConf,
        category: &str,
        name: Option<&str>,
    ) -> Result<()> {
        conf.validate()?;
        let (path, toml_value) = if self.separation && name.is_some() {
            conf.get_toml(category, name)?
        } else {
            conf.get_toml(category, None)?
        };
        let key = pingap_util::path_join(&self.path, &path);
        let mut c = self.connect().await?;
        if toml_value.is_empty() {
            c.delete(key, None)
                .await
                .map_err(|e| Error::Etcd { source: e })?;
        } else {
            c.put(key, toml_value, None)
                .await
                .map_err(|e| Error::Etcd { source: e })?;
        }
        Ok(())
    }
    /// Indicates that this storage supports watching for changes
    fn support_observer(&self) -> bool {
        true
    }
    /// Sets up a watch on the config path to observe changes
    /// Note: May miss changes if processing takes too long between updates
    /// Should be used with periodic full fetches to ensure consistency
    async fn observe(&self) -> Result<Observer> {
        // 逻辑并不完善，有可能因为变更处理中途又发生其它变更导致缺失
        // 因此还需配合fetch的形式比对
        let mut c = self.connect().await?;
        let (_, stream) = c
            .watch(
                self.path.as_bytes(),
                Some(WatchOptions::default().with_prefix()),
            )
            .await
            .map_err(|e| Error::Etcd { source: e })?;
        Ok(Observer {
            etcd_watch_stream: Some(stream),
        })
    }
    /// Save key-value data under the base path
    async fn save(&self, key: &str, data: &[u8]) -> Result<()> {
        let key = pingap_util::path_join(&self.path, key);
        let mut c = self.connect().await?;
        c.put(key, data, None)
            .await
            .map_err(|e| Error::Etcd { source: e })?;
        Ok(())
    }
    /// Load key-value data from under the base path
    async fn load(&self, key: &str) -> Result<Vec<u8>> {
        let key = pingap_util::path_join(&self.path, key);
        let mut c = self.connect().await?;
        let arr = c
            .get(key, None)
            .await
            .map_err(|e| Error::Etcd { source: e })?
            .take_kvs();
        let buf = if arr.is_empty() { b"" } else { arr[0].value() };
        Ok(buf.into())
    }
}

#[cfg(test)]
mod tests {
    use super::EtcdStorage;
    use crate::{
        read_all_toml_files, ConfigStorage, LoadConfigOptions, PingapConf,
        CATEGORY_BASIC, CATEGORY_LOCATION, CATEGORY_PLUGIN, CATEGORY_SERVER,
        CATEGORY_STORAGE, CATEGORY_UPSTREAM,
    };
    use nanoid::nanoid;
    use pretty_assertions::assert_eq;

    #[tokio::test]
    async fn test_etcd_storage() {
        let url = format!(
            "etcd://127.0.0.1:2379/{}?timeout=10s&connect_timeout=5s",
            nanoid!(16)
        );
        let storage = EtcdStorage::new(&url).unwrap();
        let toml_data = read_all_toml_files("../../conf").await.unwrap();
        let conf =
            PingapConf::new(toml_data.to_vec().as_slice(), false).unwrap();

        storage
            .save_config(&conf, CATEGORY_BASIC, None)
            .await
            .unwrap();
        storage
            .save_config(&conf, CATEGORY_UPSTREAM, None)
            .await
            .unwrap();
        storage
            .save_config(&conf, CATEGORY_LOCATION, None)
            .await
            .unwrap();
        storage
            .save_config(&conf, CATEGORY_PLUGIN, None)
            .await
            .unwrap();
        storage
            .save_config(&conf, CATEGORY_SERVER, None)
            .await
            .unwrap();
        storage
            .save_config(&conf, CATEGORY_STORAGE, None)
            .await
            .unwrap();

        let current_conf = storage
            .load_config(LoadConfigOptions::default())
            .await
            .unwrap();
        assert_eq!(current_conf.hash().unwrap(), conf.hash().unwrap());
    }
}
