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

use crate::storage::Storage;
use crate::Error;
use async_trait::async_trait;
use etcd_client::{Client, ConnectOptions, GetOptions, WatchOptions};
use humantime::parse_duration;
use pingap_util::path_join;
use substring::Substring;

type Result<T, E = Error> = std::result::Result<T, E>;

pub struct EtcdStorage {
    // Base path for all config entries in etcd
    path: String,
    // List of etcd server addresses
    addrs: Vec<String>,
    // Connection options (timeout, auth, etc)
    options: ConnectOptions,
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
        for (key, value) in pingap_core::parse_query_string(&query) {
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
        })
    }
    /// Connect to etcd server.
    async fn connect(&self) -> Result<Client> {
        Client::connect(&self.addrs, Some(self.options.clone()))
            .await
            .map_err(|e| Error::Etcd {
                source: Box::new(e),
            })
    }
    fn get_path(&self, key: &str) -> String {
        path_join(&self.path, key)
    }
}

#[async_trait]
impl Storage for EtcdStorage {
    async fn fetch(&self, key: &str) -> Result<String> {
        let mut c = self.connect().await?;
        let key = self.get_path(key);
        let mut opts = GetOptions::new().with_prefix();
        if !key.ends_with(".toml") {
            opts = opts.with_prefix();
        }

        let arr = c
            .get(key.as_bytes(), Some(opts))
            .await
            .map_err(|e| Error::Etcd {
                source: Box::new(e),
            })?
            .take_kvs();
        let mut buffer = vec![];
        for item in arr {
            buffer.extend(item.value());
            buffer.push(0x0a);
        }
        Ok(String::from_utf8_lossy(buffer.as_slice()).to_string())
    }

    async fn save(&self, key: &str, value: &str) -> Result<()> {
        let key = self.get_path(key);
        let mut c = self.connect().await?;
        c.put(key, value, None).await.map_err(|e| Error::Etcd {
            source: Box::new(e),
        })?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let key = self.get_path(key);
        let mut c = self.connect().await?;
        c.delete(key, None).await.map_err(|e| Error::Etcd {
            source: Box::new(e),
        })?;
        Ok(())
    }
}
