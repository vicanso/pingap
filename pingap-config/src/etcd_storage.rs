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

use crate::storage::{History, Storage};
use crate::{Error, Observer};
use async_trait::async_trait;
use etcd_client::{
    Client, ConnectOptions, GetOptions, KeyValue, SortOrder, SortTarget,
    WatchOptions,
};
use pingap_core::now_sec;
use pingap_util::path_join;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use substring::Substring;

type Result<T, E = Error> = std::result::Result<T, E>;

pub struct EtcdStorage {
    // Base path for all config entries in etcd
    path: String,
    // History path for all config entries in etcd
    history_path: String,
    // List of etcd server addresses
    addrs: Vec<String>,
    // Connection options (timeout, auth, etc)
    options: ConnectOptions,
    // Enable history
    enable_history: bool,
}
pub const ETCD_PROTOCOL: &str = "etcd://";

#[derive(Debug, PartialEq, Deserialize, Serialize, Default)]
struct EtcdStorageParams {
    #[serde(default)]
    user: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    timeout: Option<Duration>,
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    connect_timeout: Option<Duration>,
    #[serde(default)]
    enable_history: bool,
}

impl TryFrom<&str> for EtcdStorageParams {
    type Error = Error;
    fn try_from(value: &str) -> Result<Self> {
        let params = serde_qs::from_str(value).map_err(|e| Error::Invalid {
            message: e.to_string(),
        })?;
        Ok(params)
    }
}

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
        let params = EtcdStorageParams::try_from(query.as_str())?;
        let mut options = ConnectOptions::default();

        if !params.user.is_empty() && !params.password.is_empty() {
            options = options.with_user(params.user, params.password);
        };
        if let Some(timeout) = params.timeout {
            options = options.with_timeout(timeout);
        };
        if let Some(connect_timeout) = params.connect_timeout {
            options = options.with_connect_timeout(connect_timeout);
        };
        let history_path = if path.ends_with("/") {
            format!("{}-history", path.substring(0, path.len() - 1))
        } else {
            format!("{path}-history")
        };

        Ok(Self {
            addrs,
            options,
            path,
            history_path,
            enable_history: params.enable_history,
        })
    }

    /// Connect to etcd server.
    async fn connect(&self) -> Result<Client> {
        // TODO
        // 使用client.clone()会导致第二次请求时失败
        // 暂时未明确为什么不可复用，后续再优化
        Client::connect(&self.addrs, Some(self.options.clone()))
            .await
            .map_err(|e| Error::Etcd {
                source: Box::new(e),
            })
    }
    fn get_path(&self, key: &str) -> String {
        path_join(&self.path, key)
    }
    fn get_history_path(&self, key: &str) -> String {
        path_join(&self.history_path, key)
    }
    async fn fetch_latest(&self, key: &str) -> Result<Option<KeyValue>> {
        let key = self.get_path(key);
        let mut c = self.connect().await?.kv_client();
        let arr = c
            .get(key.as_bytes(), None)
            .await
            .map_err(|e| Error::Etcd {
                source: Box::new(e),
            })?
            .take_kvs();
        Ok(arr.first().cloned())
    }

    async fn save_history(&self, key: &str) -> Result<()> {
        if !self.enable_history {
            return Ok(());
        }
        let latest = self.fetch_latest(key).await?;
        let Some(latest) = latest else {
            return Ok(());
        };

        let name = format!("{}-{}", latest.mod_revision(), now_sec());

        let history_key = path_join(&self.get_history_path(key), &name);
        let mut c = self.connect().await?.kv_client();
        c.put(history_key, latest.value(), None)
            .await
            .map_err(|e| Error::Etcd {
                source: Box::new(e),
            })?;
        Ok(())
    }
}

#[async_trait]
impl Storage for EtcdStorage {
    async fn fetch(&self, key: &str) -> Result<String> {
        let mut c = self.connect().await?.kv_client();
        let key = self.get_path(key);
        let mut opts = GetOptions::new();
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
        self.save_history(key).await?;
        let key = self.get_path(key);
        let mut c = self.connect().await?.kv_client();
        c.put(key, value, None).await.map_err(|e| Error::Etcd {
            source: Box::new(e),
        })?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let key = self.get_path(key);
        let mut c = self.connect().await?.kv_client();
        c.delete(key, None).await.map_err(|e| Error::Etcd {
            source: Box::new(e),
        })?;
        Ok(())
    }

    /// Indicates that this storage supports watching for changes
    fn support_observer(&self) -> bool {
        true
    }
    fn support_history(&self) -> bool {
        self.enable_history
    }
    async fn fetch_history(&self, key: &str) -> Result<Option<Vec<History>>> {
        let key = self.get_history_path(key);
        let mut c = self.connect().await?.kv_client();
        let opts = GetOptions::new()
            .with_prefix()
            .with_sort(SortTarget::Create, SortOrder::Descend)
            .with_limit(10);

        let kvs = c
            .get(key.as_bytes(), Some(opts))
            .await
            .map_err(|e| Error::Etcd {
                source: Box::new(e),
            })?
            .take_kvs();

        let histories = kvs
            .iter()
            .filter_map(|item| {
                let key_str = item.key_str().ok()?;
                let value_str = item.value_str().ok()?;
                let created_at = key_str
                    .split('-')
                    .next_back()
                    .and_then(|s| s.parse::<u64>().ok())?;
                Some(History {
                    data: value_str.to_string(),
                    created_at,
                })
            })
            .collect();

        Ok(Some(histories))
    }
    /// Sets up a watch on the config path to observe changes
    /// Note: May miss changes if processing takes too long between updates
    /// Should be used with periodic full fetches to ensure consistency
    async fn observe(&self) -> Result<Observer> {
        // 逻辑并不完善，有可能因为变更处理中途又发生其它变更导致缺失
        // 因此还需配合fetch的形式比对
        let mut c = self.connect().await?.watch_client();
        let (_, stream) = c
            .watch(
                self.path.as_bytes(),
                Some(WatchOptions::default().with_prefix()),
            )
            .await
            .map_err(|e| Error::Etcd {
                source: Box::new(e),
            })?;
        Ok(Observer {
            etcd_watch_stream: Some(stream),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_parse_params() {
        // timeout=10s&connect_timeout=5s&user=abc&password=pwd
        let params = EtcdStorageParams::try_from(
            "timeout=10s&connect_timeout=5s&user=abc&password=pwd",
        )
        .unwrap();
        assert_eq!(params.timeout, Some(Duration::from_secs(10)));
        assert_eq!(params.connect_timeout, Some(Duration::from_secs(5)));
        assert_eq!(params.user, "abc");
        assert_eq!(params.password, "pwd");
    }
}
