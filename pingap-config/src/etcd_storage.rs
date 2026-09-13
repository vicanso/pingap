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
    Client, ConnectOptions, GetOptions, KeyValue, KvClient, SortOrder,
    SortTarget, WatchOptions,
};
use pingap_core::now_sec;
use pingap_util::path_join;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::debug;

type Result<T, E = Error> = std::result::Result<T, E>;

fn etcd_error(e: etcd_client::Error) -> Error {
    Error::Etcd {
        source: Box::new(e),
    }
}

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
    /// The connection, made on first use and kept. `etcd_client::Client`
    /// is a handle over a shared channel, so handing out clones is cheap;
    /// every request used to open a fresh connection, which the reload loop
    /// did every few seconds.
    client: Mutex<Option<Client>>,
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
        let rest = value.strip_prefix(ETCD_PROTOCOL).unwrap_or(value);
        // `hosts/path?query`; a missing path is the root.
        let (hosts, path_query) = rest.split_once('/').unwrap_or((rest, ""));
        let (path, query) =
            path_query.split_once('?').unwrap_or((path_query, ""));
        if hosts.is_empty() {
            return Err(Error::Invalid {
                message: format!("etcd url {value} names no host"),
            });
        }
        let path = format!("/{path}");

        let addrs: Vec<String> =
            hosts.split(',').map(|item| item.to_string()).collect();
        let params = EtcdStorageParams::try_from(query)?;
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
        let history_path = format!("{}-history", path.trim_end_matches('/'));

        Ok(Self {
            addrs,
            options,
            path,
            history_path,
            enable_history: params.enable_history,
            client: Mutex::new(None),
        })
    }

    /// The shared connection, opened on first use.
    async fn client(&self) -> Result<Client> {
        let mut slot = self.client.lock().await;
        if let Some(client) = slot.as_ref() {
            return Ok(client.clone());
        }
        let client = Client::connect(&self.addrs, Some(self.options.clone()))
            .await
            .map_err(etcd_error)?;
        *slot = Some(client.clone());
        Ok(client)
    }

    /// Runs `op` on the shared connection. A request that fails is tried
    /// once more on a fresh connection, in case the old one went stale
    /// (etcd restarted, an auth token expired); every operation here is
    /// idempotent, so the retry is safe.
    async fn with_kv<T, F, Fut>(&self, op: F) -> Result<T>
    where
        F: Fn(KvClient) -> Fut,
        Fut: Future<Output = std::result::Result<T, etcd_client::Error>>,
    {
        let client = self.client().await?;
        match op(client.kv_client()).await {
            Ok(value) => Ok(value),
            Err(e) => {
                debug!(error = %e, "etcd request failed, reconnecting");
                *self.client.lock().await = None;
                let client = self.client().await?;
                op(client.kv_client()).await.map_err(etcd_error)
            },
        }
    }

    fn get_path(&self, key: &str) -> String {
        path_join(&self.path, key)
    }
    fn get_history_path(&self, key: &str) -> String {
        path_join(&self.history_path, key)
    }
    async fn fetch_latest(&self, key: &str) -> Result<Option<KeyValue>> {
        let key = self.get_path(key);
        let mut resp = self
            .with_kv(|mut kv| {
                let key = key.clone();
                async move { kv.get(key, None).await }
            })
            .await?;
        Ok(resp.take_kvs().into_iter().next())
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
        let value = latest.value().to_vec();
        self.with_kv(|mut kv| {
            let history_key = history_key.clone();
            let value = value.clone();
            async move { kv.put(history_key, value, None).await }
        })
        .await?;
        Ok(())
    }
}

#[async_trait]
impl Storage for EtcdStorage {
    async fn fetch(&self, key: &str) -> Result<String> {
        let key = self.get_path(key);
        let mut opts = GetOptions::new();
        if !key.ends_with(".toml") {
            opts = opts.with_prefix();
        }

        let mut resp = self
            .with_kv(|mut kv| {
                let key = key.clone();
                let opts = opts.clone();
                async move { kv.get(key, Some(opts)).await }
            })
            .await?;
        let mut buffer = vec![];
        for item in resp.take_kvs() {
            buffer.extend(item.value());
            buffer.push(0x0a);
        }
        Ok(String::from_utf8_lossy(buffer.as_slice()).to_string())
    }

    async fn save(&self, key: &str, value: &str) -> Result<()> {
        self.save_history(key).await?;
        let key = self.get_path(key);
        self.with_kv(|mut kv| {
            let key = key.clone();
            let value = value.to_string();
            async move { kv.put(key, value, None).await }
        })
        .await?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let key = self.get_path(key);
        self.with_kv(|mut kv| {
            let key = key.clone();
            async move { kv.delete(key, None).await }
        })
        .await?;
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
        let opts = GetOptions::new()
            .with_prefix()
            .with_sort(SortTarget::Create, SortOrder::Descend)
            .with_limit(10);

        let mut resp = self
            .with_kv(|mut kv| {
                let key = key.clone();
                let opts = opts.clone();
                async move { kv.get(key, Some(opts)).await }
            })
            .await?;

        let histories = resp
            .take_kvs()
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
        // A watch can miss a change made while an earlier one is still being
        // handled, so the caller pairs it with periodic full fetches.
        let mut c = self.client().await?.watch_client();
        let stream = c
            .watch(
                self.path.as_bytes(),
                Some(WatchOptions::default().with_prefix()),
            )
            .await
            .map_err(etcd_error)?;
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

    #[test]
    fn test_parse_url() {
        let storage = EtcdStorage::new(
            "etcd://a:2379,b:2379/pingap/?timeout=10s&enable_history=true",
        )
        .unwrap();
        assert_eq!(
            vec!["a:2379".to_string(), "b:2379".to_string()],
            storage.addrs
        );
        assert_eq!("/pingap/", storage.path);
        assert_eq!("/pingap-history", storage.history_path);
        assert_eq!(true, storage.enable_history);
        assert_eq!("/pingap/basic.toml", storage.get_path("basic.toml"));

        // No path means the root; no host is an error rather than a
        // connection attempt to "".
        let storage = EtcdStorage::new("etcd://127.0.0.1:2379").unwrap();
        assert_eq!("/", storage.path);
        assert_eq!(true, EtcdStorage::new("etcd:///pingap").is_err());
    }
}
