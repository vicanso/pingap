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

use super::PingapConf;
use super::{ConfigStorage, Error, Result};
use async_trait::async_trait;
use etcd_client::{Client, ConnectOptions, GetOptions};
use humantime::parse_duration;
use substring::Substring;

pub struct EtcdStorage {
    path: String,
    addrs: Vec<String>,
    options: ConnectOptions,
}

pub const ETCD_PROTOCOL: &str = "etcd://";

impl EtcdStorage {
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

        let addrs: Vec<String> = hosts.split(',').map(|item| item.to_string()).collect();
        let mut user = "".to_string();
        let mut password = "".to_string();
        let mut options = ConnectOptions::default();
        for item in query.split('&') {
            if let Some((key, value)) = item.split_once('=') {
                match key {
                    "user" => user = value.to_string(),
                    "passwrod" => password = value.to_string(),
                    "timeout" => {
                        if let Ok(d) = parse_duration(value) {
                            options = options.with_timeout(d);
                        }
                    }
                    "connect_timeout" => {
                        if let Ok(d) = parse_duration(value) {
                            options = options.with_connect_timeout(d);
                        }
                    }
                    _ => {}
                }
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
    async fn connect(&self) -> Result<Client> {
        Client::connect(&self.addrs, Some(self.options.clone()))
            .await
            .map_err(|e| Error::Etcd { source: e })
    }
}

#[async_trait]
impl ConfigStorage for EtcdStorage {
    async fn load_config(&self, _admin: bool) -> Result<PingapConf> {
        let mut c = self.connect().await?;
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
        PingapConf::try_from(buffer)
    }
    async fn save_config(&self, conf: &PingapConf, category: &str) -> Result<()> {
        let filepath = self.path.clone();
        conf.validate()?;
        let (path, toml_value) = conf.get_toml(category)?;
        let key = format!("{filepath}{path}");
        let mut c = self.connect().await?;
        c.put(key, toml_value, None)
            .await
            .map_err(|e| Error::Etcd { source: e })?;
        Ok(())
    }
}
