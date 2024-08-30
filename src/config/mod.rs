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

use std::time::Duration;

use async_trait::async_trait;
use etcd_client::WatchStream;
use once_cell::sync::OnceCell;
use snafu::Snafu;

mod common;
mod etcd;
mod file;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Invalid error {message}"))]
    Invalid { message: String },
    #[snafu(display("Glob pattern error {source}, {path}"))]
    Pattern {
        source: glob::PatternError,
        path: String,
    },
    #[snafu(display("Glob error {source}"))]
    Glob { source: glob::GlobError },
    #[snafu(display("Io error {source}, {file}"))]
    Io {
        source: std::io::Error,
        file: String,
    },
    #[snafu(display("Toml de error {source}"))]
    De { source: toml::de::Error },
    #[snafu(display("Toml ser error {source}"))]
    Ser { source: toml::ser::Error },
    #[snafu(display("Url parse error {source}, {url}"))]
    UrlParse {
        source: url::ParseError,
        url: String,
    },
    #[snafu(display("Addr parse error {source}, {addr}"))]
    AddrParse {
        source: std::net::AddrParseError,
        addr: String,
    },
    #[snafu(display("Base64 decode error {source}"))]
    Base64Decode { source: base64::DecodeError },
    #[snafu(display("Regex error {source}"))]
    Regex { source: regex::Error },
    #[snafu(display("Etcd error {source}"))]
    Etcd { source: etcd_client::Error },
}
type Result<T, E = Error> = std::result::Result<T, E>;

pub struct Observer {
    etcd_watch_stream: Option<WatchStream>,
}

impl Observer {
    pub async fn watch(&mut self) -> Result<bool> {
        let sleep_time = Duration::from_secs(30);
        // no watch stream, just sleep a moment
        let Some(stream) = self.etcd_watch_stream.as_mut() else {
            tokio::time::sleep(sleep_time).await;
            return Ok(false);
        };
        let resp = stream
            .message()
            .await
            .map_err(|e| Error::Etcd { source: e })?;

        Ok(resp.is_some())
    }
}

#[async_trait]
pub trait ConfigStorage {
    async fn load_config(&self, admin: bool) -> Result<PingapConf>;
    async fn save_config(
        &self,
        conf: &PingapConf,
        category: &str,
    ) -> Result<()>;
    fn support_observer(&self) -> bool {
        false
    }
    async fn observe(&self) -> Result<Observer> {
        Ok(Observer {
            etcd_watch_stream: None,
        })
    }
}

static CONFIG_STORAGE: OnceCell<Box<(dyn ConfigStorage + Sync + Send)>> =
    OnceCell::new();

pub fn try_init_config_storage(
    path: &str,
) -> Result<&'static (dyn ConfigStorage + Sync + Send)> {
    let conf = CONFIG_STORAGE.get_or_try_init(|| {
        let s: Box<(dyn ConfigStorage + Sync + Send)> =
            if path.starts_with(ETCD_PROTOCOL) {
                let storage = EtcdStorage::new(path)?;
                Box::new(storage)
            } else {
                let storage = FileStorage::new(path)?;
                Box::new(storage)
            };
        Ok(s)
    })?;
    Ok(conf.as_ref())
}

pub async fn load_config(admin: bool) -> Result<PingapConf> {
    let Some(storage) = CONFIG_STORAGE.get() else {
        return Err(Error::Invalid {
            message: "storage is not inited".to_string(),
        });
    };
    storage.load_config(admin).await
}

pub fn support_observer() -> bool {
    if let Some(storage) = CONFIG_STORAGE.get() {
        storage.support_observer()
    } else {
        false
    }
}

pub fn get_config_storage() -> Option<&'static (dyn ConfigStorage + Sync + Send)>
{
    if let Some(storage) = CONFIG_STORAGE.get() {
        Some(storage.as_ref())
    } else {
        None
    }
}

pub async fn save_config(conf: &PingapConf, category: &str) -> Result<()> {
    let Some(storage) = CONFIG_STORAGE.get() else {
        return Err(Error::Invalid {
            message: "storage is not inited".to_string(),
        });
    };
    storage.save_config(conf, category).await
}

pub use common::*;
pub use etcd::{EtcdStorage, ETCD_PROTOCOL};
pub use file::FileStorage;
