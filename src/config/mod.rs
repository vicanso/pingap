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

use async_trait::async_trait;
use etcd_client::WatchStream;
use once_cell::sync::OnceCell;
use snafu::Snafu;
use std::time::Duration;

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

#[derive(Debug, Default, Clone)]
pub struct LoadConfigOptions {
    pub replace_include: bool,
    pub admin: bool,
}

#[async_trait]
pub trait ConfigStorage {
    async fn load_config(&self, opts: LoadConfigOptions) -> Result<PingapConf>;
    async fn save_config(
        &self,
        conf: &PingapConf,
        category: &str,
        name: Option<&str>,
    ) -> Result<()>;
    fn support_observer(&self) -> bool {
        false
    }
    async fn observe(&self) -> Result<Observer> {
        Ok(Observer {
            etcd_watch_stream: None,
        })
    }
    async fn save(&self, key: &str, data: &[u8]) -> Result<()>;
    async fn load(&self, key: &str) -> Result<Vec<u8>>;
}

static CONFIG_STORAGE: OnceCell<Box<(dyn ConfigStorage + Sync + Send)>> =
    OnceCell::new();

fn new_config_storage(
    path: &str,
) -> Result<Box<(dyn ConfigStorage + Sync + Send)>> {
    let s: Box<(dyn ConfigStorage + Sync + Send)> =
        if path.starts_with(ETCD_PROTOCOL) {
            let storage = EtcdStorage::new(path)?;
            Box::new(storage)
        } else {
            let storage = FileStorage::new(path)?;
            Box::new(storage)
        };
    Ok(s)
}

pub fn try_init_config_storage(
    path: &str,
) -> Result<&'static (dyn ConfigStorage + Sync + Send)> {
    let conf = CONFIG_STORAGE.get_or_try_init(|| new_config_storage(path))?;
    Ok(conf.as_ref())
}

pub async fn load_config(opts: LoadConfigOptions) -> Result<PingapConf> {
    let Some(storage) = CONFIG_STORAGE.get() else {
        return Err(Error::Invalid {
            message: "storage is not inited".to_string(),
        });
    };
    storage.load_config(opts).await
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

pub async fn save_config(
    conf: &PingapConf,
    category: &str,
    name: Option<&str>,
) -> Result<()> {
    let Some(storage) = CONFIG_STORAGE.get() else {
        return Err(Error::Invalid {
            message: "storage is not inited".to_string(),
        });
    };
    storage.save_config(conf, category, name).await
}
pub async fn sync_to_path(path: &str) -> Result<()> {
    let conf = get_current_config();
    let storage = new_config_storage(path)?;
    sync_config(&conf, storage.as_ref()).await
}

pub async fn sync_config(
    conf: &PingapConf,
    storage: &(dyn ConfigStorage + Send + Sync),
) -> Result<()> {
    let mut arr = vec![(common::CATEGORY_BASIC, None)];
    for key in conf.servers.keys() {
        arr.push((common::CATEGORY_SERVER, Some(key.as_str())));
    }
    for key in conf.locations.keys() {
        arr.push((common::CATEGORY_LOCATION, Some(key.as_str())));
    }
    for key in conf.upstreams.keys() {
        arr.push((common::CATEGORY_UPSTREAM, Some(key.as_str())));
    }
    for key in conf.plugins.keys() {
        arr.push((common::CATEGORY_PLUGIN, Some(key.as_str())));
    }
    for key in conf.certificates.keys() {
        arr.push((common::CATEGORY_CERTIFICATE, Some(key.as_str())));
    }
    for key in conf.storages.keys() {
        arr.push((common::CATEGORY_STORAGE, Some(key.as_str())));
    }
    for (category, name) in arr {
        storage.save_config(conf, category, name).await?;
    }
    Ok(())
}

pub use common::*;
pub use etcd::{EtcdStorage, ETCD_PROTOCOL};
pub use file::FileStorage;

#[cfg(test)]
mod tests {
    use super::{
        get_config_storage, load_config, support_observer, sync_to_path,
        try_init_config_storage, LoadConfigOptions,
    };
    use pretty_assertions::assert_eq;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_load_config() {
        assert_eq!(true, get_config_storage().is_none());
        try_init_config_storage("./conf/pingap.toml").unwrap();
        let conf = load_config(LoadConfigOptions {
            replace_include: true,
            ..Default::default()
        })
        .await
        .unwrap();
        assert_eq!("BDEE23BF", conf.hash().unwrap());
        assert_eq!(false, support_observer());
        assert_eq!(true, get_config_storage().is_some());
        let dir = TempDir::new().unwrap();
        let file = dir.into_path().join("pingap.toml");
        tokio::fs::write(&file, b"").await.unwrap();
        sync_to_path(file.to_string_lossy().as_ref()).await.unwrap();
    }
}
