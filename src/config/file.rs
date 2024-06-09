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

use super::{ConfigStorage, Error, PingapConf, Result};
use crate::util;
use async_trait::async_trait;
use futures_util::TryFutureExt;
use glob::glob;
use log::debug;
use std::path::Path;
use tokio::fs;

pub struct FileStorage {
    path: String,
}
impl FileStorage {
    /// Create a new file storage for config.
    pub fn new(path: &str) -> Result<Self> {
        let filepath = util::resolve_path(path);
        if filepath.is_empty() {
            return Err(Error::Invalid {
                message: "Config path is empty".to_string(),
            });
        }

        Ok(Self { path: filepath })
    }
}

#[async_trait]
impl ConfigStorage for FileStorage {
    /// Load config from file.
    async fn load_config(&self, admin: bool) -> Result<PingapConf> {
        let filepath = self.path.clone();
        let dir = Path::new(&filepath);
        if admin && !dir.exists() {
            return Ok(PingapConf::default());
        }
        // create dir
        if !filepath.ends_with(".toml") && !dir.exists() {
            fs::create_dir_all(&filepath)
                .map_err(|e| Error::Io {
                    source: e,
                    file: filepath.clone(),
                })
                .await?;
        }

        let mut data = vec![];
        if dir.is_dir() {
            for entry in glob(&format!("{filepath}/**/*.toml")).map_err(|e| Error::Pattern {
                source: e,
                path: filepath,
            })? {
                let f = entry.map_err(|e| Error::Glob { source: e })?;
                let mut buf = fs::read(&f).await.map_err(|e| Error::Io {
                    source: e,
                    file: f.to_string_lossy().to_string(),
                })?;
                debug!("Load config from: {:?}", f.file_name());
                data.append(&mut buf);
                data.push(0x0a);
            }
        } else {
            let mut buf = fs::read(&filepath).await.map_err(|e| Error::Io {
                source: e,
                file: filepath,
            })?;
            data.append(&mut buf);
        }
        PingapConf::try_from(data.as_slice())
    }
    /// Save config to file by category.
    async fn save_config(&self, conf: &PingapConf, category: &str) -> Result<()> {
        let filepath = self.path.clone();
        conf.validate()?;
        if Path::new(&filepath).is_file() {
            let ping_conf = toml::to_string_pretty(&conf).map_err(|e| Error::Ser { source: e })?;
            return fs::write(&filepath, ping_conf)
                .await
                .map_err(|e| Error::Io {
                    source: e,
                    file: filepath,
                });
        }

        let (path, toml_value) = conf.get_toml(category)?;
        let filepath = format!("{filepath}{path}");
        fs::write(&filepath, toml_value)
            .await
            .map_err(|e| Error::Io {
                source: e,
                file: filepath,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::FileStorage;
    use crate::config::{
        ConfigStorage, PingapConf, CATEGORY_BASIC, CATEGORY_LOCATION, CATEGORY_PLUGIN,
        CATEGORY_SERVER, CATEGORY_UPSTREAM,
    };
    use nanoid::nanoid;
    use pretty_assertions::assert_eq;

    #[tokio::test]
    async fn test_file_storage() {
        let result = FileStorage::new("");
        assert_eq!(
            "Invalid error Config path is empty",
            result.err().unwrap().to_string()
        );

        let path = format!("/tmp/{}", nanoid!(16));
        tokio::fs::create_dir(&path).await.unwrap();
        let storage = FileStorage::new(&path).unwrap();
        let result = storage.load_config(false).await;
        assert_eq!(true, result.is_ok());

        let toml_data = include_bytes!("../../conf/pingap.toml");
        let conf = PingapConf::try_from(toml_data.to_vec().as_slice()).unwrap();

        storage.save_config(&conf, CATEGORY_BASIC).await.unwrap();
        storage.save_config(&conf, CATEGORY_UPSTREAM).await.unwrap();
        storage.save_config(&conf, CATEGORY_LOCATION).await.unwrap();
        storage.save_config(&conf, CATEGORY_PLUGIN).await.unwrap();
        storage.save_config(&conf, CATEGORY_SERVER).await.unwrap();

        let current_conf = storage.load_config(false).await.unwrap();
        assert_eq!(current_conf.hash().unwrap(), conf.hash().unwrap());
    }
}
