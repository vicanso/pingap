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
use std::path::Path;
use tokio::fs;
use tracing::debug;

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
    async fn load_config(
        &self,
        replace_include: bool,
        admin: bool,
    ) -> Result<PingapConf> {
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
            for entry in
                glob(&format!("{filepath}/**/*.toml")).map_err(|e| {
                    Error::Pattern {
                        source: e,
                        path: filepath,
                    }
                })?
            {
                let f = entry.map_err(|e| Error::Glob { source: e })?;
                let mut buf = fs::read(&f).await.map_err(|e| Error::Io {
                    source: e,
                    file: f.to_string_lossy().to_string(),
                })?;
                debug!(filename = format!("{f:?}"), "load config");
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
        PingapConf::new(data.as_slice(), replace_include)
    }
    /// Save config to file by category.
    async fn save_config(
        &self,
        conf: &PingapConf,
        category: &str,
    ) -> Result<()> {
        let filepath = self.path.clone();
        conf.validate()?;
        let path = Path::new(&filepath);
        if !path.exists() && path.extension().unwrap_or_default() == "toml" {
            fs::File::create(&path).await.map_err(|e| Error::Io {
                source: e,
                file: filepath.clone(),
            })?;
        }

        if path.is_file() {
            let ping_conf = toml::to_string_pretty(&conf)
                .map_err(|e| Error::Ser { source: e })?;
            let mut values: toml::Table = toml::from_str(&ping_conf)
                .map_err(|e| Error::De { source: e })?;
            let mut omit_keys = vec![];
            for key in values.keys() {
                if let Some(value) = values.get(key) {
                    if value.to_string() == "{}" {
                        omit_keys.push(key.clone());
                    }
                }
            }
            for key in omit_keys {
                values.remove(&key);
            }
            let ping_conf = toml::to_string_pretty(&values)
                .map_err(|e| Error::Ser { source: e })?;
            return fs::write(path, ping_conf).await.map_err(|e| Error::Io {
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
    use crate::config::{list_category, ConfigStorage, PingapConf};
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
        let file = format!("/tmp/{}.toml", nanoid!(16));
        tokio::fs::write(&file, b"").await.unwrap();
        let storage = FileStorage::new(&path).unwrap();
        let file_storage = FileStorage::new(&file).unwrap();
        let result = storage.load_config(false, false).await;
        assert_eq!(true, result.is_ok());

        let toml_data = include_bytes!("../../conf/pingap.toml");
        let conf =
            PingapConf::new(toml_data.to_vec().as_slice(), false).unwrap();
        for category in list_category().iter() {
            storage.save_config(&conf, category).await.unwrap();
            file_storage.save_config(&conf, category).await.unwrap();
        }

        let current_conf = storage.load_config(false, false).await.unwrap();
        assert_eq!(current_conf.hash().unwrap(), conf.hash().unwrap());

        let current_conf =
            file_storage.load_config(false, false).await.unwrap();
        assert_eq!(current_conf.hash().unwrap(), conf.hash().unwrap());
    }
}
