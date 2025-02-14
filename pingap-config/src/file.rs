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

use super::{
    read_all_toml_files, ConfigStorage, Error, LoadConfigOptions, PingapConf,
    Result,
};
use async_trait::async_trait;
use futures_util::TryFutureExt;
use std::path::Path;
use tokio::fs;

pub struct FileStorage {
    // Path to the configuration file or directory
    path: String,
    // Whether to separate config files by category/name
    separation: bool,
}
impl FileStorage {
    /// Create a new file storage for config.
    pub fn new(path: &str) -> Result<Self> {
        let mut separation = false;
        let mut filepath = pingap_util::resolve_path(path);
        // Parse query parameters if present (e.g., "path/to/config?separation=true")
        if let Some((path, query)) = path.split_once('?') {
            let m = pingap_core::convert_query_map(query);
            separation = m.contains_key("separation");
            filepath = pingap_util::resolve_path(path);
        }
        // Validate path is not empty
        if filepath.is_empty() {
            return Err(Error::Invalid {
                message: "Config path is empty".to_string(),
            });
        }

        Ok(Self {
            path: filepath,
            separation,
        })
    }
}

#[async_trait]
impl ConfigStorage for FileStorage {
    /// Load config from file.
    async fn load_config(&self, opts: LoadConfigOptions) -> Result<PingapConf> {
        let filepath = self.path.clone();
        let dir = Path::new(&filepath);
        // Return default config if admin mode and path doesn't exist
        if opts.admin && !dir.exists() {
            return Ok(PingapConf::default());
        }
        // Create directory if needed for non-TOML paths
        if !filepath.ends_with(".toml") && !dir.exists() {
            fs::create_dir_all(&filepath)
                .map_err(|e| Error::Io {
                    source: e,
                    file: filepath.clone(),
                })
                .await?;
        }

        let mut data = vec![];
        // Handle directory of TOML files
        if dir.is_dir() {
            let mut result = read_all_toml_files(&filepath).await?;
            data.append(&mut result);
        } else {
            // Handle single TOML file
            let mut buf = fs::read(&filepath).await.map_err(|e| Error::Io {
                source: e,
                file: filepath,
            })?;
            data.append(&mut buf);
        }
        PingapConf::new(data.as_slice(), opts.replace_include)
    }
    /// Save config to file by category.
    async fn save_config(
        &self,
        conf: &PingapConf,
        category: &str,
        name: Option<&str>,
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
            // For single file storage:
            // 1. Convert config to TOML
            // 2. Remove empty sections
            // 3. Write back to file
            let ping_conf = toml::to_string_pretty(&conf)
                .map_err(|e| Error::Ser { source: e })?;
            let mut values: toml::Table = toml::from_str(&ping_conf)
                .map_err(|e| Error::De { source: e })?;
            // Remove empty sections
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

        // For directory storage:
        // Get TOML content based on category and optional name
        let (path, toml_value) = if self.separation && name.is_some() {
            conf.get_toml(category, name)?
        } else {
            conf.get_toml(category, None)?
        };

        let filepath = pingap_util::path_join(&filepath, &path);
        let target_file = Path::new(&filepath);
        if let Some(p) = Path::new(&target_file).parent() {
            fs::create_dir_all(p).await.map_err(|e| Error::Io {
                source: e,
                file: filepath.clone(),
            })?;
        }
        if toml_value.is_empty() {
            if target_file.exists() {
                fs::remove_file(&filepath).await.map_err(|e| Error::Io {
                    source: e,
                    file: filepath,
                })?;
            }
        } else {
            fs::write(&filepath, toml_value)
                .await
                .map_err(|e| Error::Io {
                    source: e,
                    file: filepath,
                })?;
        }

        Ok(())
    }
    async fn save(&self, key: &str, data: &[u8]) -> Result<()> {
        let key = pingap_util::path_join(&self.path, key);
        let path = Path::new(&key);
        if let Some(p) = path.parent() {
            fs::create_dir_all(p).await.map_err(|e| Error::Io {
                source: e,
                file: key.to_string(),
            })?;
        }
        fs::write(path, data).await.map_err(|e| Error::Io {
            source: e,
            file: key.to_string(),
        })?;
        Ok(())
    }
    async fn load(&self, key: &str) -> Result<Vec<u8>> {
        let key = pingap_util::path_join(&self.path, key);
        let path = Path::new(&key);
        let buf = fs::read(path).await.map_err(|e| Error::Io {
            source: e,
            file: key.to_string(),
        })?;
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::FileStorage;
    use crate::*;
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
        let result = storage.load_config(LoadConfigOptions::default()).await;
        assert_eq!(true, result.is_ok());

        let toml_data = read_all_toml_files("../../conf").await.unwrap();
        let conf =
            PingapConf::new(toml_data.to_vec().as_slice(), false).unwrap();
        for category in [
            CATEGORY_CERTIFICATE.to_string(),
            CATEGORY_UPSTREAM.to_string(),
            CATEGORY_LOCATION.to_string(),
            CATEGORY_SERVER.to_string(),
            CATEGORY_PLUGIN.to_string(),
            CATEGORY_STORAGE.to_string(),
            CATEGORY_BASIC.to_string(),
        ]
        .iter()
        {
            storage.save_config(&conf, category, None).await.unwrap();
            file_storage
                .save_config(&conf, category, None)
                .await
                .unwrap();
        }

        let current_conf = storage
            .load_config(LoadConfigOptions::default())
            .await
            .unwrap();
        assert_eq!(current_conf.hash().unwrap(), conf.hash().unwrap());

        let current_conf = file_storage
            .load_config(LoadConfigOptions::default())
            .await
            .unwrap();
        assert_eq!(current_conf.hash().unwrap(), conf.hash().unwrap());
    }
}
