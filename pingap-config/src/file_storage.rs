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

use crate::Error;
use crate::hcl::convert_hcl_to_toml;
use crate::kdl::convert_kdl_to_toml;
use crate::permission_error_message;
use crate::storage::{History, Storage};
use async_trait::async_trait;
use glob::glob;
use pingap_core::now_sec;
use pingap_util::resolve_path;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::debug;

type Result<T, E = Error> = std::result::Result<T, E>;

pub struct FileStorage {
    path: PathBuf,
    history_path: Option<PathBuf>,
}

impl FileStorage {
    pub fn new(path: &str) -> Result<Self> {
        let filepath = resolve_path(path);
        let path = Path::new(&filepath);
        if path.is_dir() {
            std::fs::create_dir_all(path).map_err(|e| Error::Io {
                source: e,
                file: filepath.clone(),
            })?;
        } else if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| Error::Io {
                source: e,
                file: filepath.clone(),
            })?;
        }
        Ok(Self {
            path: path.to_path_buf(),
            history_path: None,
        })
    }
    pub fn with_history_path(&mut self, history_path: &str) -> Result<()> {
        let filepath = resolve_path(history_path);
        let path = Path::new(&filepath);
        std::fs::create_dir_all(path).map_err(|e| Error::Io {
            source: e,
            file: filepath.clone(),
        })?;
        self.history_path = Some(path.to_path_buf());
        Ok(())
    }
    fn get_target_path(&self, key: &str) -> PathBuf {
        if self.path.is_file() {
            self.path.clone()
        } else {
            self.path.join(key)
        }
    }
    fn convert_history_key(&self, key: &str) -> String {
        key.replace("/", "-")
    }
    async fn save_history(&self, key: &str) -> Result<()> {
        let Some(history_path) = &self.history_path else {
            return Ok(());
        };
        let value = self.fetch(key).await?;
        if value.is_empty() {
            return Ok(());
        }
        let name = format!("{}-{}", self.convert_history_key(key), now_sec());
        let file = history_path.join(name).clone();
        fs::write(&file, value).await.map_err(|e| Error::Io {
            source: e,
            file: file.to_string_lossy().to_string(),
        })?;
        Ok(())
    }
}

async fn read_all_config_files(dir: &str) -> Result<Vec<u8>> {
    let mut data = vec![];
    // Collect .toml files first
    let toml_files: std::result::Result<Vec<_>, _> =
        glob(&format!("{dir}/**/*.toml"))
            .map_err(|e| Error::Pattern {
                source: e,
                path: dir.to_string(),
            })?
            .collect();
    let toml_files = toml_files.map_err(|e| Error::Glob { source: e })?;

    if !toml_files.is_empty() {
        // .toml files found, use only .toml
        for f in toml_files {
            let buf = fs::read(&f)
                .await
                .map_err(|e| permission_error_message(&f, e))?;
            toml::from_str::<toml::Value>(&String::from_utf8_lossy(&buf))
                .map_err(|e| Error::Invalid {
                    message: format!("{}: {e}", f.display()),
                })?;
            debug!(filename = format!("{f:?}"), "read toml file");
            data.extend_from_slice(&buf);
            data.push(0x0a);
        }
    } else {
        // No .toml files, check for .hcl
        let hcl_files: std::result::Result<Vec<_>, _> =
            glob(&format!("{dir}/**/*.hcl"))
                .map_err(|e| Error::Pattern {
                    source: e,
                    path: dir.to_string(),
                })?
                .collect();
        let hcl_files = hcl_files.map_err(|e| Error::Glob { source: e })?;

        if !hcl_files.is_empty() {
            for f in hcl_files {
                let buf = fs::read(&f)
                    .await
                    .map_err(|e| permission_error_message(&f, e))?;
                debug!(filename = format!("{f:?}"), "read hcl file");
                let hcl_str = String::from_utf8_lossy(&buf);
                let toml_str = convert_hcl_to_toml(&hcl_str)?;
                data.extend_from_slice(toml_str.as_bytes());
                data.push(0x0a);
            }
        } else {
            // No .hcl files, fall back to .kdl
            for entry in glob(&format!("{dir}/**/*.kdl")).map_err(|e| {
                Error::Pattern {
                    source: e,
                    path: dir.to_string(),
                }
            })? {
                let f = entry.map_err(|e| Error::Glob { source: e })?;
                let buf = fs::read(&f)
                    .await
                    .map_err(|e| permission_error_message(&f, e))?;
                debug!(filename = format!("{f:?}"), "read kdl file");
                let kdl_str = String::from_utf8_lossy(&buf);
                let toml_str = convert_kdl_to_toml(&kdl_str).map_err(|e| {
                    Error::Invalid {
                        message: format!("{}: {e}", f.display()),
                    }
                })?;
                data.extend_from_slice(toml_str.as_bytes());
                data.push(0x0a);
            }
        }
    }
    Ok(data)
}

#[async_trait]
impl Storage for FileStorage {
    fn support_history(&self) -> bool {
        self.history_path.is_some()
    }
    async fn fetch(&self, key: &str) -> Result<String> {
        let target_path = self.get_target_path(key);
        if target_path.is_file() {
            let data = match fs::read(&target_path).await {
                Ok(data) => Ok(data),
                Err(e) if e.kind() == ErrorKind::NotFound => Ok(Vec::new()),
                Err(e) => Err(permission_error_message(&target_path, e)),
            }?;
            let ext = target_path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("");
            if ext == "hcl" {
                let hcl_str = String::from_utf8_lossy(&data);
                return convert_hcl_to_toml(&hcl_str);
            }
            if ext == "kdl" {
                let kdl_str = String::from_utf8_lossy(&data);
                return convert_kdl_to_toml(&kdl_str);
            }
            let content = String::from_utf8_lossy(&data);
            if !content.trim().is_empty() {
                toml::from_str::<toml::Value>(content.as_ref()).map_err(
                    |e| Error::Invalid {
                        message: format!("{}: {e}", target_path.display()),
                    },
                )?;
            }
            Ok(content.trim().to_string())
        } else {
            let value =
                read_all_config_files(&target_path.to_string_lossy()).await?;
            Ok(String::from_utf8_lossy(&value).trim().to_string())
        }
    }

    async fn save(&self, key: &str, value: &str) -> Result<()> {
        self.save_history(key).await?;
        let file = self.get_target_path(key);
        if let Some(parent) = file.parent() {
            fs::create_dir_all(parent).await.map_err(|e| Error::Io {
                source: e,
                file: file.to_string_lossy().to_string(),
            })?;
        }
        fs::write(&file, value).await.map_err(|e| Error::Io {
            source: e,
            file: file.to_string_lossy().to_string(),
        })?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let file = self.get_target_path(key);
        match fs::remove_file(&file).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::Io {
                source: e,
                file: file.to_string_lossy().to_string(),
            }),
        }
    }
    async fn fetch_history(&self, key: &str) -> Result<Option<Vec<History>>> {
        let Some(history_path) = &self.history_path else {
            return Ok(None);
        };

        let file = history_path
            .join(self.convert_history_key(key))
            .to_string_lossy()
            .to_string();

        let mut history = vec![];

        for entry in glob(&format!("{file}*")).map_err(|e| Error::Pattern {
            source: e,
            path: file,
        })? {
            let f = entry.map_err(|e| Error::Glob { source: e })?;
            let Some(filename) = f.file_name() else {
                continue;
            };
            let Some(created_at) = filename
                .to_string_lossy()
                .split('-')
                .next_back()
                .and_then(|s| s.parse::<u64>().ok())
            else {
                continue;
            };
            history.push(History {
                created_at,
                data: f.to_path_buf().to_string_lossy().to_string(),
            });
        }
        history.sort_by_key(|h| h.created_at);
        history.reverse();
        history.truncate(10);
        for item in history.iter_mut() {
            let data = fs::read(&item.data).await.map_err(|e| Error::Io {
                source: e,
                file: item.data.clone(),
            })?;
            item.data = String::from_utf8_lossy(&data).trim().to_string();
        }

        Ok(Some(history))
    }
}

#[cfg(test)]
mod tests {
    use super::FileStorage;
    use crate::storage::Storage;
    use pretty_assertions::assert_eq;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_dir_storage() {
        let dir = tempdir().unwrap();
        let storage = FileStorage::new(&dir.path().to_string_lossy()).unwrap();
        // save config (must be valid TOML since fetch validates syntax)
        storage.save("servers.toml", "[servers]").await.unwrap();
        storage.save("locations.toml", "[locations]").await.unwrap();

        let data = storage.fetch("servers.toml").await.unwrap();
        assert_eq!("[servers]", data);

        // fetch all (concatenated)
        let data = storage.fetch("").await.unwrap();
        assert_eq!("[locations]\n[servers]", data);

        storage.delete("servers.toml").await.unwrap();
        let data = storage.fetch("servers.toml").await.unwrap();
        assert_eq!("", data);

        let data = storage.fetch("").await.unwrap();
        assert_eq!("[locations]", data);
    }

    #[tokio::test]
    async fn test_file_storage() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let storage = FileStorage::new(&file.path().to_string_lossy()).unwrap();
        // must be valid TOML since fetch validates syntax
        storage.save("pingap.toml", "[basic]").await.unwrap();
        let data = storage.fetch("pingap.toml").await.unwrap();
        assert_eq!("[basic]", data);

        storage.delete("pingap.toml").await.unwrap();
        let data = storage.fetch("pingap.toml").await.unwrap();
        assert_eq!("", data);
    }
}
