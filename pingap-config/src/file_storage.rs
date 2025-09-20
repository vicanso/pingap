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
use glob::glob;
use pingap_util::resolve_path;
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::debug;

type Result<T, E = Error> = std::result::Result<T, E>;

pub struct FileStorage {
    path: PathBuf,
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
        })
    }
}

async fn read_all_toml_files(dir: &str) -> Result<Vec<u8>> {
    let mut data = vec![];
    for entry in
        glob(&format!("{dir}/**/*.toml")).map_err(|e| Error::Pattern {
            source: e,
            path: dir.to_string(),
        })?
    {
        let f = entry.map_err(|e| Error::Glob { source: e })?;
        let mut buf = fs::read(&f).await.map_err(|e| Error::Io {
            source: e,
            file: f.to_string_lossy().to_string(),
        })?;
        debug!(filename = format!("{f:?}"), "read toml file");
        // Append file contents and newline
        data.append(&mut buf);
        data.push(0x0a);
    }
    Ok(data)
}

#[async_trait]
impl Storage for FileStorage {
    async fn fetch(&self, key: &str) -> Result<String> {
        let value = if self.path.is_file() {
            fs::read(&self.path).await.map_err(|e| Error::Io {
                source: e,
                file: self.path.to_string_lossy().to_string(),
            })
        } else {
            let path = self.path.join(key);
            if path.is_file() {
                fs::read(&path).await.map_err(|e| Error::Io {
                    source: e,
                    file: path.to_string_lossy().to_string(),
                })
            } else {
                read_all_toml_files(&path.to_string_lossy()).await
            }
        }?;

        Ok(String::from_utf8_lossy(&value).trim().to_string())
    }

    async fn save(&self, key: &str, value: &str) -> Result<()> {
        let file = if self.path.is_file() {
            self.path.clone()
        } else {
            self.path.join(key)
        };
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
        let file = if self.path.is_file() {
            self.path.clone()
        } else {
            self.path.join(key)
        };
        fs::remove_file(&file).await.map_err(|e| Error::Io {
            source: e,
            file: file.to_string_lossy().to_string(),
        })?;
        Ok(())
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
        // save config
        storage
            .save("servers.toml", "server configs")
            .await
            .unwrap();
        storage
            .save("locations.toml", "location configs")
            .await
            .unwrap();

        let data = storage.fetch("servers.toml").await.unwrap();
        assert_eq!("server configs", data);

        // fetch all
        let data = storage.fetch("").await.unwrap();
        assert_eq!(
            r#"location configs
server configs"#,
            data
        );

        storage.delete("servers.toml").await.unwrap();
        let data = storage.fetch("servers.toml").await.unwrap();
        assert_eq!("", data);

        let data = storage.fetch("").await.unwrap();
        assert_eq!("location configs", data);
    }

    #[tokio::test]
    async fn test_file_storage() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let storage = FileStorage::new(&file.path().to_string_lossy()).unwrap();
        storage.save("pingap.toml", "pingap config").await.unwrap();
        let data = storage.fetch("pingap.toml").await.unwrap();
        assert_eq!("pingap config", data);

        storage.delete("pingap.toml").await.unwrap();
        let data = storage.fetch("pingap.toml").await.unwrap();
        assert_eq!("", data);
    }
}
