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
use crate::{Error, Result};
use async_trait::async_trait;
use std::path::PathBuf;
use std::sync::RwLock;
use tokio::fs;

/// Configuration held in memory instead of in a file or in etcd.
///
/// Used when the whole configuration is synthesized rather than read from a
/// store — e.g. the command line quick start, where `--domain` / `--upstream` /
/// `--cert` describe the proxy and there is no config file at all.
///
/// Writes are accepted because ACME goes through the config storage: the
/// HTTP-01 challenge token is stored and read back while the challenge is in
/// flight, and the issued certificate is written back once it is signed. With
/// `with_path` those writes are mirrored to a file, so a restart reuses the
/// certificate a previous run obtained instead of asking let's encrypt for a
/// new one — which is rate limited. Without a path the config only lives as
/// long as the process.
pub struct MemoryStorage {
    data: RwLock<String>,
    path: Option<PathBuf>,
}

impl MemoryStorage {
    pub fn new(data: &str) -> Self {
        Self {
            data: RwLock::new(data.to_string()),
            path: None,
        }
    }
    /// Mirrors every write to `path`. The file holds the private key of the
    /// issued certificate, so it is created with owner-only permissions.
    pub fn with_path(mut self, path: PathBuf) -> Self {
        self.path = Some(path);
        self
    }
    fn io_error(file: &std::path::Path, source: std::io::Error) -> Error {
        Error::Io {
            source,
            file: file.to_string_lossy().to_string(),
        }
    }
}

#[async_trait]
impl Storage for MemoryStorage {
    async fn fetch(&self, _key: &str) -> Result<String> {
        // The config is a single blob, the key selects nothing.
        let data = self.data.read().map_err(|e| Error::Invalid {
            message: e.to_string(),
        })?;
        Ok(data.clone())
    }
    async fn save(&self, _key: &str, value: &str) -> Result<()> {
        {
            let mut data = self.data.write().map_err(|e| Error::Invalid {
                message: e.to_string(),
            })?;
            *data = value.to_string();
        }
        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| Self::io_error(path, e))?;
        }
        fs::write(path, value)
            .await
            .map_err(|e| Self::io_error(path, e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .await
                .map_err(|e| Self::io_error(path, e))?;
        }
        Ok(())
    }
    async fn delete(&self, _key: &str) -> Result<()> {
        // Single mode never deletes: `ConfigManager` rewrites the whole config
        // through `save` instead.
        Err(Error::Invalid {
            message: "delete is not supported by memory storage".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[tokio::test]
    async fn test_memory_storage() {
        let storage = MemoryStorage::new("[basic]\nname = \"pingap\"\n");

        assert_eq!(
            "[basic]\nname = \"pingap\"\n",
            storage.fetch("").await.unwrap()
        );
        // the key is ignored, the whole config is a single blob
        assert_eq!(
            "[basic]\nname = \"pingap\"\n",
            storage.fetch("basic.toml").await.unwrap()
        );

        assert!(!storage.support_observer());
        assert!(!storage.support_history());

        // writes are kept, ACME stores its challenge token and the issued
        // certificate this way
        storage.save("", "[basic]\nname = \"new\"\n").await.unwrap();
        assert_eq!(
            "[basic]\nname = \"new\"\n",
            storage.fetch("").await.unwrap()
        );

        assert_eq!(
            "Invalid error delete is not supported by memory storage",
            storage.delete("basic.toml").await.unwrap_err().to_string()
        );
    }

    #[tokio::test]
    async fn test_memory_storage_with_path() {
        let dir = tempfile::tempdir().unwrap();
        // the parent directory is created on demand
        let file = dir.path().join("acme").join("pingap.io.toml");
        let storage = MemoryStorage::new("[basic]\n").with_path(file.clone());

        storage
            .save("", "[basic]\nname = \"pingap\"\n")
            .await
            .unwrap();
        assert_eq!(
            "[basic]\nname = \"pingap\"\n",
            tokio::fs::read_to_string(&file).await.unwrap()
        );
        assert_eq!(
            "[basic]\nname = \"pingap\"\n",
            storage.fetch("").await.unwrap()
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&file).unwrap().permissions().mode();
            assert_eq!(0o600, mode & 0o777);
        }
    }
}
