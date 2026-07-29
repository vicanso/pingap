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

/// Whether `path` names a directory of config files rather than a single one.
///
/// A path that exists answers for itself. One that does not exist yet has to be
/// classified by intent, and guessing wrong is not harmless in either
/// direction: a directory mistaken for a file drops the config manager into
/// [`crate::ConfigMode::Single`], which silently ignores `separation` and
/// leaves every later run - which does find a directory by then - reading a
/// layout it would never have written itself.
pub(crate) fn is_config_dir(path: &Path) -> bool {
    if path.exists() {
        return path.is_dir();
    }
    // A config file always carries one of the extensions the loader knows how
    // to parse. Anything else is a directory that has not been created yet.
    !matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some("toml") | Some("hcl") | Some("kdl")
    )
}

pub struct FileStorage {
    path: PathBuf,
    /// Whether [`Self::path`] is a directory of config files.
    ///
    /// Decided once, at construction, rather than probed on every access: a
    /// path that does not exist yet is neither `is_file` nor `is_dir`, so
    /// asking the filesystem each time made a single file storage resolve its
    /// keys *underneath* the file, and the first write then created the file
    /// as a directory holding `pingap.toml`.
    is_dir: bool,
    history_path: Option<PathBuf>,
}

impl FileStorage {
    pub fn new(path: &str) -> Result<Self> {
        let filepath = resolve_path(path);
        let path = Path::new(&filepath);
        let is_dir = is_config_dir(path);
        let created = if is_dir { Some(path) } else { path.parent() };
        if let Some(dir) = created {
            std::fs::create_dir_all(dir).map_err(|e| Error::Io {
                source: e,
                file: filepath.clone(),
            })?;
        }
        Ok(Self {
            path: path.to_path_buf(),
            is_dir,
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
        if self.is_dir {
            self.path.join(key)
        } else {
            self.path.clone()
        }
    }
    fn convert_history_key(&self, key: &str) -> String {
        key.replace("/", "-")
    }
    /// Copies the current value of `key` into the history directory.
    ///
    /// Returns whether the value is recoverable afterwards: `false` only when
    /// history is disabled and there was something to keep. A caller about to
    /// destroy the value uses this to decide whether it still needs a backup
    /// of its own.
    async fn save_history(&self, key: &str) -> Result<bool> {
        let Some(history_path) = &self.history_path else {
            return Ok(false);
        };
        let value = self.fetch(key).await?;
        if value.is_empty() {
            return Ok(true);
        }
        let name = format!("{}-{}", self.convert_history_key(key), now_sec());
        let file = history_path.join(name).clone();
        fs::write(&file, value).await.map_err(|e| Error::Io {
            source: e,
            file: file.to_string_lossy().to_string(),
        })?;
        Ok(true)
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
        } else if self.is_dir {
            let value =
                read_all_config_files(&target_path.to_string_lossy()).await?;
            Ok(String::from_utf8_lossy(&value).trim().to_string())
        } else {
            // A single config file that has not been written yet. Reading it
            // as a directory would work by accident - the glob matches
            // nothing - but it would also hide the case from anyone reading
            // this.
            Ok(String::new())
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

    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>> {
        // A single config file holds every category, so it has no keys to
        // enumerate underneath it.
        if !self.is_dir {
            return Ok(vec![]);
        }
        // Recursive on purpose, matching the loader: `fetch("")` globs
        // `**/*.toml`, so a file in any subdirectory is part of the loaded
        // configuration and has to show up here too - a layout check that
        // sees less than the loader would miss exactly the files it exists
        // to find.
        let base = if prefix.is_empty() {
            self.path.clone()
        } else {
            self.path.join(prefix)
        };
        let pattern = format!("{}/**/*.toml", base.to_string_lossy());
        let entries = glob(&pattern).map_err(|e| Error::Pattern {
            source: e,
            path: pattern.clone(),
        })?;
        let mut keys = vec![];
        for entry in entries {
            let file = entry.map_err(|e| Error::Glob { source: e })?;
            if let Ok(rel) = file.strip_prefix(&self.path) {
                keys.push(rel.to_string_lossy().replace('\\', "/"));
            }
        }
        Ok(keys)
    }

    async fn retire(&self, key: &str) -> Result<String> {
        let file = self.get_target_path(key);
        // With history enabled the value survives in the history directory, so
        // the file itself can go.
        if self.save_history(key).await? {
            self.delete(key).await?;
            return Ok(format!("{} (kept in history)", file.display()));
        }
        // Otherwise leave the bytes exactly where they are, under a name the
        // loader ignores: a config directory is read by globbing `*.toml`, so
        // the extra suffix is enough to take the file out of the picture while
        // keeping it one rename away from being restored.
        let backup = file.with_extension("toml.bak");
        fs::rename(&file, &backup).await.map_err(|e| Error::Io {
            source: e,
            file: file.to_string_lossy().to_string(),
        })?;
        Ok(format!(
            "{} (renamed to {})",
            file.display(),
            backup.display()
        ))
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
