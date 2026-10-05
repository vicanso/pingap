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
use crate::hcl::{convert_hcl_to_toml, convert_toml_to_hcl};
use crate::kdl::{convert_kdl_to_toml, convert_toml_to_kdl};
use crate::storage::{History, Storage};
use crate::{
    list_config_files, permission_error_message, read_all_config_files,
};
use async_trait::async_trait;
use glob::glob;
use pingap_core::now_sec;
use pingap_util::resolve_path;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use tokio::fs;

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

/// Drops what a config does not tell apart: an empty list and an empty
/// table read like a key that is not there, and the hcl and kdl forms do
/// not keep them apart either.
fn without_empty(value: toml::Value) -> Option<toml::Value> {
    match value {
        toml::Value::Table(table) => {
            let table: toml::Table = table
                .into_iter()
                .filter_map(|(key, value)| Some((key, without_empty(value)?)))
                .collect();
            (!table.is_empty()).then_some(toml::Value::Table(table))
        },
        toml::Value::Array(items) => {
            let items: Vec<toml::Value> =
                items.into_iter().filter_map(without_empty).collect();
            (!items.is_empty()).then_some(toml::Value::Array(items))
        },
        other => Some(other),
    }
}

/// `value`, a toml document, in the format of the `file` it is saved to.
///
/// A config kept in one `.hcl` or `.kdl` file is read by converting it to
/// toml, and used to be saved as that toml, under the same name: after the
/// first change made through the admin or by a certificate renewal the file
/// no longer parsed, and the next start failed.
///
/// What is written is read back and compared before it replaces anything.
/// A config that does not survive the conversion is refused instead of
/// being saved with a part missing.
fn encode_for_file(file: &Path, value: &str) -> Result<String> {
    type Convert = fn(&str) -> Result<String>;
    let (ext, to, from): (&str, Convert, Convert) =
        match file.extension().and_then(|ext| ext.to_str()) {
            Some("hcl") => ("hcl", convert_toml_to_hcl, convert_hcl_to_toml),
            Some("kdl") => ("kdl", convert_toml_to_kdl, convert_kdl_to_toml),
            _ => return Ok(value.to_string()),
        };
    if value.trim().is_empty() {
        return Ok(String::new());
    }
    let parse = |text: &str| {
        toml::from_str::<toml::Value>(text)
            .map(without_empty)
            .map_err(|e| Error::Invalid {
                message: format!("{}: {e}", file.display()),
            })
    };
    let encoded = to(value)?;
    if parse(value)? != parse(&from(&encoded)?)? {
        return Err(Error::Invalid {
            message: format!(
                "{}: the config can not be written as {ext} without losing part of it, nothing was saved; keep the config in toml to change it through pingap",
                file.display()
            ),
        });
    }
    Ok(encoded)
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
    /// Fails for a directory whose config is kept in hcl or kdl files.
    ///
    /// Such a directory is read as a whole, and its files are laid out as
    /// whoever wrote them saw fit, so there is no file a change to one
    /// entry belongs in. Writing the entry as a toml file - what used to
    /// happen - was worse than not writing at all: toml files take
    /// precedence when the directory is read, so that one file became the
    /// entire config and everything in the hcl files was gone.
    fn ensure_writable(&self) -> Result<()> {
        if !self.is_dir {
            return Ok(());
        }
        let dir = self.path.to_string_lossy();
        if !list_config_files(&dir, "toml")?.is_empty() {
            return Ok(());
        }
        for ext in ["hcl", "kdl"] {
            if !list_config_files(&dir, ext)?.is_empty() {
                return Err(Error::Invalid {
                    message: format!(
                        "{dir} holds {ext} files, which are read but not written; change the files themselves, or keep the config in toml to change it through pingap"
                    ),
                });
            }
        }
        Ok(())
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

#[async_trait]
impl Storage for FileStorage {
    fn support_history(&self) -> bool {
        self.history_path.is_some()
    }
    fn ensure_writable(&self) -> Result<()> {
        FileStorage::ensure_writable(self)
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
        self.ensure_writable()?;
        let file = self.get_target_path(key);
        // Before the history is written: a config that can not be saved
        // leaves nothing behind.
        let value = &encode_for_file(&file, value)?;
        self.save_history(key).await?;
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
        self.ensure_writable()?;
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

    /// A syntax error in one file of a directory names that file, not a
    /// line in the concatenated document.
    #[tokio::test]
    async fn test_dir_storage_names_the_broken_file() {
        for (name, content) in [
            ("broken.toml", "[servers"),
            ("broken.hcl", "upstreams \"api\" {"),
        ] {
            let dir = tempdir().unwrap();
            let storage =
                FileStorage::new(&dir.path().to_string_lossy()).unwrap();
            tokio::fs::write(dir.path().join(name), content)
                .await
                .unwrap();
            let err = storage.fetch("").await.unwrap_err().to_string();
            assert!(err.contains(name), "{err}");
        }
    }

    /// Regression: a config kept in one hcl or kdl file was saved as toml
    /// under the same name, and did not load again.
    #[tokio::test]
    async fn test_single_file_keeps_its_format() {
        let config = r#"
[basic]
log_level = "info"
trusted_proxies = ["10.0.0.0/8"]

[locations.app]
plugins = ["deny"]
upstream = "api"

[plugins.deny]
category = "ip_restriction"
ip_list = ["1.2.3.4"]
type = "deny"

[servers.web]
addr = "127.0.0.1:6188"
locations = ["app"]

[upstreams.api]
addrs = ["127.0.0.1:5000"]
"#;
        let expected: toml::Value = toml::from_str(config).unwrap();
        for ext in ["hcl", "kdl", "toml"] {
            let dir = tempdir().unwrap();
            let file = dir.path().join(format!("pingap.{ext}"));
            let storage = FileStorage::new(&file.to_string_lossy()).unwrap();
            storage.save("pingap.toml", config).await.unwrap();

            let written = std::fs::read_to_string(&file).unwrap();
            // toml only in the toml file
            assert_eq!(ext == "toml", written.contains("[basic]"), "{ext}");
            // and what was saved is what loads, the list of one included
            let loaded = storage.fetch("pingap.toml").await.unwrap();
            assert_eq!(
                expected,
                toml::from_str::<toml::Value>(&loaded).unwrap(),
                "{ext}"
            );
            // Saving what was loaded changes nothing (toml is kept as it
            // was given, down to the blank lines, so it is left out here).
            if ext != "toml" {
                storage.save("pingap.toml", &loaded).await.unwrap();
                assert_eq!(written, std::fs::read_to_string(&file).unwrap());
            }
        }
    }

    /// The check before a save must not refuse a config for being a real
    /// one: the sample configs convert to both formats and back unchanged.
    #[test]
    fn test_sample_configs_can_be_saved_in_each_format() {
        use super::encode_for_file;
        use crate::hcl::convert_hcl_to_toml;
        use crate::kdl::convert_kdl_to_toml;
        use std::path::Path;

        let conf = Path::new(env!("CARGO_MANIFEST_DIR")).join("../conf");
        let read =
            |name: &str| std::fs::read_to_string(conf.join(name)).unwrap();
        let samples = [
            ("test.hcl", convert_hcl_to_toml(&read("test.hcl")).unwrap()),
            ("test.kdl", convert_kdl_to_toml(&read("test.kdl")).unwrap()),
            (
                "*.toml",
                [
                    "basic.toml",
                    "certificates.toml",
                    "locations.toml",
                    "plugins.toml",
                    "servers.toml",
                    "upstreams.toml",
                ]
                .map(read)
                .join("\n"),
            ),
        ];
        for (name, config) in samples {
            for target in ["pingap.hcl", "pingap.kdl"] {
                let result = encode_for_file(Path::new(target), &config);
                assert_eq!(
                    true,
                    result.is_ok(),
                    "{name} as {target}: {:?}",
                    result.err().map(|e| e.to_string())
                );
            }
        }
    }

    /// Multi-line values are what a certificate renewal saves. They have
    /// to come back byte for byte, or the check before a save refuses the
    /// config and the new certificate is never stored.
    #[test]
    fn test_multiline_values_can_be_saved_in_each_format() {
        use super::encode_for_file;
        use std::path::Path;

        for value in [
            "-----BEGIN CERTIFICATE-----\nMIIB\nabc=\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nMIIB\nabc=\n-----END CERTIFICATE-----",
            "two\n\nblank lines between\n\n",
            "  indented first\n    and more\nback\n",
            "\nstarts with a newline",
            "windows\r\nline ends\r\n",
            "tab\tand \"quotes\" and a \\ backslash\n",
            "EOT\nthe heredoc marker as a line\nEOT\n",
            "a ${template} and %{directive}\nin it\n",
        ] {
            let mut table = toml::Table::new();
            table.insert("tls_cert".to_string(), value.into());
            let mut certificates = toml::Table::new();
            certificates.insert("site".to_string(), table.into());
            let mut root = toml::Table::new();
            root.insert("certificates".to_string(), certificates.into());
            let config = toml::to_string(&root).unwrap();
            for target in ["pingap.hcl", "pingap.kdl"] {
                let result = encode_for_file(Path::new(target), &config);
                assert_eq!(
                    true,
                    result.is_ok(),
                    "{value:?} as {target}: {:?}",
                    result.err().map(|e| e.to_string())
                );
            }
        }
    }

    /// A config that does not survive the conversion is not saved.
    #[tokio::test]
    async fn test_single_file_refuses_a_lossy_save() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("pingap.kdl");
        let storage = FileStorage::new(&file.to_string_lossy()).unwrap();
        storage
            .save("pingap.toml", "[basic]\nlog_level = \"info\"")
            .await
            .unwrap();
        let before = std::fs::read_to_string(&file).unwrap();

        // A list of lists has no kdl form here.
        let err = storage
            .save(
                "pingap.toml",
                "[plugins.x]\ncategory = \"mock\"\nmatrix = [[1, 2], [3, 4]]",
            )
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(true, err.contains("without losing part of it"), "{err}");
        assert_eq!(before, std::fs::read_to_string(&file).unwrap());
    }

    /// A caller can ask before it has anything to save.
    #[test]
    fn test_ensure_writable() {
        let dir = tempdir().unwrap();
        let storage = FileStorage::new(&dir.path().to_string_lossy()).unwrap();
        assert_eq!(true, Storage::ensure_writable(&storage).is_ok());
        std::fs::write(dir.path().join("main.hcl"), "basic {}\n").unwrap();
        let err = Storage::ensure_writable(&storage).unwrap_err().to_string();
        assert_eq!(true, err.contains("read but not written"), "{err}");
        // toml next to it: that is what gets read, and written.
        std::fs::write(dir.path().join("basic.toml"), "[basic]\n").unwrap();
        assert_eq!(true, Storage::ensure_writable(&storage).is_ok());
    }

    /// Regression: saving one entry into a directory of hcl files wrote a
    /// toml file, and toml files win when the directory is read - that one
    /// entry became the whole config.
    #[tokio::test]
    async fn test_dir_of_hcl_files_is_read_only() {
        for (name, content) in [
            (
                "main.hcl",
                "upstream \"api\" {\n  addrs = [\"127.0.0.1:5000\"]\n}\n",
            ),
            (
                "main.kdl",
                "upstream \"api\" {\n  addrs \"127.0.0.1:5000\"\n}\n",
            ),
        ] {
            let dir = tempdir().unwrap();
            std::fs::write(dir.path().join(name), content).unwrap();
            let storage =
                FileStorage::new(&dir.path().to_string_lossy()).unwrap();
            let before = storage.fetch("").await.unwrap();
            assert_eq!(true, before.contains("127.0.0.1:5000"), "{before}");

            let err = storage
                .save("plugins.toml", "[plugins.x]\ncategory = \"mock\"")
                .await
                .unwrap_err()
                .to_string();
            assert_eq!(true, err.contains("read but not written"), "{err}");
            let err = storage
                .delete("upstreams.toml")
                .await
                .unwrap_err()
                .to_string();
            assert_eq!(true, err.contains("read but not written"), "{err}");

            assert_eq!(false, dir.path().join("plugins.toml").exists());
            assert_eq!(before, storage.fetch("").await.unwrap());
        }
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
