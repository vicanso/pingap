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

// External crate imports for async operations, etcd client, and error handling
use etcd_client::WatchStream;
use glob::glob;
use snafu::Snafu;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tracing::debug;

mod common;
mod config_convert;
mod etcd_storage;
mod file_storage;
pub mod hcl;
pub mod kdl;
mod manager;
mod memory_storage;
mod storage;

// Error enum for all possible configuration-related errors
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
    Etcd { source: Box<etcd_client::Error> },
}
type Result<T, E = Error> = std::result::Result<T, E>;

// Observer struct for watching configuration changes
pub struct Observer {
    // Optional watch stream for etcd-based configuration
    etcd_watch_stream: Option<WatchStream>,
    // The connection the stream runs on, kept for as long as the stream.
    _etcd_client: Option<etcd_client::Client>,
}

impl Observer {
    /// Waits for the next configuration change, `true` when there is one.
    ///
    /// An error means this observer is finished - the watch broke, or the
    /// server closed or canceled it - and a new one has to be created. The end of the
    /// stream used to be reported as "no change": the caller asked again at
    /// once, got the same answer, and spun on one core without ever seeing
    /// another change.
    pub async fn watch(&mut self) -> Result<bool> {
        let sleep_time = Duration::from_secs(30);
        // no watch stream, just sleep a moment
        let Some(stream) = self.etcd_watch_stream.as_mut() else {
            tokio::time::sleep(sleep_time).await;
            return Ok(false);
        };
        let resp = stream.message().await.map_err(|e| Error::Etcd {
            source: Box::new(e),
        })?;
        let Some(resp) = resp else {
            return Err(Error::Invalid {
                message: "etcd watch stream is closed".to_string(),
            });
        };
        // The server ended the watch - no permission for the prefix, a
        // compacted revision - and may well leave the stream open. Nothing
        // more would ever come over it.
        if resp.canceled() {
            return Err(Error::Invalid {
                message: format!(
                    "etcd watch is canceled: {}",
                    resp.cancel_reason()
                ),
            });
        }
        // The first message only acknowledges the watch; a change is a
        // message with events in it.
        Ok(!resp.events().is_empty())
    }
}

#[derive(PartialEq, Clone, Debug)]
pub enum Category {
    Basic,
    Server,
    Location,
    Upstream,
    Plugin,
    Certificate,
    Storage,
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 使用 match 来为每个变体指定其字符串表示
        // write! 宏将字符串写入格式化器
        match self {
            Category::Basic => write!(f, "basic"),
            Category::Server => write!(f, "server"),
            Category::Location => write!(f, "location"),
            Category::Upstream => write!(f, "upstream"),
            Category::Plugin => write!(f, "plugin"),
            Category::Certificate => write!(f, "certificate"),
            Category::Storage => write!(f, "storage"),
        }
    }
}
impl FromStr for Category {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "basic" => Ok(Category::Basic),
            "server" => Ok(Category::Server),
            "location" => Ok(Category::Location),
            "upstream" => Ok(Category::Upstream),
            "plugin" => Ok(Category::Plugin),
            "certificate" => Ok(Category::Certificate),
            "storage" => Ok(Category::Storage),
            _ => Err(Error::Invalid {
                message: format!("invalid category: {s}"),
            }),
        }
    }
}

pub fn new_config_manager(value: &str) -> Result<ConfigManager> {
    if value.starts_with(etcd_storage::ETCD_PROTOCOL) {
        new_etcd_config_manager(value)
    } else {
        new_file_config_manager(value)
    }
}

/// Build a detailed error message when a config file cannot be read due to
/// permission issues, including the file's owner/group/mode so the operator
/// knows exactly what to fix.
fn permission_error_message(
    path: &std::path::Path,
    source: std::io::Error,
) -> Error {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if source.kind() == std::io::ErrorKind::PermissionDenied
            && let Ok(meta) = std::fs::metadata(path)
        {
            let mode = meta.mode() & 0o7777;
            let uid = meta.uid();
            let gid = meta.gid();
            return Error::Invalid {
                message: format!(
                    "Config file '{}' is not readable: permission denied \
                         (owner uid:{} gid:{}, mode:{:04o}). \
                         Please ensure the pingap process user can read this file, \
                         e.g.: chown <pingap-user>:<pingap-group> '{}' or chmod o+r '{}'",
                    path.display(),
                    uid,
                    gid,
                    mode,
                    path.display(),
                    path.display(),
                ),
            };
        }
    }
    Error::Io {
        source,
        file: path.to_string_lossy().to_string(),
    }
}

/// Whether `file` lies in a directory, below `root`, whose name starts
/// with `..`: the `..data` and `..<timestamp>` of a mounted ConfigMap.
/// Only directories count - a file may be called `..x.toml` - and only
/// those below `root`, however `root` itself is reached.
pub(crate) fn is_under_hidden_dir(
    root: &std::path::Path,
    file: &std::path::Path,
) -> bool {
    file.strip_prefix(root)
        .ok()
        .and_then(|below| below.parent())
        .is_some_and(|dirs| {
            dirs.components().any(|part| {
                part.as_os_str().to_string_lossy().starts_with("..")
            })
        })
}

/// Every `*.<ext>` file under `dir`, recursively, in glob order, each
/// file once.
///
/// A directory that Kubernetes mounts from a ConfigMap or a Secret holds
/// every file three times over: `a.toml` is a link to `..data/a.toml`,
/// and `..data` a link to a `..<timestamp>` directory with the file in
/// it. Read as three files, the config was three copies of itself and
/// did not load (`duplicate key`). Whatever lies under a name starting
/// with `..` is left out, and two paths to one file count once.
pub(crate) fn list_config_files(
    dir: &str,
    ext: &str,
) -> Result<Vec<std::path::PathBuf>> {
    let pattern = format!("{dir}/**/*.{ext}");
    let files = glob(&pattern)
        .map_err(|e| Error::Pattern {
            source: e,
            path: dir.to_string(),
        })?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::Glob { source: e })?;
    let root = std::path::Path::new(dir);
    let mut seen = std::collections::HashSet::new();
    Ok(files
        .into_iter()
        .filter(|file| {
            // A file that does not resolve is kept, for the read to report.
            !is_under_hidden_dir(root, file)
                && seen.insert(
                    std::fs::canonicalize(file)
                        .unwrap_or_else(|_| file.clone()),
                )
        })
        .collect())
}

/// Adds the tables of one file to the document the directory makes up.
///
/// A category may be spread over files - `[upstreams.a]` here,
/// `[upstreams.b]` there - but an entry is defined in one place: the same
/// name in two files is an error that names both. `sources` remembers
/// which file each entry came from.
fn merge_config_file(
    merged: &mut toml::Table,
    sources: &mut std::collections::HashMap<String, std::path::PathBuf>,
    table: toml::Table,
    file: &std::path::Path,
) -> Result<()> {
    let duplicate =
        |key: &str, first: Option<&std::path::PathBuf>| Error::Invalid {
            message: format!(
                "duplicate {key}: defined in {} and in {}",
                first.map_or_else(String::new, |f| f.display().to_string()),
                file.display()
            ),
        };
    for (category, value) in table {
        let Some(existing) = merged.get_mut(&category) else {
            for name in value.as_table().iter().flat_map(|t| t.keys()) {
                sources
                    .insert(format!("{category}.{name}"), file.to_path_buf());
            }
            sources.insert(category.clone(), file.to_path_buf());
            merged.insert(category, value);
            continue;
        };
        // `basic` is one entry, not a table of them, and like any entry
        // it is defined in one file.
        if category == CATEGORY_BASIC {
            return Err(duplicate(&category, sources.get(&category)));
        }
        let (Some(existing), toml::Value::Table(entries)) =
            (existing.as_table_mut(), value)
        else {
            return Err(duplicate(&category, sources.get(&category)));
        };
        for (name, entry) in entries {
            let key = format!("{category}.{name}");
            if existing.contains_key(&name) {
                return Err(duplicate(&key, sources.get(&key)));
            }
            sources.insert(key, file.to_path_buf());
            existing.insert(name, entry);
        }
    }
    Ok(())
}

/// Reads a config directory into one TOML document. The first format that
/// has any file wins - `toml`, then `hcl`, then `kdl` - and every file is
/// parsed (or converted) on its own and its tables merged into the
/// document, so a syntax error names the file it is in.
///
/// The files used to be joined as text and parsed as one. A file then
/// continued the last table of the one before it: top level keys written
/// with dots (`upstreams.extra.addrs = [..]`) ended up as unknown keys of
/// that table and were dropped without a word.
pub async fn read_all_config_files(dir: &str) -> Result<Vec<u8>> {
    type Convert = fn(&str) -> Result<String>;
    let formats: [(&str, Option<Convert>); 3] = [
        ("toml", None),
        ("hcl", Some(hcl::convert_hcl_to_toml)),
        ("kdl", Some(kdl::convert_kdl_to_toml)),
    ];
    for (ext, convert) in formats {
        let files = list_config_files(dir, ext)?;
        if files.is_empty() {
            continue;
        }
        let mut merged = toml::Table::new();
        let mut sources = std::collections::HashMap::new();
        for f in files {
            let buf = fs::read(&f)
                .await
                .map_err(|e| permission_error_message(&f, e))?;
            debug!(filename = ?f, "read config file");
            let text = String::from_utf8_lossy(&buf);
            let in_file = |e: String| Error::Invalid {
                message: format!("{}: {e}", f.display()),
            };
            let toml_str = match convert {
                None => text,
                Some(convert) => std::borrow::Cow::Owned(
                    convert(&text).map_err(|e| in_file(e.to_string()))?,
                ),
            };
            let table = toml::from_str::<toml::Table>(&toml_str)
                .map_err(|e| in_file(e.to_string()))?;
            merge_config_file(&mut merged, &mut sources, table, &f)?;
        }
        return toml::to_string(&merged)
            .map(String::into_bytes)
            .map_err(|e| Error::Ser { source: e });
    }
    Ok(vec![])
}

/// Copies the configuration to another storage as it is stored, with the
/// `includes` of its entries left as they are. It used to copy the config
/// this process had loaded, in which every include is already replaced by
/// what it names: the copy kept the shared fragments but no entry referred
/// to them any more, so changing one changed nothing.
pub async fn sync_to_path(
    config_manager: Arc<ConfigManager>,
    path: &str,
) -> Result<()> {
    let config = config_manager.load_all().await?;
    let new_config_manager = new_config_manager(path)?;
    new_config_manager.save_all(&config).await?;
    Ok(())
}

pub use common::*;
pub use etcd_storage::ETCD_PROTOCOL;
pub use manager::*;
pub use memory_storage::MemoryStorage;
pub use storage::*;

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    async fn load(dir: &std::path::Path) -> Result<PingapConfig> {
        let data = read_all_config_files(&dir.to_string_lossy()).await?;
        PingapConfig::new(&data, false)
    }

    /// Regression: the files of a directory were joined as text. Top level
    /// keys written with dots in the second file continued the last table
    /// of the first, where they were unknown keys and dropped: the
    /// upstream they defined was not there, and nothing said so.
    #[tokio::test]
    async fn test_config_files_are_merged_not_joined() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("a.toml"),
            "[basic]\nname = \"pingap\"\n\n[upstreams.main]\naddrs = [\"127.0.0.1:9001\"]\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("b.toml"),
            "upstreams.extra.addrs = [\"127.0.0.1:9002\"]\n",
        )
        .unwrap();
        let config = load(dir.path()).await.unwrap();
        assert_eq!(Some("pingap".to_string()), config.basic.name);
        assert_eq!(
            vec!["127.0.0.1:9001".to_string()],
            config.upstreams["main"].addrs
        );
        assert_eq!(
            vec!["127.0.0.1:9002".to_string()],
            config.upstreams["extra"].addrs
        );

        // An entry is defined in one file; the error names both.
        std::fs::write(
            dir.path().join("c.toml"),
            "[upstreams.main]\naddrs = [\"127.0.0.1:9003\"]\n",
        )
        .unwrap();
        let message = load(dir.path()).await.unwrap_err().to_string();
        assert_eq!(
            true,
            message.contains("duplicate upstreams.main"),
            "{message}"
        );
        assert_eq!(true, message.contains("a.toml"), "{message}");
        assert_eq!(true, message.contains("c.toml"), "{message}");

        // So is `basic`.
        std::fs::write(dir.path().join("c.toml"), "[basic]\nthreads = 2\n")
            .unwrap();
        let message = load(dir.path()).await.unwrap_err().to_string();
        assert_eq!(true, message.contains("duplicate basic"), "{message}");

        // A file that does not parse is named.
        std::fs::write(dir.path().join("c.toml"), "[basic\n").unwrap();
        let message = load(dir.path()).await.unwrap_err().to_string();
        assert_eq!(true, message.contains("c.toml"), "{message}");
    }

    /// Regression: the layout Kubernetes mounts a ConfigMap in. Each file
    /// is reachable three ways - the link at the top, `..data`, and the
    /// timestamped directory behind that - and was read three times.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_config_files_of_a_mounted_config_map() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let version = dir.path().join("..2026_10_06_08_00_00.123456789");
        std::fs::create_dir(&version).unwrap();
        std::fs::write(
            version.join("pingap.toml"),
            "[upstreams.main]\naddrs = [\"127.0.0.1:9001\"]\n",
        )
        .unwrap();
        symlink(&version, dir.path().join("..data")).unwrap();
        symlink("..data/pingap.toml", dir.path().join("pingap.toml")).unwrap();

        let files =
            list_config_files(&dir.path().to_string_lossy(), "toml").unwrap();
        assert_eq!(vec![dir.path().join("pingap.toml")], files);
        let config = load(dir.path()).await.unwrap();
        assert_eq!(1, config.upstreams.len());

        // Two names for one file count once as well.
        symlink("pingap.toml", dir.path().join("again.toml")).unwrap();
        let config = load(dir.path()).await.unwrap();
        assert_eq!(1, config.upstreams.len());
    }

    /// What is left out is what lies in a directory named `..something`
    /// below the config directory. A file of such a name is read, and so
    /// is everything when the config directory is itself reached through
    /// `..`.
    #[test]
    fn test_only_hidden_directories_are_left_out() {
        let root = std::path::Path::new("/etc/pingap");
        let hidden =
            |file: &str| is_under_hidden_dir(root, std::path::Path::new(file));
        assert_eq!(true, hidden("/etc/pingap/..data/pingap.toml"));
        assert_eq!(true, hidden("/etc/pingap/a/..2026_10_06/pingap.toml"));
        assert_eq!(false, hidden("/etc/pingap/pingap.toml"));
        assert_eq!(false, hidden("/etc/pingap/upstreams/..x.toml"));
        assert_eq!(false, hidden("/etc/pingap/.git/x.toml"));
        // Not below the root at all: nothing to say about it.
        assert_eq!(false, hidden("/srv/..data/pingap.toml"));
        let odd_root = std::path::Path::new("../conf");
        assert_eq!(
            false,
            is_under_hidden_dir(
                odd_root,
                std::path::Path::new("../conf/pingap.toml")
            )
        );
    }

    /// Regression: `--sync` wrote the config this process had loaded, in
    /// which every include is already replaced by what it names. The copy
    /// had the shared fragment and no entry that still referred to it.
    #[tokio::test]
    async fn test_sync_keeps_the_includes() {
        let source = tempfile::NamedTempFile::with_suffix(".toml").unwrap();
        std::fs::write(
            source.path(),
            r#"
[upstreams.main]
addrs = ["127.0.0.1:9001"]
includes = ["common"]

[storages.common]
category = "config"
value = 'read_timeout = "7s"'
"#,
        )
        .unwrap();
        let manager = Arc::new(
            new_config_manager(&source.path().to_string_lossy()).unwrap(),
        );
        // What a running process holds.
        manager.set_current_config(
            manager
                .load_all()
                .await
                .unwrap()
                .to_pingap_config(true)
                .unwrap(),
        );

        let target = tempfile::NamedTempFile::with_suffix(".toml").unwrap();
        sync_to_path(manager, &target.path().to_string_lossy())
            .await
            .unwrap();
        let data = std::fs::read(target.path()).unwrap();
        let synced = PingapConfig::new(&data, false).unwrap();
        assert_eq!(
            Some(vec!["common".to_string()]),
            synced.upstreams["main"].includes
        );
        assert_eq!(None, synced.upstreams["main"].read_timeout);
        // And it still resolves to the same thing.
        let resolved = PingapConfig::new(&data, true).unwrap();
        assert_eq!(
            Some(std::time::Duration::from_secs(7)),
            resolved.upstreams["main"].read_timeout
        );
    }
}
