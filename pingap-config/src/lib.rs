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
}

impl Observer {
    // Watches for configuration changes, returns true if changes detected
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

        Ok(resp.is_some())
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

/// Every `*.<ext>` file under `dir`, recursively, in glob order.
fn list_config_files(dir: &str, ext: &str) -> Result<Vec<std::path::PathBuf>> {
    let pattern = format!("{dir}/**/*.{ext}");
    glob(&pattern)
        .map_err(|e| Error::Pattern {
            source: e,
            path: dir.to_string(),
        })?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::Glob { source: e })
}

/// Reads a config directory into one TOML document. The first format that
/// has any file wins - `toml`, then `hcl`, then `kdl` - and every file is
/// checked (or converted) on its own, so a syntax error names the file it
/// is in rather than a line in the concatenation.
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
        let mut data = vec![];
        for f in files {
            let buf = fs::read(&f)
                .await
                .map_err(|e| permission_error_message(&f, e))?;
            debug!(filename = ?f, "read config file");
            let text = String::from_utf8_lossy(&buf);
            let in_file = |e: String| Error::Invalid {
                message: format!("{}: {e}", f.display()),
            };
            match convert {
                None => {
                    toml::from_str::<toml::Value>(&text)
                        .map_err(|e| in_file(e.to_string()))?;
                    data.extend_from_slice(&buf);
                },
                Some(convert) => {
                    let toml_str =
                        convert(&text).map_err(|e| in_file(e.to_string()))?;
                    data.extend_from_slice(toml_str.as_bytes());
                },
            }
            data.push(b'\n');
        }
        return Ok(data);
    }
    Ok(vec![])
}

pub async fn sync_to_path(
    config_manager: Arc<ConfigManager>,
    path: &str,
) -> Result<()> {
    let config = config_manager.get_current_config();
    let config = PingapTomlConfig::from_pingap_config(&config)?;
    let new_config_manager = new_config_manager(path)?;
    new_config_manager.save_all(&config).await?;
    Ok(())
}

pub use common::*;
pub use etcd_storage::ETCD_PROTOCOL;
pub use manager::*;
pub use memory_storage::MemoryStorage;
pub use storage::*;
