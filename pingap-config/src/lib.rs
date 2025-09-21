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
mod etcd_storage;
mod file_storage;
mod manager;
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

pub async fn read_all_toml_files(dir: &str) -> Result<Vec<u8>> {
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

pub async fn sync_to_path(
    config_manager: Arc<ConfigManager>,
    path: &str,
) -> Result<()> {
    let config = config_manager.get_current_config();
    let config = toml::to_string_pretty(&config.as_ref().clone())
        .map_err(|e| Error::Ser { source: e })?;
    let config = toml::from_str::<PingapTomlConfig>(&config)
        .map_err(|e| Error::De { source: e })?;
    let new_config_manager = new_config_manager(path)?;
    new_config_manager.save_all(&config).await?;
    Ok(())
}

pub use common::*;
pub use etcd_storage::ETCD_PROTOCOL;
pub use manager::*;
pub use storage::*;
