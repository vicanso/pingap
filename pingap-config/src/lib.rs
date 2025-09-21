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
use async_trait::async_trait;
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

// Options for loading configuration
#[derive(Debug, Default, Clone)]
pub struct LoadConfigOptions {
    pub replace_include: bool, // Whether to replace include directives
    pub admin: bool,           // Whether this is an admin configuration
}

// Trait defining storage backend operations for configuration
#[async_trait]
pub trait ConfigStorage {
    // Load configuration with specified options
    async fn load_config(
        &self,
        opts: LoadConfigOptions,
    ) -> Result<PingapConfig>;

    // Save configuration for a specific category and optional name
    async fn save_config(
        &self,
        conf: &PingapConfig,
        category: &str,
        name: Option<&str>,
    ) -> Result<()>;

    // Whether this storage supports change observation
    fn support_observer(&self) -> bool {
        false
    }

    // Create an observer for this storage
    async fn observe(&self) -> Result<Observer> {
        Ok(Observer {
            etcd_watch_stream: None,
        })
    }

    // Low-level storage operations
    async fn save(&self, key: &str, data: &[u8]) -> Result<()>;
    async fn load(&self, key: &str) -> Result<Vec<u8>>;
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
