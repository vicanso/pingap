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

use pingap_config::PluginConf;
use snafu::Snafu;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Plugin poisoned, {message}"))]
    Poisoned { message: String },
    #[snafu(display("Plugin {category} not found"))]
    NotFound { category: String },
}

/// Helper functions for accessing plugin configuration values
pub(crate) fn get_str_conf(value: &PluginConf, key: &str) -> String {
    if let Some(value) = value.get(key) {
        value.as_str().unwrap_or_default().to_string()
    } else {
        "".to_string()
    }
}

pub(crate) fn get_bool_conf(value: &PluginConf, key: &str) -> bool {
    if let Some(value) = value.get(key) {
        value.as_bool().unwrap_or_default()
    } else {
        false
    }
}

/// Generates a unique hash key for a plugin configuration to detect changes.
///
/// # Arguments
/// * `conf` - The plugin configuration to hash
///
/// # Returns
/// A string containing the CRC32 hash of the sorted configuration key-value pairs
pub(crate) fn get_hash_key(conf: &PluginConf) -> String {
    let mut keys: Vec<String> =
        conf.keys().map(|item| item.to_string()).collect();
    keys.sort();
    let mut lines = vec![];
    for key in keys {
        let value = if let Some(value) = conf.get(&key) {
            value.to_string()
        } else {
            "".to_string()
        };
        lines.push(format!("{key}:{value}"));
    }
    let hash = crc32fast::hash(lines.join("\n").as_bytes());
    format!("{:X}", hash)
}

mod accept_encoding;
mod plugin;

pub use plugin::{get_plugin_factory, Plugin};
