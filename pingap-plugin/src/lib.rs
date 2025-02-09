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

use pingap_config::{PluginConf, PluginStep};
use snafu::Snafu;
use std::str::FromStr;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Plugin {category} invalid, message: {message}"))]
    Invalid { category: String, message: String },
    #[snafu(display("Plugin {category} not found"))]
    NotFound { category: String },
    #[snafu(display("Plugin {category}, base64 decode error {source}"))]
    Base64Decode {
        category: String,
        source: base64::DecodeError,
    },
    #[snafu(display("Plugin {category}, exceed limit {value}/{max}"))]
    Exceed {
        category: String,
        max: isize,
        value: isize,
    },
    #[snafu(display("Plugin {category}, regex error {source}"))]
    Regex {
        category: String,
        source: Box<fancy_regex::Error>,
    },
    #[snafu(display("Plugin {category}, base64 decode error {source}"))]
    ParseDuration {
        category: String,
        source: humantime::DurationError,
    },
}

/// Helper functions for accessing plugin configuration values
pub(crate) fn get_str_conf(value: &PluginConf, key: &str) -> String {
    if let Some(value) = value.get(key) {
        value.as_str().unwrap_or_default().to_string()
    } else {
        "".to_string()
    }
}

pub(crate) fn get_str_slice_conf(value: &PluginConf, key: &str) -> Vec<String> {
    if let Some(value) = value.get(key) {
        if let Some(values) = value.as_array() {
            return values
                .iter()
                .map(|item| item.as_str().unwrap_or_default().to_string())
                .collect();
        }
    }
    vec![]
}

pub(crate) fn get_bool_conf(value: &PluginConf, key: &str) -> bool {
    if let Some(value) = value.get(key) {
        value.as_bool().unwrap_or_default()
    } else {
        false
    }
}

pub(crate) fn get_int_conf(value: &PluginConf, key: &str) -> i64 {
    if let Some(value) = value.get(key) {
        value.as_integer().unwrap_or_default()
    } else {
        0
    }
}

pub(crate) fn get_step_conf(
    value: &PluginConf,
    default_value: PluginStep,
) -> PluginStep {
    let step = get_str_conf(value, "step");
    if step.is_empty() {
        return default_value;
    }

    PluginStep::from_str(step.as_str()).unwrap_or(default_value)
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
mod basic_auth;
mod cache;
mod combined_auth;
mod compression;
mod cors;
mod csrf;
mod directory;
mod ip_restriction;
mod jwt;
mod key_auth;
mod limit;
mod mock;
mod ping;
mod redirect;
mod referer_restriction;
mod request_id;
mod response_headers;
mod sub_filter;
mod ua_restriction;

mod plugin;

pub use plugin::{get_plugin_factory, Plugin};
