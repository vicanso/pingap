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

use humantime::parse_duration;
use pingap_config::PluginConf;
use pingap_core::PluginStep;
use snafu::Snafu;
use std::fmt::Write;
use std::str::FromStr;
use std::time::Duration;

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
        max: f64,
        value: f64,
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
pub fn get_str_conf(value: &PluginConf, key: &str) -> String {
    value
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

/// Helper functions for accessing plugin configuration values
pub fn get_duration_conf(value: &PluginConf, key: &str) -> Option<Duration> {
    value
        .get(key)
        .and_then(|v| v.as_str())
        .and_then(|s| parse_duration(s).ok())
}

pub(crate) fn get_str_slice_conf(value: &PluginConf, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| item.as_str())
                .map(String::from) // same as .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn get_bool_conf(value: &PluginConf, key: &str) -> bool {
    value.get(key).and_then(|v| v.as_bool()).unwrap_or(false)
}

pub fn get_int_conf(value: &PluginConf, key: &str) -> i64 {
    get_int_conf_or_default(value, key, 0)
}

pub fn get_int_conf_or_default(
    value: &PluginConf,
    key: &str,
    default_value: i64,
) -> i64 {
    value
        .get(key)
        .and_then(|v| v.as_integer()) // assume PluginConf value can be converted to i64
        .unwrap_or(default_value)
}

pub(crate) fn get_step_conf(
    value: &PluginConf,
    default_value: PluginStep,
) -> PluginStep {
    value
        .get("step")
        .and_then(|v| v.as_str())
        .and_then(|s| PluginStep::from_str(s).ok())
        .unwrap_or(default_value)
}

/// Generates a unique hash key for a plugin configuration to detect changes.
///
/// # Arguments
/// * `conf` - The plugin configuration to hash
///
/// # Returns
/// A string containing the CRC32 hash of the sorted configuration key-value pairs
pub fn get_hash_key(conf: &PluginConf) -> String {
    let mut items: Vec<_> = conf.iter().collect();
    // sort by key
    items.sort_unstable_by_key(|(k, _)| *k);

    // pre-allocate capacity to reduce subsequent memory reallocation.
    let mut buf = String::with_capacity(256);
    for (i, (key, value)) in items.iter().enumerate() {
        if i > 0 {
            buf.push('\n');
        }
        // use write! macro to write the formatted string directly into the buffer, avoid format! to produce temporary String.
        // because writing to String will not fail, so it can be safely.
        let _ = write!(&mut buf, "{key}:{value}");
    }

    let hash = crc32fast::hash(buf.as_bytes());
    format!("{hash:X}")
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

pub use plugin::get_plugin_factory;
