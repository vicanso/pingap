// Copyright 2024 Tree xie.
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

use once_cell::sync::OnceCell;

mod load;

pub use load::{
    load_config, save_config, LocationConf, PingapConf, ServerConf, UpstreamConf,
    CATEGORY_LOCATION, CATEGORY_SERVER, CATEGORY_UPSTREAM,
};

static CONFIG_PATH: OnceCell<String> = OnceCell::new();
pub fn set_config_path(conf_path: &str) {
    CONFIG_PATH.get_or_init(|| conf_path.to_string());
}

pub fn get_config_path() -> String {
    CONFIG_PATH.get_or_init(|| "".to_string()).to_owned()
}

static CONFIG_HASH: OnceCell<String> = OnceCell::new();
/// Sets pingap running config's crc hash
pub fn set_config_hash(version: &str) {
    CONFIG_HASH.get_or_init(|| version.to_string());
}

/// Returns current running pingap's config crc hash
pub fn get_config_hash() -> String {
    if let Some(value) = CONFIG_HASH.get() {
        value.to_string()
    } else {
        "".to_string()
    }
}
