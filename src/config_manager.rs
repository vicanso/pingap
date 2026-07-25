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

use pingap_config::ConfigManager;
use pingap_config::{Error, new_config_manager, new_memory_config_manager};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::OnceLock;

type Result<T> = std::result::Result<T, Error>;

static CONFIG_MANAGER: OnceLock<Result<Arc<ConfigManager>>> = OnceLock::new();

fn try_init<F>(new_manager: F) -> Result<Arc<ConfigManager>>
where
    F: FnOnce() -> Result<ConfigManager>,
{
    let result_ref = CONFIG_MANAGER.get_or_init(|| {
        new_manager().map(Arc::new).map_err(|e| Error::Invalid {
            message: e.to_string(),
        })
    });
    result_ref
        .as_ref()
        .map(|arc_cm| arc_cm.clone())
        .map_err(|e| Error::Invalid {
            message: e.to_string(),
        })
}

pub fn try_init_config_manager(value: &str) -> Result<Arc<ConfigManager>> {
    try_init(|| new_config_manager(value))
}

/// Initializes the config manager from a config that is already in memory,
/// used by the command line proxy (`--upstream`) where there is no file or
/// etcd backing store to read from. `path` receives the acme state so an issued
/// certificate is not thrown away on restart.
pub fn try_init_memory_config_manager(
    data: &str,
    path: Option<PathBuf>,
) -> Result<Arc<ConfigManager>> {
    try_init(move || Ok(new_memory_config_manager(data, path)))
}

pub fn get_config_manager() -> Result<Arc<ConfigManager>> {
    CONFIG_MANAGER
        .get()
        .ok_or_else(|| Error::Invalid {
            message: "config manager not initialized".to_string(),
        })
        .and_then(|result_ref| {
            result_ref
                .as_ref()
                .map(|arc_cm| arc_cm.clone())
                .map_err(|e| Error::Invalid {
                    message: e.to_string(),
                })
        })
}
