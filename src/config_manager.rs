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
use pingap_config::{new_config_manager, Error};
use std::sync::Arc;
use std::sync::OnceLock;

type Result<T> = std::result::Result<T, Error>;

static CONFIG_MANAGER: OnceLock<Result<Arc<ConfigManager>>> = OnceLock::new();

pub fn try_init_config_manager(value: &str) -> Result<Arc<ConfigManager>> {
    let result_ref = CONFIG_MANAGER.get_or_init(|| {
        new_config_manager(value)
            .map(Arc::new)
            .map_err(|e| Error::Invalid {
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
