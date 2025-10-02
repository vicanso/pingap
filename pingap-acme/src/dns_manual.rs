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

use super::{AcmeDnsTask, Error, LOG_TARGET};
use async_trait::async_trait;
use nanoid::nanoid;
use pingap_config::{Category, ConfigManager};
use serde_json::json;
use std::sync::Arc;
use tracing::{error, info};

type Result<T, E = Error> = std::result::Result<T, E>;

pub(crate) struct ManualDnsTask {
    config_manager: Arc<ConfigManager>,
}

impl ManualDnsTask {
    pub fn new(config_manager: Arc<ConfigManager>) -> Self {
        Self { config_manager }
    }
}

#[async_trait]
impl AcmeDnsTask for ManualDnsTask {
    async fn add_txt_record(&self, domain: &str, value: &str) -> Result<()> {
        info!(
            target: LOG_TARGET,
            "set the DNS record {domain} IN TXT {value}",
        );
        let name = nanoid!(8);
        // let key = format!("storages/{name}.toml");
        let data = json!({
            "category": "config",
            "secret": "",
            "value": value,
            "remark": "dns text value for acme challenge, it will be removed later auto"
        });
        if let Err(e) = self
            .config_manager
            .update(Category::Storage, &name, &data)
            .await
        {
            error!(error = e.to_string(), "save dns txt record fail");
        };
        Ok(())
    }

    async fn done(&self) -> Result<()> {
        Ok(())
    }
}
