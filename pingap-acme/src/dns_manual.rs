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
use pingap_config::{Category, ConfigManager, StorageConf};
use std::sync::Arc;
use tracing::{error, info};

type Result<T, E = Error> = std::result::Result<T, E>;

/// The remark every manual TXT value is stored with; the token cleanup in
/// `lets_encrypt` removes these by age like the http-01 tokens.
pub(crate) static MANUAL_DNS_REMARK: &str =
    "dns txt value for acme challenge, it will be removed later auto";

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
        let conf = StorageConf {
            category: "config".to_string(),
            value: value.to_string(),
            secret: None,
            remark: Some(MANUAL_DNS_REMARK.to_string()),
            // Never deleted on completion; the age based cleanup keys off
            // this instead. Entries used to stay forever.
            created_at: Some(pingap_core::now_sec()),
        };
        if let Err(e) = self
            .config_manager
            .update(Category::Storage, &name, &conf)
            .await
        {
            error!(
                target: LOG_TARGET,
                error = %e,
                "save dns txt record fail"
            );
        };
        Ok(())
    }

    async fn done(&self) -> Result<()> {
        Ok(())
    }
}
