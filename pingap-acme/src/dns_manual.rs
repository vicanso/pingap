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

#[cfg(test)]
mod tests {
    use super::{AcmeDnsTask, MANUAL_DNS_REMARK, ManualDnsTask};
    use pingap_config::{
        Category, StorageConf, new_file_config_manager,
        new_memory_config_manager,
    };
    use pretty_assertions::assert_eq;
    use std::sync::Arc;

    async fn stored(
        manager: &pingap_config::ConfigManager,
    ) -> Vec<StorageConf> {
        let doc = match manager.load_all().await {
            Ok(doc) => doc,
            Err(err) => panic!("load: {err}"),
        };
        let Some(storages) = doc.storages else {
            return Vec::new();
        };
        let mut found = Vec::new();
        for name in storages.keys() {
            let conf =
                match manager.get::<StorageConf>(Category::Storage, name).await
                {
                    Ok(Some(conf)) => conf,
                    Ok(None) => panic!("{name} was listed and not stored"),
                    Err(err) => panic!("get {name}: {err}"),
                };
            found.push(conf);
        }
        found
    }

    /// The value is kept for the age-based cleanup, under the remark that
    /// cleanup looks for. `done` does not remove it.
    #[tokio::test]
    async fn test_manual_dns_stores_the_value() {
        let manager = new_memory_config_manager("#\n", None);
        let task = ManualDnsTask::new(Arc::new(manager));
        match task
            .add_txt_record("_acme-challenge.example.com", "one")
            .await
        {
            Ok(()) => {},
            Err(err) => panic!("{err}"),
        }
        match task
            .add_txt_record("_acme-challenge.example.com", "two")
            .await
        {
            Ok(()) => {},
            Err(err) => panic!("{err}"),
        }
        match task.done().await {
            Ok(()) => {},
            Err(err) => panic!("done: {err}"),
        }
        let mut values = stored(&task.config_manager).await;
        values.sort_by(|left, right| left.value.cmp(&right.value));
        assert_eq!(2, values.len());
        let now = pingap_core::now_sec();
        for (conf, value) in values.iter().zip(["one", "two"]) {
            assert_eq!("config", conf.category);
            assert_eq!(value, conf.value);
            assert_eq!(None, conf.secret);
            assert_eq!(Some(MANUAL_DNS_REMARK.to_string()), conf.remark);
            let created = conf.created_at.unwrap_or_else(|| {
                panic!("created_at was not stored for {value}")
            });
            assert_eq!(true, created + 5 >= now && created <= now + 5);
        }
    }

    /// A storage that cannot be read is logged and then treated as
    /// success. The challenge still goes on, and nothing was written.
    #[tokio::test]
    async fn test_manual_dns_ignores_a_storage_error() {
        let file = match tempfile::NamedTempFile::new() {
            Ok(file) => file,
            Err(err) => panic!("{err}"),
        };
        match std::fs::write(file.path(), b"not = [toml") {
            Ok(()) => {},
            Err(err) => panic!("{err}"),
        }
        let path = file.path().to_string_lossy().to_string();
        let manager = match new_file_config_manager(&path) {
            Ok(manager) => manager,
            Err(err) => panic!("{err}"),
        };
        let task = ManualDnsTask::new(Arc::new(manager));
        match task
            .add_txt_record("_acme-challenge.example.com", "one")
            .await
        {
            Ok(()) => {},
            Err(err) => panic!("a storage error was returned: {err}"),
        }
        let left = match std::fs::read(file.path()) {
            Ok(left) => left,
            Err(err) => panic!("{err}"),
        };
        assert_eq!(b"not = [toml".to_vec(), left);
    }
}
