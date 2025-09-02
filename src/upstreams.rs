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

use ahash::AHashMap;
use arc_swap::ArcSwap;
use once_cell::sync::Lazy;
use pingap_config::UpstreamConf;
use pingap_core::{Error, NotificationSender};
use pingap_upstream::{Upstream, UpstreamProvider, Upstreams};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::error;

type Result<T, E = Error> = std::result::Result<T, E>;

static UPSTREAM_MAP: Lazy<ArcSwap<Upstreams>> =
    Lazy::new(|| ArcSwap::from_pointee(AHashMap::new()));

fn new_ahash_upstreams(
    upstream_configs: &HashMap<String, UpstreamConf>,
    sender: Option<Arc<NotificationSender>>,
) -> Result<(Upstreams, Vec<String>)> {
    let mut upstreams = AHashMap::new();
    let mut updated_upstreams = vec![];
    for (name, conf) in upstream_configs.iter() {
        let key = conf.hash_key();
        if let Some(found) = UPSTREAM_MAP.load().get(name).cloned() {
            // not modified
            if found.key == key {
                upstreams.insert(name.to_string(), found);
                continue;
            }
        }
        let up = Arc::new(Upstream::new(name, conf, sender.clone()).map_err(
            |e| Error::Invalid {
                message: e.to_string(),
            },
        )?);
        upstreams.insert(name.to_string(), up);
        updated_upstreams.push(name.to_string());
    }
    Ok((upstreams, updated_upstreams))
}

/// Initialize the upstreams
///
/// # Arguments
/// * `upstream_configs` - The upstream configurations
/// * `sender` - The notification sender
///
/// # Returns
pub fn try_init_upstreams(
    upstream_configs: &HashMap<String, UpstreamConf>,
    sender: Option<Arc<NotificationSender>>,
) -> Result<()> {
    let (upstreams, _) = new_ahash_upstreams(upstream_configs, sender)?;
    UPSTREAM_MAP.store(Arc::new(upstreams));
    Ok(())
}

pub async fn try_update_upstreams(
    upstream_configs: &HashMap<String, UpstreamConf>,
    sender: Option<Arc<NotificationSender>>,
) -> Result<Vec<String>> {
    let (upstreams, updated_upstreams) =
        new_ahash_upstreams(upstream_configs, sender)?;
    for (name, up) in upstreams.iter() {
        // no need to run health check if not new upstream
        if !updated_upstreams.contains(name) {
            continue;
        }
        // run health check before switch to new upstream
        if let Err(e) = up.run_health_check().await {
            error!(
                category = "upstream",
                error = %e,
                upstream = name,
                "update upstream health check fail"
            );
        }
    }
    UPSTREAM_MAP.store(Arc::new(upstreams));
    Ok(updated_upstreams)
}

struct Provider {}
impl UpstreamProvider for Provider {
    fn load(&self, name: &str) -> Option<Arc<Upstream>> {
        UPSTREAM_MAP.load().get(name).cloned()
    }

    fn list(&self) -> Vec<(String, Arc<Upstream>)> {
        UPSTREAM_MAP
            .load()
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }
}

pub fn new_upstreams() -> Arc<dyn UpstreamProvider> {
    Arc::new(Provider {})
}
