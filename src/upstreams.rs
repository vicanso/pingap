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
use pingap_config::UpstreamConf;
use pingap_core::{Error, NotificationSender};
use pingap_upstream::{
    Upstream, UpstreamProvider, Upstreams, new_ahash_upstreams,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::LazyLock;
use tracing::error;

static LOG_TARGET: &str = "main::upstreams";

type Result<T, E = Error> = std::result::Result<T, E>;

struct Provider {
    upstreams: ArcSwap<Upstreams>,
}

impl Provider {
    fn store(&self, data: Upstreams) {
        self.upstreams.store(Arc::new(data));
    }
}

impl UpstreamProvider for Provider {
    fn get(&self, name: &str) -> Option<Arc<Upstream>> {
        self.upstreams.load().get(name).cloned()
    }

    fn list(&self) -> Vec<(String, Arc<Upstream>)> {
        self.upstreams
            .load()
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }
}

static UPSTREAM_PROVIDER: LazyLock<Arc<Provider>> = LazyLock::new(|| {
    Arc::new(Provider {
        upstreams: ArcSwap::from_pointee(AHashMap::new()),
    })
});

pub fn new_upstream_provider() -> Arc<dyn UpstreamProvider> {
    UPSTREAM_PROVIDER.clone()
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
    let (upstreams, _) = new_ahash_upstreams(
        upstream_configs,
        UPSTREAM_PROVIDER.clone(),
        sender,
    )
    .map_err(|e| Error::Invalid {
        message: e.to_string(),
    })?;

    UPSTREAM_PROVIDER.store(upstreams);
    Ok(())
}

/// Brings the upstreams up to date with `upstream_configs`. The ones it no
/// longer has are kept for now, see [`remove_unconfigured_upstreams`].
pub async fn try_update_upstreams(
    upstream_configs: &HashMap<String, UpstreamConf>,
    sender: Option<Arc<NotificationSender>>,
) -> Result<Vec<String>> {
    let (mut upstreams, updated_upstreams) = new_ahash_upstreams(
        upstream_configs,
        UPSTREAM_PROVIDER.clone(),
        sender,
    )
    .map_err(|e| Error::Invalid {
        message: e.to_string(),
    })?;
    for (name, up) in upstreams.iter() {
        // no need to run health check if not new upstream
        if !updated_upstreams.contains(name) {
            continue;
        }
        // run health check before switch to new upstream
        if let Err(e) = up.run_health_check().await {
            error!(
                target: LOG_TARGET,
                error = %e,
                upstream = name,
                "update upstream health check fail"
            );
        }
    }
    for (name, upstream) in UPSTREAM_PROVIDER.list() {
        upstreams.entry(name).or_insert(upstream);
    }
    UPSTREAM_PROVIDER.store(upstreams);
    Ok(updated_upstreams)
}

/// Drops the upstreams that `upstream_configs` no longer has, the second
/// half of an upstream reload.
///
/// A change that takes an upstream away takes it away from the locations
/// too, and those are replaced after the upstreams. Removed at once, the
/// upstream was gone while the locations still in place went on routing
/// to it, and their requests failed until the reload had got to them.
pub fn remove_unconfigured_upstreams(
    upstream_configs: &HashMap<String, UpstreamConf>,
) {
    let current = UPSTREAM_PROVIDER.upstreams.load();
    if current
        .keys()
        .all(|name| upstream_configs.contains_key(name))
    {
        return;
    }
    let upstreams: Upstreams = current
        .iter()
        .filter(|(name, _)| upstream_configs.contains_key(*name))
        .map(|(name, upstream)| (name.clone(), upstream.clone()))
        .collect();
    UPSTREAM_PROVIDER.store(upstreams);
}
