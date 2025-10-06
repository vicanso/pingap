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
use std::collections::HashMap;
use std::sync::Arc;

mod hash_strategy;
mod peer_tracer;
mod upstream;

pub(crate) static LOG_TARGET: &str = "upstream";

pub type Upstreams = AHashMap<String, Arc<Upstream>>;

/// Upstream provider trait
pub trait UpstreamProvider: Send + Sync {
    /// Get an upstream by name
    ///
    /// # Arguments
    /// * `name` - The name of the upstream to get
    ///
    /// # Returns
    /// * `Option<Arc<Upstream>>` - The upstream if found, None otherwise
    fn get(&self, name: &str) -> Option<Arc<Upstream>>;
    /// Get the list of upstreams
    ///
    /// # Returns
    /// * `Vec<(String, Arc<Upstream>)>` - The list of upstreams
    fn list(&self) -> Vec<(String, Arc<Upstream>)>;

    /// Get the healthy status of all upstreams
    ///
    /// # Returns
    /// * `HashMap<String, UpstreamHealthyStatus>` - Healthy status of all upstreams
    ///
    /// This function iterates through all upstreams and checks their health status.
    fn healthy_status(&self) -> HashMap<String, UpstreamHealthyStatus> {
        let mut healthy_status = HashMap::new();
        self.list().iter().for_each(|(k, v)| {
            let mut total = 0;
            let mut healthy = 0;
            let mut unhealthy_backends = vec![];
            if let Some(backends) = v.get_backends() {
                let backend_set = backends.get_backend();
                total = backend_set.len();
                backend_set.iter().for_each(|backend| {
                    if backends.ready(backend) {
                        healthy += 1;
                    } else {
                        unhealthy_backends.push(backend.to_string());
                    }
                });
            }
            healthy_status.insert(
                k.to_string(),
                UpstreamHealthyStatus {
                    healthy,
                    total: total as u32,
                    unhealthy_backends,
                },
            );
        });
        healthy_status
    }

    /// Get the processing and connected status of all upstreams
    ///
    /// # Returns
    /// * `HashMap<String, (i32, Option<i32>)>` - Processing and connected status of all upstreams
    fn processing_connected(&self) -> HashMap<String, (i32, Option<i32>)> {
        let mut processing_connected = HashMap::new();
        self.list().iter().for_each(|(k, v)| {
            let count = v.processing();
            let connected = v.connected();
            processing_connected.insert(k.to_string(), (count, connected));
        });
        processing_connected
    }
}

pub use hash_strategy::HashStrategy;
pub use upstream::*;
