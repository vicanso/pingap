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
use std::sync::Arc;

mod hash_strategy;
mod peer_tracer;
mod upstream;

pub(crate) const LOG_CATEGORY: &str = "upstream";

pub type Upstreams = AHashMap<String, Arc<Upstream>>;

/// Upstream provider trait
pub trait UpstreamProvider: Send + Sync {
    /// Load an upstream by name
    ///
    /// # Arguments
    /// * `name` - The name of the upstream to load
    ///
    /// # Returns
    /// * `Option<Arc<Upstream>>` - The upstream if found, None otherwise
    fn load(&self, name: &str) -> Option<Arc<Upstream>>;
    /// Get the list of upstreams
    ///
    /// # Returns
    /// * `Vec<(String, Arc<Upstream>)>` - The list of upstreams
    fn list(&self) -> Vec<(String, Arc<Upstream>)>;
}

pub use hash_strategy::HashStrategy;
pub use upstream::*;
