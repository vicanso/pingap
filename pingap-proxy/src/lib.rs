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

mod headers;
mod server;
mod server_conf;
#[cfg(feature = "tracing")]
mod tracing;
static LOG_CATEGORY: &str = "proxy";

pub(crate) use headers::*;
pub use server::*;
pub use server_conf::*;
#[allow(unused_imports)]
#[cfg(feature = "tracing")]
pub(crate) use tracing::*;

pub trait ServerLocationsProvider: Send + Sync {
    /// Get the locations of the server
    ///
    /// # Arguments
    /// * `name` - The name of the server to get
    ///
    /// # Returns
    /// * `Option<Arc<Vec<String>>>` - The locations of the server if found, None otherwise
    fn get(&self, name: &str) -> Option<Arc<Vec<String>>>;
}
pub type ServerLocations = AHashMap<String, Arc<Vec<String>>>;
