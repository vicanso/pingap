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

use std::sync::Arc;

mod hash_strategy;
mod peer_tracer;
mod upstream;

pub(crate) const LOG_CATEGORY: &str = "upstream";

pub trait UpstreamProvider: Send + Sync {
    fn load(&self, name: &str) -> Option<Arc<Upstream>>;
    fn list(&self) -> Vec<(String, Arc<Upstream>)>;
}

pub use upstream::*;
