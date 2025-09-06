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

use std::collections::HashMap;
use std::sync::Arc;

/// Location provider trait
pub trait LocationProvider: Send + Sync {
    /// Get a location by name
    ///
    /// # Arguments
    /// * `name` - The name of the location to get
    ///
    /// # Returns
    /// * `Option<Arc<Location>>` - The location if found, None otherwise
    fn get(&self, name: &str) -> Option<Arc<Location>>;
    /// Get the stats of the locations
    ///
    /// # Returns
    /// * `HashMap<String, LocationStats>` - The stats of the locations
    fn stats(&self) -> HashMap<String, LocationStats>;
}

mod location;

mod regex;

pub use location::*;
