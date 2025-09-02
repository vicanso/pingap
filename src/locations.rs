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
use pingap_config::Error;
use pingap_config::LocationConf;
use pingap_location::{Location, LocationProvider, LocationStats};
use std::collections::HashMap;
use std::sync::Arc;

type LocationsMap = AHashMap<String, Arc<Location>>;
static LOCATION_MAP: Lazy<ArcSwap<LocationsMap>> =
    Lazy::new(|| ArcSwap::from_pointee(AHashMap::new()));

type Result<T> = std::result::Result<T, Error>;

/// Gets a map of current request processing and accepted counts for all locations.
///
/// # Returns
/// * `HashMap<String, (i32, u64)>` - Map of location names to their current processing and accepted counts
pub fn get_locations_stats() -> HashMap<String, LocationStats> {
    let mut stats = HashMap::new();
    LOCATION_MAP.load().iter().for_each(|(k, v)| {
        stats.insert(k.to_string(), v.stats());
    });
    stats
}

/// Initializes or updates the global location configurations
/// Returns list of location names that were updated
pub fn try_init_locations(
    location_configs: &HashMap<String, LocationConf>,
) -> Result<Vec<String>> {
    let mut locations = AHashMap::new();
    let mut updated_locations = vec![];
    for (name, conf) in location_configs.iter() {
        if let Some(found) = get_location(name) {
            if found.key == conf.hash_key() {
                locations.insert(name.to_string(), found);
                continue;
            }
        }
        updated_locations.push(name.clone());
        let lo = Location::new(name, conf).map_err(|e| Error::Invalid {
            message: e.to_string(),
        })?;
        locations.insert(name.to_string(), Arc::new(lo));
    }
    LOCATION_MAP.store(Arc::new(locations));
    Ok(updated_locations)
}

/// Gets a location configuration by name from the global location map.
///
/// # Arguments
/// * `name` - Name of the location to retrieve
///
/// # Returns
/// * `Option<Arc<Location>>` - The location if found, None otherwise
pub fn get_location(name: &str) -> Option<Arc<Location>> {
    if name.is_empty() {
        return None;
    }
    LOCATION_MAP.load().get(name).cloned()
}

struct Provider {}

impl LocationProvider for Provider {
    fn load(&self, name: &str) -> Option<Arc<Location>> {
        get_location(name)
    }
    fn stats(&self) -> HashMap<String, LocationStats> {
        get_locations_stats()
    }
}

pub fn new_locations() -> Arc<dyn LocationProvider> {
    Arc::new(Provider {})
}
