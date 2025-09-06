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
use pingap_location::{Location, LocationProvider, LocationStats, Locations};
use std::collections::HashMap;
use std::sync::Arc;

type Result<T> = std::result::Result<T, Error>;

struct Provider {
    locations: ArcSwap<Locations>,
}

impl Provider {
    fn store(&self, data: Locations) {
        self.locations.store(Arc::new(data));
    }
}

impl LocationProvider for Provider {
    fn get(&self, name: &str) -> Option<Arc<Location>> {
        if name.is_empty() {
            return None;
        }
        self.locations.load().get(name).cloned()
    }
    fn stats(&self) -> HashMap<String, LocationStats> {
        let mut stats = HashMap::new();
        self.locations.load().iter().for_each(|(k, v)| {
            stats.insert(k.to_string(), v.stats());
        });
        stats
    }
}

static LOCATION_PROVIDER: Lazy<Arc<Provider>> = Lazy::new(|| {
    Arc::new(Provider {
        locations: ArcSwap::from_pointee(AHashMap::new()),
    })
});
pub fn new_location_provider() -> Arc<dyn LocationProvider> {
    LOCATION_PROVIDER.clone()
}

/// Initializes or updates the global location configurations
/// Returns list of location names that were updated
pub fn try_init_locations(
    location_configs: &HashMap<String, LocationConf>,
) -> Result<Vec<String>> {
    let mut locations = AHashMap::new();
    let mut updated_locations = vec![];
    for (name, conf) in location_configs.iter() {
        if let Some(found) = LOCATION_PROVIDER.get(name) {
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
    LOCATION_PROVIDER.store(locations);
    Ok(updated_locations)
}
