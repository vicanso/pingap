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
use pingap_core::Error;
use pingap_proxy::{ServerLocations, ServerLocationsProvider};
use std::collections::HashMap;
use std::sync::Arc;

type Result<T> = std::result::Result<T, Error>;

struct Provider {
    server_locations: ArcSwap<ServerLocations>,
}

impl Provider {
    fn store(&self, data: ServerLocations) {
        self.server_locations.store(Arc::new(data));
    }
}

impl ServerLocationsProvider for Provider {
    fn get(&self, name: &str) -> Option<Arc<Vec<String>>> {
        self.server_locations.load().get(name).cloned()
    }
}

static SERVER_LOCATIONS_PROVIDER: Lazy<Arc<Provider>> = Lazy::new(|| {
    Arc::new(Provider {
        server_locations: ArcSwap::from_pointee(AHashMap::new()),
    })
});

/// Creates a new instance of the server locations provider
///
/// # Returns
/// * `Arc<dyn ServerLocationsProvider>` - The server locations provider
pub fn new_server_locations_provider() -> Arc<dyn ServerLocationsProvider> {
    SERVER_LOCATIONS_PROVIDER.clone()
}

pub fn try_init_server_locations(
    servers: &HashMap<String, pingap_config::ServerConf>,
    locations: &HashMap<String, pingap_config::LocationConf>,
) -> Result<Vec<String>> {
    // get the location weight
    let mut location_weights = HashMap::new();
    for (name, item) in locations.iter() {
        location_weights.insert(name.to_string(), item.get_weight());
    }
    let mut server_locations = AHashMap::new();
    let mut updated_servers = vec![];
    for (name, server) in servers.iter() {
        if let Some(items) = &server.locations {
            let mut items = items.clone();
            // sort the location by weight
            items.sort_by_key(|item| {
                let weight = location_weights
                    .get(item.as_str())
                    .map(|value| value.to_owned())
                    .unwrap_or_default();
                std::cmp::Reverse(weight)
            });
            let mut not_modified = false;
            if let Some(current_locations) = SERVER_LOCATIONS_PROVIDER.get(name)
            {
                if current_locations.join(",") == items.join(",") {
                    not_modified = true;
                }
            }
            if !not_modified {
                updated_servers.push(name.to_string());
            }

            server_locations.insert(name.to_string(), Arc::new(items));
        }
    }
    SERVER_LOCATIONS_PROVIDER.store(server_locations);
    Ok(updated_servers)
}
