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
use pingap_config::StreamConf;
use pingap_proxy::{Error, StreamProvider, StreamRuntime};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

type StreamRuntimes = AHashMap<String, Arc<StreamRuntime>>;

struct Provider {
    streams: ArcSwap<StreamRuntimes>,
    configs: ArcSwap<HashMap<String, StreamConf>>,
}

impl Provider {
    fn store(
        &self,
        data: StreamRuntimes,
        configs: HashMap<String, StreamConf>,
    ) {
        self.streams.store(Arc::new(data));
        self.configs.store(Arc::new(configs));
    }
}

impl StreamProvider for Provider {
    fn get(&self, name: &str) -> Option<Arc<StreamRuntime>> {
        self.streams.load().get(name).cloned()
    }
}

static STREAM_PROVIDER: LazyLock<Arc<Provider>> = LazyLock::new(|| {
    Arc::new(Provider {
        streams: ArcSwap::from_pointee(AHashMap::new()),
        configs: ArcSwap::from_pointee(HashMap::new()),
    })
});

pub fn new_stream_provider() -> Arc<dyn StreamProvider> {
    STREAM_PROVIDER.clone()
}

pub fn try_init_streams(
    configs: &HashMap<String, StreamConf>,
) -> Result<Vec<String>, Error> {
    let current = STREAM_PROVIDER.streams.load();
    let prev_configs = STREAM_PROVIDER.configs.load();
    let mut new_streams = AHashMap::new();
    let mut updated = Vec::new();
    for (name, conf) in configs.iter() {
        if prev_configs.get(name) == Some(conf)
            && let Some(existing) = current.get(name.as_str())
        {
            new_streams.insert(name.to_string(), existing.clone());
            continue;
        }
        updated.push(name.clone());
        let runtime = StreamRuntime::try_from_conf(name, conf)?;
        new_streams.insert(name.to_string(), Arc::new(runtime));
    }
    STREAM_PROVIDER.store(new_streams, configs.clone());
    Ok(updated)
}
