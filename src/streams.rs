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
use parking_lot::RwLock;
use pingap_config::StreamConf;
use pingap_proxy::{Error, StreamProvider, StreamRuntime, access_log_sink_key};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

type StreamRuntimes = AHashMap<String, Arc<StreamRuntime>>;

struct Provider {
    streams: ArcSwap<StreamRuntimes>,
    configs: ArcSwap<HashMap<String, StreamConf>>,
    startup_sink_keys: RwLock<AHashMap<String, Option<String>>>,
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
        startup_sink_keys: RwLock::new(AHashMap::new()),
    })
});

pub fn new_stream_provider() -> Arc<dyn StreamProvider> {
    STREAM_PROVIDER.clone()
}

/// Records the access-log sink opened at startup for stream `name`, used later
/// during hot reloads to distinguish filter/format updates from sink changes
/// that require a process restart.
pub fn record_stream_startup_sink(name: &str, access_log: Option<&String>) {
    let sink_key = access_log_sink_key(access_log);
    STREAM_PROVIDER
        .startup_sink_keys
        .write()
        .insert(name.to_string(), sink_key);
}

/// Returns whether changing `old_access_log` to `new_access_log` on stream
/// `name` can be hot-reloaded in place without restarting the process.
pub fn can_hot_reload_stream_access_log(
    name: &str,
    old_access_log: Option<&String>,
    new_access_log: Option<&String>,
) -> bool {
    let new_sink_key = access_log_sink_key(new_access_log);
    if new_sink_key.is_none() {
        return true;
    }
    let old_sink_key = access_log_sink_key(old_access_log);
    if new_sink_key == old_sink_key {
        return true;
    }
    STREAM_PROVIDER
        .startup_sink_keys
        .read()
        .get(name)
        .is_some_and(|startup| *startup == new_sink_key)
}

pub fn try_init_streams(
    configs: &HashMap<String, StreamConf>,
) -> Result<Vec<String>, Error> {
    let current = STREAM_PROVIDER.streams.load();
    let prev_configs = STREAM_PROVIDER.configs.load();
    let startup_sinks = STREAM_PROVIDER.startup_sink_keys.read();
    let mut new_streams = AHashMap::new();
    let mut updated = Vec::new();
    for (name, conf) in configs.iter() {
        let new_sink_key = access_log_sink_key(conf.access_log.as_ref());
        if let Some(startup_sink_key) = startup_sinks.get(name.as_str())
            && new_sink_key.is_some()
            && new_sink_key != *startup_sink_key
        {
            return Err(Error::Common {
                category: "access_log".to_string(),
                message: format!(
                    "stream({name}) access_log sink changed and requires restart"
                ),
            });
        }
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
    drop(startup_sinks);
    STREAM_PROVIDER.store(new_streams, configs.clone());
    Ok(updated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_stream_access_log_sink_reload_gate() {
        let stream_name = format!("stream-sink-gate-{}", std::process::id());
        let dir = tempfile::tempdir().unwrap();
        let file_a = dir.path().join("a.log");
        let file_b = dir.path().join("b.log");
        let access_a =
            format!("{}?rolling=hourly&skip=^health$ tiny", file_a.display());
        let access_a_new = format!(
            "{}?rolling=hourly&min_latency=10ms json",
            file_a.display()
        );
        let access_b = format!("{}?rolling=hourly tiny", file_b.display());

        record_stream_startup_sink(&stream_name, Some(&access_a));
        assert_eq!(
            true,
            can_hot_reload_stream_access_log(
                &stream_name,
                Some(&access_a),
                Some(&access_a_new),
            )
        );
        assert_eq!(
            true,
            can_hot_reload_stream_access_log(
                &stream_name,
                Some(&access_a_new),
                Some(&"json".to_string()),
            )
        );
        assert_eq!(
            true,
            can_hot_reload_stream_access_log(
                &stream_name,
                Some(&"json".to_string()),
                Some(&access_a_new),
            )
        );
        assert_eq!(
            false,
            can_hot_reload_stream_access_log(
                &stream_name,
                Some(&access_a),
                Some(&access_b),
            )
        );

        let mut bad_configs = HashMap::new();
        bad_configs.insert(
            stream_name.clone(),
            StreamConf {
                addr: "127.0.0.1:0".to_string(),
                upstream: Some("u".to_string()),
                access_log: Some(access_b),
                ..Default::default()
            },
        );
        assert_eq!(true, try_init_streams(&bad_configs).is_err());

        STREAM_PROVIDER
            .startup_sink_keys
            .write()
            .remove(stream_name.as_str());
    }
}
