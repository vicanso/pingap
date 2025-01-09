// Copyright 2025 Tree xie.
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

use crate::cache::get_cache_backend;
use crate::proxy::{
    get_locations_processing, get_upstreams_processing_connected,
};
use crate::service::SimpleServiceTaskFuture;
use crate::state::{get_process_system_info, get_processing_accepted};
use tracing::info;

static PERFORMANCE_METRICS_LOG_SERVICE: &str = "performanceMetricsLog";

pub fn new_performance_metrics_log_service() -> (String, SimpleServiceTaskFuture)
{
    let task: SimpleServiceTaskFuture = Box::new(move |_count: u32| {
        Box::pin({
            async move {
                let mut cache_reading: i64 = -1;
                let mut cache_writing: i64 = -1;
                if let Ok(cache) = get_cache_backend() {
                    if let Some(stats) = cache.stats() {
                        cache_reading = stats.reading as i64;
                        cache_writing = stats.writing as i64;
                    }
                }
                let locations_processing = get_locations_processing()
                    .into_iter()
                    .filter(|(_, count)| *count != 0)
                    .map(|(name, count)| format!("{name}:{count}"))
                    .collect::<Vec<String>>()
                    .join(", ");
                let mut upstreams_processing = vec![];
                let mut upstreams_connected = vec![];
                for (name, (processing, connected)) in
                    get_upstreams_processing_connected()
                {
                    if processing != 0 {
                        upstreams_processing
                            .push(format!("{name}:{processing}"));
                    }
                    if let Some(connected) = connected {
                        if connected != 0 {
                            upstreams_connected
                                .push(format!("{name}:{connected}"));
                        }
                    }
                }

                let system_info = get_process_system_info();
                let (processing, accepted) = get_processing_accepted();
                info!(
                    category = PERFORMANCE_METRICS_LOG_SERVICE,
                    threads = system_info.threads,
                    locations_processing,
                    upstreams_processing = upstreams_processing.join(", "),
                    upstreams_connected = upstreams_connected.join(", "),
                    accepted,
                    processing,
                    used_memory = system_info.memory,
                    fd_count = system_info.fd_count,
                    tcp_count = system_info.tcp_count,
                    tcp6_count = system_info.tcp6_count,
                    cache_reading,
                    cache_writing,
                    "performance metrics"
                );
                Ok(true)
            }
        })
    });
    (PERFORMANCE_METRICS_LOG_SERVICE.to_string(), task)
}
