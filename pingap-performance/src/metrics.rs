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

use super::{get_process_system_info, get_processing_accepted, LOG_CATEGORY};
use async_trait::async_trait;
use pingap_cache::{get_cache_backend, is_cache_backend_init};
use pingap_core::{BackgroundTask, Error};
use pingap_location::get_locations_stats;
use pingap_upstream::{
    get_upstream_healthy_status, get_upstreams_processing_connected,
};
use tracing::info;

struct PerformanceMetricsLogTask {}

#[async_trait]
impl BackgroundTask for PerformanceMetricsLogTask {
    async fn execute(&self, _count: u32) -> Result<bool, Error> {
        // Get cache statistics (reading/writing counts)
        let mut cache_reading: i64 = -1;
        let mut cache_writing: i64 = -1;
        // if cache backend not initialized, do not get cache statistics
        if is_cache_backend_init() {
            // the cache backend is initialized once,
            // we can use the default option
            if let Ok(cache) = get_cache_backend(None) {
                if let Some(stats) = cache.stats() {
                    cache_reading = stats.reading as i64;
                    cache_writing = stats.writing as i64;
                }
            }
        }

        // Collect active location processing counts
        // Format: "location1:count1, location2:count2, ..."
        let locations_stats = get_locations_stats()
            .into_iter()
            .filter(|(_, (processing, _))| *processing != 0)
            .map(|(name, (processing, accepted))| {
                format!("{name}:{processing}/{accepted}")
            })
            .collect::<Vec<String>>()
            .join(", ");
        let locations_stats = if locations_stats.is_empty() {
            None
        } else {
            Some(locations_stats)
        };

        // Collect upstream processing and connection counts
        let mut upstreams_processing = vec![];
        let mut upstreams_connected = vec![];
        for (name, (processing, connected)) in
            get_upstreams_processing_connected()
        {
            // Track non-zero processing counts
            if processing != 0 {
                upstreams_processing.push(format!("{name}:{processing}"));
            }
            // Track non-zero connection counts
            if let Some(connected) = connected {
                if connected != 0 {
                    upstreams_connected.push(format!("{name}:{connected}"));
                }
            }
        }
        let upstreams_processing = if upstreams_processing.is_empty() {
            None
        } else {
            Some(upstreams_processing.join(", "))
        };
        let upstreams_connected = if upstreams_connected.is_empty() {
            None
        } else {
            Some(upstreams_connected.join(", "))
        };

        // Get system metrics and request processing stats
        let system_info = get_process_system_info();
        let (processing, accepted) = get_processing_accepted();
        let upstreams_healthy_status = get_upstream_healthy_status()
            .iter()
            .map(|(name, status)| {
                format!("{name}:{}/{}", status.healthy, status.total)
            })
            .collect::<Vec<String>>()
            .join(", ");

        // Log all metrics using the tracing framework
        info!(
            category = LOG_CATEGORY,
            threads = system_info.threads, // Number of threads
            locations_stats,               // Active location requests
            upstreams_healthy_status,      // Upstream healthy status
            upstreams_processing,          // Active upstream requests
            upstreams_connected,           // Active upstream connections
            accepted,                      // Total accepted requests
            processing,                    // Currently processing requests
            used_memory = system_info.memory, // Memory usage
            fd_count = system_info.fd_count, // File descriptor count
            tcp_count = system_info.tcp_count, // IPv4 TCP connection count
            tcp6_count = system_info.tcp6_count, // IPv6 TCP connection count
            cache_reading,                 // Active cache reads
            cache_writing,                 // Active cache writes
        );
        Ok(true)
    }
}

/// Creates a new service that periodically logs performance metrics
/// Returns a tuple of (service name, service task)
pub fn new_performance_metrics_log_service() -> Box<dyn BackgroundTask> {
    Box::new(PerformanceMetricsLogTask {})
}
