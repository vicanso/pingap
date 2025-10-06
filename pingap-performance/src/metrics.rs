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

use super::{get_process_system_info, get_processing_accepted, LOG_TARGET};
use async_trait::async_trait;
use pingap_core::{BackgroundTask, Error};
use pingap_location::LocationProvider;
use pingap_upstream::UpstreamProvider;
use std::sync::Arc;
use tracing::info;

struct PerformanceMetricsLogTask {
    location_provider: Arc<dyn LocationProvider>,
    upstream_provider: Arc<dyn UpstreamProvider>,
}

/// Joins a vector of strings into a single string separated by ", ".
/// Returns `None` if the input vector is empty.
fn join_non_empty(items: Vec<String>) -> Option<String> {
    if items.is_empty() {
        None
    } else {
        Some(items.join(", "))
    }
}

#[async_trait]
impl BackgroundTask for PerformanceMetricsLogTask {
    async fn execute(&self, _count: u32) -> Result<bool, Error> {
        // Collect active location processing counts
        // Format: "location1:count1, location2:count2, ..."
        let locations_stats_vec = self
            .location_provider
            .stats()
            .into_iter()
            .filter(|(_, stats)| stats.processing != 0)
            .map(|(name, stats)| {
                format!("{name}:{}/{}", stats.processing, stats.accepted)
            })
            .collect::<Vec<_>>();
        let locations_stats = join_non_empty(locations_stats_vec);

        // Collect upstream processing and connection counts

        let (processing_vec, connected_vec) = self
            .upstream_provider
            .clone()
            .processing_connected()
            .into_iter()
            .fold(
                (Vec::new(), Vec::new()), // 初始值：一个包含两个空 Vec 的元组
                |mut acc, (name, (processing, connected))| {
                    if processing != 0 {
                        acc.0.push(format!("{name}:{processing}"));
                    }
                    if let Some(conn) = connected.filter(|&c| c != 0) {
                        acc.1.push(format!("{name}:{conn}"));
                    }
                    acc
                },
            );

        let upstreams_processing = join_non_empty(processing_vec);
        let upstreams_connected = join_non_empty(connected_vec);

        // Get system metrics and request processing stats
        let system_info = get_process_system_info();
        let (processing, accepted) = get_processing_accepted();
        let upstreams_healthy_status = self
            .upstream_provider
            .healthy_status()
            .iter()
            .map(|(name, status)| {
                format!("{name}:{}/{}", status.healthy, status.total)
            })
            .collect::<Vec<String>>()
            .join(", ");

        // Log all metrics using the tracing framework
        info!(
            target: LOG_TARGET,
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
        );
        Ok(true)
    }
}

/// Creates a new service that periodically logs performance metrics
/// Returns a tuple of (service name, service task)
pub fn new_performance_metrics_log_service(
    location_provider: Arc<dyn LocationProvider>,
    upstream_provider: Arc<dyn UpstreamProvider>,
) -> Box<dyn BackgroundTask> {
    Box::new(PerformanceMetricsLogTask {
        location_provider,
        upstream_provider,
    })
}
