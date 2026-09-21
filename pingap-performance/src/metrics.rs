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

use super::{LOG_TARGET, get_process_system_info, get_processing_accepted};
use async_trait::async_trait;
use pingap_core::{BackgroundTask, Error};
use pingap_location::LocationProvider;
use pingap_upstream::{UpstreamProvider, UpstreamStats};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::info;

struct PerformanceMetricsLogTask {
    location_provider: Arc<dyn LocationProvider>,
    upstream_provider: Arc<dyn UpstreamProvider>,
}

/// Joins into one `", "` separated string, sorted so the order does not
/// change from one minute to the next (the sources are hash maps).
/// `None` when there is nothing to report, which leaves the field out of
/// the log line entirely.
fn join_non_empty(mut items: Vec<String>) -> Option<String> {
    if items.is_empty() {
        return None;
    }
    items.sort();
    Some(items.join(", "))
}

/// A compact per-upstream summary: `name:processing[/connected]`, plus any
/// backend whose circuit breaker is not closed.
///
/// The whole `UpstreamStats` map used to be `Debug`-formatted into the log
/// line, which with a few upstreams and their backends made one very long
/// entry every minute. Upstreams with nothing in flight and no tripped
/// breaker are left out, the same way idle locations are.
fn format_upstream_stats(
    stats: &HashMap<String, UpstreamStats>,
) -> Option<String> {
    join_non_empty(
        stats
            .iter()
            .filter_map(|(name, stat)| {
                let mut tripped: Vec<&str> = stat
                    .circuit_states
                    .iter()
                    .filter(|(_, state)| **state != 0)
                    .map(|(addr, _)| addr.as_str())
                    .collect();
                if stat.processing == 0 && tripped.is_empty() {
                    return None;
                }
                let mut item = format!("{name}:{}", stat.processing);
                if let Some(connected) = stat.connected {
                    item.push('/');
                    item.push_str(&connected.to_string());
                }
                if !tripped.is_empty() {
                    tripped.sort();
                    item.push_str(&format!(
                        "(circuit open: {})",
                        tripped.join(" ")
                    ));
                }
                Some(item)
            })
            .collect(),
    )
}

#[async_trait]
impl BackgroundTask for PerformanceMetricsLogTask {
    async fn execute(&self, _count: u32) -> Result<bool, Error> {
        // Collect active location processing counts
        // Format: "location1:count1, location2:count2, ..."
        let locations_stats = join_non_empty(
            self.location_provider
                .stats()
                .into_iter()
                .filter(|(_, stats)| stats.processing != 0)
                .map(|(name, stats)| {
                    format!("{name}:{}/{}", stats.processing, stats.accepted)
                })
                .collect(),
        );

        let upstream_stats =
            format_upstream_stats(&self.upstream_provider.get_all_stats());

        // Get system metrics and request processing stats
        let system_info = get_process_system_info();
        let (processing, accepted) = get_processing_accepted();
        let upstreams_healthy_status = join_non_empty(
            self.upstream_provider
                .healthy_status()
                .iter()
                .map(|(name, status)| {
                    format!("{name}:{}/{}", status.healthy, status.total)
                })
                .collect(),
        );

        // Log all metrics using the tracing framework
        info!(
            target: LOG_TARGET,
            threads = system_info.threads, // Number of threads
            locations_stats,               // Active location requests
            upstreams_healthy_status,      // Upstream healthy status
            upstream_stats,                // Busy or circuit-broken upstreams
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

#[cfg(test)]
mod tests {
    use super::{
        format_upstream_stats, join_non_empty,
        new_performance_metrics_log_service,
    };
    use pingap_location::{Location, LocationProvider, LocationStats};
    use pingap_upstream::{Upstream, UpstreamProvider, UpstreamStats};
    use pretty_assertions::assert_eq;
    use std::collections::HashMap;
    use std::sync::Arc;

    /// Enough to run the task: it only reads through the providers.
    struct EmptyProviders;
    impl LocationProvider for EmptyProviders {
        fn get(&self, _name: &str) -> Option<Arc<Location>> {
            None
        }
        fn stats(&self) -> HashMap<String, LocationStats> {
            HashMap::new()
        }
    }
    impl UpstreamProvider for EmptyProviders {
        fn get(&self, _name: &str) -> Option<Arc<Upstream>> {
            None
        }
        fn list(&self) -> Vec<(String, Arc<Upstream>)> {
            vec![]
        }
    }

    #[test]
    fn test_join_non_empty() {
        assert_eq!(None, join_non_empty(vec![]));
        assert_eq!(
            Some("a, b".to_string()),
            join_non_empty(vec!["b".to_string(), "a".to_string()])
        );
    }

    #[test]
    fn test_format_upstream_stats() {
        // Idle and healthy: nothing worth a line.
        let quiet =
            HashMap::from([("idle".to_string(), UpstreamStats::default())]);
        assert_eq!(None, format_upstream_stats(&quiet));

        let busy = HashMap::from([
            ("idle".to_string(), UpstreamStats::default()),
            (
                "live".to_string(),
                UpstreamStats {
                    processing: 3,
                    connected: Some(2),
                    ..Default::default()
                },
            ),
            (
                "broken".to_string(),
                UpstreamStats {
                    circuit_states: HashMap::from([
                        ("10.0.0.1:80".to_string(), 1u8),
                        ("10.0.0.2:80".to_string(), 0u8),
                    ]),
                    ..Default::default()
                },
            ),
        ]);
        assert_eq!(
            Some("broken:0(circuit open: 10.0.0.1:80), live:3/2".to_string()),
            format_upstream_stats(&busy)
        );
    }

    #[tokio::test]
    async fn test_log_task_runs() {
        let providers = Arc::new(EmptyProviders);
        let task =
            new_performance_metrics_log_service(providers.clone(), providers);
        assert_eq!(true, task.execute(0).await.unwrap());
    }
}
