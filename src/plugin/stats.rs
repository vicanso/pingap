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

use super::{get_hash_key, get_step_conf, get_str_conf, Plugin};
use crate::process::get_start_time;
use async_trait::async_trait;
use bytes::Bytes;
use ctor::ctor;
use pingap_config::{PluginCategory, PluginConf};
use pingap_core::{
    get_hostname, Ctx, HttpResponse, PluginStep, RequestPluginResult,
};
use pingap_location::get_locations_stats;
use pingap_performance::{get_process_system_info, get_processing_accepted};
use pingap_plugin::{get_plugin_factory, Error};
use pingap_upstream::{get_upstream_healthy_status, UpstreamHealthyStatus};
use pingora::proxy::Session;
use serde::Serialize;
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

type Result<T> = std::result::Result<T, Error>;

/// ServerStats collects and represents comprehensive server metrics including:
/// - Request processing statistics
/// - System resource utilization
/// - Server identification information
/// - Network connection details
#[derive(Serialize)]
struct ServerStats {
    // Request Processing Metrics
    processing: i32, // Number of requests currently being processed across all locations
    accepted: u64,   // Total number of requests accepted since server start
    location_processing: i32, // Number of requests currently being processed in this specific location
    location_accepted: u64, // Total number of requests accepted in this specific location

    // Server Identification
    hostname: String,      // Server's network hostname
    version: String,       // Current version of the application
    rustc_version: String, // Version of the Rust compiler used to build the application

    // Uptime Information
    start_time: u64, // Unix timestamp when the server was started
    uptime: String, // Human-readable duration since server start (e.g., "2 days 3 hours")

    // Memory Statistics
    memory_mb: usize, // Current process memory usage in megabytes
    memory: String,   // Human-readable process memory usage (e.g., "1.2 GB")
    total_memory: String, // Total system memory available (e.g., "16 GB")
    used_memory: String, // Total system memory in use (e.g., "8.5 GB")

    // System Information
    arch: String, // System architecture (e.g., "x86_64", "aarch64")
    cpus: usize,  // Number of logical CPU cores (including hyperthreading)
    physical_cpus: usize, // Number of physical CPU cores

    // Resource Usage
    threads: usize,  // Number of threads in the current process
    fd_count: usize, // Number of open file descriptors in the process

    // Network Connections
    tcp_count: usize,  // Number of active IPv4 TCP connections
    tcp6_count: usize, // Number of active IPv6 TCP connections

    upstream_healthy_status: HashMap<String, UpstreamHealthyStatus>, // Upstream healthy status
    locations_stats: HashMap<String, (i32, u64)>, // Locations stats
}

/// Stats plugin that exposes server metrics and statistics via an HTTP endpoint
pub struct Stats {
    path: String,            // HTTP path to expose stats on
    plugin_step: PluginStep, // Step at which this plugin executes
    hash_value: String,      // Unique hash identifying this plugin instance
}

/// Implementation for creating a Stats instance from plugin configuration
impl TryFrom<&PluginConf> for Stats {
    type Error = Error;

    /// Attempts to create a Stats instance from the provided configuration
    ///
    /// # Arguments
    ///
    /// * `value` - Plugin configuration containing path and step settings
    ///
    /// # Returns
    ///
    /// Returns a Result containing the Stats instance if configuration is valid,
    /// or an Error if the configuration is invalid
    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);
        let step = get_step_conf(value, PluginStep::Request);

        let params = Self {
            hash_value,
            plugin_step: step,
            path: get_str_conf(value, "path"),
        };
        if ![PluginStep::Request, PluginStep::ProxyUpstream]
            .contains(&params.plugin_step)
        {
            return Err(Error::Invalid {
                category: PluginCategory::Stats.to_string(),
                message: "Stats plugin should be executed at request or proxy upstream step".to_string(),
            });
        }
        Ok(params)
    }
}

impl Stats {
    /// Creates a new Stats plugin instance from the given plugin configuration
    ///
    /// # Arguments
    ///
    /// * `params` - The plugin configuration parameters
    ///
    /// # Returns
    ///
    /// Returns a Result containing the Stats plugin instance or an error
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new stats plugin");
        Self::try_from(params)
    }
}

#[async_trait]
impl Plugin for Stats {
    #[inline]
    fn hash_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }
    /// Handles incoming HTTP requests for the Stats plugin
    ///
    /// # Arguments
    ///
    /// * `step` - The current plugin execution step
    /// * `session` - The HTTP session containing request details
    /// * `ctx` - The current state context
    ///
    /// # Returns
    ///
    /// Returns a Result containing an optional HTTP response. Returns Some(response)
    /// when the request matches the stats path, None otherwise.
    #[inline]
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        if step != self.plugin_step {
            return Ok(RequestPluginResult::Skipped);
        }
        if session.req_header().uri.path() != self.path {
            return Ok(RequestPluginResult::Skipped);
        }
        let uptime: humantime::Duration =
            Duration::from_secs(pingap_util::now_sec() - get_start_time())
                .into();
        let (processing, accepted) = get_processing_accepted();
        let info = get_process_system_info();
        let resp = HttpResponse::try_from_json(&ServerStats {
            accepted,
            processing,
            location_processing: ctx.state.location_processing_count,
            location_accepted: ctx.state.location_accepted_count,
            hostname: get_hostname().to_string(),
            version: pingap_util::get_pkg_version().to_string(),
            rustc_version: pingap_util::get_rustc_version(),
            start_time: get_start_time(),
            uptime: uptime.to_string(),
            memory_mb: info.memory_mb,
            memory: info.memory,
            arch: info.arch,
            cpus: info.cpus,
            physical_cpus: info.physical_cpus,
            total_memory: info.total_memory,
            used_memory: info.used_memory,
            threads: info.threads,
            fd_count: info.fd_count,
            tcp_count: info.tcp_count,
            tcp6_count: info.tcp6_count,
            upstream_healthy_status: get_upstream_healthy_status(),
            locations_stats: get_locations_stats(),
        })
        .unwrap_or_else(|e| {
            HttpResponse::unknown_error(Bytes::from(e.to_string()))
        });
        Ok(RequestPluginResult::Respond(resp))
    }
}

#[ctor]
fn init() {
    get_plugin_factory()
        .register("stats", |params| Ok(Arc::new(Stats::new(params)?)));
}

#[cfg(test)]
mod tests {
    use super::Stats;
    use pingap_config::PluginConf;
    use pingap_core::{Ctx, Plugin, PluginStep, RequestPluginResult};
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    #[test]
    fn test_stats_params() {
        let params = Stats::try_from(
            &toml::from_str::<PluginConf>(
                r###"
        path = "/stats"
    "###,
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!("/stats", params.path);

        let result = Stats::try_from(
            &toml::from_str::<PluginConf>(
                r###"
        step = "response"
        path = "/stats"
    "###,
            )
            .unwrap(),
        );

        assert_eq!(
            "Plugin stats invalid, message: Stats plugin should be executed at request or proxy upstream step",
            result.err().unwrap().to_string()
        );
    }

    #[tokio::test]
    async fn test_stats() {
        let stats = Stats::new(
            &toml::from_str::<PluginConf>(
                r###"
            path = "/stats"
        "###,
            )
            .unwrap(),
        )
        .unwrap();

        let headers = ["Accept-Encoding: gzip"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let result = stats
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result == RequestPluginResult::Skipped);

        let headers = ["Accept-Encoding: gzip"].join("\r\n");
        let input_header = format!("GET /stats HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        // pass
        let result = stats
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        let RequestPluginResult::Respond(resp) = result else {
            panic!("result is not Respond");
        };
        assert_eq!(200, resp.status.as_u16());
    }
}
