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

use super::{Error, LOG_TARGET, Result, get_process_system_info};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use humantime::parse_duration;
use pingap_cache::{CACHE_READING_TIME, CACHE_WRITING_TIME};
use pingap_core::BackgroundTask;
use pingap_core::Error as ServiceError;
use pingap_core::{Ctx, get_hostname};
use pingap_upstream::UpstreamProvider;
use pingora::proxy::Session;
use prometheus::core::Collector;
use prometheus::{
    Encoder, GaugeVec, HistogramVec, Opts, ProtobufEncoder, Registry,
    TextEncoder,
};
use prometheus::{
    Histogram, HistogramOpts, IntCounter, IntCounterVec, IntGauge, IntGaugeVec,
};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tracing::{error, warn};
use url::Url;

/// Optional upstream provider used to refresh per-backend gauges on scrape.
static METRICS_UPSTREAM_PROVIDER: OnceLock<Arc<dyn UpstreamProvider>> =
    OnceLock::new();

/// Registers the process-wide upstream provider so Prometheus scrapes can
/// export per-backend failure rate and circuit-breaker state.
pub fn set_metrics_upstream_provider(provider: Arc<dyn UpstreamProvider>) {
    let _ = METRICS_UPSTREAM_PROVIDER.set(provider);
}

/// Tag used to dynamically replace with actual hostname in prometheus push URLs.
/// This allows for dynamic host identification in distributed deployments.
static HOST_NAME_TAG: &str = "$HOSTNAME";

/// Comprehensive metrics collector for HTTP server monitoring.
///
/// This struct maintains various Prometheus metrics types to track:
/// - HTTP traffic patterns (requests, responses, payload sizes)
/// - Connection handling (reuse, TLS handshakes)
/// - Upstream server performance
/// - Cache efficiency
/// - System resource utilization
///
/// Each metric is labeled with appropriate dimensions (e.g., location, status code)
/// to enable detailed analysis and alerting.
pub struct Prometheus {
    /// Central registry for all metrics
    r: Registry,

    /// The children of the empty `location` label - the "every request"
    /// series - resolved once at construction. They are touched by every
    /// request, and looking them up means hashing the label set inside
    /// prometheus' `MetricVec` each time.
    all: LocationMetrics,

    /// `http_responses_codes` children of the empty `location` label, one
    /// per status class, indexed by [`code_class`].
    all_codes: [IntCounter; CODE_LABELS.len()],

    /// Upstream names seen by the previous metrics refresh, so the
    /// per-upstream series of an upstream that has since been removed from
    /// the configuration can be dropped rather than exported forever.
    known_upstreams: ArcSwap<Vec<String>>,

    /// Counter tracking total HTTP requests by location.
    /// Helps understand traffic patterns and load distribution.
    http_requests_total: IntCounterVec,

    /// Gauge showing current active requests by location.
    /// Useful for monitoring concurrent load and detecting potential bottlenecks.
    http_requests_current: IntGaugeVec,

    /// Histogram of request payload sizes in KB.
    /// Helps identify unusual request patterns and potential DoS attempts.
    http_received: HistogramVec,

    /// Total bytes received from clients, labeled by location
    http_received_bytes: IntCounterVec,

    /// Count of HTTP response codes grouped by category (2xx, 3xx, etc.), labeled by location and code
    http_responses_codes: IntCounterVec,

    /// Histogram of HTTP request processing times in seconds, labeled by location
    http_response_time: HistogramVec,

    /// Histogram of response payload sizes sent to clients in KB, labeled by location
    http_sent: HistogramVec,

    /// Total bytes sent to clients, labeled by location
    http_sent_bytes: IntCounterVec,

    /// Count of TCP connection reuses
    connection_reuses: IntCounter,

    /// Histogram of TLS handshake durations in seconds
    tls_handshake_time: Histogram,

    /// Total number of connections to upstream servers, labeled by upstream
    upstream_connections: IntGaugeVec,

    /// Current number of active upstream connections, labeled by upstream
    upstream_connections_current: IntGaugeVec,

    /// Histogram of TCP connection times to upstream servers in seconds, labeled by upstream
    upstream_tcp_connect_time: HistogramVec,

    /// Histogram of TLS handshake times with upstream servers in seconds, labeled by upstream
    upstream_tls_handshake_time: HistogramVec,

    /// Count of upstream connection reuses, labeled by upstream
    upstream_reuses: IntCounterVec,

    /// Histogram of upstream request processing times in seconds, labeled by upstream
    upstream_processing_time: HistogramVec,

    /// Histogram of upstream response times in seconds, labeled by upstream
    upstream_response_time: HistogramVec,

    /// Histogram of cache lookup times in seconds
    cache_lookup_time: Histogram,

    /// Histogram of cache lock acquisition times in seconds
    cache_lock_time: Histogram,

    /// Current number of cache read operations in progress
    cache_reading: IntGauge,

    /// Current number of cache write operations in progress
    cache_writing: IntGauge,

    /// Histogram of response compression ratios
    compression_ratio: Histogram,

    /// Current memory usage in megabytes
    memory: IntGauge,

    /// Current number of open file descriptors
    fd_count: IntGauge,

    /// Current number of IPv4 TCP connections
    tcp_count: IntGauge,

    /// Current number of IPv6 TCP connections
    tcp6_count: IntGauge,

    /// Sliding-window failure rate percent per upstream backend (0–100)
    upstream_backend_failure_rate: GaugeVec,

    /// Sliding-window request count per upstream backend
    upstream_backend_requests: IntGaugeVec,

    /// Circuit breaker state per upstream backend: 0 closed, 1 open, 2 half-open
    upstream_backend_circuit_state: IntGaugeVec,
    /// Seconds the latest backend refresh spent in service discovery, per upstream
    upstream_discovery_time: GaugeVec,
    /// Seconds the latest backend refresh spent rebuilding the selector, per upstream
    upstream_selector_build_time: GaugeVec,
    /// Histogram of how long upstream connections had been idle when the
    /// keep-alive pool evicted them to make room, in seconds; the count is
    /// the number of evictions
    upstream_pool_eviction_idle_time: Histogram,
}

/// The per-request metrics of one `location` label value.
struct LocationMetrics {
    requests_total: IntCounter,
    requests_current: IntGauge,
    received: Histogram,
    received_bytes: IntCounter,
    response_time: Histogram,
    sent: Histogram,
    sent_bytes: IntCounter,
}

impl LocationMetrics {
    /// The children of `location`, resolved once.
    fn new(p: &PrometheusVecs<'_>, location: &str) -> Self {
        let labels = [location];
        Self {
            requests_total: p.requests_total.with_label_values(&labels),
            requests_current: p.requests_current.with_label_values(&labels),
            received: p.received.with_label_values(&labels),
            received_bytes: p.received_bytes.with_label_values(&labels),
            response_time: p.response_time.with_label_values(&labels),
            sent: p.sent.with_label_values(&labels),
            sent_bytes: p.sent_bytes.with_label_values(&labels),
        }
    }
}

/// The vectors [`LocationMetrics::new`] resolves its children from.
struct PrometheusVecs<'a> {
    requests_total: &'a IntCounterVec,
    requests_current: &'a IntGaugeVec,
    received: &'a HistogramVec,
    received_bytes: &'a IntCounterVec,
    response_time: &'a HistogramVec,
    sent: &'a HistogramVec,
    sent_bytes: &'a IntCounterVec,
}

/// Status classes of `http_responses_codes`, in the order [`code_class`]
/// indexes them.
const CODE_LABELS: [&str; 6] = ["1xx", "2xx", "3xx", "4xx", "5xx", "unknown"];

/// Index of a status code in [`CODE_LABELS`].
#[inline]
fn code_class(code: u16) -> usize {
    match code {
        100..=199 => 0,
        200..=299 => 1,
        300..=399 => 2,
        400..=499 => 3,
        500..=599 => 4,
        _ => 5,
    }
}

/// Milliseconds to seconds conversion factor
const SECOND: f64 = 1000.0;

impl Prometheus {
    /// Counts a request as accepted, before any location has been matched.
    ///
    /// Called for every request, so the empty-`location` series really is
    /// the total: requests that match no location (a 404), the admin
    /// endpoints, ACME challenges and the metrics endpoint itself used to
    /// be missing from it entirely, because counting only started once a
    /// location had been matched.
    ///
    /// Paired with [`Prometheus::after`], which runs for every request.
    pub fn on_request_start(&self) {
        self.all.requests_total.inc();
        self.all.requests_current.inc();
    }

    /// Counts the request against the location it was routed to. A request
    /// that matched none is only counted by [`Prometheus::on_request_start`].
    pub fn on_location_matched(&self, location: &str) {
        if location.is_empty() {
            return;
        }
        self.http_requests_total
            .with_label_values(&[location])
            .inc();
        self.http_requests_current
            .with_label_values(&[location])
            .inc();
    }

    /// Records comprehensive metrics at request completion.
    ///
    /// # Arguments
    /// * `session` - The HTTP session containing request/response details
    /// * `ctx` - Request context with timing and state information
    ///
    /// # Metrics Updated
    /// - Response timing and size metrics
    /// - HTTP status code distribution
    /// - Connection reuse statistics
    /// - TLS handshake timing
    /// - Upstream server performance metrics
    /// - Cache operation statistics
    /// - Compression effectiveness
    ///
    /// # Performance Impact
    /// This method performs multiple metric updates but uses efficient
    /// atomic operations to minimize overhead.
    pub fn after(&self, session: &Session, ctx: &Ctx) {
        // `location` is an `Arc<str>`; bind it as `&str` so the prometheus 0.14
        // generic `with_label_values<V: AsRef<str>>` infers `V = &str` uniformly
        // when it is mixed with `&str` literals in multi-label arrays below.
        let location: &str = &ctx.upstream.location;
        let upstream = &ctx.upstream.name;
        let elapsed = ctx.timing.created_at.elapsed().as_millis();
        let response_time = elapsed as f64 / SECOND;
        let payload_bytes = ctx.state.payload_size as u64;
        // payload size(kb)
        let payload_size = payload_bytes as f64 / 1024.0;
        let code = ctx.state.status.map(|status| status.as_u16()).unwrap_or(0);
        let class = code_class(code);
        let sent_bytes = session.body_bytes_sent() as u64;
        let sent = sent_bytes as f64 / 1024.0;

        // Every request, through the children resolved at construction.
        self.all.requests_current.dec();
        self.all.received.observe(payload_size);
        self.all.received_bytes.inc_by(payload_bytes);
        // response time x second
        self.all.response_time.observe(response_time);
        // response body size(kb)
        self.all.sent.observe(sent);
        if sent_bytes > 0 {
            self.all.sent_bytes.inc_by(sent_bytes);
        }
        self.all_codes[class].inc();

        if !location.is_empty() {
            let labels = [location];
            self.http_requests_current.with_label_values(&labels).dec();
            self.http_received
                .with_label_values(&labels)
                .observe(payload_size);
            self.http_received_bytes
                .with_label_values(&labels)
                .inc_by(payload_bytes);
            self.http_response_time
                .with_label_values(&labels)
                .observe(response_time);
            self.http_sent.with_label_values(&labels).observe(sent);
            if sent_bytes > 0 {
                self.http_sent_bytes
                    .with_label_values(&labels)
                    .inc_by(sent_bytes);
            }
            self.http_responses_codes
                .with_label_values(&[location, CODE_LABELS[class]])
                .inc();
        }

        // reused connection
        if ctx.conn.reused {
            self.connection_reuses.inc();
        }

        if let Some(tls_handshake_time) = ctx.timing.tls_handshake {
            self.tls_handshake_time
                .observe(tls_handshake_time as f64 / SECOND);
        }

        // upstream
        if !upstream.is_empty() {
            let upstream_labels = &[upstream.as_ref()];
            if let Some(count) = ctx.upstream.connected_count {
                self.upstream_connections
                    .with_label_values(upstream_labels)
                    .set(count as i64);
            }
            if let Some(count) = ctx.upstream.processing_count {
                self.upstream_connections_current
                    .with_label_values(upstream_labels)
                    .set(count as i64);
            }
            // upstream stats
            if let Some(upstream_tcp_connect_time) =
                ctx.timing.upstream_tcp_connect
            {
                self.upstream_tcp_connect_time
                    .with_label_values(upstream_labels)
                    .observe(upstream_tcp_connect_time as f64 / SECOND);
            }
            if let Some(upstream_tls_handshake_time) =
                ctx.timing.upstream_tls_handshake
            {
                self.upstream_tls_handshake_time
                    .with_label_values(upstream_labels)
                    .observe(upstream_tls_handshake_time as f64 / SECOND);
            }
            if ctx.upstream.reused {
                self.upstream_reuses
                    .with_label_values(upstream_labels)
                    .inc();
            }
            if let Some(upstream_processing_time) =
                ctx.timing.upstream_processing
            {
                self.upstream_processing_time
                    .with_label_values(upstream_labels)
                    .observe(upstream_processing_time as f64 / SECOND);
            }
            if let Some(upstream_response_time) = ctx.timing.upstream_response {
                self.upstream_response_time
                    .with_label_values(upstream_labels)
                    .observe(upstream_response_time as f64 / SECOND);
            }
        }

        // cache stats
        if let Some(cache_lookup_time) = ctx.timing.cache_lookup {
            self.cache_lookup_time
                .observe(cache_lookup_time as f64 / SECOND);
        }
        if let Some(cache_lock_time) = ctx.timing.cache_lock {
            self.cache_lock_time
                .observe(cache_lock_time as f64 / SECOND);
        }
        if let Some(cache_info) = &ctx.cache {
            if let Some(cache_reading) = cache_info.reading_count {
                self.cache_reading.set(cache_reading as i64);
            }
            if let Some(cache_writing) = cache_info.writing_count {
                self.cache_writing.set(cache_writing as i64);
            }
        }

        // compression stats
        if let Some(features) = &ctx.features
            && let Some(compression_stat) = &features.compression_stat
        {
            self.compression_ratio.observe(compression_stat.ratio());
        }
    }

    /// Collects all registered metrics and updates system resource gauges.
    ///
    /// Updates the following system metrics before collection:
    /// - Memory usage in MB
    /// - Open file descriptor count
    /// - IPv4 and IPv6 TCP connection counts
    fn gather(&self) -> Vec<prometheus::proto::MetricFamily> {
        let info = get_process_system_info();
        self.memory.set(info.memory_mb as i64);
        self.fd_count.set(info.fd_count as i64);
        self.tcp_count.set(info.tcp_count as i64);
        self.tcp6_count.set(info.tcp6_count as i64);
        self.refresh_upstream_backend_metrics();
        self.r.gather()
    }

    /// Push current per-backend stats/circuit state into the gauge vectors.
    fn refresh_upstream_backend_metrics(&self) {
        let Some(provider) = METRICS_UPSTREAM_PROVIDER.get() else {
            return;
        };
        let all_stats = provider.get_all_stats();
        // These gauges describe the state as of this scrape and every one of
        // them is written again below, so clearing them first is what drops
        // the label sets of backends that no longer exist. Without it a
        // backend address that came from DNS or docker discovery keeps being
        // exported with its last value forever: prometheus holds a child
        // until it is removed, and those addresses churn.
        self.upstream_backend_failure_rate.reset();
        self.upstream_backend_requests.reset();
        self.upstream_backend_circuit_state.reset();
        self.upstream_discovery_time.reset();
        self.upstream_selector_build_time.reset();
        // The per-upstream series are written on the request path instead, so
        // they cannot be rebuilt here; drop the ones whose upstream is gone.
        self.forget_removed_upstreams(&all_stats);

        for (upstream_name, stats) in all_stats {
            self.refresh_upstream_update_timing(&upstream_name, &stats);
            // Union of backends that have window stats and/or a circuit state.
            let mut backends: HashSet<&str> =
                stats.backend_stats.keys().map(|s| s.as_str()).collect();
            backends.extend(stats.circuit_states.keys().map(|s| s.as_str()));
            for backend in backends {
                let labels = [upstream_name.as_str(), backend];
                if let Some(window) = stats.backend_stats.get(backend) {
                    self.upstream_backend_failure_rate
                        .with_label_values(&labels)
                        .set(window.failure_rate_percent);
                    self.upstream_backend_requests
                        .with_label_values(&labels)
                        .set(window.total_requests as i64);
                }
                let state =
                    stats.circuit_states.get(backend).copied().unwrap_or(0);
                self.upstream_backend_circuit_state
                    .with_label_values(&labels)
                    .set(state as i64);
            }
        }
    }

    /// Removes the per-upstream series of every upstream that was present at
    /// the previous refresh but is no longer configured, and remembers the
    /// current set for the next one.
    fn forget_removed_upstreams(
        &self,
        live: &HashMap<String, pingap_upstream::UpstreamStats>,
    ) {
        let previous = self.known_upstreams.load();
        for name in previous.iter() {
            if live.contains_key(name) {
                continue;
            }
            let labels = [name.as_str()];
            let _ = self.upstream_connections.remove_label_values(&labels);
            let _ = self
                .upstream_connections_current
                .remove_label_values(&labels);
            let _ = self.upstream_tcp_connect_time.remove_label_values(&labels);
            let _ = self
                .upstream_tls_handshake_time
                .remove_label_values(&labels);
            let _ = self.upstream_reuses.remove_label_values(&labels);
            let _ = self.upstream_processing_time.remove_label_values(&labels);
            let _ = self.upstream_response_time.remove_label_values(&labels);
        }
        // Equal length plus every old name still live means the same set.
        let unchanged = previous.len() == live.len()
            && previous.iter().all(|name| live.contains_key(name));
        if !unchanged {
            self.known_upstreams
                .store(Arc::new(live.keys().cloned().collect()));
        }
    }

    /// Push the discovery/selector-build durations of the latest backend
    /// refresh into the per-upstream gauges.
    fn refresh_upstream_update_timing(
        &self,
        upstream_name: &str,
        stats: &pingap_upstream::UpstreamStats,
    ) {
        let labels = [upstream_name];
        if let Some(duration) = stats.discovery_duration {
            self.upstream_discovery_time
                .with_label_values(&labels)
                .set(duration.as_secs_f64());
        }
        if let Some(duration) = stats.selector_build_duration {
            self.upstream_selector_build_time
                .with_label_values(&labels)
                .set(duration.as_secs_f64());
        }
    }

    /// Records how long an upstream connection had been idle when the
    /// keep-alive pool evicted it to make room for a newer one (pingora only
    /// reports evictions, not idle timeouts or peer closes). The proxy server
    /// wires this into the connector's `keepalive_pool_callback`; a growing
    /// count means `upstream_keepalive_pool_size` is too small.
    pub fn observe_upstream_pool_eviction(&self, idle: Duration) {
        self.upstream_pool_eviction_idle_time
            .observe(idle.as_secs_f64());
    }

    /// Formats all metrics in Prometheus text format for scraping.
    ///
    /// # Returns
    /// - `Ok(Vec<u8>)` containing UTF-8 encoded metrics in Prometheus format
    /// - `Err(Error)` if metric encoding fails
    pub fn metrics(&self) -> Result<Vec<u8>> {
        let mut buffer = vec![];
        let encoder = TextEncoder::new();
        let metrics = self.gather();
        encoder.encode(&metrics, &mut buffer).map_err(|e| {
            Error::Prometheus {
                message: e.to_string(),
            }
        })?;
        Ok(buffer)
    }
}

/// Configuration for Prometheus push gateway integration
#[derive(Clone)]
struct PrometheusPushParams {
    /// Service identifier
    name: String,
    /// Push gateway URL
    url: String,
    /// Reference to metrics collector
    p: Arc<Prometheus>,
    /// Basic auth username
    username: String,
    /// Optional basic auth password
    password: Option<String>,
    /// Reused across pushes so the connection to the gateway is kept.
    client: reqwest::Client,
}

/// Pushes metrics to Prometheus pushgateway
///
/// # Arguments
/// * `count` - Current iteration count
/// * `offset` - Push frequency control
/// * `params` - Push configuration parameters
///
/// # Returns
/// * `Ok(true)` if push was attempted
/// * `Ok(false)` if skipped due to offset
/// * `Err` if push failed
async fn do_push(
    count: u32,
    offset: u32,
    params: &PrometheusPushParams,
) -> Result<bool, ServiceError> {
    if !count.is_multiple_of(offset) {
        return Ok(false);
    }
    // http push metrics
    let encoder = ProtobufEncoder::new();
    let mut buf = Vec::new();
    if let Err(e) = encoder.encode(&params.p.gather(), &mut buf) {
        error!(
            target: LOG_TARGET,
            name = params.name,
            error = %e,
            "encode prometheus metrics fail"
        );
        return Ok(true);
    }
    let mut builder = params
        .client
        .post(&params.url)
        .header(http::header::CONTENT_TYPE, encoder.format_type())
        .body(buf);

    if !params.username.is_empty() {
        builder = builder.basic_auth(&params.username, params.password.clone());
    }

    match builder.timeout(Duration::from_secs(60)).send().await {
        Ok(res) => {
            if res.status().as_u16() >= 400 {
                error!(
                    target: LOG_TARGET,
                    name = params.name,
                    status = res.status().to_string(),
                    "push prometheus fail"
                );
            }
        },
        Err(e) => {
            error!(
                target: LOG_TARGET,
                name = params.name,
                error = %e,
                "push prometheus fail"
            );
        },
    };
    Ok(true)
}

struct PrometheusPushTask {
    offset: u32,
    params: PrometheusPushParams,
}

#[async_trait]
impl BackgroundTask for PrometheusPushTask {
    async fn execute(&self, count: u32) -> Result<bool, ServiceError> {
        do_push(count, self.offset, &self.params).await?;
        Ok(true)
    }
}

/// Create a new prometheus push service
pub fn new_prometheus_push_service(
    name: &str,
    url: &str,
    p: Arc<Prometheus>,
) -> Result<Box<dyn BackgroundTask>> {
    let mut info = Url::parse(url).map_err(|e| Error::Url { source: e })?;

    let username = info.username().to_string();
    let password = info.password().map(|value| value.to_string());
    let _ = info.set_username("");
    let _ = info.set_password(None);
    let mut interval = Duration::from_secs(60);
    // push interval
    for (key, value) in info.query_pairs().into_iter() {
        if key == "interval"
            && let Ok(v) = parse_duration(&value)
        {
            interval = v;
        }
    }
    let mut url = info.to_string();
    if url.contains(HOST_NAME_TAG) {
        url = url.replace(HOST_NAME_TAG, get_hostname());
    }

    let params = PrometheusPushParams {
        name: name.to_string(),
        url,
        username,
        password,
        p,
        client: reqwest::Client::new(),
    };
    // The push runs as a task of the shared background service, which ticks
    // once a minute, so the interval can only be a whole number of minutes.
    let offset = ((interval.as_secs() / 60) as u32).max(1);
    let effective = Duration::from_secs(offset as u64 * 60);
    if effective != interval {
        warn!(
            target: LOG_TARGET,
            name,
            requested = humantime::Duration::from(interval).to_string(),
            effective = humantime::Duration::from(effective).to_string(),
            "prometheus push interval is rounded to whole minutes"
        );
    }

    let task = Box::new(PrometheusPushTask { offset, params });
    Ok(task)
}

fn new_int_counter(server: &str, name: &str, help: &str) -> Result<IntCounter> {
    let mut opts = Opts::new(name, help);
    opts = opts.const_label("server", server);
    let counter =
        IntCounter::with_opts(opts).map_err(|e| Error::Prometheus {
            message: e.to_string(),
        })?;
    Ok(counter)
}

fn new_int_gauge(server: &str, name: &str, help: &str) -> Result<IntGauge> {
    let mut opts = Opts::new(name, help);
    opts = opts.const_label("server", server);
    let gauge = IntGauge::with_opts(opts).map_err(|e| Error::Prometheus {
        message: e.to_string(),
    })?;
    Ok(gauge)
}

fn new_int_counter_vec(
    server: &str,
    name: &str,
    help: &str,
    label_names: &[&str],
) -> Result<IntCounterVec> {
    let mut opts = Opts::new(name, help);
    opts = opts.const_label("server", server);
    let counter = IntCounterVec::new(opts, label_names).map_err(|e| {
        Error::Prometheus {
            message: e.to_string(),
        }
    })?;
    Ok(counter)
}

fn new_int_gauge_vec(
    server: &str,
    name: &str,
    help: &str,
    label_names: &[&str],
) -> Result<IntGaugeVec> {
    let mut opts = Opts::new(name, help);
    opts = opts.const_label("server", server);
    let gauge =
        IntGaugeVec::new(opts, label_names).map_err(|e| Error::Prometheus {
            message: e.to_string(),
        })?;
    Ok(gauge)
}

fn new_gauge_vec(
    server: &str,
    name: &str,
    help: &str,
    label_names: &[&str],
) -> Result<GaugeVec> {
    let mut opts = Opts::new(name, help);
    opts = opts.const_label("server", server);
    let gauge =
        GaugeVec::new(opts, label_names).map_err(|e| Error::Prometheus {
            message: e.to_string(),
        })?;
    Ok(gauge)
}

fn new_histogram(
    server: &str,
    name: &str,
    help: &str,
    buckets: &[f64],
) -> Result<Histogram> {
    let mut opts = Opts::new(name, help);
    if !server.is_empty() {
        opts = opts.const_label("server", server);
    }
    let histogram = Histogram::with_opts(HistogramOpts {
        common_opts: opts,
        buckets: Vec::from(buckets),
    })
    .map_err(|e| Error::Prometheus {
        message: e.to_string(),
    })?;
    Ok(histogram)
}
fn new_histogram_vec(
    server: &str,
    name: &str,
    help: &str,
    label_names: &[&str],
    buckets: &[f64],
) -> Result<HistogramVec> {
    let mut opts = HistogramOpts::new(name, help);
    if !server.is_empty() {
        opts = opts.const_label("server", server);
    }
    opts = opts.buckets(buckets.into());

    let histogram = HistogramVec::new(opts, label_names).map_err(|e| {
        Error::Prometheus {
            message: e.to_string(),
        }
    })?;

    Ok(histogram)
}

macro_rules! register_metric {
    ($r:expr, $constructor:ident, $($args:expr),*) => {{
        // call the constructor to create the metric
        let metric = $constructor($($args),*)?;
        $r.register(Box::new(metric.clone())).map_err(|e| Error::Prometheus {
            message: e.to_string(),
        })?;
        Ok(metric)
    }};
}

/// Create a prometheus metrics for server
pub fn new_prometheus(server: &str) -> Result<Prometheus> {
    let r = Registry::new();
    let http_requests_total = register_metric!(
        r,
        new_int_counter_vec,
        server,
        "pingap_http_requests_total",
        "pingap total http requests",
        &["location"]
    )?;

    let http_requests_current = register_metric!(
        r,
        new_int_gauge_vec,
        server,
        "pingap_http_requests_current",
        "pingap current http requests",
        &["location"]
    )?;

    let http_received = register_metric!(
        r,
        new_histogram_vec,
        server,
        "pingap_http_received",
        "pingap http received from clients(KB)",
        &["location"],
        &[1.0, 5.0, 10.0, 50.0, 100.0, 1000.0]
    )?;
    let http_received_bytes = register_metric!(
        r,
        new_int_counter_vec,
        server,
        "pingap_http_received_bytes",
        "pingap http received from clients(bytes)",
        &["location"]
    )?;
    let http_responses_codes = register_metric!(
        r,
        new_int_counter_vec,
        server,
        "pingap_http_responses_codes",
        "pingap total responses sent to clients by code",
        &["location", "code"]
    )?;
    let http_response_time = register_metric!(
        r,
        new_histogram_vec,
        server,
        "pingap_http_response_time",
        "pingap http response time(second)",
        &["location"],
        &[
            0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0
        ]
    )?;
    let http_sent = register_metric!(
        r,
        new_histogram_vec,
        server,
        "pingap_http_sent",
        "pingap http sent to clients(KB)",
        &["location"],
        &[1.0, 5.0, 10.0, 50.0, 100.0, 1000.0, 10000.0]
    )?;
    let http_sent_bytes = register_metric!(
        r,
        new_int_counter_vec,
        server,
        "pingap_http_sent_bytes",
        "pingap http sent to clients(bytes)",
        &["location"]
    )?;
    let connection_reuses = register_metric!(
        r,
        new_int_counter,
        server,
        "pingap_connection_reuses",
        "pingap connection reuses during tcp connect"
    )?;
    let tls_handshake_time = register_metric!(
        r,
        new_histogram,
        server,
        "pingap_tls_handshake_time",
        "pingap tls handshake time(second)",
        &[0.01, 0.05, 0.1, 0.5, 1.0]
    )?;

    let upstream_connections = register_metric!(
        r,
        new_int_gauge_vec,
        server,
        "pingap_upstream_connections",
        "pingap connected connections of upstream",
        &["upstream"]
    )?;
    let upstream_connections_current = register_metric!(
        r,
        new_int_gauge_vec,
        server,
        "pingap_upstream_connections_current",
        "pingap current connections of upstream",
        &["upstream"]
    )?;
    let upstream_tcp_connect_time = register_metric!(
        r,
        new_histogram_vec,
        server,
        "pingap_upstream_tcp_connect_time",
        "pingap upstream tcp connect time(second)",
        &["upstream"],
        &[0.005, 0.01, 0.05, 0.1, 0.5, 1.0]
    )?;
    let upstream_tls_handshake_time = register_metric!(
        r,
        new_histogram_vec,
        server,
        "pingap_upstream_tls_handshake_time",
        "pingap upstream tsl handshake time(second)",
        &["upstream"],
        &[0.01, 0.05, 0.1, 0.5, 1.0]
    )?;
    let upstream_reuses = register_metric!(
        r,
        new_int_counter_vec,
        server,
        "pingap_upstream_reuses",
        "pingap connection reuse during connect to upstream",
        &["upstream"]
    )?;
    let upstream_processing_time = register_metric!(
        r,
        new_histogram_vec,
        server,
        "pingap_upstream_processing_time",
        "pingap upstream processing time(second)",
        &["upstream"],
        &[0.01, 0.02, 0.1, 0.5, 1.0, 5.0, 10.0]
    )?;
    let upstream_response_time = register_metric!(
        r,
        new_histogram_vec,
        server,
        "pingap_upstream_response_time",
        "pingap upstream response time(second)",
        &["upstream"],
        &[0.005, 0.01, 0.05, 0.1, 0.5, 1.0]
    )?;
    let cache_lookup_time = register_metric!(
        r,
        new_histogram,
        server,
        "pingap_cache_lookup_time",
        "pingap cache lookup time(second)",
        &[0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0]
    )?;
    let cache_lock_time = register_metric!(
        r,
        new_histogram,
        server,
        "pingap_cache_lock_time",
        "pingap cache lock time(second)",
        &[0.01, 0.05, 0.1, 1.0, 3.0]
    )?;
    let cache_reading = register_metric!(
        r,
        new_int_gauge,
        server,
        "pingap_cache_reading",
        "pingap cache reading count"
    )?;
    let cache_writing = register_metric!(
        r,
        new_int_gauge,
        server,
        "pingap_cache_writing",
        "pingap cache writing count"
    )?;
    let compression_ratio = register_metric!(
        r,
        new_histogram,
        server,
        "pingap_compression_ratio",
        "pingap response compression ratio",
        &[1.0, 2.0, 3.0, 5.0, 10.0]
    )?;

    let memory = register_metric!(
        r,
        new_int_gauge,
        server,
        "pingap_memory",
        "pingap memory size(mb)"
    )?;
    let fd_count = register_metric!(
        r,
        new_int_gauge,
        server,
        "pingap_fd_count",
        "pingap open file count"
    )?;
    let tcp_count = register_metric!(
        r,
        new_int_gauge,
        server,
        "pingap_tcp_count",
        "pingap ipv4 tcp sockets in the network namespace"
    )?;
    let tcp6_count = register_metric!(
        r,
        new_int_gauge,
        server,
        "pingap_tcp6_count",
        "pingap ipv6 tcp sockets in the network namespace"
    )?;
    let upstream_backend_failure_rate = register_metric!(
        r,
        new_gauge_vec,
        server,
        "pingap_upstream_backend_failure_rate",
        "pingap sliding-window backend failure rate percent (0-100)",
        &["upstream", "backend"]
    )?;
    let upstream_backend_requests = register_metric!(
        r,
        new_int_gauge_vec,
        server,
        "pingap_upstream_backend_requests",
        "pingap sliding-window backend request count",
        &["upstream", "backend"]
    )?;
    let upstream_backend_circuit_state = register_metric!(
        r,
        new_int_gauge_vec,
        server,
        "pingap_upstream_backend_circuit_state",
        "pingap backend circuit state (0=closed,1=open,2=half-open)",
        &["upstream", "backend"]
    )?;

    let collectors: Vec<Box<dyn Collector>> =
        vec![CACHE_READING_TIME.clone(), CACHE_WRITING_TIME.clone()];
    for c in collectors {
        r.register(c).map_err(|e| Error::Prometheus {
            message: e.to_string(),
        })?;
    }

    let upstream_discovery_time = register_metric!(
        r,
        new_gauge_vec,
        server,
        "pingap_upstream_discovery_time",
        "pingap service discovery time of the latest backend refresh(second)",
        &["upstream"]
    )?;
    let upstream_selector_build_time = register_metric!(
        r,
        new_gauge_vec,
        server,
        "pingap_upstream_selector_build_time",
        "pingap selector build time of the latest backend refresh(second)",
        &["upstream"]
    )?;
    let upstream_pool_eviction_idle_time = register_metric!(
        r,
        new_histogram,
        server,
        "pingap_upstream_pool_eviction_idle_time",
        "pingap idle time of upstream keepalive connections when evicted from the pool(second)",
        &[0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0]
    )?;

    let all = LocationMetrics::new(
        &PrometheusVecs {
            requests_total: &http_requests_total,
            requests_current: &http_requests_current,
            received: &http_received,
            received_bytes: &http_received_bytes,
            response_time: &http_response_time,
            sent: &http_sent,
            sent_bytes: &http_sent_bytes,
        },
        "",
    );
    let all_codes = CODE_LABELS
        .map(|code| http_responses_codes.with_label_values(&["", code]));

    Ok(Prometheus {
        r,
        all,
        all_codes,
        known_upstreams: ArcSwap::from_pointee(Vec::new()),
        http_requests_total,
        http_requests_current,
        http_received,
        http_received_bytes,
        http_responses_codes,
        http_response_time,
        http_sent,
        http_sent_bytes,
        connection_reuses,
        tls_handshake_time,
        upstream_connections,
        upstream_connections_current,
        upstream_tcp_connect_time,
        upstream_tls_handshake_time,
        upstream_reuses,
        upstream_processing_time,
        upstream_response_time,
        cache_lookup_time,
        cache_lock_time,
        cache_reading,
        cache_writing,
        compression_ratio,
        memory,
        fd_count,
        tcp_count,
        tcp6_count,
        upstream_backend_failure_rate,
        upstream_backend_requests,
        upstream_backend_circuit_state,
        upstream_discovery_time,
        upstream_selector_build_time,
        upstream_pool_eviction_idle_time,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::StatusCode;
    use pingap_core::{
        CompressionStat, ConnectionInfo, Ctx, Features, RequestState, Timing,
    };
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use std::time::{Duration, Instant};
    use tokio_test::io::Builder;

    /// The value of the exported series whose name starts with `name` and
    /// whose line carries every fragment of `labels`. Order-independent, so
    /// it does not depend on how the encoder sorts label pairs.
    fn metric_value(buf: &str, name: &str, labels: &[&str]) -> Option<String> {
        buf.lines()
            .filter(|line| line.starts_with(name))
            .find(|line| labels.iter().all(|label| line.contains(label)))
            .and_then(|line| line.split_whitespace().next_back())
            .map(str::to_string)
    }

    #[test]
    fn test_code_class() {
        for (code, label) in [
            (100, "1xx"),
            (204, "2xx"),
            (302, "3xx"),
            (404, "4xx"),
            (502, "5xx"),
            (0, "unknown"),
            (999, "unknown"),
        ] {
            assert_eq!(label, CODE_LABELS[code_class(code)], "{code}");
        }
    }

    #[test]
    fn test_upstream_pool_eviction_idle_time() {
        let p = new_prometheus("pingap").unwrap();
        p.observe_upstream_pool_eviction(Duration::from_secs(3));
        let buf = String::from_utf8(p.metrics().unwrap()).unwrap();
        assert_eq!(
            true,
            buf.contains(
                "pingap_upstream_pool_eviction_idle_time_count{server=\"pingap\"} 1"
            ),
            "{buf}"
        );
        assert_eq!(
            true,
            buf.contains(
                "pingap_upstream_pool_eviction_idle_time_sum{server=\"pingap\"} 3"
            ),
            "{buf}"
        );
    }

    #[tokio::test]
    async fn test_new_prometheus() {
        let headers = [
            "Host: github.com",
            "Referer: https://github.com/",
            "user-agent: pingap/0.1.1",
            "Cookie: deviceId=abc",
            "Accept: application/json",
            "X-Forwarded-For: 1.1.1.1, 2.2.2.2",
        ]
        .join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();

        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let p = new_prometheus("pingap").unwrap();
        p.on_request_start();
        p.on_location_matched("lo");

        p.after(
            &session,
            &Ctx {
                timing: Timing {
                    created_at: Instant::now(),
                    tls_handshake: Some(1),
                    upstream_tcp_connect: Some(2),
                    upstream_tls_handshake: Some(3),
                    upstream_processing: Some(10),
                    upstream_response: Some(5),
                    cache_lookup: Some(11),
                    cache_lock: Some(12),
                    ..Default::default()
                },
                state: RequestState {
                    status: Some(StatusCode::from_u16(200).unwrap()),
                    payload_size: 1024,
                    ..Default::default()
                },
                conn: ConnectionInfo {
                    reused: true,
                    ..Default::default()
                },
                features: Some(Box::new(Features {
                    compression_stat: Some(CompressionStat {
                        in_bytes: 1024,
                        out_bytes: 512,
                        duration: Duration::from_millis(20),
                        ..Default::default()
                    }),
                    ..Default::default()
                })),
                upstream: pingap_core::UpstreamInfo {
                    name: "upstream".into(),
                    location: "lo".into(),
                    reused: true,
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        let buf = String::from_utf8(p.metrics().unwrap()).unwrap();
        // Counted once for the total and once for the matched location, and
        // the in-flight gauge is back to zero on both.
        for labels in ["location=\"\"", "location=\"lo\""] {
            assert_eq!(
                Some("1".to_string()),
                metric_value(&buf, "pingap_http_requests_total{", &[labels]),
                "{labels}: {buf}"
            );
            assert_eq!(
                Some("0".to_string()),
                metric_value(&buf, "pingap_http_requests_current{", &[labels]),
                "{labels}: {buf}"
            );
            assert_eq!(
                Some("1".to_string()),
                metric_value(
                    &buf,
                    "pingap_http_responses_codes{",
                    &[labels, "code=\"2xx\""]
                ),
                "{labels}: {buf}"
            );
            assert_eq!(
                Some("1024".to_string()),
                metric_value(&buf, "pingap_http_received_bytes{", &[labels]),
                "{labels}: {buf}"
            );
        }
        // Upstream and cache timings reached their histograms.
        assert_eq!(
            Some("1".to_string()),
            metric_value(
                &buf,
                "pingap_upstream_response_time_count{",
                &["upstream=\"upstream\""]
            ),
            "{buf}"
        );
        assert_eq!(
            Some("1".to_string()),
            metric_value(&buf, "pingap_cache_lookup_time_count{", &[]),
            "{buf}"
        );
    }

    /// A request that matches no location still counts towards the totals;
    /// it used to be invisible, so a flood of 404s showed up nowhere.
    #[tokio::test]
    async fn test_request_without_location_is_counted() {
        let input_header = "GET /nope HTTP/1.1\r\nHost: github.com\r\n\r\n";
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let p = new_prometheus("pingap").unwrap();
        p.on_request_start();
        p.on_location_matched("");
        p.after(&session, &Ctx::default());

        let buf = String::from_utf8(p.metrics().unwrap()).unwrap();
        assert_eq!(
            Some("1".to_string()),
            metric_value(&buf, "pingap_http_requests_total{", &[]),
            "{buf}"
        );
        assert_eq!(
            Some("0".to_string()),
            metric_value(&buf, "pingap_http_requests_current{", &[]),
            "{buf}"
        );
        // No status was set, so it lands in the unknown class.
        assert_eq!(
            Some("1".to_string()),
            metric_value(
                &buf,
                "pingap_http_responses_codes{",
                &["code=\"unknown\""]
            ),
            "{buf}"
        );
        // And no per-location series was created.
        assert_eq!(false, buf.contains("location=\"lo\""), "{buf}");
    }

    /// The per-upstream series of an upstream that left the configuration
    /// stop being exported instead of lingering with their last value.
    #[test]
    fn test_forget_removed_upstreams() {
        let p = new_prometheus("pingap").unwrap();
        p.upstream_connections.with_label_values(&["kept"]).set(1);
        p.upstream_connections.with_label_values(&["gone"]).set(2);
        p.upstream_reuses.with_label_values(&["gone"]).inc();

        let live: HashMap<String, pingap_upstream::UpstreamStats> =
            ["kept", "gone"]
                .into_iter()
                .map(|name| (name.to_string(), Default::default()))
                .collect();
        p.forget_removed_upstreams(&live);
        let buf = String::from_utf8(p.metrics().unwrap()).unwrap();
        assert_eq!(true, buf.contains("upstream=\"gone\""), "{buf}");

        let live: HashMap<String, pingap_upstream::UpstreamStats> =
            HashMap::from([("kept".to_string(), Default::default())]);
        p.forget_removed_upstreams(&live);
        let buf = String::from_utf8(p.metrics().unwrap()).unwrap();
        assert_eq!(false, buf.contains("upstream=\"gone\""), "{buf}");
        assert_eq!(true, buf.contains("upstream=\"kept\""), "{buf}");
    }
}
