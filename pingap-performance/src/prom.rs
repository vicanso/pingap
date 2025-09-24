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

use super::{get_process_system_info, Error, Result, LOG_CATEGORY};
use async_trait::async_trait;
use humantime::parse_duration;
use pingap_cache::{CACHE_READING_TIME, CACHE_WRITING_TIME};
use pingap_core::BackgroundTask;
use pingap_core::Error as ServiceError;
use pingap_core::{get_hostname, Ctx};
use pingora::proxy::Session;
use prometheus::core::Collector;
use prometheus::{
    Encoder, HistogramVec, Opts, ProtobufEncoder, Registry, TextEncoder,
};
use prometheus::{
    Histogram, HistogramOpts, IntCounter, IntCounterVec, IntGauge, IntGaugeVec,
};
use smallvec::SmallVec;
use std::sync::Arc;
use std::time::Duration;
use tracing::error;
use url::Url;

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

    /// Counter tracking total HTTP requests by location.
    /// Helps understand traffic patterns and load distribution.
    http_requests_total: Box<IntCounterVec>,

    /// Gauge showing current active requests by location.
    /// Useful for monitoring concurrent load and detecting potential bottlenecks.
    http_requests_current: Box<IntGaugeVec>,

    /// Histogram of request payload sizes in KB.
    /// Helps identify unusual request patterns and potential DoS attempts.
    http_received: Box<HistogramVec>,

    /// Total bytes received from clients, labeled by location
    http_received_bytes: Box<IntCounterVec>,

    /// Count of HTTP response codes grouped by category (2xx, 3xx, etc.), labeled by location and code
    http_responses_codes: Box<IntCounterVec>,

    /// Histogram of HTTP request processing times in seconds, labeled by location
    http_response_time: Box<HistogramVec>,

    /// Histogram of response payload sizes sent to clients in KB, labeled by location
    http_sent: Box<HistogramVec>,

    /// Total bytes sent to clients, labeled by location
    http_sent_bytes: Box<IntCounterVec>,

    /// Count of TCP connection reuses
    connection_reuses: Box<IntCounter>,

    /// Histogram of TLS handshake durations in seconds
    tls_handshake_time: Box<Histogram>,

    /// Total number of connections to upstream servers, labeled by upstream
    upstream_connections: Box<IntGaugeVec>,

    /// Current number of active upstream connections, labeled by upstream
    upstream_connections_current: Box<IntGaugeVec>,

    /// Histogram of TCP connection times to upstream servers in seconds, labeled by upstream
    upstream_tcp_connect_time: Box<HistogramVec>,

    /// Histogram of TLS handshake times with upstream servers in seconds, labeled by upstream
    upstream_tls_handshake_time: Box<HistogramVec>,

    /// Count of upstream connection reuses, labeled by upstream
    upstream_reuses: Box<IntCounterVec>,

    /// Histogram of upstream request processing times in seconds, labeled by upstream
    upstream_processing_time: Box<HistogramVec>,

    /// Histogram of upstream response times in seconds, labeled by upstream
    upstream_response_time: Box<HistogramVec>,

    /// Histogram of cache lookup times in seconds
    cache_lookup_time: Box<Histogram>,

    /// Histogram of cache lock acquisition times in seconds
    cache_lock_time: Box<Histogram>,

    /// Current number of cache read operations in progress
    cache_reading: Box<IntGauge>,

    /// Current number of cache write operations in progress
    cache_writing: Box<IntGauge>,

    /// Histogram of response compression ratios
    compression_ratio: Box<Histogram>,

    /// Current memory usage in megabytes
    memory: Box<IntGauge>,

    /// Current number of open file descriptors
    fd_count: Box<IntGauge>,

    /// Current number of IPv4 TCP connections
    tcp_count: Box<IntGauge>,

    /// Current number of IPv6 TCP connections
    tcp6_count: Box<IntGauge>,
}

/// Milliseconds to seconds conversion factor
const SECOND: f64 = 1000.0;

impl Prometheus {
    /// Records metrics at the start of request processing.
    ///
    /// # Arguments
    /// * `location` - The routing location identifier for the request
    ///
    /// # Metrics Updated
    /// - Increments total request counter
    /// - Increments current request gauge
    /// - Updates location-specific counters if location is provided
    pub fn before(&self, location: &str) {
        self.http_requests_total.with_label_values(&[""]).inc();
        self.http_requests_current.with_label_values(&[""]).inc();
        if !location.is_empty() {
            self.http_requests_total
                .with_label_values(&[location])
                .inc();
            self.http_requests_current
                .with_label_values(&[location])
                .inc();
        }
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
        let location = &ctx.upstream.location;
        let upstream = &ctx.upstream.name;
        let elapsed = ctx.timing.created_at.elapsed().as_millis();
        let response_time = elapsed as f64 / SECOND;
        // payload size(kb)
        let payload_size = ctx.state.payload_size as f64 / 1024.0;
        let mut code = 0;
        if let Some(status) = &ctx.state.status {
            code = status.as_u16();
        }
        let sent_bytes = session.body_bytes_sent() as u64;
        let sent = sent_bytes as f64 / 1024.0;

        // http response code
        let code_label = match code {
            100..=199 => "1xx",
            200..=299 => "2xx",
            300..=399 => "3xx",
            400..=499 => "4xx",
            500..=599 => "5xx",
            _ => "unknown",
        };
        let mut labels_list: SmallVec<[[&str; 1]; 2]> = SmallVec::new();

        labels_list.push([""]);
        if !location.is_empty() {
            labels_list.push([location]);
        }
        for labels in labels_list.iter() {
            self.http_requests_current.with_label_values(labels).dec();
            self.http_received
                .with_label_values(labels)
                .observe(payload_size);
            self.http_received_bytes
                .with_label_values(labels)
                .inc_by(ctx.state.payload_size as u64);

            // response time x second
            self.http_response_time
                .with_label_values(labels)
                .observe(response_time);

            // response body size(kb)
            self.http_sent.with_label_values(labels).observe(sent);
            if sent_bytes > 0 {
                self.http_sent_bytes
                    .with_label_values(labels)
                    .inc_by(sent_bytes);
            }
        }

        self.http_responses_codes
            .with_label_values(&["", code_label])
            .inc();

        if !location.is_empty() {
            self.http_responses_codes
                .with_label_values(&[location, code_label])
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
            let upstream_labels = &[upstream.as_str()];
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
        if let Some(features) = &ctx.features {
            if let Some(compression_stat) = &features.compression_stat {
                self.compression_ratio.observe(compression_stat.ratio());
            }
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
        self.r.gather()
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
    if count % offset != 0 {
        return Ok(false);
    }
    // http push metrics
    let encoder = ProtobufEncoder::new();
    let mut buf = Vec::new();

    for mf in params.p.gather() {
        let _ = encoder.encode(&[mf], &mut buf);
    }
    let client = reqwest::Client::new();
    let mut builder = client
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
                    category = LOG_CATEGORY,
                    name = params.name,
                    status = res.status().to_string(),
                    "push prometheus fail"
                );
            }
        },
        Err(e) => {
            error!(
                category = LOG_CATEGORY,
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
        if key == "interval" {
            if let Ok(v) = parse_duration(&value) {
                interval = v;
            }
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
    };
    let offset = ((interval.as_secs() / 60) as u32).max(1);

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
        // return the boxed original metric
        Ok(Box::new(metric))
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
        &[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
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
        "pingap tcp connections"
    )?;
    let tcp6_count = register_metric!(
        r,
        new_int_gauge,
        server,
        "pingap_tcp6_count",
        "pingap tcp6 connections"
    )?;

    let collectors: Vec<Box<dyn Collector>> =
        vec![CACHE_READING_TIME.clone(), CACHE_WRITING_TIME.clone()];
    for c in collectors {
        r.register(c).map_err(|e| Error::Prometheus {
            message: e.to_string(),
        })?;
    }

    Ok(Prometheus {
        r,
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
        p.before("");

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
                features: Some(Features {
                    compression_stat: Some(CompressionStat {
                        in_bytes: 1024,
                        out_bytes: 512,
                        duration: Duration::from_millis(20),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                upstream: pingap_core::UpstreamInfo {
                    name: "upstream".to_string(),
                    location: "lo".to_string(),
                    reused: true,
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        let buf = p.metrics().unwrap();
        assert_eq!(225, std::str::from_utf8(&buf).unwrap().split('\n').count());
    }
}
