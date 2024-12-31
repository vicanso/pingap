// Copyright 2024 Tree xie.
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

use super::{get_hostname, get_process_system_info, Error, Result, State};
use crate::service::Error as ServiceError;
use crate::service::SimpleServiceTaskFuture;
use crate::util;
use humantime::parse_duration;
use once_cell::sync::Lazy;
use pingora::proxy::Session;
use prometheus::core::Collector;
use prometheus::{
    Encoder, HistogramVec, Opts, ProtobufEncoder, Registry, TextEncoder,
};
use prometheus::{
    Histogram, HistogramOpts, IntCounter, IntCounterVec, IntGauge, IntGaugeVec,
};
use std::sync::Arc;
use std::time::Duration;
use tracing::error;
use url::Url;

static HOST_NAME_TAG: &str = "$HOSTNAME";

pub static CACHE_READING_TIME: Lazy<Box<Histogram>> = Lazy::new(|| {
    Box::new(
        new_histogram(
            "",
            "pingap_cache_storage_read_time",
            "pingap cache storage read time(second)",
            &[0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0],
        )
        .unwrap(),
    )
});
pub static CACHE_WRITING_TIME: Lazy<Box<Histogram>> = Lazy::new(|| {
    Box::new(
        new_histogram(
            "",
            "pingap_cache_storage_write_time",
            "pingap cache storage write time(second)",
            &[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
        )
        .unwrap(),
    )
});

/// Prometheus metrics collector for monitoring HTTP server performance and resource usage
pub struct Prometheus {
    /// Prometheus registry for collecting all metrics
    r: Registry,
    /// Total number of HTTP requests received, labeled by location
    http_requests_total: Box<IntCounterVec>,
    /// Current number of active HTTP requests, labeled by location
    http_requests_current: Box<IntGaugeVec>,
    /// Histogram of request payload sizes received from clients in KB, labeled by location
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

const SECOND: f64 = 1000.0;

impl Prometheus {
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
    pub fn after(&self, session: &Session, ctx: &State) {
        let mut location = "";
        let mut upstream = "";
        if let Some(lo) = &ctx.location {
            location = &lo.name;
            upstream = &lo.upstream;
        }
        let response_time =
            ((util::now().as_millis() as u64) - ctx.created_at) as f64 / SECOND;
        // payload size(kb)
        let payload_size = ctx.payload_size as f64 / 1024.0;
        let mut code = 0;
        if let Some(status) = &ctx.status {
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
        let mut labels_list = Vec::with_capacity(2);
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
                .inc_by(ctx.payload_size as u64);

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
        if ctx.connection_reused {
            self.connection_reuses.inc();
        }

        if let Some(tls_handshake_time) = ctx.tls_handshake_time {
            self.tls_handshake_time
                .observe(tls_handshake_time as f64 / SECOND);
        }

        // upstream
        if !upstream.is_empty() {
            let upstream_labels = &[upstream];
            if let Some(count) = ctx.upstream_connected {
                self.upstream_connections
                    .with_label_values(upstream_labels)
                    .set(count as i64);
            }
            if let Some(count) = ctx.upstream_processing {
                self.upstream_connections_current
                    .with_label_values(upstream_labels)
                    .set(count as i64);
            }
            // upstream stats
            if let Some(upstream_tcp_connect_time) =
                ctx.upstream_tcp_connect_time
            {
                self.upstream_tcp_connect_time
                    .with_label_values(upstream_labels)
                    .observe(upstream_tcp_connect_time as f64 / SECOND);
            }
            if let Some(upstream_tls_handshake_time) =
                ctx.upstream_tls_handshake_time
            {
                self.upstream_tls_handshake_time
                    .with_label_values(upstream_labels)
                    .observe(upstream_tls_handshake_time as f64 / SECOND);
            }
            if ctx.upstream_reused {
                self.upstream_reuses
                    .with_label_values(upstream_labels)
                    .inc();
            }
            if let Some(upstream_processing_time) = ctx.upstream_processing_time
            {
                self.upstream_processing_time
                    .with_label_values(upstream_labels)
                    .observe(upstream_processing_time as f64 / SECOND);
            }
            if let Some(upstream_response_time) = ctx.upstream_response_time {
                self.upstream_response_time
                    .with_label_values(upstream_labels)
                    .observe(upstream_response_time as f64 / SECOND);
            }
        }

        // cache stats
        if let Some(cache_lookup_time) = ctx.cache_lookup_time {
            self.cache_lookup_time
                .observe(cache_lookup_time as f64 / SECOND);
        }
        if let Some(cache_lock_time) = ctx.cache_lock_time {
            self.cache_lock_time
                .observe(cache_lock_time as f64 / SECOND);
        }
        if let Some(cache_reading) = ctx.cache_reading {
            self.cache_reading.set(cache_reading as i64);
        }
        if let Some(cache_writing) = ctx.cache_writing {
            self.cache_writing.set(cache_writing as i64);
        }

        // compression stats
        if let Some(compression_stat) = &ctx.compression_stat {
            self.compression_ratio.observe(compression_stat.ratio());
        }
    }
    fn gather(&self) -> Vec<prometheus::proto::MetricFamily> {
        let info = get_process_system_info();
        self.memory.set(info.memory_mb as i64);
        self.fd_count.set(info.fd_count as i64);
        self.tcp_count.set(info.tcp_count as i64);
        self.tcp6_count.set(info.tcp6_count as i64);
        self.r.gather()
    }
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

#[derive(Clone)]
struct PrometheusPushParams {
    name: String,
    url: String,
    p: Arc<Prometheus>,
    username: String,
    password: Option<String>,
}

async fn do_push(
    count: u32,
    offset: u32,
    params: PrometheusPushParams,
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
                    name = params.name,
                    status = res.status().to_string(),
                    "push prometheus fail"
                );
            }
        },
        Err(e) => {
            error!(
                name = params.name,
                error = e.to_string(),
                "push prometheus fail"
            );
        },
    };
    Ok(true)
}

/// Create a new prometheus push service
pub fn new_prometheus_push_service(
    name: &str,
    url: &str,
    p: Arc<Prometheus>,
) -> Result<(String, SimpleServiceTaskFuture)> {
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

    let task: SimpleServiceTaskFuture = Box::new(move |count: u32| {
        Box::pin({
            let value = params.clone();
            async move {
                let value = value.clone();
                do_push(count, offset, value).await
            }
        })
    });
    Ok(("prometheusPush".to_string(), task))
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

/// Create a prometheus metrics for server
pub fn new_prometheus(server: &str) -> Result<Prometheus> {
    let r = Registry::new();
    let http_requests_total = Box::new(new_int_counter_vec(
        server,
        "pingap_http_requests_total",
        "pingap total http requests",
        &["location"],
    )?);
    let http_requests_current = Box::new(new_int_gauge_vec(
        server,
        "pingap_http_requests_current",
        "pingap current http requests",
        &["location"],
    )?);
    let http_received = Box::new(new_histogram_vec(
        server,
        "pingap_http_received",
        "pingap http received from clients(KB)",
        &["location"],
        &[1.0, 5.0, 10.0, 50.0, 100.0, 1000.0],
    )?);
    let http_received_bytes = Box::new(new_int_counter_vec(
        server,
        "pingap_http_received_bytes",
        "pingap http received from clients(bytes)",
        &["location"],
    )?);
    let http_responses_codes = Box::new(new_int_counter_vec(
        server,
        "pingap_http_responses_codes",
        "pingap total responses sent to clients by code",
        &["location", "code"],
    )?);
    let http_response_time = Box::new(new_histogram_vec(
        server,
        "pingap_http_response_time",
        "pingap http response time(second)",
        &["location"],
        &[
            0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
        ],
    )?);
    let http_sent = Box::new(new_histogram_vec(
        server,
        "pingap_http_sent",
        "pingap http sent to clients(KB)",
        &["location"],
        &[1.0, 5.0, 10.0, 50.0, 100.0, 1000.0, 10000.0],
    )?);
    let http_sent_bytes = Box::new(new_int_counter_vec(
        server,
        "pingap_http_sent_bytes",
        "pingap http sent to clients(bytes)",
        &["location"],
    )?);
    let connection_reuses = Box::new(new_int_counter(
        server,
        "pingap_connection_reuses",
        "pingap connection reuses during tcp connect",
    )?);
    let tls_handshake_time = Box::new(new_histogram(
        server,
        "pingap_tls_handshake_time",
        "pingap tls handshake time(second)",
        &[0.01, 0.05, 0.1, 0.5, 1.0],
    )?);

    let upstream_connections = Box::new(new_int_gauge_vec(
        server,
        "pingap_upstream_connections",
        "pingap connected connections of upstream",
        &["upstream"],
    )?);
    let upstream_connections_current = Box::new(new_int_gauge_vec(
        server,
        "pingap_upstream_connections_current",
        "pingap current connections of upstream",
        &["upstream"],
    )?);
    let upstream_tcp_connect_time = Box::new(new_histogram_vec(
        server,
        "pingap_upstream_tcp_connect_time",
        "pingap upstream tcp connect time(second)",
        &["upstream"],
        &[0.005, 0.01, 0.05, 0.1, 0.5, 1.0],
    )?);
    let upstream_tls_handshake_time = Box::new(new_histogram_vec(
        server,
        "pingap_upstream_tls_handshake_time",
        "pingap upstream tsl handshake time(second)",
        &["upstream"],
        &[0.01, 0.05, 0.1, 0.5, 1.0],
    )?);
    let upstream_reuses = Box::new(new_int_counter_vec(
        server,
        "pingap_upstream_reuses",
        "pingap connection reuse during connect to upstream",
        &["upstream"],
    )?);
    let upstream_processing_time = Box::new(new_histogram_vec(
        server,
        "pingap_upstream_processing_time",
        "pingap upstream processing time(second)",
        &["upstream"],
        &[0.01, 0.02, 0.1, 0.5, 1.0, 5.0, 10.0],
    )?);
    let upstream_response_time = Box::new(new_histogram_vec(
        server,
        "pingap_upstream_response_time",
        "pingap upstream response time(second)",
        &["upstream"],
        &[0.005, 0.01, 0.05, 0.1, 0.5, 1.0],
    )?);
    let cache_lookup_time = Box::new(new_histogram(
        server,
        "pingap_cache_lookup_time",
        "pingap cache lookup time(second)",
        &[0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0],
    )?);
    let cache_lock_time = Box::new(new_histogram(
        server,
        "pingap_cache_lock_time",
        "pingap cache lock time(second)",
        &[0.01, 0.05, 0.1, 1.0, 3.0],
    )?);
    let cache_reading = Box::new(new_int_gauge(
        server,
        "pingap_cache_reading",
        "pingap cache reading count",
    )?);
    let cache_writing = Box::new(new_int_gauge(
        server,
        "pingap_cache_writing",
        "pingap cache writing count",
    )?);
    let compression_ratio = Box::new(new_histogram(
        server,
        "pingap_compression_ratio",
        "pingap response compression ratio",
        &[1.0, 2.0, 3.0, 5.0, 10.0],
    )?);

    let memory = Box::new(new_int_gauge(
        server,
        "pingap_memory",
        "pingap memory size(mb)",
    )?);
    let fd_count = Box::new(new_int_gauge(
        server,
        "pingap_fd_count",
        "pingap open file count",
    )?);
    let tcp_count = Box::new(new_int_gauge(
        server,
        "pingap_tcp_count",
        "pingap tcp connections",
    )?);
    let tcp6_count = Box::new(new_int_gauge(
        server,
        "pingap_tcp6_count",
        "pingap tcp6 connections",
    )?);

    let collectors: Vec<Box<dyn Collector>> = vec![
        http_requests_total.clone(),
        http_requests_current.clone(),
        http_received.clone(),
        http_received_bytes.clone(),
        http_responses_codes.clone(),
        http_response_time.clone(),
        http_sent.clone(),
        http_sent_bytes.clone(),
        connection_reuses.clone(),
        tls_handshake_time.clone(),
        upstream_connections.clone(),
        upstream_connections_current.clone(),
        upstream_tcp_connect_time.clone(),
        upstream_tls_handshake_time.clone(),
        upstream_reuses.clone(),
        upstream_processing_time.clone(),
        upstream_response_time.clone(),
        cache_lookup_time.clone(),
        cache_lock_time.clone(),
        cache_reading.clone(),
        cache_writing.clone(),
        CACHE_READING_TIME.clone(),
        CACHE_WRITING_TIME.clone(),
        compression_ratio.clone(),
        memory.clone(),
        fd_count.clone(),
        tcp_count.clone(),
        tcp6_count.clone(),
    ];
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
    use super::new_prometheus;
    use crate::{
        config::LocationConf,
        proxy::Location,
        state::{CompressionStat, State},
        util,
    };
    use http::StatusCode;
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use std::sync::Arc;
    use std::time::Duration;
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

        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some("upstream".to_string()),
                ..Default::default()
            },
        )
        .unwrap();

        p.after(
            &session,
            &State {
                created_at: util::now().as_millis() as u64 - 10,
                status: Some(StatusCode::from_u16(200).unwrap()),
                connection_reused: true,
                tls_handshake_time: Some(1),
                payload_size: 1024,
                upstream_tcp_connect_time: Some(2),
                upstream_tls_handshake_time: Some(3),
                upstream_reused: true,
                upstream_processing_time: Some(10),
                upstream_response_time: Some(5),
                cache_lookup_time: Some(11),
                cache_lock_time: Some(12),
                compression_stat: Some(CompressionStat {
                    in_bytes: 1024,
                    out_bytes: 512,
                    duration: Duration::from_millis(20),
                }),
                location: Some(Arc::new(lo)),
                ..Default::default()
            },
        );
        let buf = p.metrics().unwrap();
        assert_eq!(225, std::str::from_utf8(&buf).unwrap().split('\n').count());
    }
}
