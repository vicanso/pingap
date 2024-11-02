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
use crate::service::{CommonServiceTask, ServiceTask};
use crate::util;
use async_trait::async_trait;
use humantime::parse_duration;
use once_cell::sync::Lazy;
use pingora::proxy::Session;
use prometheus::core::Collector;
use prometheus::{Encoder, Opts, ProtobufEncoder, Registry, TextEncoder};
use prometheus::{
    Histogram, HistogramOpts, IntCounter, IntCounterVec, IntGauge, IntGaugeVec,
};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};
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

pub struct Prometheus {
    r: Registry,
    http_request_accepted: Box<IntCounter>,
    http_request_processing: Box<IntGauge>,
    http_reqesut_body_received: Box<Histogram>,
    http_response_codes: Box<IntCounterVec>,
    http_response_time: Box<Histogram>,
    http_response_body_sent: Box<Histogram>,
    connection_reused: Box<IntCounter>,
    tls_handshake_time: Box<Histogram>,
    upstream_connected: Box<IntGaugeVec>,
    upstream_processing: Box<IntGaugeVec>,
    upstream_tcp_connect_time: Box<Histogram>,
    upstream_tls_handshake_time: Box<Histogram>,
    upstream_reused: Box<IntCounter>,
    upstream_processing_time: Box<Histogram>,
    upstream_response_time: Box<Histogram>,
    cache_lookup_time: Box<Histogram>,
    cache_lock_time: Box<Histogram>,
    cache_reading: Box<IntGauge>,
    cache_writing: Box<IntGauge>,
    compression_ratio: Box<Histogram>,
    memory: Box<IntGauge>,
    fd_count: Box<IntGauge>,
    tcp_count: Box<IntGauge>,
    tcp6_count: Box<IntGauge>,
}

const SECOND: f64 = 1000.0;

impl Prometheus {
    pub fn before(&self) {
        self.http_request_accepted.inc();
        self.http_request_processing.inc();
    }
    pub fn after(&self, session: &Session, ctx: &State) {
        let ms = (util::now().as_millis() as u64) - ctx.created_at;
        let mut code = 0;
        if let Some(status) = &ctx.status {
            code = status.as_u16();
        }
        self.http_request_processing.dec();

        // http response code
        let label_values = match code {
            100..=199 => Some(["1xx"]),
            200..=299 => Some(["2xx"]),
            300..=399 => Some(["3xx"]),
            400..=499 => Some(["4xx"]),
            500..=599 => Some(["5xx"]),
            _ => None,
        };
        if let Some(label_values) = &label_values {
            self.http_response_codes
                .with_label_values(label_values)
                .inc();
        }

        // response time x second
        self.http_response_time.observe(ms as f64 / SECOND);

        // reused connection
        if ctx.connection_reused {
            self.connection_reused.inc();
        }

        if let Some(tls_handshake_time) = ctx.tls_handshake_time {
            self.tls_handshake_time
                .observe(tls_handshake_time as f64 / SECOND);
        }
        // response body size(kb)
        self.http_response_body_sent
            .observe(session.body_bytes_sent() as f64 / 1024.0);

        // payload size(kb)
        if ctx.payload_size != 0 {
            self.http_reqesut_body_received
                .observe(ctx.payload_size as f64 / 1024.0);
        }

        // location stats
        if let Some(lo) = &ctx.location {
            if let Some(count) = ctx.upstream_connected {
                self.upstream_connected
                    .with_label_values(&[&lo.upstream])
                    .set(count as i64);
            }
            if let Some(count) = ctx.upstream_processing {
                self.upstream_processing
                    .with_label_values(&[&lo.upstream])
                    .set(count as i64);
            }
        }

        // upstream stats
        if let Some(upstream_tcp_connect_time) = ctx.upstream_tcp_connect_time {
            self.upstream_tcp_connect_time
                .observe(upstream_tcp_connect_time as f64 / SECOND);
        }
        if let Some(upstream_tls_handshake_time) =
            ctx.upstream_tls_handshake_time
        {
            self.upstream_tls_handshake_time
                .observe(upstream_tls_handshake_time as f64 / SECOND);
        }
        if ctx.upstream_reused {
            self.upstream_reused.inc();
        }
        if let Some(upstream_processing_time) = ctx.upstream_processing_time {
            self.upstream_processing_time
                .observe(upstream_processing_time as f64 / SECOND);
        }
        if let Some(upstream_response_time) = ctx.upstream_response_time {
            self.upstream_response_time
                .observe(upstream_response_time as f64 / SECOND);
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

/// Create a new prometheus push service
pub fn new_prometheus_push_service(
    name: &str,
    url: &str,
    p: Arc<Prometheus>,
) -> Result<CommonServiceTask> {
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

    let push = PrometheusPush {
        name: name.to_string(),
        url,
        username,
        password,
        p,
    };
    Ok(CommonServiceTask::new(interval, push))
}

struct PrometheusPush {
    name: String,
    url: String,
    p: Arc<Prometheus>,
    username: String,
    password: Option<String>,
}

#[async_trait]
impl ServiceTask for PrometheusPush {
    async fn run(&self) -> Option<bool> {
        // http push metrics
        let encoder = ProtobufEncoder::new();
        let mut buf = Vec::new();

        for mf in self.p.gather() {
            let _ = encoder.encode(&[mf], &mut buf);
        }
        let client = reqwest::Client::new();
        let mut builder = client
            .post(&self.url)
            .header(http::header::CONTENT_TYPE, encoder.format_type())
            .body(buf);

        if !self.username.is_empty() {
            builder = builder.basic_auth(&self.username, self.password.clone());
        }

        match builder.timeout(Duration::from_secs(60)).send().await {
            Ok(res) => {
                if res.status().as_u16() >= 400 {
                    error!(
                        name = self.name,
                        status = res.status().to_string(),
                        "push prometheus fail"
                    );
                } else {
                    info!(name = self.name, "push prometheus success");
                }
            },
            Err(e) => {
                error!(
                    name = self.name,
                    error = e.to_string(),
                    "push prometheus fail"
                );
            },
        }

        None
    }
    fn description(&self) -> String {
        "PrometheusPush".to_string()
    }
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
    let guage = IntGauge::with_opts(opts).map_err(|e| Error::Prometheus {
        message: e.to_string(),
    })?;
    Ok(guage)
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

fn new_intgauge_vec(
    server: &str,
    name: &str,
    help: &str,
    label_names: &[&str],
) -> Result<IntGaugeVec> {
    let mut opts = Opts::new(name, help);
    opts = opts.const_label("server", server);
    let guage =
        IntGaugeVec::new(opts, label_names).map_err(|e| Error::Prometheus {
            message: e.to_string(),
        })?;
    Ok(guage)
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

/// Create a prometheus metrics for server
pub fn new_prometheus(server: &str) -> Result<Prometheus> {
    let r = Registry::new();
    let http_request_accepted = Box::new(new_int_counter(
        server,
        "pingap_http_request_accepted",
        "pingap http request accepted count",
    )?);
    let http_request_processing = Box::new(new_int_gauge(
        server,
        "pingap_http_request_processing",
        "pingap http request processing count",
    )?);
    let http_reqesut_body_received = Box::new(new_histogram(
        server,
        "pingap_http_reqesut_body_received",
        "pingap http request body received(KB)",
        &[1.0, 5.0, 10.0, 50.0, 100.0, 1000.0],
    )?);
    let http_response_codes = Box::new(new_int_counter_vec(
        server,
        "pingap_http_response_codes",
        "pingap http response codes",
        &["status_code"],
    )?);
    let http_response_time = Box::new(new_histogram(
        server,
        "pingap_http_response_time",
        "pingap http response time(second)",
        &[
            0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
        ],
    )?);
    let http_response_body_sent = Box::new(new_histogram(
        server,
        "pingap_http_response_body_sent",
        "pingap http resonse body send(KB)",
        &[1.0, 5.0, 10.0, 50.0, 100.0, 1000.0, 10000.0],
    )?);
    let connection_reused = Box::new(new_int_counter(
        server,
        "pingap_connection_reused",
        "pingap connection reused count",
    )?);
    let tls_handshake_time = Box::new(new_histogram(
        server,
        "pingap_tls_handshake_time",
        "pingap tls handshake time(second)",
        &[0.01, 0.05, 0.1, 0.5, 1.0],
    )?);

    let upstream_connected = Box::new(new_intgauge_vec(
        server,
        "pingap_upstream_connected",
        "pingap upstream connnected count",
        &["upstream"],
    )?);
    let upstream_processing = Box::new(new_intgauge_vec(
        server,
        "pingap_upstream_processing",
        "pingap upstream processing count",
        &["upstream"],
    )?);
    let upstream_tcp_connect_time = Box::new(new_histogram(
        server,
        "pingap_upstream_tcp_connect_time",
        "pingap upstream tcp connect time(second)",
        &[0.005, 0.01, 0.05, 0.1, 0.5, 1.0],
    )?);
    let upstream_tls_handshake_time = Box::new(new_histogram(
        server,
        "pingap_upstream_tls_handshake_time",
        "pingap upstream tsl handshake time(second)",
        &[0.01, 0.05, 0.1, 0.5, 1.0],
    )?);
    let upstream_reused = Box::new(new_int_counter(
        server,
        "pingap_upstream_reused",
        "pingap upstream reused count",
    )?);
    let upstream_processing_time = Box::new(new_histogram(
        server,
        "pingap_upstream_processing_time",
        "pingap upstream processing time(second)",
        &[0.01, 0.02, 0.1, 0.5, 1.0, 5.0, 10.0],
    )?);
    let upstream_response_time = Box::new(new_histogram(
        server,
        "pingap_upstream_response_time",
        "pingap upstream response time(second)",
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
        http_request_accepted.clone(),
        http_request_processing.clone(),
        http_reqesut_body_received.clone(),
        http_response_codes.clone(),
        http_response_time.clone(),
        http_response_body_sent.clone(),
        connection_reused.clone(),
        tls_handshake_time.clone(),
        upstream_connected.clone(),
        upstream_processing.clone(),
        upstream_tcp_connect_time.clone(),
        upstream_tls_handshake_time.clone(),
        upstream_reused.clone(),
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
        http_request_accepted,
        http_request_processing,
        http_reqesut_body_received,
        http_response_codes,
        http_response_time,
        http_response_body_sent,
        connection_reused,
        tls_handshake_time,
        upstream_connected,
        upstream_processing,
        upstream_tcp_connect_time,
        upstream_tls_handshake_time,
        upstream_reused,
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
    use std::time::Duration;

    use super::new_prometheus;
    use crate::{
        state::{CompressionStat, State},
        util,
    };
    use http::StatusCode;
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
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
        p.before();

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
                ..Default::default()
            },
        );
        let buf = p.metrics().unwrap();
        assert_eq!(186, std::str::from_utf8(&buf).unwrap().split('\n').count());
    }
}
