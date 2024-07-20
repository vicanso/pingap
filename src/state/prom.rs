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

use super::{Error, Result, State};
use crate::service::{CommonServiceTask, ServiceTask};
use crate::util;
use async_trait::async_trait;
use humantime::parse_duration;
use pingora::proxy::Session;
use prometheus::ProtobufEncoder;
use prometheus::{
    core::Collector, Encoder, Histogram, HistogramOpts, IntCounter,
    IntCounterVec, IntGauge, Opts, Registry, TextEncoder,
};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};
use url::Url;

pub struct Prometheus {
    r: Registry,
    http_request_accepted: IntCounter,
    http_request_processing: IntGauge,
    http_reqesut_body_received: Histogram,
    http_response_codes: IntCounterVec,
    http_response_time: Histogram,
    http_response_body_sent: Histogram,
    connection_reused: IntCounter,
    tls_handshake_time: Histogram,
    upstream_tcp_connect_time: Histogram,
    upstream_tls_handshake_time: Histogram,
    upstream_reused: IntCounter,
    upstream_processing_time: Histogram,
    upstream_response_time: Histogram,
    cache_lookup_time: Histogram,
    cache_lock_time: Histogram,
    compression_ratio: Histogram,
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
        self.http_response_time.observe(ms as f64 / SECOND);
        if ctx.connection_reused {
            self.connection_reused.inc();
        }
        if let Some(tls_handshake_time) = ctx.tls_handshake_time {
            self.tls_handshake_time
                .observe(tls_handshake_time as f64 / SECOND);
        }
        self.http_response_body_sent
            .observe(session.body_bytes_sent() as f64 / 1024.0);
        if ctx.payload_size != 0 {
            self.http_reqesut_body_received
                .observe(ctx.payload_size as f64 / 1024.0);
        }
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
        if let Some(cache_lookup_time) = ctx.cache_lookup_time {
            self.cache_lookup_time
                .observe(cache_lookup_time as f64 / SECOND);
        }
        if let Some(cache_lock_time) = ctx.cache_lock_time {
            self.cache_lock_time
                .observe(cache_lock_time as f64 / SECOND);
        }
        if let Some(compression_stat) = &ctx.compression_stat {
            self.compression_ratio.observe(compression_stat.ratio());
        }
    }
    fn gather(&self) -> Vec<prometheus::proto::MetricFamily> {
        self.r.gather()
    }
    pub fn metrics(&self) -> Result<Vec<u8>> {
        let mut buffer = vec![];
        let encoder = TextEncoder::new();
        let metrics = self.r.gather();
        encoder
            .encode(&metrics, &mut buffer)
            .map_err(|e| Error::Prometheus { source: e })?;
        Ok(buffer)
    }
}

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
    for (key, value) in info.query_pairs().into_iter() {
        if key == "interval" {
            if let Ok(v) = parse_duration(&value) {
                interval = v;
            }
        }
    }

    let push = PrometheusPush {
        name: name.to_string(),
        url: info.to_string(),
        username,
        password,
        p,
    };
    Ok(CommonServiceTask::new(
        &format!("Prometheus push service, server:{name}"),
        interval,
        push,
    ))
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
}

fn new_int_counter(server: &str, name: &str, help: &str) -> Result<IntCounter> {
    let mut opts = Opts::new(name, help);
    opts = opts.const_label("server", server);
    let counter = IntCounter::with_opts(opts)
        .map_err(|e| Error::Prometheus { source: e })?;
    Ok(counter)
}

fn new_int_gauge(server: &str, name: &str, help: &str) -> Result<IntGauge> {
    let mut opts = Opts::new(name, help);
    opts = opts.const_label("server", server);
    let guage = IntGauge::with_opts(opts)
        .map_err(|e| Error::Prometheus { source: e })?;
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
    let guage = IntCounterVec::new(opts, label_names)
        .map_err(|e| Error::Prometheus { source: e })?;
    Ok(guage)
}

fn new_histogram(
    server: &str,
    name: &str,
    help: &str,
    buckets: &[f64],
) -> Result<Histogram> {
    let mut opts = Opts::new(name, help);
    opts = opts.const_label("server", server);
    let histogram = Histogram::with_opts(HistogramOpts {
        common_opts: opts,
        buckets: Vec::from(buckets),
    })
    .map_err(|e| Error::Prometheus { source: e })?;
    Ok(histogram)
}

/// Create a prometheus metrics for server
pub fn new_prometheus(server: &str) -> Result<Prometheus> {
    let r = Registry::new();
    let http_request_accepted = new_int_counter(
        server,
        "pingap_http_request_accepted",
        "pingap http request accepted count",
    )?;
    let http_request_processing = new_int_gauge(
        server,
        "pingap_http_request_processing",
        "pingap http request processing count",
    )?;
    let http_reqesut_body_received = new_histogram(
        server,
        "pingap_http_reqesut_body_received",
        "pingap http request body received(KB)",
        &[1.0, 5.0, 10.0, 50.0, 100.0, 1000.0],
    )?;
    let http_response_codes = new_int_counter_vec(
        server,
        "pingap_http_response_codes",
        "pingap http response codes",
        &["status_code"],
    )?;
    let http_response_time = new_histogram(
        server,
        "pingap_http_response_time",
        "pingap http response time(second)",
        &[
            0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
        ],
    )?;
    let http_response_body_sent = new_histogram(
        server,
        "pingap_http_response_body_sent",
        "pingap http resonse body send(KB)",
        &[1.0, 5.0, 10.0, 50.0, 100.0, 1000.0, 10000.0],
    )?;
    let connection_reused = new_int_counter(
        server,
        "pingap_connection_reused",
        "pingap connection reused count",
    )?;
    let tls_handshake_time = new_histogram(
        server,
        "pingap_tls_handshake_time",
        "pingap tls handshake time(second)",
        &[0.01, 0.05, 0.1, 0.5, 1.0],
    )?;

    let upstream_tcp_connect_time = new_histogram(
        server,
        "pingap_upstream_tcp_connect_time",
        "pingap upstream tcp connect time(second)",
        &[0.005, 0.01, 0.05, 0.1, 0.5, 1.0],
    )?;
    let upstream_tls_handshake_time = new_histogram(
        server,
        "pingap_upstream_tls_handshake_time",
        "pingap upstream tsl handshake time(second)",
        &[0.01, 0.05, 0.1, 0.5, 1.0],
    )?;
    let upstream_reused = new_int_counter(
        server,
        "pingap_upstream_reused",
        "pingap upstream reused count",
    )?;
    let upstream_processing_time = new_histogram(
        server,
        "pingap_upstream_processing_time",
        "pingap upstream processing time(second)",
        &[0.01, 0.02, 0.1, 0.5, 1.0, 5.0, 10.0],
    )?;
    let upstream_response_time = new_histogram(
        server,
        "pingap_upstream_response_time",
        "pingap upstream response time(second)",
        &[0.005, 0.01, 0.05, 0.1, 0.5, 1.0],
    )?;
    let cache_lookup_time = new_histogram(
        server,
        "pingap_cache_lookup_time",
        "pingap cache lookup time(second)",
        &[0.001, 0.005, 0.01, 0.05, 0.1, 1.0],
    )?;
    let cache_lock_time = new_histogram(
        server,
        "pingap_cache_lock_time",
        "pingap cache lock time(second)",
        &[0.01, 0.05, 0.1, 1.0, 3.0],
    )?;
    let compression_ratio = new_histogram(
        server,
        "pingap_compression_ratio",
        "pingap response compression ratio",
        &[1.0, 2.0, 3.0, 5.0, 10.0],
    )?;

    let collectors: Vec<Box<dyn Collector>> = vec![
        Box::new(http_request_accepted.clone()),
        Box::new(http_request_processing.clone()),
        Box::new(http_reqesut_body_received.clone()),
        Box::new(http_response_codes.clone()),
        Box::new(http_response_time.clone()),
        Box::new(http_response_body_sent.clone()),
        Box::new(connection_reused.clone()),
        Box::new(tls_handshake_time.clone()),
        Box::new(upstream_tcp_connect_time.clone()),
        Box::new(upstream_tls_handshake_time.clone()),
        Box::new(upstream_reused.clone()),
        Box::new(upstream_processing_time.clone()),
        Box::new(upstream_response_time.clone()),
        Box::new(cache_lookup_time.clone()),
        Box::new(cache_lock_time.clone()),
        Box::new(compression_ratio.clone()),
    ];
    for c in collectors {
        r.register(c).map_err(|e| Error::Prometheus { source: e })?;
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
        upstream_tcp_connect_time,
        upstream_tls_handshake_time,
        upstream_reused,
        upstream_processing_time,
        upstream_response_time,
        cache_lookup_time,
        cache_lock_time,
        compression_ratio,
    })
}
