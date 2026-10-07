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
use pingora::cache::{CachePhase, NoCacheReason};
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
use std::sync::atomic::{AtomicU64, Ordering};
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

    /// The exact status codes and the cache results of every request, the
    /// children of the empty `location` label.
    all_status: StatusSeries,
    all_cache: [OnceLock<IntCounter>; CACHE_LABELS.len()],

    /// The children of each location a request was counted against, found
    /// in the vectors once and kept. A request used to look every one of
    /// them up again - nine lookups for its location and five for its
    /// upstream, each a hash of the labels, a read lock on the vector and a
    /// reference count taken and given back - on state all worker threads
    /// share.
    location_series: ArcSwap<HashMap<String, Arc<LocationSeries>>>,

    /// The same for each upstream. An upstream that is removed is dropped
    /// from here together with its series.
    upstream_series: ArcSwap<HashMap<String, Arc<UpstreamSeries>>>,

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

    /// Count of responses by their exact status code, labeled by location
    /// and status
    http_responses_status: IntCounterVec,
    /// Count of the requests a cache was asked about, by what it had for
    /// them, labeled by location and status
    cache_responses: IntCounterVec,
    /// Count of requests whose upstream failed: it could not be connected
    /// to, or the connection broke or timed out
    upstream_errors: IntCounterVec,
    /// Count of the times a request was sent to an upstream again after a
    /// failed connection
    upstream_retries: IntCounterVec,
    /// Count of access log lines dropped because the logger was behind
    access_log_dropped: IntCounter,
    /// Objects the memory cache evicted to stay within its size
    cache_memory_evictions: Mirrored,
    /// Reloads of the configuration, by result
    config_reload_success: Mirrored,
    config_reload_failure: Mirrored,
    /// Whether the last reload of the configuration was applied
    config_last_reload_successful: IntGauge,
    /// Unix time of the last reload that was applied
    config_last_reload_success_time: IntGauge,
}

/// A counter of this registry that follows a count kept for the whole
/// process, by adding what the count has grown by since it was last
/// looked at.
struct Mirrored {
    counter: IntCounter,
    seen: AtomicU64,
}

impl Mirrored {
    fn new(counter: IntCounter) -> Self {
        Self {
            counter,
            seen: AtomicU64::new(0),
        }
    }
    fn follow(&self, value: u64) {
        // The largest that was seen, not the last: two scrapes at once
        // read the count one after the other and may get here the other
        // way round, and with the smaller value put back the difference
        // was added a second time by the next.
        let seen = self.seen.fetch_max(value, Ordering::Relaxed);
        if value > seen {
            self.counter.inc_by(value - seen);
        }
    }
}

/// What a cache had for a request, as the `status` label of
/// `cache_responses`, in the order [`cache_class`] indexes them.
const CACHE_LABELS: [&str; 7] = [
    "hit",
    "miss",
    "expired",
    "stale",
    "revalidated",
    "bypass",
    "uncacheable",
];

/// Index of a cache phase in [`CACHE_LABELS`]; `None` for a request no
/// cache was asked about, or one that never got as far as an answer.
#[inline]
fn cache_class(phase: CachePhase) -> Option<usize> {
    Some(match phase {
        CachePhase::Hit => 0,
        CachePhase::Miss => 1,
        CachePhase::Expired => 2,
        CachePhase::Stale | CachePhase::StaleUpdating => 3,
        CachePhase::Revalidated | CachePhase::RevalidatedNoCache(_) => 4,
        CachePhase::Bypass => 5,
        // Never asked, or not as far as an answer.
        CachePhase::Disabled(NoCacheReason::NeverEnabled)
        | CachePhase::Uninit
        | CachePhase::CacheKey => return None,
        // Asked, had nothing, and what the upstream answered with is not
        // kept: no `Cache-Control` that allows it, a status that is not
        // cached, a body over the limit. pingora switches the cache off
        // for the request then, and left out these were missing from the
        // total a hit ratio is taken of.
        CachePhase::Disabled(_) => 6,
    })
}

/// The counters of the exact status codes of one location, each found in
/// the vector when its code is first answered and kept. A location answers
/// with a handful of codes, so they are a short list that is gone through:
/// no hash of the labels and no lock per request.
#[derive(Default)]
struct StatusSeries(ArcSwap<Vec<(u16, IntCounter)>>);

impl StatusSeries {
    #[inline]
    fn inc(&self, code: u16, new: impl FnOnce() -> IntCounter) {
        let current = self.0.load();
        if let Some((_, counter)) =
            current.iter().find(|(known, _)| *known == code)
        {
            counter.inc();
            return;
        }
        drop(current);
        let created = new();
        self.0.rcu(|current| {
            let mut next = current.as_ref().clone();
            if !next.iter().any(|(known, _)| *known == code) {
                next.push((code, created.clone()));
            }
            next
        });
        created.inc();
    }
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

/// The series of one location. Those every request touches are found when
/// the location is first seen; the others when they first have something
/// to count, so a series still appears only once it has a value.
struct LocationSeries {
    requests_total: IntCounter,
    requests_current: IntGauge,
    received: Histogram,
    received_bytes: IntCounter,
    response_time: Histogram,
    sent: Histogram,
    sent_bytes: OnceLock<IntCounter>,
    codes: [OnceLock<IntCounter>; CODE_LABELS.len()],
    status: StatusSeries,
    cache: [OnceLock<IntCounter>; CACHE_LABELS.len()],
}

/// The series of one upstream, each found when it first has a value.
#[derive(Default)]
struct UpstreamSeries {
    connections: OnceLock<IntGauge>,
    connections_current: OnceLock<IntGauge>,
    tcp_connect_time: OnceLock<Histogram>,
    tls_handshake_time: OnceLock<Histogram>,
    reuses: OnceLock<IntCounter>,
    processing_time: OnceLock<Histogram>,
    response_time: OnceLock<Histogram>,
    errors: OnceLock<IntCounter>,
    retries: OnceLock<IntCounter>,
}

/// Runs `f` on the entry of `name` in a map of series; the entry is made
/// with `new` and added when there is none. Two threads that miss together
/// both make one; one of the two is kept, and both point at the same
/// children of the vectors.
///
/// The entry is used where it is, without taking a reference to it: that
/// would be a count every worker thread writes to, per request.
#[inline]
fn with_series<T, R>(
    map: &ArcSwap<HashMap<String, Arc<T>>>,
    name: &str,
    new: impl FnOnce() -> T,
    f: impl FnOnce(&T) -> R,
) -> R {
    let current = map.load();
    if let Some(found) = current.get(name) {
        return f(found);
    }
    drop(current);
    let created = Arc::new(new());
    map.rcu(|current| {
        let mut next = current.as_ref().clone();
        next.entry(name.to_string())
            .or_insert_with(|| created.clone());
        next
    });
    f(&created)
}

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
        self.with_location(location, |series| {
            series.requests_total.inc();
            series.requests_current.inc();
        });
    }

    /// Runs `f` on the series of `location`.
    #[inline]
    fn with_location<R>(
        &self,
        location: &str,
        f: impl FnOnce(&LocationSeries) -> R,
    ) -> R {
        with_series(
            &self.location_series,
            location,
            || {
                let labels = [location];
                LocationSeries {
                    requests_total: self
                        .http_requests_total
                        .with_label_values(&labels),
                    requests_current: self
                        .http_requests_current
                        .with_label_values(&labels),
                    received: self.http_received.with_label_values(&labels),
                    received_bytes: self
                        .http_received_bytes
                        .with_label_values(&labels),
                    response_time: self
                        .http_response_time
                        .with_label_values(&labels),
                    sent: self.http_sent.with_label_values(&labels),
                    sent_bytes: OnceLock::new(),
                    codes: Default::default(),
                    status: Default::default(),
                    cache: Default::default(),
                }
            },
            f,
        )
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
        // The status itself: `4xx` does not tell a `404` from a `429`. A
        // request that ended without one has none to count, and a code
        // outside what HTTP defines is left to its class: the list of a
        // location stays as short as the codes there are. The label is
        // only written out the first time a code is seen.
        let has_status = (100..=599).contains(&code);
        if has_status {
            self.all_status.inc(code, || {
                self.http_responses_status
                    .with_label_values(&["", code.to_string().as_str()])
            });
        }
        // What the cache had for the request, where one was asked.
        let cache = cache_class(session.cache.phase());
        if let Some(cache) = cache {
            self.all_cache[cache]
                .get_or_init(|| {
                    self.cache_responses
                        .with_label_values(&["", CACHE_LABELS[cache]])
                })
                .inc();
        }

        if !location.is_empty() {
            self.with_location(location, |series| {
                series.requests_current.dec();
                series.received.observe(payload_size);
                series.received_bytes.inc_by(payload_bytes);
                series.response_time.observe(response_time);
                series.sent.observe(sent);
                if sent_bytes > 0 {
                    series
                        .sent_bytes
                        .get_or_init(|| {
                            self.http_sent_bytes.with_label_values(&[location])
                        })
                        .inc_by(sent_bytes);
                }
                series.codes[class]
                    .get_or_init(|| {
                        self.http_responses_codes
                            .with_label_values(&[location, CODE_LABELS[class]])
                    })
                    .inc();
                if has_status {
                    series.status.inc(code, || {
                        self.http_responses_status.with_label_values(&[
                            location,
                            code.to_string().as_str(),
                        ])
                    });
                }
                if let Some(cache) = cache {
                    series.cache[cache]
                        .get_or_init(|| {
                            self.cache_responses.with_label_values(&[
                                location,
                                CACHE_LABELS[cache],
                            ])
                        })
                        .inc();
                }
            });
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
            with_series(
                &self.upstream_series,
                upstream,
                UpstreamSeries::default,
                |series| self.count_upstream(series, upstream_labels, ctx),
            );
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

    /// Counts a finished request against the series of its upstream.
    #[inline]
    fn count_upstream(
        &self,
        series: &UpstreamSeries,
        upstream_labels: &[&str; 1],
        ctx: &Ctx,
    ) {
        if let Some(count) = ctx.upstream.connected_count {
            series
                .connections
                .get_or_init(|| {
                    self.upstream_connections.with_label_values(upstream_labels)
                })
                .set(count as i64);
        }
        if let Some(count) = ctx.upstream.processing_count {
            series
                .connections_current
                .get_or_init(|| {
                    self.upstream_connections_current
                        .with_label_values(upstream_labels)
                })
                .set(count as i64);
        }
        // upstream stats
        if let Some(upstream_tcp_connect_time) = ctx.timing.upstream_tcp_connect
        {
            series
                .tcp_connect_time
                .get_or_init(|| {
                    self.upstream_tcp_connect_time
                        .with_label_values(upstream_labels)
                })
                .observe(upstream_tcp_connect_time as f64 / SECOND);
        }
        if let Some(upstream_tls_handshake_time) =
            ctx.timing.upstream_tls_handshake
        {
            series
                .tls_handshake_time
                .get_or_init(|| {
                    self.upstream_tls_handshake_time
                        .with_label_values(upstream_labels)
                })
                .observe(upstream_tls_handshake_time as f64 / SECOND);
        }
        if ctx.upstream.reused {
            series
                .reuses
                .get_or_init(|| {
                    self.upstream_reuses.with_label_values(upstream_labels)
                })
                .inc();
        }
        if ctx.upstream.retries > 0 {
            series
                .retries
                .get_or_init(|| {
                    self.upstream_retries.with_label_values(upstream_labels)
                })
                .inc_by(u64::from(ctx.upstream.retries));
        }
        // Through the getters, which leave out a phase that never
        // finished. Its field still holds the start marker, a negative
        // number: a HEAD or a 204 has no body to end the response phase,
        // an upstream that never answers none to end the processing one,
        // and each took its marker off the histogram's sum and landed in
        // the fastest bucket.
        if let Some(upstream_processing_time) =
            ctx.get_upstream_processing_time()
        {
            series
                .processing_time
                .get_or_init(|| {
                    self.upstream_processing_time
                        .with_label_values(upstream_labels)
                })
                .observe(upstream_processing_time as f64 / SECOND);
        }
        if let Some(upstream_response_time) = ctx.get_upstream_response_time() {
            series
                .response_time
                .get_or_init(|| {
                    self.upstream_response_time
                        .with_label_values(upstream_labels)
                })
                .observe(upstream_response_time as f64 / SECOND);
        }
    }

    /// Counts a request that failed because of its upstream: no connection
    /// could be made, or the one it had broke or timed out. Called where
    /// the proxy learns of it, with the error at hand: by the end of the
    /// request all that is left of it is a `502` or `504`, which a plugin
    /// or the upstream itself answers with as well.
    pub fn on_upstream_error(&self, upstream: &str) {
        if upstream.is_empty() {
            return;
        }
        with_series(
            &self.upstream_series,
            upstream,
            UpstreamSeries::default,
            |series| {
                series
                    .errors
                    .get_or_init(|| {
                        self.upstream_errors.with_label_values(&[upstream])
                    })
                    .inc();
            },
        );
    }

    /// Counts an access log line that was dropped because the logger was
    /// behind and its channel full.
    pub fn on_access_log_dropped(&self) {
        self.access_log_dropped.inc();
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
        // What is counted for the process as a whole.
        self.cache_memory_evictions
            .follow(pingap_cache::memory_cache_evictions());
        let reloads = super::config_reloads();
        self.config_reload_success.follow(reloads.success);
        self.config_reload_failure.follow(reloads.failure);
        self.config_last_reload_successful
            .set(i64::from(reloads.last_successful));
        if reloads.last_success_at > 0 {
            self.config_last_reload_success_time
                .set(reloads.last_success_at as i64);
        }
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
            let _ = self.upstream_errors.remove_label_values(&labels);
            let _ = self.upstream_retries.remove_label_values(&labels);
            // After the series, not before: what is kept here points at
            // them, and an upstream of this name that comes back has to
            // find its series anew.
            if self.upstream_series.load().contains_key(name) {
                self.upstream_series.rcu(|current| {
                    let mut next = current.as_ref().clone();
                    next.remove(name);
                    next
                });
            }
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
            // Without the url, which may carry a token in its query.
            error!(
                target: LOG_TARGET,
                name = params.name,
                error = %e.without_url(),
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

    let http_responses_status = register_metric!(
        r,
        new_int_counter_vec,
        server,
        "pingap_http_responses_status",
        "pingap http responses by exact status code",
        &["location", "status"]
    )?;
    let cache_responses = register_metric!(
        r,
        new_int_counter_vec,
        server,
        "pingap_cache_responses",
        "pingap requests a cache was asked about, by what it had for them",
        &["location", "status"]
    )?;
    let upstream_errors = register_metric!(
        r,
        new_int_counter_vec,
        server,
        "pingap_upstream_errors",
        "pingap requests that failed because of their upstream",
        &["upstream"]
    )?;
    let upstream_retries = register_metric!(
        r,
        new_int_counter_vec,
        server,
        "pingap_upstream_retries",
        "pingap retries of requests after a failed upstream connection",
        &["upstream"]
    )?;
    let access_log_dropped = register_metric!(
        r,
        new_int_counter,
        server,
        "pingap_access_log_dropped",
        "pingap access log lines dropped because the logger was behind"
    )?;
    let cache_memory_evictions = register_metric!(
        r,
        new_int_counter,
        server,
        "pingap_cache_memory_evictions",
        "pingap objects evicted from the memory cache to stay within its size"
    )?;
    let config_reloads = register_metric!(
        r,
        new_int_counter_vec,
        server,
        "pingap_config_reloads",
        "pingap reloads of the configuration by result",
        &["result"]
    )?;
    let config_last_reload_successful = register_metric!(
        r,
        new_int_gauge,
        server,
        "pingap_config_last_reload_successful",
        "pingap whether the last reload of the configuration was applied"
    )?;
    let config_last_reload_success_time = register_metric!(
        r,
        new_int_gauge,
        server,
        "pingap_config_last_reload_success_timestamp_seconds",
        "pingap unix time the configuration was last loaded or reloaded"
    )?;
    // The configuration this process runs was loaded when it started.
    config_last_reload_successful.set(1);
    config_last_reload_success_time.set(pingap_core::now_sec() as i64);
    let build_info = register_metric!(
        r,
        new_int_gauge_vec,
        server,
        "pingap_build_info",
        "pingap build information, the value is always 1",
        &["version", "rustc_version"]
    )?;
    build_info
        .with_label_values(&[
            pingap_util::get_pkg_version(),
            pingap_util::get_rustc_version(),
        ])
        .set(1);
    let start_time = register_metric!(
        r,
        new_int_gauge,
        server,
        "pingap_start_time_seconds",
        "pingap unix time this server was started"
    )?;
    start_time.set(pingap_core::now_sec() as i64);
    // What was counted before this registry was there is not its to
    // report: a server made by a restart starts from the count as it is.
    let mirrored = |counter: IntCounter, value: u64| {
        let mirrored = Mirrored::new(counter);
        mirrored.seen.store(value, Ordering::Relaxed);
        mirrored
    };
    let reloads = super::config_reloads();

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
        all_status: Default::default(),
        all_cache: Default::default(),
        cache_memory_evictions: mirrored(
            cache_memory_evictions,
            pingap_cache::memory_cache_evictions(),
        ),
        config_reload_success: mirrored(
            config_reloads.with_label_values(&["success"]),
            reloads.success,
        ),
        config_reload_failure: mirrored(
            config_reloads.with_label_values(&["failure"]),
            reloads.failure,
        ),
        config_last_reload_successful,
        config_last_reload_success_time,
        http_responses_status,
        cache_responses,
        upstream_errors,
        upstream_retries,
        access_log_dropped,
        location_series: ArcSwap::from_pointee(HashMap::new()),
        upstream_series: ArcSwap::from_pointee(HashMap::new()),
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

    /// Regression: a phase that never finished still holds its start
    /// marker, a negative number - a HEAD or a 204 has no body to end the
    /// response phase, an upstream that never answers nothing to end the
    /// processing one. The histograms took the marker for a duration: it
    /// came off their sum and counted in the fastest bucket.
    #[tokio::test]
    async fn test_unfinished_upstream_phases_are_not_observed() {
        let mock_io = Builder::new()
            .read(b"HEAD / HTTP/1.1\r\nHost: github.com\r\n\r\n")
            .build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let p = new_prometheus("pingap").unwrap();
        let request = |processing: i32, response: i32| {
            p.on_request_start();
            p.on_location_matched("lo");
            p.after(
                &session,
                &Ctx {
                    timing: Timing {
                        created_at: Instant::now(),
                        upstream_processing: Some(processing),
                        upstream_response: Some(response),
                        ..Default::default()
                    },
                    state: RequestState {
                        status: Some(StatusCode::OK),
                        ..Default::default()
                    },
                    upstream: pingap_core::UpstreamInfo {
                        name: "markers".into(),
                        location: "lo".into(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            );
        };
        let value = |name: &str| {
            let buf = String::from_utf8(p.metrics().unwrap()).unwrap();
            metric_value(&buf, name, &["upstream=\"markers\""])
        };

        // Both phases finished: 20ms and 10ms.
        request(20, 10);
        assert_eq!(
            Some("1".to_string()),
            value("pingap_upstream_response_time_count{")
        );
        // Neither did: the markers of a start at 50ms and at 60ms.
        request(-51, -61);
        for name in [
            "pingap_upstream_processing_time",
            "pingap_upstream_response_time",
        ] {
            assert_eq!(
                Some("1".to_string()),
                value(&format!("{name}_count{{")),
                "{name}"
            );
            let sum: f64 =
                value(&format!("{name}_sum{{")).unwrap().parse().unwrap();
            assert_eq!(true, sum > 0.0, "{name}: {sum}");
        }
    }

    /// The per-upstream series of an upstream that left the configuration
    /// stop being exported instead of lingering with their last value.
    #[test]
    fn test_cache_class() {
        let label = |phase| cache_class(phase).map(|index| CACHE_LABELS[index]);
        assert_eq!(Some("hit"), label(CachePhase::Hit));
        assert_eq!(Some("miss"), label(CachePhase::Miss));
        assert_eq!(Some("expired"), label(CachePhase::Expired));
        assert_eq!(Some("stale"), label(CachePhase::Stale));
        assert_eq!(Some("stale"), label(CachePhase::StaleUpdating));
        assert_eq!(Some("revalidated"), label(CachePhase::Revalidated));
        assert_eq!(
            Some("revalidated"),
            label(CachePhase::RevalidatedNoCache(NoCacheReason::Custom("x")))
        );
        assert_eq!(Some("bypass"), label(CachePhase::Bypass));
        // Asked, and the response was not one to keep.
        assert_eq!(
            Some("uncacheable"),
            label(CachePhase::Disabled(NoCacheReason::OriginNotCache))
        );
        assert_eq!(
            Some("uncacheable"),
            label(CachePhase::Disabled(NoCacheReason::ResponseTooLarge))
        );
        // No cache was asked, or it never got to an answer.
        assert_eq!(None, label(CachePhase::Uninit));
        assert_eq!(None, label(CachePhase::CacheKey));
        assert_eq!(
            None,
            label(CachePhase::Disabled(NoCacheReason::NeverEnabled))
        );
    }

    /// A counter that follows a count of the process adds what the count
    /// grew by, and nothing of what was there before it.
    #[test]
    fn test_mirrored_counter() {
        let mirrored =
            Mirrored::new(IntCounter::new("mirrored", "help").unwrap());
        mirrored.seen.store(40, Ordering::Relaxed);
        mirrored.follow(40);
        assert_eq!(0, mirrored.counter.get());
        mirrored.follow(43);
        assert_eq!(3, mirrored.counter.get());
        mirrored.follow(43);
        assert_eq!(3, mirrored.counter.get());
        mirrored.follow(50);
        assert_eq!(10, mirrored.counter.get());
        // A count never goes back; if it did, nothing is taken off.
        mirrored.follow(10);
        assert_eq!(10, mirrored.counter.get());
        mirrored.follow(12);
        assert_eq!(10, mirrored.counter.get());
        mirrored.follow(52);
        assert_eq!(12, mirrored.counter.get());
    }

    /// The exact status, the retries and the errors of an upstream, the
    /// dropped access log lines, and what says which build this is.
    #[tokio::test]
    async fn test_status_upstream_and_process_metrics() {
        let mock_io = Builder::new()
            .read(b"GET / HTTP/1.1\r\nHost: github.com\r\n\r\n")
            .build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let p = new_prometheus("pingap").unwrap();
        let request = |status: u16, location: &str, retries: u8| {
            p.on_request_start();
            p.on_location_matched(location);
            p.after(
                &session,
                &Ctx {
                    state: RequestState {
                        status: StatusCode::from_u16(status).ok(),
                        ..Default::default()
                    },
                    upstream: pingap_core::UpstreamInfo {
                        name: if location.is_empty() { "" } else { "up" }
                            .into(),
                        location: location.into(),
                        retries,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            );
        };
        request(200, "lo", 0);
        request(200, "lo", 2);
        request(404, "lo", 0);
        request(429, "other", 1);
        // Matched no location: counted for the total alone.
        request(404, "", 0);
        // Ended without a status: none to count.
        request(0, "lo", 0);
        p.on_upstream_error("up");
        p.on_upstream_error("up");
        p.on_upstream_error("");
        p.on_access_log_dropped();

        let buf = String::from_utf8(p.metrics().unwrap()).unwrap();
        let value = |name: &str, labels: &[&str]| {
            metric_value(&buf, name, labels).unwrap_or_else(|| "-".to_string())
        };
        for (location, status, expected) in [
            ("lo", "200", "2"),
            ("lo", "404", "1"),
            ("other", "429", "1"),
            ("", "200", "2"),
            ("", "404", "2"),
            ("", "429", "1"),
            // Not answered there: no series, not one that reads 0.
            ("lo", "429", "-"),
            ("other", "200", "-"),
        ] {
            assert_eq!(
                expected,
                value(
                    "pingap_http_responses_status{",
                    &[
                        &format!("location=\"{location}\""),
                        &format!("status=\"{status}\"")
                    ]
                ),
                "{location} {status}: {buf}"
            );
        }
        // The classes go on as before, the request without a status in
        // `unknown`.
        assert_eq!(
            "2",
            value(
                "pingap_http_responses_codes{",
                &["location=\"lo\"", "code=\"2xx\""]
            )
        );
        assert_eq!(
            "1",
            value(
                "pingap_http_responses_codes{",
                &["location=\"lo\"", "code=\"unknown\""]
            )
        );
        assert_eq!(
            "3",
            value("pingap_upstream_retries{", &["upstream=\"up\""])
        );
        assert_eq!("2", value("pingap_upstream_errors{", &["upstream=\"up\""]));
        assert_eq!("1", value("pingap_access_log_dropped{", &[]));
        // No cache was asked about any of these.
        assert_eq!("-", value("pingap_cache_responses{", &[]));
        assert_eq!(
            "1",
            value(
                "pingap_build_info{",
                &[&format!("version=\"{}\"", pingap_util::get_pkg_version())]
            )
        );
        let started: u64 =
            value("pingap_start_time_seconds{", &[]).parse().unwrap();
        assert_eq!(true, started + 60 > pingap_core::now_sec());
        // There from the first scrape on, whatever the reloads were.
        for name in [
            "pingap_config_last_reload_successful{",
            "pingap_config_last_reload_success_timestamp_seconds{",
            "pingap_cache_memory_evictions{",
        ] {
            assert_eq!(false, "-" == value(name, &[]), "{name}: {buf}");
        }

        // An upstream that is gone takes its errors and retries with it.
        let stats = |names: &[&str]| -> HashMap<String, pingap_upstream::UpstreamStats> {
            names
                .iter()
                .map(|name| (name.to_string(), Default::default()))
                .collect()
        };
        p.forget_removed_upstreams(&stats(&["up"]));
        p.forget_removed_upstreams(&stats(&[]));
        let buf = String::from_utf8(p.metrics().unwrap()).unwrap();
        for name in ["pingap_upstream_retries{", "pingap_upstream_errors{"] {
            assert_eq!(None, metric_value(&buf, name, &[]), "{name}: {buf}");
        }
    }

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

    /// The series of a location and of an upstream are found once and kept.
    /// What is kept for an upstream goes when the upstream does: one that
    /// comes back under its name is counted in its new series, not in ones
    /// that are no longer exported. And a series still only appears once
    /// it has a value.
    #[tokio::test]
    async fn test_series_are_kept_and_follow_removal() {
        let mock_io = Builder::new()
            .read(b"GET / HTTP/1.1\r\nHost: github.com\r\n\r\n")
            .build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let p = new_prometheus("pingap").unwrap();
        let ctx = Ctx {
            state: RequestState {
                status: Some(StatusCode::OK),
                ..Default::default()
            },
            upstream: pingap_core::UpstreamInfo {
                name: "up".into(),
                location: "lo".into(),
                reused: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let request = || {
            p.on_request_start();
            p.on_location_matched("lo");
            p.after(&session, &ctx);
        };
        let metrics = || String::from_utf8(p.metrics().unwrap()).unwrap();
        let reuses = |buf: &str| {
            metric_value(buf, "pingap_upstream_reuses{", &["upstream=\"up\""])
        };

        request();
        request();
        let buf = metrics();
        assert_eq!(
            Some("2".to_string()),
            metric_value(
                &buf,
                "pingap_http_requests_total{",
                &["location=\"lo\""]
            ),
            "{buf}"
        );
        assert_eq!(
            Some("2".to_string()),
            metric_value(
                &buf,
                "pingap_http_responses_codes{",
                &["location=\"lo\"", "code=\"2xx\""]
            ),
            "{buf}"
        );
        assert_eq!(Some("2".to_string()), reuses(&buf), "{buf}");
        // Nothing was sent and nothing failed: no series for either.
        assert_eq!(
            None,
            metric_value(&buf, "pingap_http_sent_bytes{", &["location=\"lo\""]),
            "{buf}"
        );
        assert_eq!(false, buf.contains("code=\"5xx\",location=\"lo\""));
        assert_eq!(
            false,
            buf.contains("pingap_upstream_tls_handshake_time"),
            "{buf}"
        );

        // The upstream leaves the configuration, and comes back.
        let live: HashMap<String, pingap_upstream::UpstreamStats> =
            HashMap::from([("up".to_string(), Default::default())]);
        p.forget_removed_upstreams(&live);
        p.forget_removed_upstreams(&HashMap::new());
        assert_eq!(None, reuses(&metrics()));
        assert_eq!(true, p.upstream_series.load().is_empty());
        request();
        assert_eq!(Some("1".to_string()), reuses(&metrics()));
    }
}
