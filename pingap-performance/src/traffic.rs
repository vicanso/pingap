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

//! What the requests of the last fifteen minutes came to, kept in memory
//! for the dashboard of the admin: how many there were, how they were
//! answered, how long they took, and the same for each upstream. A
//! deployment without Prometheus sees its traffic that way, in any build.
//!
//! The time is cut into buckets of ten seconds, in a ring that each
//! bucket comes round in again fifteen minutes later and is then started
//! anew. A request is counted with a few atomic additions into the bucket
//! of the moment it ends. Counts that come in while a bucket is being
//! started anew can be lost: the figures are for a look, not an account.

use arc_swap::ArcSwap;
use pingap_core::Ctx;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};

/// The seconds of one bucket.
pub const TRAFFIC_INTERVAL: u64 = 10;
/// Ninety buckets of ten seconds: fifteen minutes.
const BUCKETS: u64 = 90;
/// The upper bounds of the latency histogram of a bucket, in
/// milliseconds. The last bucket of it takes everything above.
const LATENCY_BOUNDS: [u64; 11] =
    [5, 10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000];

/// The requests of ten seconds, as the client saw them.
#[derive(Default)]
struct Bucket {
    /// The ten seconds counted here: the time divided by the interval.
    epoch: AtomicU64,
    requests: AtomicU64,
    /// By the class of the status the client was sent: 2xx, 3xx, 4xx and
    /// 5xx. A request without one (the client went away) is in none.
    status: [AtomicU64; 4],
    /// The requests the latency is of: not an upgraded connection, whose
    /// time is that of the tunnel, minutes or hours.
    latency_count: AtomicU64,
    latency_sum: AtomicU64,
    latency_max: AtomicU64,
    latency_histogram: [AtomicU64; LATENCY_BOUNDS.len() + 1],
}

impl Bucket {
    fn reset(&self) {
        let counters = [
            &self.requests,
            &self.latency_count,
            &self.latency_sum,
            &self.latency_max,
        ]
        .into_iter()
        .chain(self.status.iter())
        .chain(self.latency_histogram.iter());
        for counter in counters {
            counter.store(0, Ordering::Relaxed);
        }
    }
}

/// The requests of ten seconds that went to one upstream.
#[derive(Default)]
struct UpstreamBucket {
    epoch: AtomicU64,
    requests: AtomicU64,
    /// Answered with a 5xx, or not at all: no connection, a timeout.
    errors: AtomicU64,
    /// The requests that got a response header, which the latency is of.
    latency_count: AtomicU64,
    latency_sum: AtomicU64,
    latency_max: AtomicU64,
}

impl UpstreamBucket {
    fn reset(&self) {
        for counter in [
            &self.requests,
            &self.errors,
            &self.latency_count,
            &self.latency_sum,
            &self.latency_max,
        ] {
            counter.store(0, Ordering::Relaxed);
        }
    }
}

/// Something with an epoch that is started anew when it comes round.
trait Epoch {
    fn epoch(&self) -> &AtomicU64;
    fn reset(&self);
}

impl Epoch for Bucket {
    fn epoch(&self) -> &AtomicU64 {
        &self.epoch
    }
    fn reset(&self) {
        Bucket::reset(self)
    }
}

impl Epoch for UpstreamBucket {
    fn epoch(&self) -> &AtomicU64 {
        &self.epoch
    }
    fn reset(&self) {
        UpstreamBucket::reset(self)
    }
}

/// The ring of the buckets of one kind.
struct Ring<T> {
    buckets: Box<[T]>,
}

impl<T: Default + Epoch> Ring<T> {
    fn new() -> Self {
        Self {
            buckets: (0..BUCKETS).map(|_| T::default()).collect(),
        }
    }

    /// The bucket of `epoch` to count into, started anew when it was
    /// another's.
    fn current(&self, epoch: u64) -> &T {
        let bucket = &self.buckets[(epoch % BUCKETS) as usize];
        let seen = bucket.epoch().load(Ordering::Acquire);
        if seen != epoch
            && bucket
                .epoch()
                .compare_exchange(
                    seen,
                    epoch,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
        {
            bucket.reset();
        }
        bucket
    }

    /// The bucket of `epoch` to read, if it still holds that one.
    fn get(&self, epoch: u64) -> Option<&T> {
        let bucket = &self.buckets[(epoch % BUCKETS) as usize];
        (bucket.epoch().load(Ordering::Acquire) == epoch).then_some(bucket)
    }
}

struct UpstreamRing {
    ring: Ring<UpstreamBucket>,
    /// The epoch of the last request: an upstream with none in the window
    /// (one taken out of the configuration) is let go.
    last: AtomicU64,
}

struct Traffic {
    ring: Ring<Bucket>,
    /// By name. Written when a name is seen first, which is rare, and read
    /// by every request without a lock.
    upstreams: ArcSwap<HashMap<Arc<str>, Arc<UpstreamRing>>>,
}

static TRAFFIC: LazyLock<Traffic> = LazyLock::new(Traffic::new);

impl Traffic {
    fn new() -> Self {
        Self {
            ring: Ring::new(),
            upstreams: ArcSwap::from_pointee(HashMap::new()),
        }
    }

    /// Runs `f` with the ring of the upstream `name`, which is made for
    /// its first request. Read without taking a reference of the ring:
    /// every request to an upstream comes here.
    fn with_upstream(
        &self,
        name: &Arc<str>,
        epoch: u64,
        f: impl FnOnce(&UpstreamRing),
    ) {
        if let Some(ring) = self.upstreams.load().get(name) {
            f(ring);
            return;
        }
        self.upstreams.rcu(|upstreams| {
            let mut upstreams = HashMap::clone(upstreams);
            upstreams.entry(name.clone()).or_insert_with(|| {
                Arc::new(UpstreamRing {
                    ring: Ring::new(),
                    // Of now: not let go by a snapshot before it counts.
                    last: AtomicU64::new(epoch),
                })
            });
            upstreams
        });
        if let Some(ring) = self.upstreams.load().get(name) {
            f(ring);
        }
    }

    fn record(&self, now: u64, request: &Request) {
        let epoch = now / TRAFFIC_INTERVAL;
        let bucket = self.ring.current(epoch);
        bucket.requests.fetch_add(1, Ordering::Relaxed);
        if let Some(class) = request
            .status
            .and_then(|status| (200..600).contains(&status).then_some(status))
            .map(|status| usize::from(status / 100 - 2))
        {
            bucket.status[class].fetch_add(1, Ordering::Relaxed);
        }
        if let Some(latency) = request.latency {
            bucket.latency_count.fetch_add(1, Ordering::Relaxed);
            bucket.latency_sum.fetch_add(latency, Ordering::Relaxed);
            bucket.latency_max.fetch_max(latency, Ordering::Relaxed);
            let slot = LATENCY_BOUNDS
                .iter()
                .position(|bound| latency <= *bound)
                .unwrap_or(LATENCY_BOUNDS.len());
            bucket.latency_histogram[slot].fetch_add(1, Ordering::Relaxed);
        }

        if let Some(name) = &request.fallback_from {
            self.with_upstream(name, epoch, |ring| {
                if ring.last.load(Ordering::Relaxed) != epoch {
                    ring.last.store(epoch, Ordering::Relaxed);
                }
                let bucket = ring.ring.current(epoch);
                bucket.requests.fetch_add(1, Ordering::Relaxed);
                bucket.errors.fetch_add(1, Ordering::Relaxed);
            });
        }
        let Some((name, upstream)) = &request.upstream else {
            return;
        };
        self.with_upstream(name, epoch, |ring| {
            if ring.last.load(Ordering::Relaxed) != epoch {
                ring.last.store(epoch, Ordering::Relaxed);
            }
            let bucket = ring.ring.current(epoch);
            bucket.requests.fetch_add(1, Ordering::Relaxed);
            if upstream.error {
                bucket.errors.fetch_add(1, Ordering::Relaxed);
            }
            if let Some(latency) = upstream.latency {
                bucket.latency_count.fetch_add(1, Ordering::Relaxed);
                bucket.latency_sum.fetch_add(latency, Ordering::Relaxed);
                bucket.latency_max.fetch_max(latency, Ordering::Relaxed);
            }
        });
    }

    fn snapshot(&self, now: u64) -> TrafficSnapshot {
        let last = now / TRAFFIC_INTERVAL;
        // Fewer buckets on a clock that has not yet run fifteen minutes
        // from its start: a board without a clock that boots in 1970.
        let first = (last + 1).saturating_sub(BUCKETS);
        let mut snapshot = TrafficSnapshot {
            interval: TRAFFIC_INTERVAL,
            ..Default::default()
        };
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        for epoch in first..=last {
            snapshot.time.push(epoch * TRAFFIC_INTERVAL);
            let Some(bucket) = self.ring.get(epoch) else {
                snapshot.push_empty();
                continue;
            };
            let requests = load(&bucket.requests);
            snapshot.requests.push(requests);
            for (class, counts) in [
                &mut snapshot.status_2xx,
                &mut snapshot.status_3xx,
                &mut snapshot.status_4xx,
                &mut snapshot.status_5xx,
            ]
            .into_iter()
            .enumerate()
            {
                counts.push(load(&bucket.status[class]));
            }
            let max = load(&bucket.latency_max);
            let timed = load(&bucket.latency_count);
            snapshot.latency_count.push(timed);
            snapshot
                .latency_avg
                .push(average(load(&bucket.latency_sum), timed));
            snapshot.latency_max.push(max);
            let histogram: Vec<u64> =
                bucket.latency_histogram.iter().map(load).collect();
            snapshot.latency_p95.push(percentile(&histogram, 95, max));
        }

        // Let go of the upstreams that had no request in the window.
        let stale = |ring: &Arc<UpstreamRing>| {
            ring.last.load(Ordering::Relaxed) < first
        };
        if self.upstreams.load().values().any(stale) {
            self.upstreams.rcu(|upstreams| {
                let mut upstreams = HashMap::clone(upstreams);
                upstreams.retain(|_, ring| !stale(ring));
                upstreams
            });
        }
        for (name, ring) in self.upstreams.load().iter() {
            let mut traffic = UpstreamTraffic::default();
            for epoch in first..=last {
                let Some(bucket) = ring.ring.get(epoch) else {
                    traffic.requests.push(0);
                    traffic.errors.push(0);
                    traffic.latency_count.push(0);
                    traffic.latency_avg.push(0);
                    traffic.latency_max.push(0);
                    continue;
                };
                traffic.requests.push(load(&bucket.requests));
                traffic.errors.push(load(&bucket.errors));
                let timed = load(&bucket.latency_count);
                traffic.latency_count.push(timed);
                traffic
                    .latency_avg
                    .push(average(load(&bucket.latency_sum), timed));
                traffic.latency_max.push(load(&bucket.latency_max));
            }
            snapshot.upstreams.insert(name.to_string(), traffic);
        }
        snapshot
    }
}

fn average(sum: u64, count: u64) -> u64 {
    sum.checked_div(count).unwrap_or_default()
}

/// The upper bound of the histogram bucket the `percent`th percentile
/// falls in, `max` for the last one, which has no bound: an estimate that
/// is never below the truth.
fn percentile(histogram: &[u64], percent: u64, max: u64) -> u64 {
    let total: u64 = histogram.iter().sum();
    if total == 0 {
        return 0;
    }
    // The rank of the request the percentile is, counted from one.
    let rank = (total * percent).div_ceil(100);
    let mut seen = 0;
    for (index, count) in histogram.iter().enumerate() {
        seen += count;
        if seen >= rank {
            return LATENCY_BOUNDS
                .get(index)
                .map_or(max, |bound| (*bound).min(max));
        }
    }
    max
}

/// What one request comes to.
struct Request {
    /// The status the client was sent.
    status: Option<u16>,
    /// From its arrival to the end, in milliseconds. None for an upgraded
    /// connection (a WebSocket), which ends when the tunnel closes.
    latency: Option<u64>,
    upstream: Option<(Arc<str>, UpstreamRequest)>,
    /// The upstream that could not take the request and left it to the
    /// fallback: an error of that one as well.
    fallback_from: Option<Arc<str>>,
}

struct UpstreamRequest {
    error: bool,
    /// The wait for the response header, in milliseconds.
    latency: Option<u64>,
}

impl Request {
    fn of(ctx: &Ctx, error: Option<&pingora::Error>) -> Self {
        // A client that went away before the upstream answered is no
        // failure of the upstream.
        let client_gone = error.is_some_and(|error| {
            matches!(error.esource(), pingora::ErrorSource::Downstream)
        });
        // A request on its way to an upstream: also one that found no
        // backend there, which is an error of that upstream. One answered
        // by a plugin or from the cache is not.
        let upstream = (ctx.state.proxying && !ctx.upstream.name.is_empty())
            .then(|| {
                (
                    ctx.upstream.name.clone(),
                    UpstreamRequest {
                        error: ctx
                            .upstream
                            .status
                            .map_or(!client_gone, |status| {
                                status.is_server_error()
                            }),
                        latency: ctx
                            .get_upstream_processing_time()
                            .map(u64::from),
                    },
                )
            });
        let status = ctx.state.status.map(|status| status.as_u16());
        Self {
            status,
            latency: (status != Some(101))
                .then(|| ctx.timing.created_at.elapsed().as_millis() as u64),
            upstream,
            fallback_from: ctx
                .upstream
                .fallback_from
                .clone()
                .filter(|_| ctx.state.proxying),
        }
    }
}

/// Counts the request of `ctx`, once it has ended with `error` or none,
/// for the dashboard.
pub fn record_traffic(ctx: &Ctx, error: Option<&pingora::Error>) {
    TRAFFIC.record(pingap_core::now_sec(), &Request::of(ctx, error));
}

/// What the requests of the last fifteen minutes came to, by bucket of
/// [`TRAFFIC_INTERVAL`] seconds, the oldest first; the last bucket is the
/// one under way. Each list has one value for each bucket.
#[derive(Debug, Default, Serialize)]
pub struct TrafficSnapshot {
    pub interval: u64,
    /// The start of each bucket, in seconds since the epoch.
    pub time: Vec<u64>,
    pub requests: Vec<u64>,
    pub status_2xx: Vec<u64>,
    pub status_3xx: Vec<u64>,
    pub status_4xx: Vec<u64>,
    pub status_5xx: Vec<u64>,
    /// The requests the latencies are of: not the upgraded connections.
    pub latency_count: Vec<u64>,
    /// In milliseconds, as are the other latencies; 0 for a bucket
    /// without requests.
    pub latency_avg: Vec<u64>,
    /// An estimate that is never below the truth: the upper bound of the
    /// part of the histogram it falls in.
    pub latency_p95: Vec<u64>,
    pub latency_max: Vec<u64>,
    /// The upstreams that had requests in the window, by name.
    pub upstreams: BTreeMap<String, UpstreamTraffic>,
}

impl TrafficSnapshot {
    fn push_empty(&mut self) {
        for values in [
            &mut self.requests,
            &mut self.status_2xx,
            &mut self.status_3xx,
            &mut self.status_4xx,
            &mut self.status_5xx,
            &mut self.latency_count,
            &mut self.latency_avg,
            &mut self.latency_p95,
            &mut self.latency_max,
        ] {
            values.push(0);
        }
    }
}

/// The requests of one upstream, by the buckets of [`TrafficSnapshot`].
#[derive(Debug, Default, Serialize)]
pub struct UpstreamTraffic {
    pub requests: Vec<u64>,
    /// Answered with a 5xx, or not at all.
    pub errors: Vec<u64>,
    /// The requests that got a response header, which the latencies are
    /// of.
    pub latency_count: Vec<u64>,
    /// The wait for the response header, in milliseconds.
    pub latency_avg: Vec<u64>,
    pub latency_max: Vec<u64>,
}

/// What the requests of the last fifteen minutes came to: see
/// [`TrafficSnapshot`].
pub fn traffic_snapshot() -> TrafficSnapshot {
    TRAFFIC.snapshot(pingap_core::now_sec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn request(status: u16, latency: u64) -> Request {
        Request {
            status: Some(status),
            latency: Some(latency),
            upstream: None,
            fallback_from: None,
        }
    }

    fn to_upstream(name: &str, error: bool, latency: Option<u64>) -> Request {
        Request {
            status: Some(if error { 502 } else { 200 }),
            latency,
            upstream: Some((name.into(), UpstreamRequest { error, latency })),
            fallback_from: None,
        }
    }

    #[test]
    fn test_traffic_buckets() {
        let traffic = Traffic::new();
        // ten seconds a bucket: 1000 and 1009 are one, 1010 the next
        let now = 1_000_000;
        traffic.record(now, &request(200, 20));
        traffic.record(now + 9, &request(404, 40));
        traffic.record(now + 9, &request(503, 3_000));
        traffic.record(now + 10, &request(301, 1));
        // a client that went away
        traffic.record(
            now + 10,
            &Request {
                status: None,
                latency: Some(7),
                upstream: None,
                fallback_from: None,
            },
        );
        // a WebSocket of an hour: counted, its time not
        traffic.record(
            now + 10,
            &Request {
                status: Some(101),
                latency: None,
                upstream: None,
                fallback_from: None,
            },
        );

        let snapshot = traffic.snapshot(now + 10);
        assert_eq!(10, snapshot.interval);
        assert_eq!(90, snapshot.time.len());
        assert_eq!(now + 10, *snapshot.time.last().unwrap());
        assert_eq!(now, snapshot.time[88]);
        let last_two = |values: &Vec<u64>| values[88..].to_vec();
        assert_eq!(vec![3, 3], last_two(&snapshot.requests));
        assert_eq!(vec![3, 2], last_two(&snapshot.latency_count));
        assert_eq!(vec![1, 0], last_two(&snapshot.status_2xx));
        assert_eq!(vec![0, 1], last_two(&snapshot.status_3xx));
        assert_eq!(vec![1, 0], last_two(&snapshot.status_4xx));
        assert_eq!(vec![1, 0], last_two(&snapshot.status_5xx));
        assert_eq!(vec![1020, 4], last_two(&snapshot.latency_avg));
        assert_eq!(vec![3000, 7], last_two(&snapshot.latency_max));
        // the third of three: in the part up to 5000, held to the max
        assert_eq!(vec![3000, 7], last_two(&snapshot.latency_p95));
        // nothing before
        assert_eq!(0, snapshot.requests[..88].iter().sum::<u64>());

        // Fifteen minutes on, the bucket of `now` is another's: started
        // anew, and not read as that one any more. The one of `now + 10`
        // is the oldest of the window.
        let later = now + 900;
        traffic.record(later, &request(200, 5));
        let snapshot = traffic.snapshot(later);
        assert_eq!(vec![0, 1], last_two(&snapshot.requests));
        assert_eq!(3, snapshot.requests[0]);
        assert_eq!(4, snapshot.requests.iter().sum::<u64>());

        // A clock that has not run fifteen minutes: the buckets there are.
        let snapshot = Traffic::new().snapshot(25);
        assert_eq!(vec![0, 10, 20], snapshot.time);
        assert_eq!(3, snapshot.latency_p95.len());
    }

    #[test]
    fn test_traffic_upstreams() {
        let traffic = Traffic::new();
        let now = 2_000_000;
        traffic.record(now, &to_upstream("api", false, Some(30)));
        traffic.record(now, &to_upstream("api", true, None));
        traffic.record(now, &to_upstream("standby", false, Some(10)));
        // a request no upstream had a part in
        traffic.record(now, &request(200, 1));
        // one `down` could not take, which went to `standby`: an error of
        // `down` as well
        let mut rescued = to_upstream("standby", false, Some(10));
        rescued.fallback_from = Some("down".into());
        traffic.record(now, &rescued);
        let snapshot = traffic.snapshot(now);
        assert_eq!(5, *snapshot.requests.last().unwrap());
        assert_eq!(
            vec!["api", "down", "standby"],
            snapshot.upstreams.keys().collect::<Vec<_>>()
        );
        let down = &snapshot.upstreams["down"];
        assert_eq!(1, *down.requests.last().unwrap());
        assert_eq!(1, *down.errors.last().unwrap());
        assert_eq!(0, *down.latency_count.last().unwrap());
        assert_eq!(2, *snapshot.upstreams["standby"].requests.last().unwrap());
        let api = &snapshot.upstreams["api"];
        assert_eq!(90, api.requests.len());
        assert_eq!(2, *api.requests.last().unwrap());
        assert_eq!(1, *api.errors.last().unwrap());
        // the latency of the request that had one, not over both
        assert_eq!(1, *api.latency_count.last().unwrap());
        assert_eq!(30, *api.latency_avg.last().unwrap());
        assert_eq!(30, *api.latency_max.last().unwrap());

        // An upstream with no request in the window is let go.
        let later = now + 900;
        traffic.record(later, &to_upstream("api", false, Some(1)));
        let snapshot = traffic.snapshot(later);
        assert_eq!(vec!["api"], snapshot.upstreams.keys().collect::<Vec<_>>());
        assert_eq!(1, traffic.upstreams.load().len());
    }

    #[test]
    fn test_request_of_ctx() {
        let mut ctx = Ctx::default();
        ctx.state.status = Some(pingora::http::StatusCode::OK);
        let request = Request::of(&ctx, None);
        assert_eq!(Some(200), request.status);
        // answered without an upstream
        assert_eq!(true, request.upstream.is_none());
        ctx.upstream.name = "api".into();
        assert_eq!(true, Request::of(&ctx, None).upstream.is_none());
        // on its way to one that had no backend for it: an error of it
        ctx.state.proxying = true;
        let (name, upstream) = Request::of(&ctx, None).upstream.unwrap();
        assert_eq!("api", &*name);
        assert_eq!(true, upstream.error);
        assert_eq!(None, upstream.latency);
        // unless the client went away before it answered
        let gone = pingora::Error::new(pingora::ErrorType::ConnectionClosed)
            .into_down();
        assert_eq!(
            false,
            Request::of(&ctx, Some(&gone)).upstream.unwrap().1.error
        );
        let failed = pingora::Error::new_up(pingora::ErrorType::ConnectRefused);
        assert_eq!(
            true,
            Request::of(&ctx, Some(&failed)).upstream.unwrap().1.error
        );
        ctx.upstream.status = Some(pingora::http::StatusCode::NO_CONTENT);
        assert_eq!(false, Request::of(&ctx, None).upstream.unwrap().1.error);
        // an upgraded connection: no latency
        ctx.state.status = Some(pingora::http::StatusCode::SWITCHING_PROTOCOLS);
        assert_eq!(None, Request::of(&ctx, None).latency);
    }

    #[test]
    fn test_percentile() {
        let mut histogram = vec![0; LATENCY_BOUNDS.len() + 1];
        assert_eq!(0, percentile(&histogram, 95, 0));
        // 95 of 100 within 10ms, the rest up to 100ms
        histogram[1] = 95;
        histogram[4] = 5;
        assert_eq!(10, percentile(&histogram, 95, 80));
        histogram[1] = 94;
        histogram[4] = 6;
        assert_eq!(80, percentile(&histogram, 95, 80));
        // above the last bound: the max
        let mut histogram = vec![0; LATENCY_BOUNDS.len() + 1];
        histogram[LATENCY_BOUNDS.len()] = 1;
        assert_eq!(42_000, percentile(&histogram, 95, 42_000));
    }
}
