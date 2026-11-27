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

//! Lightweight counters for Layer 4 (`[streams.*]`) connections and traffic.
//!
//! Always compiled (independent of the `tracing` feature) so `pingap-proxy`
//! can record L4 activity without feature-gating every call site.

use ahash::AHashMap;
use arc_swap::ArcSwap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};

#[repr(align(128))]
#[derive(Default)]
struct StreamEntry {
    active: AtomicI64,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
    outcomes: ArcSwap<AHashMap<String, AHashMap<String, Arc<AtomicU64>>>>,
}

impl StreamEntry {
    fn record_outcome(&self, upstream: &str, result: &str) {
        let outcomes = self.outcomes.load();
        if let Some(counter) = outcomes
            .get(upstream)
            .and_then(|results| results.get(result))
        {
            counter.fetch_add(1, Ordering::Relaxed);
            return;
        }
        drop(outcomes);
        let created = Arc::new(AtomicU64::new(0));
        self.outcomes.rcu(|current| {
            let mut next = current.as_ref().clone();
            let results = next
                .entry(upstream.to_string())
                .or_insert_with(AHashMap::new);
            results
                .entry(result.to_string())
                .or_insert_with(|| created.clone());
            next
        });
        if let Some(counter) = self
            .outcomes
            .load()
            .get(upstream)
            .and_then(|results| results.get(result))
        {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }
}

struct StreamMetrics {
    entries: ArcSwap<AHashMap<String, Arc<StreamEntry>>>,
}

impl StreamMetrics {
    fn new() -> Self {
        Self {
            entries: ArcSwap::from_pointee(AHashMap::new()),
        }
    }

    fn with_entry(&self, stream: &str, f: impl FnOnce(&StreamEntry)) {
        let current = self.entries.load();
        if let Some(entry) = current.get(stream) {
            f(entry);
            return;
        }
        drop(current);
        let created = Arc::new(StreamEntry::default());
        self.entries.rcu(|current| {
            let mut next = current.as_ref().clone();
            next.entry(stream.to_string())
                .or_insert_with(|| created.clone());
            next
        });
        if let Some(entry) = self.entries.load().get(stream) {
            f(entry);
        }
    }

    fn open(&self, stream: &str) {
        if stream.is_empty() {
            return;
        }
        self.with_entry(stream, |entry| {
            entry.active.fetch_add(1, Ordering::Relaxed);
        });
    }

    fn close(
        &self,
        stream: &str,
        upstream: &str,
        result: &str,
        tx_bytes: u64,
        rx_bytes: u64,
    ) {
        if stream.is_empty() {
            return;
        }
        self.with_entry(stream, |entry| {
            let _ = entry.active.try_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |count| (count > 0).then_some(count - 1),
            );
            entry.record_outcome(upstream, result);
            if tx_bytes > 0 {
                entry.tx_bytes.fetch_add(tx_bytes, Ordering::Relaxed);
            }
            if rx_bytes > 0 {
                entry.rx_bytes.fetch_add(rx_bytes, Ordering::Relaxed);
            }
        });
    }

    fn snapshot(&self) -> StreamMetricsSnapshot {
        let entries = self.entries.load();
        let mut snapshot = StreamMetricsSnapshot {
            active: Vec::with_capacity(entries.len()),
            connections: Vec::new(),
            bytes: Vec::with_capacity(entries.len() * 2),
        };
        for (stream, entry) in entries.iter() {
            snapshot.active.push((
                stream.clone(),
                entry.active.load(Ordering::Relaxed).max(0),
            ));
            let tx = entry.tx_bytes.load(Ordering::Relaxed);
            if tx > 0 {
                snapshot.bytes.push(((stream.clone(), "tx"), tx));
            }
            let rx = entry.rx_bytes.load(Ordering::Relaxed);
            if rx > 0 {
                snapshot.bytes.push(((stream.clone(), "rx"), rx));
            }
            let outcomes = entry.outcomes.load();
            for (upstream, results) in outcomes.iter() {
                for (result, count) in results.iter() {
                    snapshot.connections.push((
                        (stream.clone(), upstream.clone(), result.clone()),
                        count.load(Ordering::Relaxed),
                    ));
                }
            }
        }
        snapshot
    }

    fn forget_removed(&self, active_names: &[&str]) {
        let current = self.entries.load();
        let has_removed = current
            .keys()
            .any(|name| !active_names.contains(&name.as_str()));
        if !has_removed {
            return;
        }
        drop(current);
        self.entries.rcu(|current| {
            let mut next = current.as_ref().clone();
            next.retain(|name, _| active_names.contains(&name.as_str()));
            next
        });
    }
}

/// Point-in-time snapshot of L4 stream metrics exported during Prometheus scrapes.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StreamMetricsSnapshot {
    pub active: Vec<(String, i64)>,
    pub connections: Vec<((String, String, String), u64)>,
    pub bytes: Vec<((String, &'static str), u64)>,
}

static STREAM_METRICS: LazyLock<StreamMetrics> =
    LazyLock::new(StreamMetrics::new);

/// Increments the active connection gauge for `stream`.
pub fn stream_connection_open(stream: &str) {
    STREAM_METRICS.open(stream);
}

/// Decrements active connections for `stream` and accumulates connection total
/// and bidirectional byte counters upon connection close.
pub fn stream_connection_close(
    stream: &str,
    upstream: &str,
    result: &str,
    tx_bytes: u64,
    rx_bytes: u64,
) {
    STREAM_METRICS.close(stream, upstream, result, tx_bytes, rx_bytes);
}

/// Returns a consistent snapshot of all recorded L4 stream counters.
pub fn stream_metrics_snapshot() -> StreamMetricsSnapshot {
    STREAM_METRICS.snapshot()
}

/// Drops metrics entries for streams no longer present in `active_names`.
pub fn forget_removed_streams(active_names: &[&str]) {
    STREAM_METRICS.forget_removed(active_names);
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_stream_metrics_lifecycle() {
        let name = format!("test-stream-{}", std::process::id());
        stream_connection_open(&name);
        let mid = stream_metrics_snapshot();
        assert_eq!(
            Some(1),
            mid.active.iter().find(|(k, _)| k == &name).map(|(_, v)| *v)
        );

        stream_connection_close(&name, "pg_up", "ok", 128, 256);
        let after = stream_metrics_snapshot();
        assert_eq!(
            Some(0),
            after
                .active
                .iter()
                .find(|(k, _)| k == &name)
                .map(|(_, v)| *v)
        );
        assert_eq!(
            Some(1),
            after
                .connections
                .iter()
                .find(|((s, u, r), _)| s == &name && u == "pg_up" && r == "ok")
                .map(|(_, v)| *v)
        );
        assert_eq!(
            Some(128),
            after
                .bytes
                .iter()
                .find(|((s, d), _)| s == &name && *d == "tx")
                .map(|(_, v)| *v)
        );
        assert_eq!(
            Some(256),
            after
                .bytes
                .iter()
                .find(|((s, d), _)| s == &name && *d == "rx")
                .map(|(_, v)| *v)
        );
    }

    #[test]
    fn test_stream_metrics_concurrent_updates() {
        assert!(std::mem::align_of::<StreamEntry>() >= 128);
        assert!(std::mem::size_of::<StreamEntry>() >= 128);

        let metrics = Arc::new(StreamMetrics::new());
        let threads = 8usize;
        let iters = 200usize;
        let mut handles = Vec::with_capacity(threads);
        for tid in 0..threads {
            let metrics = metrics.clone();
            handles.push(std::thread::spawn(move || {
                let upstream = if tid % 2 == 0 { "up_a" } else { "up_b" };
                for i in 0..iters {
                    let result = if i % 5 == 0 { "timeout" } else { "ok" };
                    metrics.open("concurrent");
                    metrics.close("concurrent", upstream, result, 10, 20);
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }

        let snap = metrics.snapshot();
        assert_eq!(
            Some(0),
            snap.active
                .iter()
                .find(|(s, _)| s == "concurrent")
                .map(|(_, v)| *v)
        );
        assert_eq!(
            Some((threads * iters * 10) as u64),
            snap.bytes
                .iter()
                .find(|((s, d), _)| s == "concurrent" && *d == "tx")
                .map(|(_, v)| *v)
        );
        assert_eq!(
            Some((threads * iters * 20) as u64),
            snap.bytes
                .iter()
                .find(|((s, d), _)| s == "concurrent" && *d == "rx")
                .map(|(_, v)| *v)
        );
        let total_conns: u64 = snap.connections.iter().map(|(_, v)| *v).sum();
        assert_eq!((threads * iters) as u64, total_conns);

        // Close without prior open must not drive active below zero.
        metrics.close("rejected_only", "", "max_connections", 0, 0);
        let snap = metrics.snapshot();
        assert_eq!(
            Some(0),
            snap.active
                .iter()
                .find(|(s, _)| s == "rejected_only")
                .map(|(_, v)| *v)
        );
    }

    #[test]
    fn test_forget_removed_streams() {
        let metrics = StreamMetrics::new();
        metrics.open("keep");
        metrics.close("keep", "up", "ok", 64, 128);
        metrics.open("gone");
        metrics.close("gone", "up", "ok", 32, 64);

        metrics.forget_removed(&["keep"]);
        let snap = metrics.snapshot();
        assert_eq!(true, snap.active.iter().any(|(s, _)| s == "keep"));
        assert_eq!(false, snap.active.iter().any(|(s, _)| s == "gone"));
        assert_eq!(false, snap.bytes.iter().any(|((s, _), _)| s == "gone"));
        assert_eq!(
            false,
            snap.connections.iter().any(|((s, _, _), _)| s == "gone")
        );

        // Global wrapper also removes unreferenced stream entries cleanly.
        let pid = std::process::id();
        let test_stream = format!("test-stream-{pid}");
        let prom_stream = format!("prom-stream-{pid}");
        let global_gone = format!("global-gone-{pid}");
        stream_connection_open(&global_gone);
        stream_connection_close(&global_gone, "up", "ok", 1, 2);
        forget_removed_streams(&[test_stream.as_str(), prom_stream.as_str()]);
        let global_snap = stream_metrics_snapshot();
        assert_eq!(
            false,
            global_snap.active.iter().any(|(s, _)| s == &global_gone)
        );
    }
}
