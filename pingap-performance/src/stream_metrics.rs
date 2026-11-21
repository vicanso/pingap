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

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

#[derive(Default)]
struct StreamMetricsState {
    active: HashMap<String, i64>,
    connections: HashMap<(String, String, String), u64>,
    bytes: HashMap<(String, &'static str), u64>,
}

/// Point-in-time snapshot of L4 stream metrics exported during Prometheus scrapes.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StreamMetricsSnapshot {
    pub active: Vec<(String, i64)>,
    pub connections: Vec<((String, String, String), u64)>,
    pub bytes: Vec<((String, &'static str), u64)>,
}

static STREAM_METRICS: LazyLock<Mutex<StreamMetricsState>> =
    LazyLock::new(|| Mutex::new(StreamMetricsState::default()));

/// Increments the active connection gauge for `stream`.
pub fn stream_connection_open(stream: &str) {
    if stream.is_empty() {
        return;
    }
    if let Ok(mut guard) = STREAM_METRICS.lock() {
        let count = guard.active.entry(stream.to_string()).or_insert(0);
        *count += 1;
    }
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
    if stream.is_empty() {
        return;
    }
    if let Ok(mut guard) = STREAM_METRICS.lock() {
        if let Some(count) = guard.active.get_mut(stream) {
            *count = (*count - 1).max(0);
        }
        *guard
            .connections
            .entry((
                stream.to_string(),
                upstream.to_string(),
                result.to_string(),
            ))
            .or_insert(0) += 1;
        if tx_bytes > 0 {
            *guard.bytes.entry((stream.to_string(), "tx")).or_insert(0) +=
                tx_bytes;
        }
        if rx_bytes > 0 {
            *guard.bytes.entry((stream.to_string(), "rx")).or_insert(0) +=
                rx_bytes;
        }
    }
}

/// Returns a consistent snapshot of all recorded L4 stream counters.
pub fn stream_metrics_snapshot() -> StreamMetricsSnapshot {
    let Ok(guard) = STREAM_METRICS.lock() else {
        return StreamMetricsSnapshot::default();
    };
    StreamMetricsSnapshot {
        active: guard.active.iter().map(|(k, v)| (k.clone(), *v)).collect(),
        connections: guard
            .connections
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect(),
        bytes: guard.bytes.iter().map(|(k, v)| (k.clone(), *v)).collect(),
    }
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
}
