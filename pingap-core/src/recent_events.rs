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

use crate::now_sec;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

/// Maximum number of recent events kept in memory.
pub const MAX_RECENT_EVENTS: usize = 200;

/// Category of an event captured in the in-memory ring buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecentEventKind {
    /// Upstream or proxy response with status >= 500.
    #[serde(rename = "5xx")]
    Status5xx,
    /// Security or rate-limit rule matched under `dry_run = true`.
    DryRun,
    /// Configuration validation, reload, or restart-required warning.
    ReloadFail,
}

/// An operational error, dry-run match, or reload issue kept in memory for
/// Web Admin diagnostics without SSHing into log files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecentEvent {
    /// Monotonically increasing in-process event identifier.
    pub id: u64,
    /// Unix timestamp in seconds when the event was recorded.
    pub ts: u64,
    /// Event category.
    pub kind: RecentEventKind,
    /// Server name, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// Matched location name, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// HTTP status code, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// HTTP method, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Request host header, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Request URI path/query, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    /// Verified client IP address, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
    /// Plugin category or sub-component name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Human-readable summary of the event.
    pub message: String,
}

impl Default for RecentEvent {
    fn default() -> Self {
        Self {
            id: 0,
            ts: 0,
            kind: RecentEventKind::Status5xx,
            server: None,
            location: None,
            status: None,
            method: None,
            host: None,
            uri: None,
            client_ip: None,
            category: None,
            message: String::new(),
        }
    }
}

static NEXT_EVENT_ID: AtomicU64 = AtomicU64::new(0);
static RECENT_EVENTS: LazyLock<Mutex<VecDeque<RecentEvent>>> =
    LazyLock::new(|| Mutex::new(VecDeque::with_capacity(MAX_RECENT_EVENTS)));

/// Records an operational event into the fixed-capacity ring buffer.
pub fn record_recent_event(mut event: RecentEvent) {
    event.id = NEXT_EVENT_ID.fetch_add(1, Ordering::Relaxed) + 1;
    if event.ts == 0 {
        event.ts = now_sec();
    }
    let mut ring = RECENT_EVENTS.lock().unwrap_or_else(|e| e.into_inner());
    if ring.len() >= MAX_RECENT_EVENTS {
        let _ = ring.pop_front();
    }
    ring.push_back(event);
}

/// Returns up to `limit` (clamped to `1..=MAX_RECENT_EVENTS`) recent events in
/// reverse chronological order (newest first), optionally filtered by `kind`.
pub fn recent_events(
    kind: Option<RecentEventKind>,
    limit: usize,
) -> Vec<RecentEvent> {
    let limit = limit.clamp(1, MAX_RECENT_EVENTS);
    let ring = RECENT_EVENTS.lock().unwrap_or_else(|e| e.into_inner());
    ring.iter()
        .rev()
        .filter(|event| kind.is_none_or(|expected| event.kind == expected))
        .take(limit)
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_recent_events_ring_order_and_filter() {
        for i in 0..210_u64 {
            let kind = if i % 3 == 0 {
                RecentEventKind::DryRun
            } else if i % 5 == 0 {
                RecentEventKind::ReloadFail
            } else {
                RecentEventKind::Status5xx
            };
            record_recent_event(RecentEvent {
                kind,
                message: format!("event-{i}"),
                ..Default::default()
            });
        }

        let all = recent_events(None, 500);
        assert_eq!(MAX_RECENT_EVENTS, all.len());
        assert_eq!("event-209", all[0].message);
        assert!(all[0].id > all[1].id);

        let dry_runs = recent_events(Some(RecentEventKind::DryRun), 5);
        assert_eq!(5, dry_runs.len());
        for item in dry_runs {
            assert_eq!(RecentEventKind::DryRun, item.kind);
        }
    }
}
