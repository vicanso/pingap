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

use super::{Result, find_file_backend, get_memory_backend};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// One cached entry slot (the combined hash key and optional namespace tag) to
/// invalidate across the cluster.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachePurgeEntry {
    pub key: String,
    #[serde(default)]
    pub namespace: String,
}

/// What a remote instance should remove from its cache when it receives a
/// cluster purge notification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CachePurgeAction {
    Entries { entries: Vec<CachePurgeEntry> },
    Namespace { namespace: String },
}

/// Wire payload broadcast between instances running against a shared event bus
/// (such as etcd) when a local `PURGE` request succeeds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachePurgeEvent {
    /// Identifier of the originating process so it can ignore echoes of its own
    /// broadcasts while applying events from peer instances.
    #[serde(default)]
    pub origin: String,
    /// Target file-cache directory, or `None` for the process-wide memory cache.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory: Option<String>,
    pub action: CachePurgeAction,
}

impl CachePurgeEvent {
    /// Builds a purge event targeting specific combined cache keys.
    pub fn entries(
        directory: Option<String>,
        entries: Vec<CachePurgeEntry>,
    ) -> Self {
        Self {
            origin: String::new(),
            directory,
            action: CachePurgeAction::Entries { entries },
        }
    }

    /// Builds a purge event targeting a whole file-cache namespace.
    pub fn namespace(directory: Option<String>, namespace: String) -> Self {
        Self {
            origin: String::new(),
            directory,
            action: CachePurgeAction::Namespace { namespace },
        }
    }
}

/// Sink installed by the binary runtime to forward local cache `PURGE`
/// operations to peer instances without blocking the request path.
pub trait CachePurgeBroadcaster: Send + Sync {
    fn broadcast(&self, event: CachePurgeEvent);
}

static PURGE_BROADCASTER: RwLock<Option<Arc<dyn CachePurgeBroadcaster>>> =
    RwLock::new(None);

/// Installs or clears the global cluster purge broadcaster.
pub fn set_purge_broadcaster(
    broadcaster: Option<Arc<dyn CachePurgeBroadcaster>>,
) {
    *PURGE_BROADCASTER.write() = broadcaster;
}

/// Enqueues `event` for cluster broadcast if a broadcaster is installed.
pub fn broadcast_purge(event: CachePurgeEvent) {
    let broadcaster = PURGE_BROADCASTER.read().clone();
    if let Some(broadcaster) = broadcaster {
        broadcaster.broadcast(event);
    }
}

/// Applies a purge event received from a peer instance against the matching
/// local backend (`memory://` when `directory` is `None`, or the matching file
/// cache directory otherwise).
///
/// Returns `0` when no matching backend is initialized in this process.
pub async fn apply_purge_event(event: &CachePurgeEvent) -> Result<usize> {
    let Some(backend) = (match &event.directory {
        Some(directory) => find_file_backend(directory),
        None => get_memory_backend(),
    }) else {
        return Ok(0);
    };

    match &event.action {
        CachePurgeAction::Entries { entries } => {
            let mut removed = 0;
            // FileCache::remove intentionally returns Ok(None) even when it
            // unlinks a cached file, so count every entry whose removal
            // succeeds on a file backend rather than reporting 0.
            let is_file_backend = backend.directory.is_some();
            for entry in entries {
                if backend
                    .cache
                    .remove(&entry.key, entry.namespace.as_bytes())
                    .await?
                    .is_some()
                    || is_file_backend
                {
                    removed += 1;
                }
            }
            Ok(removed)
        },
        CachePurgeAction::Namespace { namespace } => {
            let stats = backend.cache.purge_namespace(namespace).await?;
            Ok(stats.map_or(0, |s| s.success.max(0) as usize))
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CacheObject, new_cache_backend};
    use bytes::Bytes;
    use pretty_assertions::assert_eq;
    use std::sync::Mutex;
    use tempfile::TempDir;

    struct RecordingBroadcaster {
        events: Mutex<Vec<CachePurgeEvent>>,
    }

    impl CachePurgeBroadcaster for RecordingBroadcaster {
        fn broadcast(&self, event: CachePurgeEvent) {
            if let Ok(mut guard) = self.events.lock() {
                guard.push(event);
            }
        }
    }

    #[test]
    fn test_broadcaster_registration() {
        let recorder = Arc::new(RecordingBroadcaster {
            events: Mutex::new(Vec::new()),
        });
        set_purge_broadcaster(Some(recorder.clone()));
        let event = CachePurgeEvent::entries(
            None,
            vec![CachePurgeEntry {
                key: "abc".to_string(),
                namespace: "ns".to_string(),
            }],
        );
        broadcast_purge(event.clone());
        set_purge_broadcaster(None);
        broadcast_purge(event.clone());

        let recorded = recorder.events.lock().unwrap();
        assert_eq!(1, recorded.len());
        assert_eq!(event, recorded[0]);
    }

    #[tokio::test]
    async fn test_apply_purge_event_memory_and_file() {
        let _guard = crate::MEMORY_BACKEND_TEST_LOCK.lock().await;
        let obj = CacheObject {
            meta: (Bytes::from_static(b"m0"), Bytes::from_static(b"m1")),
            body: Bytes::from_static(b"payload"),
        };

        // Memory backend: entries remove, missing directory -> Ok(0).
        let mem = new_cache_backend("memory://").unwrap();
        mem.cache.put("mem-k1", b"ns", obj.clone()).await.unwrap();
        assert_eq!(
            true,
            mem.cache.get("mem-k1", b"ns").await.unwrap().is_some()
        );

        let removed = apply_purge_event(&CachePurgeEvent::entries(
            None,
            vec![CachePurgeEntry {
                key: "mem-k1".to_string(),
                namespace: "ns".to_string(),
            }],
        ))
        .await
        .unwrap();
        assert_eq!(1, removed);
        assert_eq!(
            true,
            mem.cache.get("mem-k1", b"ns").await.unwrap().is_none()
        );

        let missing = apply_purge_event(&CachePurgeEvent::entries(
            Some("/no/such/pingap/cache/dir".to_string()),
            vec![CachePurgeEntry {
                key: "mem-k1".to_string(),
                namespace: "ns".to_string(),
            }],
        ))
        .await
        .unwrap();
        assert_eq!(0, missing);

        // File backend: entries remove & namespace purge.
        let dir = TempDir::new().unwrap();
        let dir_str = dir.path().to_string_lossy().to_string();
        let file = new_cache_backend(&dir_str).unwrap();
        const KEY1: &str = "00000000000000000000000000000011";
        const KEY2: &str = "00000000000000000000000000000012";
        file.cache.put(KEY1, b"site_a", obj.clone()).await.unwrap();
        file.cache.put(KEY2, b"site_a", obj).await.unwrap();

        let removed_entry = apply_purge_event(&CachePurgeEvent::entries(
            file.directory.clone(),
            vec![CachePurgeEntry {
                key: KEY1.to_string(),
                namespace: "site_a".to_string(),
            }],
        ))
        .await
        .unwrap();
        assert_eq!(1, removed_entry);
        assert_eq!(
            true,
            file.cache.get(KEY1, b"site_a").await.unwrap().is_none()
        );
        assert_eq!(
            true,
            file.cache.get(KEY2, b"site_a").await.unwrap().is_some()
        );

        let purged_ns = apply_purge_event(&CachePurgeEvent::namespace(
            file.directory.clone(),
            "site_a".to_string(),
        ))
        .await
        .unwrap();
        assert_eq!(1, purged_ns);
        assert_eq!(
            true,
            file.cache.get(KEY2, b"site_a").await.unwrap().is_none()
        );
    }
}
