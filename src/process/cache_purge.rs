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

use async_trait::async_trait;
use pingap_cache::{
    CachePurgeBroadcaster, CachePurgeEvent, apply_purge_event,
    set_purge_broadcaster,
};
use pingap_config::{ConfigManager, EventObserver};
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

static LOG_TARGET: &str = "main::cache_purge";
const CACHE_PURGE_CHANNEL: &str = "cache_purge";
const EVENT_TTL: Duration = Duration::from_secs(60);
const CHANNEL_CAPACITY: usize = 1024;
const MIN_BACKOFF_MS: u64 = 500;
const MAX_BACKOFF_MS: u64 = 60_000;
const WATCH_HELD: Duration = Duration::from_secs(60);

struct ChannelPurgeBroadcaster {
    origin: String,
    tx: mpsc::Sender<CachePurgeEvent>,
}

impl CachePurgeBroadcaster for ChannelPurgeBroadcaster {
    fn broadcast(&self, mut event: CachePurgeEvent) {
        if event.origin.is_empty() {
            event.origin.clone_from(&self.origin);
        }
        if let Err(err) = self.tx.try_send(event) {
            warn!(
                target: LOG_TARGET,
                error = %err,
                "drop cluster cache purge broadcast"
            );
        }
    }
}

/// Synchronizes cache `PURGE` operations across instances backed by an event
/// bus (`etcd://`) without adding blocking I/O to request handling.
pub struct CachePurgeService {
    config_manager: Arc<ConfigManager>,
}

/// Creates a new [`CachePurgeService`] bound to `config_manager`.
pub fn new_cache_purge_service(
    config_manager: Arc<ConfigManager>,
) -> CachePurgeService {
    CachePurgeService { config_manager }
}

async fn publish_outbound_event(
    config_manager: &ConfigManager,
    mut event: CachePurgeEvent,
    origin: &str,
) {
    if event.origin.is_empty() {
        event.origin = origin.to_string();
    }
    let payload = match serde_json::to_string(&event) {
        Ok(payload) => payload,
        Err(err) => {
            warn!(target: LOG_TARGET, error = %err, "serialize cache purge event fail");
            return;
        },
    };
    if let Err(err) = config_manager
        .publish_event(CACHE_PURGE_CHANNEL, &payload, EVENT_TTL)
        .await
    {
        warn!(
            target: LOG_TARGET,
            error = %err,
            "publish cluster cache purge event fail"
        );
    }
}

async fn handle_incoming_payload(payload: &str, local_origin: &str) {
    let event: CachePurgeEvent = match serde_json::from_str(payload) {
        Ok(event) => event,
        Err(err) => {
            warn!(
                target: LOG_TARGET,
                error = %err,
                "decode cluster cache purge event fail"
            );
            return;
        },
    };
    if event.origin == local_origin {
        return;
    }
    match apply_purge_event(&event).await {
        Ok(removed) => {
            debug!(
                target: LOG_TARGET,
                from_origin = event.origin,
                directory = event.directory.as_deref().unwrap_or("memory"),
                removed,
                "applied cluster cache purge event"
            );
        },
        Err(err) => {
            warn!(
                target: LOG_TARGET,
                error = %err,
                from_origin = event.origin,
                "apply cluster cache purge event fail"
            );
        },
    }
}

enum EventPoll {
    Connected,
    Batch(Vec<String>),
}

async fn poll_event_batch(
    config_manager: &ConfigManager,
    observer: Option<EventObserver>,
    backoff_ms: u64,
) -> (
    Option<EventObserver>,
    Result<EventPoll, pingap_config::Error>,
) {
    let Some(mut current) = observer else {
        if backoff_ms > 0 {
            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
        }
        return match config_manager.subscribe_events(CACHE_PURGE_CHANNEL).await
        {
            Ok(obs) => (obs, Ok(EventPoll::Connected)),
            Err(err) => (None, Err(err)),
        };
    };
    match current.next_events().await {
        Ok(batch) => (Some(current), Ok(EventPoll::Batch(batch))),
        Err(err) => (None, Err(err)),
    }
}

#[async_trait]
impl BackgroundService for CachePurgeService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        if !self.config_manager.support_events() {
            return;
        }
        let origin = format!("{}-{}", std::process::id(), nanoid::nanoid!(8));
        let (tx, mut rx) = mpsc::channel(CHANNEL_CAPACITY);
        set_purge_broadcaster(Some(Arc::new(ChannelPurgeBroadcaster {
            origin: origin.clone(),
            tx,
        })));
        info!(
            target: LOG_TARGET,
            origin, "cluster cache purge sync service started"
        );

        let mut backoff_ms = 0_u64;
        let mut watching_since: Option<Instant> = None;
        let next = poll_event_batch(&self.config_manager, None, 0);
        tokio::pin!(next);

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    break;
                }
                Some(event) = rx.recv() => {
                    publish_outbound_event(&self.config_manager, event, &origin).await;
                }
                (observer, result) = &mut next => {
                    match result {
                        Ok(EventPoll::Connected) => {
                            if observer.is_none() {
                                break;
                            }
                            watching_since = Some(Instant::now());
                        },
                        Ok(EventPoll::Batch(payloads)) => {
                            if !payloads.is_empty() {
                                backoff_ms = MIN_BACKOFF_MS;
                            }
                            for payload in payloads {
                                handle_incoming_payload(&payload, &origin).await;
                            }
                        },
                        Err(err) => {
                            warn!(
                                target: LOG_TARGET,
                                error = %err,
                                "cluster cache purge watch fail"
                            );
                            let held = watching_since
                                .take()
                                .is_some_and(|since| since.elapsed() >= WATCH_HELD);
                            if held || backoff_ms == 0 {
                                backoff_ms = MIN_BACKOFF_MS;
                            } else {
                                backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
                            }
                        },
                    }
                    let wait = if observer.is_none() { backoff_ms } else { 0 };
                    next.set(poll_event_batch(&self.config_manager, observer, wait));
                }
            }
        }

        set_purge_broadcaster(None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingap_cache::{
        CacheObject, CachePurgeAction, CachePurgeEntry, new_cache_backend,
    };
    use pretty_assertions::assert_eq;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_handle_incoming_payload_filters_origin_and_purges_local() {
        let dir = TempDir::new().unwrap();
        let dir_str = dir.path().to_string_lossy().to_string();
        let backend = new_cache_backend(&dir_str).unwrap();
        const KEY_SELF: &str = "00000000000000000000000000000021";
        const KEY_PEER: &str = "00000000000000000000000000000022";
        let obj = CacheObject {
            meta: (
                bytes::Bytes::from_static(b"m0"),
                bytes::Bytes::from_static(b"m1"),
            ),
            body: bytes::Bytes::from_static(b"cached"),
        };
        backend
            .cache
            .put(KEY_SELF, b"ns", obj.clone())
            .await
            .unwrap();
        backend.cache.put(KEY_PEER, b"ns", obj).await.unwrap();

        let self_event = serde_json::to_string(&CachePurgeEvent {
            origin: "node-self".to_string(),
            directory: backend.directory.clone(),
            action: CachePurgeAction::Entries {
                entries: vec![CachePurgeEntry {
                    key: KEY_SELF.to_string(),
                    namespace: "ns".to_string(),
                }],
            },
        })
        .unwrap();
        handle_incoming_payload(&self_event, "node-self").await;
        assert_eq!(
            true,
            backend.cache.get(KEY_SELF, b"ns").await.unwrap().is_some()
        );

        let peer_event = serde_json::to_string(&CachePurgeEvent {
            origin: "node-other".to_string(),
            directory: backend.directory.clone(),
            action: CachePurgeAction::Entries {
                entries: vec![CachePurgeEntry {
                    key: KEY_PEER.to_string(),
                    namespace: "ns".to_string(),
                }],
            },
        })
        .unwrap();
        handle_incoming_payload(&peer_event, "node-self").await;
        assert_eq!(
            true,
            backend.cache.get(KEY_PEER, b"ns").await.unwrap().is_none()
        );
    }
}
