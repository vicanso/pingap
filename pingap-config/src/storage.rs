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

use crate::{Error, Observer};
use async_trait::async_trait;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

type Result<T, E = Error> = std::result::Result<T, E>;

/// Guard returned by [`Storage::try_acquire_lock`].
///
/// Calling [`StorageLock::release`] explicitly revokes the underlying lease
/// right away; dropping the guard without awaiting still aborts the keep-alive
/// task so the lease expires automatically after its TTL.
pub struct StorageLock {
    release: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
    abort: Option<tokio::task::AbortHandle>,
}

impl StorageLock {
    /// A lock that does nothing on release (for single-node backends such as
    /// file or memory storage).
    pub fn noop() -> Self {
        Self {
            release: None,
            abort: None,
        }
    }

    /// Creates a lock backed by a keep-alive task and an async release action.
    pub fn new(
        release: Pin<Box<dyn Future<Output = ()> + Send>>,
        abort: tokio::task::AbortHandle,
    ) -> Self {
        Self {
            release: Some(release),
            abort: Some(abort),
        }
    }

    /// Explicitly stops keep-alive and releases the lock in storage.
    pub async fn release(mut self) {
        if let Some(abort) = self.abort.take() {
            abort.abort();
        }
        if let Some(fut) = self.release.take() {
            fut.await;
        }
    }
}

impl Drop for StorageLock {
    fn drop(&mut self) {
        if let Some(abort) = self.abort.take() {
            abort.abort();
        }
    }
}

#[derive(Debug, Clone)]
pub struct History {
    pub data: String,
    pub created_at: u64,
}

#[async_trait]
pub trait Storage: Send + Sync {
    /// fetch from storage
    async fn fetch(&self, key: &str) -> Result<String>;

    /// save to storage
    async fn save(&self, key: &str, value: &str) -> Result<()>;

    /// delete from storage
    async fn delete(&self, key: &str) -> Result<()>;

    /// Lists every key under `prefix`, recursively, as paths relative to the
    /// storage root.
    ///
    /// Only the file backend has anything to report: this is how a layout
    /// migration finds the files that a different `ConfigMode` (or a hand
    /// organised layout) wrote. Backends whose layout cannot drift return
    /// nothing.
    async fn list_keys(&self, _prefix: &str) -> Result<Vec<String>> {
        Ok(vec![])
    }

    /// Removes `key` after preserving its current value.
    ///
    /// Returns a human readable description of where the value went, so the
    /// caller can report it. Unlike [`Storage::delete`] this removes something
    /// the user never asked to remove, so losing it silently is not
    /// acceptable; a backend that cannot preserve the value has to say so in
    /// the description it returns.
    async fn retire(&self, key: &str) -> Result<String> {
        self.delete(key).await?;
        Ok(format!("{key} (removed)"))
    }

    /// Fails when nothing can be saved to this storage, with the reason.
    /// For a caller that is about to do something costly whose result has
    /// to be stored.
    fn ensure_writable(&self) -> Result<()> {
        Ok(())
    }

    fn support_observer(&self) -> bool {
        false
    }
    fn support_history(&self) -> bool {
        false
    }
    async fn fetch_history(&self, _key: &str) -> Result<Option<Vec<History>>> {
        Ok(None)
    }
    /// Sets up a watch on the config path to observe changes
    /// Note: May miss changes if processing takes too long between updates
    /// Should be used with periodic full fetches to ensure consistency
    async fn observe(&self) -> Result<Observer> {
        Ok(Observer {
            etcd_watch_stream: None,
            _etcd_client: None,
        })
    }

    /// Attempts to acquire a distributed advisory lock for `key` with the
    /// given `ttl`. Returns `Ok(Some(lock))` when acquired, `Ok(None)` when
    /// another instance currently holds it. Single-node backends return a
    /// no-op lock immediately.
    async fn try_acquire_lock(
        &self,
        _key: &str,
        _ttl: Duration,
    ) -> Result<Option<StorageLock>> {
        Ok(Some(StorageLock::noop()))
    }
}
