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

//! Makes the first health check round of an upstream decisive.
//!
//! pingora starts every backend healthy and only lets a backend flip after
//! `failure` consecutive failed checks; its health state cannot be set from
//! outside. So the round pingap runs before switching to a new upstream
//! could not keep a dead backend out: one failed check only moved the
//! counter to 1, below the default threshold of 2, and the backend went
//! live anyway.
//!
//! The threshold is the one lever there is, since pingora asks the health
//! check for it on every observation. [`FirstRoundHealthCheck`] answers 1
//! for a failure until a round has checked at least one backend, so the
//! first check of each backend decides; after that round the configured
//! `failure` applies again. A success is unaffected: a backend starts
//! healthy, so passing its first check changes nothing.

use async_trait::async_trait;
use pingora::lb::Backend;
use pingora::lb::health_check::HealthCheck;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Whether an upstream is still in its first health check round.
#[derive(Debug)]
pub(crate) struct FirstRound {
    active: AtomicBool,
    /// Backends checked while the first round was active.
    checked: AtomicUsize,
}

impl FirstRound {
    pub(crate) fn new() -> Self {
        Self {
            active: AtomicBool::new(true),
            checked: AtomicUsize::new(0),
        }
    }

    pub(crate) fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    /// Ends the first round once a round actually checked a backend. A
    /// round with nothing to check - discovery has not found any backend
    /// yet, or failed - leaves it active, so the first backends that do
    /// show up still get a decisive first check.
    pub(crate) fn finish(&self) {
        if self.checked.load(Ordering::Relaxed) > 0 {
            self.active.store(false, Ordering::Relaxed);
        }
    }
}

/// An upstream's health check, with a failure threshold of 1 during its
/// first round. Everything else is delegated.
pub(crate) struct FirstRoundHealthCheck {
    inner: Box<dyn HealthCheck + Send + Sync>,
    first_round: Arc<FirstRound>,
}

impl FirstRoundHealthCheck {
    pub(crate) fn new(
        inner: Box<dyn HealthCheck + Send + Sync>,
        first_round: Arc<FirstRound>,
    ) -> Self {
        Self { inner, first_round }
    }
}

#[async_trait]
impl HealthCheck for FirstRoundHealthCheck {
    async fn check(&self, target: &Backend) -> pingora::Result<()> {
        if self.first_round.is_active() {
            self.first_round.checked.fetch_add(1, Ordering::Relaxed);
        }
        self.inner.check(target).await
    }

    async fn health_status_change(&self, target: &Backend, healthy: bool) {
        self.inner.health_status_change(target, healthy).await
    }

    fn backend_summary(&self, target: &Backend) -> String {
        self.inner.backend_summary(target)
    }

    fn health_threshold(&self, success: bool) -> usize {
        if !success && self.first_round.is_active() {
            1
        } else {
            self.inner.health_threshold(success)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    struct Fixed(usize);

    #[async_trait]
    impl HealthCheck for Fixed {
        async fn check(&self, _target: &Backend) -> pingora::Result<()> {
            Ok(())
        }
        fn health_threshold(&self, success: bool) -> usize {
            if success { 1 } else { self.0 }
        }
    }

    #[tokio::test]
    async fn test_first_round_threshold() {
        let first_round = Arc::new(FirstRound::new());
        let check =
            FirstRoundHealthCheck::new(Box::new(Fixed(3)), first_round.clone());

        // Before and during the first round a single failure decides; a
        // success keeps the configured threshold.
        assert_eq!(1, check.health_threshold(false));
        assert_eq!(1, check.health_threshold(true));

        // A round that checked nothing does not end it.
        first_round.finish();
        assert_eq!(true, first_round.is_active());
        assert_eq!(1, check.health_threshold(false));

        // One that checked a backend does, and `failure` applies again.
        let backend = Backend::new("127.0.0.1:1").unwrap();
        check.check(&backend).await.unwrap();
        first_round.finish();
        assert_eq!(false, first_round.is_active());
        assert_eq!(3, check.health_threshold(false));
    }
}
