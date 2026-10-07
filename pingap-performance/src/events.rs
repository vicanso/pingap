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

//! What happens to the process as a whole and is counted for the metrics:
//! the reloads of the configuration.
//!
//! Counted here, without the `tracing` feature, so that whoever reloads
//! does not have to know whether anything exports the numbers.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static RELOAD_SUCCESS: AtomicU64 = AtomicU64::new(0);
static RELOAD_FAILURE: AtomicU64 = AtomicU64::new(0);
/// Unix time of the last reload that was applied, `0` before the first.
static LAST_RELOAD_SUCCESS_AT: AtomicU64 = AtomicU64::new(0);
/// Whether the last reload was applied. A process that has not reloaded
/// runs the configuration it started with, which loaded.
static LAST_RELOAD_FAILED: AtomicBool = AtomicBool::new(false);

/// How the reloads of the configuration went so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigReloads {
    /// Reloads that were applied.
    pub success: u64,
    /// Reloads that were refused: the configuration did not load or did
    /// not pass, and the running one stayed.
    pub failure: u64,
    /// Unix time of the last reload that was applied, `0` when there was
    /// none yet.
    pub last_success_at: u64,
    /// Whether the last reload was applied; `true` when there was none.
    pub last_successful: bool,
}

/// Counts a reload of the configuration: one that was applied, or one that
/// was refused and left the running configuration in place.
pub fn record_config_reload(success: bool) {
    if success {
        RELOAD_SUCCESS.fetch_add(1, Ordering::Relaxed);
        LAST_RELOAD_SUCCESS_AT.store(pingap_core::now_sec(), Ordering::Relaxed);
    } else {
        RELOAD_FAILURE.fetch_add(1, Ordering::Relaxed);
    }
    LAST_RELOAD_FAILED.store(!success, Ordering::Relaxed);
}

pub fn config_reloads() -> ConfigReloads {
    ConfigReloads {
        success: RELOAD_SUCCESS.load(Ordering::Relaxed),
        failure: RELOAD_FAILURE.load(Ordering::Relaxed),
        last_success_at: LAST_RELOAD_SUCCESS_AT.load(Ordering::Relaxed),
        last_successful: !LAST_RELOAD_FAILED.load(Ordering::Relaxed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    /// The one test that records reloads: the counters are the process's.
    #[test]
    fn test_record_config_reload() {
        let before = config_reloads();
        assert_eq!(true, before.last_successful);
        record_config_reload(false);
        let failed = config_reloads();
        assert_eq!(before.failure + 1, failed.failure);
        assert_eq!(before.success, failed.success);
        assert_eq!(false, failed.last_successful);
        assert_eq!(before.last_success_at, failed.last_success_at);

        record_config_reload(true);
        let applied = config_reloads();
        assert_eq!(before.success + 1, applied.success);
        assert_eq!(true, applied.last_successful);
        assert_eq!(true, applied.last_success_at >= pingap_core::now_sec() - 5);
    }
}
