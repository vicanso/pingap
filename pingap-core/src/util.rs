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

use coarsetime::{Clock, Updater};
use ctor::ctor;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{LazyLock, Mutex};

static CLOCK_UPDATER_PID: AtomicU32 = AtomicU32::new(0);
static CLOCK_UPDATER: Mutex<Option<Updater>> = Mutex::new(None);

/// Ensures the coarse clock background updater is running for the current
/// process. Idempotent and fork-safe: if the updater was started in a parent
/// process and we're now in a child after fork (e.g. pingora's daemonize),
/// the parent's `Updater` handle is dropped (its thread doesn't exist here)
/// and a fresh updater thread is spawned for this process.
pub fn ensure_clock_updater() {
    let pid = std::process::id();
    if CLOCK_UPDATER_PID.load(Ordering::Acquire) == pid {
        return;
    }
    let mut guard = CLOCK_UPDATER.lock().expect("clock updater mutex poisoned");
    if CLOCK_UPDATER_PID.load(Ordering::Acquire) == pid {
        return;
    }
    // Drop the parent's handle without joining — fork only carries the calling
    // thread, so the parent's updater thread does not exist in this process.
    // JoinHandle's Drop detaches rather than joining, which is what we want.
    let _ = guard.take();

    let interval = std::env::var("PINGAP_COARSE_CLOCK_INTERVAL")
        .unwrap_or_else(|_| "10".to_string())
        .parse::<u64>()
        .unwrap_or(10)
        .clamp(1, 500);
    let updater = Updater::new(interval)
        .start()
        .expect("Failed to start coarse clock updater");
    *guard = Some(updater);
    CLOCK_UPDATER_PID.store(pid, Ordering::Release);
}

// 2022-05-07: 1651852800
const SUPER_TIMESTAMP: u64 = 1651852800;

/// Returns the number of seconds since the epoch
#[inline]
pub fn now_sec() -> u64 {
    Clock::recent_since_epoch().as_secs()
}

/// Returns the number of seconds elapsed since SUPER_TIMESTAMP
/// Returns 0 if the current time is before SUPER_TIMESTAMP
#[inline]
pub fn get_super_ts() -> u32 {
    let super_ts_secs = SUPER_TIMESTAMP;
    now_sec().saturating_sub(super_ts_secs) as u32
}

static HOST_NAME: LazyLock<String> = LazyLock::new(|| {
    hostname::get()
        .ok()
        .as_deref()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or("")
        .to_string()
});

/// Returns the system hostname.
///
/// Returns:
/// * `&'static str` - The system's hostname as a string slice
pub fn get_hostname() -> &'static str {
    HOST_NAME.as_str()
}

/// Returns the number of milliseconds since the epoch
#[inline]
pub fn now_ms() -> u64 {
    Clock::recent_since_epoch().as_millis()
}

/// Returns the number of milliseconds since the epoch
/// This is the real time, not the coarse time
#[inline]
pub fn real_now_ms() -> u64 {
    Clock::now_since_epoch().as_millis()
}

#[ctor]
fn init() {
    ensure_clock_updater();
}

#[cfg(test)]
mod tests {
    use super::{
        ensure_clock_updater, get_hostname, get_super_ts, now_ms, real_now_ms,
    };
    use pretty_assertions::assert_eq;

    #[test]
    fn test_super_ts() {
        ensure_clock_updater();
        assert_eq!(true, get_super_ts() > 104017048);
    }

    #[test]
    fn test_now_ms() {
        ensure_clock_updater();
        assert_eq!(true, now_ms() > 1755870295813);
    }

    #[test]
    fn test_real_now_ms() {
        ensure_clock_updater();
        assert_eq!(true, real_now_ms() > 1755870295813);
    }

    #[test]
    fn test_get_hostname() {
        assert_eq!(false, get_hostname().is_empty());
    }
}
