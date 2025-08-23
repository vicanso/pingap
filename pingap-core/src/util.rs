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

use coarsetime::{Clock, Instant, Updater};
use once_cell::sync::Lazy;

static COARSE_CLOCK_UPDATER: Lazy<Updater> = Lazy::new(|| {
    let interval = std::env::var("PINGAP_COARSE_CLOCK_INTERVAL")
        .unwrap_or("10".to_string())
        .parse::<u64>()
        .unwrap_or(10)
        .clamp(1, 500);
    Updater::new(interval).start().unwrap()
});

/// Returns the current instant
#[inline]
pub fn now_instant() -> Instant {
    Instant::now()
}

/// Initialize the time cache
pub fn init_time_cache() {
    Lazy::force(&COARSE_CLOCK_UPDATER);
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

static HOST_NAME: Lazy<String> = Lazy::new(|| {
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

#[cfg(test)]
mod tests {
    use super::{get_super_ts, init_time_cache, now_ms, real_now_ms};
    use pretty_assertions::assert_eq;

    #[test]
    fn test_super_ts() {
        init_time_cache();
        assert_eq!(true, get_super_ts() > 104017048);
    }

    #[test]
    fn test_now_ms() {
        init_time_cache();
        assert_eq!(true, now_ms() > 1755870295813);
    }

    #[test]
    fn test_real_now_ms() {
        init_time_cache();
        assert_eq!(true, real_now_ms() > 1755870295813);
    }
}
