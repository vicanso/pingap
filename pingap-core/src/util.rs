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

use std::sync::LazyLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// 2022-05-07: 1651852800
const SUPER_TIMESTAMP: u64 = 1651852800;

/// Time since the epoch, or zero if the system clock is set before it.
#[inline]
fn since_epoch() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
}

/// Returns the number of seconds since the epoch
#[inline]
pub fn now_sec() -> u64 {
    since_epoch().as_secs()
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
    since_epoch().as_millis() as u64
}

/// Compares two byte slices in constant time relative to their length, avoiding
/// the early exit of `==` that can leak (via timing) how many leading bytes
/// matched. Use it for verifying secrets, MACs and signatures. The slice
/// lengths are not treated as secret and are compared up front.
#[inline]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    std::hint::black_box(diff) == 0
}

#[cfg(test)]
mod tests {
    use super::{
        constant_time_eq, get_hostname, get_super_ts, now_ms, now_sec,
    };
    use pretty_assertions::assert_eq;

    #[test]
    fn test_constant_time_eq() {
        assert_eq!(true, constant_time_eq(b"abc123", b"abc123"));
        assert_eq!(true, constant_time_eq(b"", b""));
        assert_eq!(false, constant_time_eq(b"abc123", b"abc124"));
        assert_eq!(false, constant_time_eq(b"abc", b"abcd"));
    }

    #[test]
    fn test_super_ts() {
        assert_eq!(true, get_super_ts() > 104017048);
    }

    #[test]
    fn test_now_ms() {
        assert_eq!(true, now_ms() > 1755870295813);
    }

    /// The clock reads straight from the system, so it advances on its own -
    /// nothing has to tick it, and two reads a moment apart cannot go backwards.
    #[test]
    fn test_now_advances_without_an_updater() {
        let start = now_ms();
        std::thread::sleep(std::time::Duration::from_millis(20));
        let elapsed = now_ms() - start;
        assert_eq!(true, elapsed >= 20, "only advanced {elapsed}ms");
        assert_eq!(now_sec(), now_ms() / 1000);
    }

    #[test]
    fn test_get_hostname() {
        assert_eq!(false, get_hostname().is_empty());
    }
}
