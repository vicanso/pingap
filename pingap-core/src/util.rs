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

use pingora::protocols::l4::ext::TcpKeepalive;
use std::sync::LazyLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// What the kernel uses for a keepalive setting that is left out (Linux'
/// `tcp_keepalive_time`, `tcp_keepalive_intvl` and `tcp_keepalive_probes`).
const DEFAULT_TCP_KEEPALIVE_IDLE: Duration = Duration::from_secs(7200);
const DEFAULT_TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(75);
const DEFAULT_TCP_KEEPALIVE_COUNT: usize = 9;

/// The keepalive options of a listener or an upstream, `None` when none of
/// the four settings is given.
///
/// pingora applies the four together, and the kernel refuses a zero for the
/// idle time, the interval or the probe count. A setting that is left out
/// therefore takes the kernel's own default. They used to be zero: giving
/// `tcp_user_timeout` alone, which has nothing to do with the other three,
/// made every connection fail on Linux.
pub fn new_tcp_keepalive(
    idle: Option<Duration>,
    interval: Option<Duration>,
    probe_count: Option<usize>,
    user_timeout: Option<Duration>,
) -> Option<TcpKeepalive> {
    if idle.is_none()
        && interval.is_none()
        && probe_count.is_none()
        && user_timeout.is_none()
    {
        return None;
    }
    Some(TcpKeepalive {
        idle: idle.unwrap_or(DEFAULT_TCP_KEEPALIVE_IDLE),
        interval: interval.unwrap_or(DEFAULT_TCP_KEEPALIVE_INTERVAL),
        count: probe_count.unwrap_or(DEFAULT_TCP_KEEPALIVE_COUNT),
        #[cfg(target_os = "linux")]
        user_timeout: user_timeout.unwrap_or_default(),
    })
}

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

    /// Regression: a setting that was left out became zero, which the
    /// kernel refuses. `tcp_user_timeout` on its own failed every
    /// connection on Linux.
    #[test]
    fn test_new_tcp_keepalive() {
        use super::new_tcp_keepalive;
        use std::time::Duration;

        assert_eq!(true, new_tcp_keepalive(None, None, None, None).is_none());

        let user_timeout = Some(Duration::from_secs(30));
        let keepalive =
            new_tcp_keepalive(None, None, None, user_timeout).unwrap();
        assert_eq!(Duration::from_secs(7200), keepalive.idle);
        assert_eq!(Duration::from_secs(75), keepalive.interval);
        assert_eq!(9, keepalive.count);
        #[cfg(target_os = "linux")]
        assert_eq!(Duration::from_secs(30), keepalive.user_timeout);

        // What is given is used, what is not takes the default.
        let keepalive =
            new_tcp_keepalive(Some(Duration::from_secs(60)), None, None, None)
                .unwrap();
        assert_eq!(Duration::from_secs(60), keepalive.idle);
        assert_eq!(Duration::from_secs(75), keepalive.interval);
        assert_eq!(9, keepalive.count);

        let keepalive = new_tcp_keepalive(
            Some(Duration::from_secs(120)),
            Some(Duration::from_secs(10)),
            Some(3),
            None,
        )
        .unwrap();
        assert_eq!(Duration::from_secs(120), keepalive.idle);
        assert_eq!(Duration::from_secs(10), keepalive.interval);
        assert_eq!(3, keepalive.count);
    }
}
