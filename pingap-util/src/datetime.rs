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

use once_cell::sync::Lazy;
use pingap_core::now_ms;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// 2022-05-07: 1651852800
// const SUPER_TIMESTAMP: u64 = 1651852800;
static SUPER_TIMESTAMP: Lazy<SystemTime> = Lazy::new(|| {
    UNIX_EPOCH
        .checked_add(Duration::from_secs(1651852800))
        .unwrap_or(SystemTime::now())
});

/// Returns the number of seconds elapsed since SUPER_TIMESTAMP
/// Returns 0 if the current time is before SUPER_TIMESTAMP
pub fn get_super_ts() -> u32 {
    if let Ok(value) = SystemTime::now().duration_since(*SUPER_TIMESTAMP) {
        value.as_secs() as u32
    } else {
        0
    }
}

/// Calculates latency between a previous timestamp and now
/// If previous timestamp is None, returns current timestamp
/// Returns: Some(latency in milliseconds) or Some(current timestamp) if input is None
#[inline]
pub fn get_latency(value: &Option<u64>) -> Option<u64> {
    let current = now_ms();
    if let Some(value) = value {
        Some(current - value)
    } else {
        Some(current)
    }
}

/// Returns the elapsed time in milliseconds since the given SystemTime
#[inline]
pub fn elapsed_ms(time: SystemTime) -> u64 {
    time.elapsed().unwrap_or_default().as_millis() as u64
}

/// Returns the elapsed time in seconds (as f64) since the given SystemTime
#[inline]
pub fn elapsed_second(time: SystemTime) -> f64 {
    time.elapsed().unwrap_or_default().as_millis() as f64 / 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingap_core::{now_ms, now_sec};
    use pretty_assertions::assert_eq;

    #[test]
    fn test_get_super_ts() {
        assert_eq!(get_super_ts().to_string().len() >= 8, true);
    }

    #[test]
    fn test_now() {
        assert_eq!(10, now_sec().to_string().len());
        assert_eq!(13, now_ms().to_string().len());
    }

    #[test]
    fn test_elapsed_ms() {
        let start = SystemTime::now()
            .checked_sub(Duration::from_secs(55))
            .unwrap();
        assert_eq!(5, elapsed_ms(start).to_string().len());
        assert_eq!(elapsed_second(start).to_string().starts_with("55"), true);
    }

    #[test]
    fn test_get_latency() {
        let d = get_latency(&None);
        assert_eq!(true, d.is_some());
        assert_eq!(true, get_latency(&d).is_some());
    }
}
