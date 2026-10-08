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

//! Which requests an access log has a line for.
//!
//! Every request used to get one. The probe a load balancer sends each
//! second was a line each second, and a busy site wrote gigabytes of
//! `200`s a day to find the few lines somebody later looks for. The
//! conditions are parameters of the log's destination, next to the ones
//! that say how it is written:
//!
//! - `skip=<regex>`: requests whose path and query match are not logged.
//! - `min_status=<status>`, `min_latency=<duration>`: a request that is
//!   an error or slow by these is always logged.
//! - `sample=<0..1>`: the share of the other requests that is logged.
//!   Without it they all are - unless `min_status` or `min_latency` is
//!   set, which says that only those are wanted.
//!
//! A request that is left out is left out before its line is made, so
//! not logging it costs less than logging it.

use super::Error;
use regex::Regex;
use serde::Deserialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

type Result<T> = std::result::Result<T, Error>;

/// The parameters of an access log's destination that say which requests
/// are logged.
pub(crate) const FILTER_PARAMS: &[&str] =
    &["skip", "min_status", "min_latency", "sample"];

#[derive(Debug, Deserialize, Default)]
struct FilterParams {
    skip: Option<String>,
    min_status: Option<u16>,
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    min_latency: Option<Duration>,
    sample: Option<f64>,
}

/// The conditions of one access log.
#[derive(Debug)]
pub struct AccessLogFilter {
    skip: Option<Regex>,
    min_status: Option<u16>,
    min_latency: Option<Duration>,
    sample: Option<f64>,
    /// The requests `sample` was asked about so far.
    seen: AtomicU64,
}

impl AccessLogFilter {
    /// The filter of the access log written to `target` - a path, `stdout`
    /// or a `syslog://` url, with its parameters after `?`. `None` when
    /// none of them is a condition: every request is logged.
    pub fn new(target: &str) -> Result<Option<Self>> {
        let Some((_, query)) = target.split_once('?') else {
            return Ok(None);
        };
        let invalid = |message: String| Error::Invalid {
            message: format!("access log {target}: {message}"),
        };
        let params: FilterParams =
            serde_qs::from_str(query).map_err(|e| invalid(e.to_string()))?;
        let skip = match params.skip.as_deref().filter(|skip| !skip.is_empty())
        {
            Some(skip) => Some(
                Regex::new(skip)
                    .map_err(|e| invalid(format!("skip is no regex: {e}")))?,
            ),
            None => None,
        };
        if params
            .min_status
            .is_some_and(|status| !(100..=599).contains(&status))
        {
            return Err(invalid(
                "min_status should be a status, 100 to 599".to_string(),
            ));
        }
        if params
            .sample
            .is_some_and(|share| !(0.0..=1.0).contains(&share))
        {
            return Err(invalid(
                "sample should be a share, 0 to 1".to_string(),
            ));
        }
        // Kept as it is, a share of all of them included: next to
        // `min_status` that says "and the rest as well", which leaving
        // `sample` out does not.
        let sample = params.sample;
        let filter = Self {
            skip,
            min_status: params.min_status,
            min_latency: params.min_latency,
            sample,
            seen: AtomicU64::new(0),
        };
        // Every request is logged: nothing is skipped, and either there
        // is no condition or the rest is all wanted too.
        let unconditional = filter.skip.is_none()
            && match filter.sample {
                Some(share) => share >= 1.0,
                None => {
                    filter.min_status.is_none() && filter.min_latency.is_none()
                },
            };
        Ok((!unconditional).then_some(filter))
    }

    /// Whether a request to `target` (path and query) that was answered
    /// with `status` after `latency` gets a line.
    #[inline]
    pub fn allows(&self, target: &str, status: u16, latency: Duration) -> bool {
        if self.skip.as_ref().is_some_and(|skip| skip.is_match(target)) {
            return false;
        }
        if self.min_status.is_some_and(|min| status >= min)
            || self.min_latency.is_some_and(|min| latency >= min)
        {
            return true;
        }
        match self.sample {
            Some(share) => self.sampled(share),
            // Only errors and slow requests were asked for.
            None => self.min_status.is_none() && self.min_latency.is_none(),
        }
    }

    /// Every so many requests one, evenly: of each thousand at a share of
    /// a tenth it is a hundred, whatever came in between. No random
    /// number, so two runs over the same requests log the same ones.
    #[inline]
    fn sampled(&self, share: f64) -> bool {
        let seen = self.seen.fetch_add(1, Ordering::Relaxed);
        ((seen + 1) as f64 * share) as u64 > (seen as f64 * share) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    const FAST: Duration = Duration::from_millis(5);
    const SLOW: Duration = Duration::from_millis(900);

    fn filter(target: &str) -> AccessLogFilter {
        AccessLogFilter::new(target).unwrap().unwrap()
    }

    #[test]
    fn test_no_condition_is_no_filter() {
        for target in [
            "/var/log/access.log",
            "/var/log/access.log?rolling=hourly&keep=14d",
            "stdout?flush_timeout=1s",
            "/var/log/access.log?sample=1",
            "/var/log/access.log?skip=",
        ] {
            assert_eq!(
                true,
                AccessLogFilter::new(target).unwrap().is_none(),
                "{target}"
            );
        }
    }

    #[test]
    fn test_skip() {
        let filter = filter("/var/log/access.log?skip=^/(health|ping)$");
        assert_eq!(false, filter.allows("/health", 200, FAST));
        assert_eq!(false, filter.allows("/ping", 500, SLOW));
        assert_eq!(true, filter.allows("/healthy", 200, FAST));
        assert_eq!(true, filter.allows("/api/health", 200, FAST));
        // The query is a part of what is matched.
        assert_eq!(true, filter.allows("/health?full=1", 200, FAST));
        // Written as a parameter of a url, so what a url has meaning for
        // is encoded.
        let encoded = super::tests::filter(
            "stdout?skip=%5E%2Fstatic%2F.%2B%5C.(css%7Cjs)%24",
        );
        assert_eq!(false, encoded.allows("/static/app.js", 200, FAST));
        assert_eq!(true, encoded.allows("/static/app.png", 200, FAST));
    }

    /// Errors and slow requests are what is wanted: nothing else is
    /// logged, unless a share of it is asked for as well.
    #[test]
    fn test_errors_and_slow_requests() {
        let errors = filter("/var/log/access.log?min_status=400");
        assert_eq!(true, errors.allows("/", 404, FAST));
        assert_eq!(true, errors.allows("/", 502, FAST));
        assert_eq!(false, errors.allows("/", 200, FAST));
        assert_eq!(false, errors.allows("/", 304, SLOW));

        let slow = filter("/var/log/access.log?min_latency=500ms");
        assert_eq!(true, slow.allows("/", 200, SLOW));
        assert_eq!(true, slow.allows("/", 200, Duration::from_millis(500)));
        assert_eq!(false, slow.allows("/", 500, FAST));

        // Either is enough.
        let both =
            filter("/var/log/access.log?min_status=500&min_latency=500ms");
        assert_eq!(true, both.allows("/", 500, FAST));
        assert_eq!(true, both.allows("/", 200, SLOW));
        assert_eq!(false, both.allows("/", 404, FAST));

        // And all of the rest, when that is what `sample` says: it used
        // to be read as if it were not there, which is none of the rest.
        assert_eq!(
            true,
            AccessLogFilter::new("/var/log/access.log?min_status=500&sample=1")
                .unwrap()
                .is_none()
        );
        let all =
            filter("/var/log/access.log?skip=^/health&min_status=500&sample=1");
        assert_eq!(true, all.allows("/", 200, FAST));
        assert_eq!(false, all.allows("/health", 200, FAST));

        // And a share of the rest.
        let sampled = filter("/var/log/access.log?min_status=500&sample=0.1");
        let logged =
            (0..1000).filter(|_| sampled.allows("/", 200, FAST)).count();
        assert_eq!(100, logged);
        // The errors are all there, and take none of the share.
        assert_eq!(
            1000,
            (0..1000).filter(|_| sampled.allows("/", 503, FAST)).count()
        );
        assert_eq!(
            100,
            (0..1000).filter(|_| sampled.allows("/", 200, FAST)).count()
        );
    }

    #[test]
    fn test_sample() {
        for (share, expected) in
            [("0.5", 500), ("0.25", 250), ("0.001", 1), ("0", 0)]
        {
            let filter = filter(&format!("stdout?sample={share}"));
            assert_eq!(
                expected,
                (0..1000).filter(|_| filter.allows("/", 200, FAST)).count(),
                "{share}"
            );
        }
        // Spread out, not the first hundred of a thousand.
        let filter = filter("stdout?sample=0.1");
        let logged: Vec<usize> = (0..50)
            .filter(|_| filter.allows("/", 200, FAST))
            .enumerate()
            .map(|(index, _)| index)
            .collect();
        assert_eq!(5, logged.len());
    }

    #[test]
    fn test_invalid_conditions() {
        let error = |target: &str| {
            AccessLogFilter::new(target).unwrap_err().to_string()
        };
        assert_eq!(
            "Invalid access log a.log?sample=2: sample should be a share, 0 to 1",
            error("a.log?sample=2")
        );
        assert_eq!(
            "Invalid access log a.log?sample=-0.1: sample should be a share, 0 to 1",
            error("a.log?sample=-0.1")
        );
        assert_eq!(
            "Invalid access log a.log?min_status=99: min_status should be a status, 100 to 599",
            error("a.log?min_status=99")
        );
        for target in [
            "a.log?min_status=abc",
            "a.log?min_latency=soon",
            "a.log?sample=half",
        ] {
            assert_eq!(
                true,
                error(target)
                    .starts_with(&format!("Invalid access log {target}: ")),
                "{target}"
            );
        }
        assert_eq!(
            true,
            error("a.log?skip=(").starts_with(
                "Invalid access log a.log?skip=(: skip is no regex: "
            )
        );
    }
}
