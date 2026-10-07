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

use super::{
    Error, get_bool_conf, get_hash_key, get_int_conf, get_step_conf_in,
    get_str_conf,
};
use async_trait::async_trait;
use bytes::Bytes;
use http::header::RETRY_AFTER;
use http::{HeaderName, HeaderValue, StatusCode};
use humantime::parse_duration;
use pingap_config::{PluginCategory, PluginConf};
use pingap_core::{
    Ctx, HttpHeader, HttpResponse, Inflight, Plugin, PluginStep, Rate,
    RateLimitQuota, RequestPluginResult, ResponsePluginResult,
};
use pingap_core::{
    ensure_verified_client_ip, get_cookie_value, get_query_value,
    get_req_header_value,
};
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use std::borrow::Cow;
use std::time::Duration;
use tracing::{debug, warn};

type Result<T, E = Error> = std::result::Result<T, E>;

// LimitTag determines what value will be used as the rate limiting key
#[derive(PartialEq, Eq, Debug)]
pub enum LimitTag {
    Ip, // Use the client IP: through trusted proxies, else the peer's own
    RequestHeader, // Use value from a specified HTTP request header
    Cookie, // Use value from a specified cookie
    Query, // Use value from a specified URL query parameter
}

// Limiter implements rate limiting and concurrent request limiting
// It can be configured via TOML with settings like:
// ```toml
// type = "rate"          # or "inflight"
// tag = "cookie"         # or "header", "query", "ip"
// key = "session_id"     # name of header/cookie/query param to use
// max = 100             # maximum requests allowed
// interval = "60s"      # time window for rate limiting
// ```
/// A rate limiter or concurrent request limiter that can be configured to limit based on
/// different request attributes (IP, headers, cookies, query params)
pub struct Limiter {
    /// Determines what value will be used as the rate limiting key (IP, header, cookie, or query param)
    tag: LimitTag,

    /// Maximum number of requests allowed within any one interval (for rate
    /// limiting) or at the same time (for inflight limiting)
    max: f64,

    /// The name of the header/cookie/query parameter to use as the limiting key
    /// Only used when tag is not LimitTag::Ip
    key: String,

    /// Tracks concurrent requests using atomic counters.
    /// When a request completes, the counter automatically decrements via RAII guard.
    /// Only used when configured as an inflight limiter (type = "inflight")
    inflight: Option<Inflight>,

    /// Tracks request counts over a sliding time window.
    /// Automatically expires old requests based on configured interval.
    /// Only used when configured as a rate limiter (type = "rate")
    rate: Option<Rate>,

    /// When to apply the limiting logic:
    /// - PluginStep::Request: During initial request processing
    /// - PluginStep::ProxyUpstream: Before forwarding to upstream server
    plugin_step: PluginStep,

    /// Unique identifier for this limiter instance, used to distinguish between
    /// different limiters in the same application
    hash_value: String,

    /// `Retry-After` for a rate limiter's 429: the window length, the
    /// soonest the budget can have moved on.
    retry_after: Option<HttpHeader>,

    /// Whether the client is told its budget, in `X-RateLimit-Limit`,
    /// `X-RateLimit-Remaining` and `X-RateLimit-Reset`.
    headers: bool,

    /// The status of the response to a request over the limit, `429`
    /// unless set.
    status: StatusCode,

    /// Its body, in place of the one that names the count and the limit.
    message: Option<Bytes>,

    /// Whether a request without a value for the key is refused. It is let
    /// through, unlimited, unless `missing_key = "reject"`.
    reject_missing_key: bool,
}

/// What became of a request at the limiter.
enum Verdict {
    /// Let through, counted or - without a value for the key - not.
    Pass,
    /// Over the limit, by the count and the limit it was held to.
    Exceeded(f64),
    /// No value for the key, and the limiter was told to refuse that.
    MissingKey,
}

static X_RATELIMIT_LIMIT: HeaderName =
    HeaderName::from_static("x-ratelimit-limit");
static X_RATELIMIT_REMAINING: HeaderName =
    HeaderName::from_static("x-ratelimit-remaining");
static X_RATELIMIT_RESET: HeaderName =
    HeaderName::from_static("x-ratelimit-reset");

/// The three headers of `quota`, `X-RateLimit-Reset` left out where there
/// is no time to name.
fn quota_headers(quota: &RateLimitQuota) -> Vec<HttpHeader> {
    let mut headers = vec![
        (X_RATELIMIT_LIMIT.clone(), HeaderValue::from(quota.limit)),
        (
            X_RATELIMIT_REMAINING.clone(),
            HeaderValue::from(quota.remaining),
        ),
    ];
    if let Some(reset) = quota.reset {
        headers.push((X_RATELIMIT_RESET.clone(), HeaderValue::from(reset)));
    }
    headers
}

/// In how many seconds a client's budget is back in full if it sends
/// nothing more, from the two windows it is counted in: what is in the
/// current one fades over the whole of the next, what is left of the one
/// before is gone when the current one ends.
///
/// `fraction` is how much of the current window has passed.
fn seconds_to_reset(
    interval: Duration,
    prev_samples: isize,
    curr_samples: isize,
    fraction: f64,
) -> u64 {
    let left = 1.0 - fraction;
    let windows = if curr_samples > 0 {
        left + 1.0
    } else if prev_samples > 0 {
        left
    } else {
        return 0;
    };
    (interval.as_secs_f64() * windows).ceil().max(1.0) as u64
}

/// Converts a plugin configuration into a Limiter instance
///
/// # Arguments
/// * `value` - Plugin configuration containing limiter settings
///
/// # Returns
/// * `Result<Self>` - New Limiter instance or error if configuration is invalid
///
/// # Configuration Options
/// * `type` - "rate" or "inflight"
/// * `tag` - "ip", "cookie", "header", or "query"
/// * `key` - Name of header/cookie/query parameter to use
/// * `max` - Maximum allowed requests/connections
/// * `interval` - Time window for rate limiting (e.g. "60s")
impl TryFrom<&PluginConf> for Limiter {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);
        let category = PluginCategory::Limit.to_string();
        let invalid = |message: String| Error::Invalid {
            category: category.clone(),
            message,
        };
        // Limiting only makes sense before the upstream is involved.
        let step = get_step_conf_in(
            value,
            &category,
            PluginStep::Request,
            &[PluginStep::Request, PluginStep::ProxyUpstream],
        )?;

        // Every setting here decides who gets limited, so a value that is
        // not one of the documented ones is an error rather than a silent
        // fallback: a misspelt `tag` used to limit by ip, a misspelt `type`
        // rate-limited, and a forgotten `max` rejected almost everything.
        let tag = match get_str_conf(value, "tag").as_str() {
            "" | "ip" => LimitTag::Ip,
            "cookie" => LimitTag::Cookie,
            "header" => LimitTag::RequestHeader,
            "query" => LimitTag::Query,
            other => {
                return Err(invalid(format!(
                    "Invalid tag({other}), expect ip, header, cookie or query"
                )));
            },
        };
        let key = get_str_conf(value, "key");
        if tag != LimitTag::Ip && key.is_empty() {
            return Err(invalid(
                "key is required for a header, cookie or query tag".to_string(),
            ));
        }
        let is_inflight = match get_str_conf(value, "type").as_str() {
            "" | "rate" => false,
            "inflight" => true,
            other => {
                return Err(invalid(format!(
                    "Invalid type({other}), expect rate or inflight"
                )));
            },
        };
        if !value.contains_key("max") {
            return Err(invalid("max is required".to_string()));
        }
        let max = get_int_conf(value, "max");
        if max < 0 {
            return Err(invalid("max must not be negative".to_string()));
        }

        // Parse time interval for rate limiting
        // Format examples: "10s", "1m", "2h"
        // Default: 10 seconds if not specified
        let interval = get_str_conf(value, "interval");
        let interval = if !interval.is_empty() {
            parse_duration(&interval).map_err(|e| invalid(e.to_string()))?
        } else {
            Duration::from_secs(10)
        };
        // The counter keeps its windows in milliseconds, and divides by
        // their length: one shorter than that is a division by zero on
        // the first request.
        if interval < Duration::from_millis(1) {
            return Err(invalid("interval must be at least 1ms".to_string()));
        }

        // Create either inflight or rate limiter based on config
        let mut inflight = None;
        let mut rate = None;
        let mut retry_after = None;
        let max = max as f64;
        if is_inflight {
            // Inflight limiter uses atomic counters to track concurrent requests
            inflight = Some(Inflight::new());
        } else {
            // Rate limiter uses time-bucketed counters
            rate = Some(Rate::new(interval));
            retry_after = Some((
                RETRY_AFTER,
                HeaderValue::from(interval.as_secs().max(1)),
            ));
        }

        // What a refused client is answered with. A status that is not an
        // error would tell it the request went through.
        let status = if value.contains_key("status") {
            u16::try_from(get_int_conf(value, "status"))
                .ok()
                .filter(|status| (400..600).contains(status))
                .and_then(|status| StatusCode::from_u16(status).ok())
                .ok_or_else(|| {
                    invalid("status must be between 400 and 599".to_string())
                })?
        } else {
            StatusCode::TOO_MANY_REQUESTS
        };
        let message = get_str_conf(value, "message");
        let message = (!message.is_empty()).then(|| Bytes::from(message));
        let reject_missing_key =
            match get_str_conf(value, "missing_key").as_str() {
                "" | "pass" => false,
                "reject" => true,
                other => {
                    return Err(invalid(format!(
                        "Invalid missing_key({other}), expect pass or reject"
                    )));
                },
            };

        // `weight` blended the previous window into the estimate by a fixed
        // share. It has no part in the sliding window that replaced that,
        // and a config that still has it is told so instead of refused.
        if value.contains_key("weight") {
            warn!(
                "the weight of the limit plugin is no longer used: max is the number of requests in any one interval"
            );
        }

        Ok(Self {
            hash_value,
            tag,
            key,
            max,
            inflight,
            rate,
            plugin_step: step,
            retry_after,
            headers: get_bool_conf(value, "headers"),
            status,
            message,
            reject_missing_key,
        })
    }
}

impl Limiter {
    /// What the key is, for the client that did not send it.
    fn key_description(&self) -> String {
        match self.tag {
            LimitTag::Ip => "the client address".to_string(),
            LimitTag::RequestHeader => format!("the header {}", self.key),
            LimitTag::Cookie => format!("the cookie {}", self.key),
            LimitTag::Query => format!("the query parameter {}", self.key),
        }
    }
    /// Creates a new Limiter instance from plugin configuration
    ///
    /// # Arguments
    /// * `params` - Plugin configuration containing limiter settings like type, tag, key, max, etc.
    ///
    /// # Returns
    /// * `Result<Self>` - New Limiter instance or error if configuration is invalid
    ///
    /// # Example Configuration
    /// ```toml
    /// type = "rate"          # or "inflight"
    /// tag = "cookie"         # or "header", "query", "ip"
    /// key = "session_id"     # name of header/cookie/query param to use
    /// max = 100             # maximum requests allowed
    /// interval = "60s"      # time window for rate limiting
    /// ```
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(
            params = pingap_config::masked_toml(params),
            "new limit plugin"
        );
        Self::try_from(params)
    }
    /// The error of a request that took the count to `value`.
    fn exceeded(&self, value: f64) -> Error {
        Error::Exceed {
            category: PluginCategory::Limit.to_string(),
            max: self.max,
            value,
        }
    }

    /// Counts the request, and fails when that takes it over the limit.
    #[cfg(test)]
    fn incr(&self, session: &Session, ctx: &mut Ctx) -> Result<()> {
        match self.check(session, ctx) {
            Verdict::Exceeded(value) => Err(self.exceeded(value)),
            _ => Ok(()),
        }
    }

    /// Notes what is left of this limit for the response headers, unless
    /// another limit of the request has less left.
    ///
    /// The limit that refuses the request is the one the refusal is about:
    /// its budget is what is reported, whatever another limit noted before
    /// it, and nothing at all when it is not one that reports.
    fn note_quota(&self, ctx: &mut Ctx, value: f64, reset: Option<u64>) {
        let refused = value > self.max;
        if !self.headers {
            if refused {
                ctx.state.rate_limit = None;
            }
            return;
        }
        let quota = RateLimitQuota {
            limit: self.max as u64,
            remaining: (self.max - value).max(0.0) as u64,
            reset,
        };
        if refused
            || ctx
                .state
                .rate_limit
                .is_none_or(|noted| quota.remaining < noted.remaining)
        {
            ctx.state.rate_limit = Some(quota);
        }
    }

    /// Counts the request against its key and says what became of it.
    fn check(&self, session: &Session, ctx: &mut Ctx) -> Verdict {
        // Extract the key value based on configured tag type.
        // Borrow where possible — Rate/Inflight only need `Hash`, not an owned String.
        let key: Cow<'_, str> = match self.tag {
            LimitTag::Query => Cow::Borrowed(
                get_query_value(session.req_header(), &self.key)
                    .unwrap_or_default(),
            ),
            LimitTag::RequestHeader => Cow::Borrowed(
                get_req_header_value(session.req_header(), &self.key)
                    .unwrap_or_default(),
            ),
            LimitTag::Cookie => Cow::Borrowed(
                get_cookie_value(session.req_header(), &self.key)
                    .unwrap_or_default(),
            ),
            // An address the client cannot choose: its own behind
            // trusted proxies, the peer's without them. By whatever
            // `X-Forwarded-For` said, a new value with every request was a
            // new client every time and nothing was ever limited.
            _ => Cow::Borrowed(ensure_verified_client_ip(session, ctx)),
        };

        // No value for the key (a missing header or cookie): unlimited,
        // unless told to refuse it.
        if key.is_empty() {
            return if self.reject_missing_key {
                Verdict::MissingKey
            } else {
                Verdict::Pass
            };
        }

        // Track request based on limiter type.
        // Pass `&Cow` (Sized) rather than `&str` — pingora-limits requires `T: Hash + Sized`.
        let mut reset = None;
        let value = if let Some(rate) = &self.rate {
            // For rate limiting:
            rate.observe(&key, 1); // Record this request
            // The requests of the last `interval`, this one included: all
            // of the current window, and of the previous one the share
            // that still lies within an interval from now. It used to be
            // half of each, as a rate per second, so a client new to the
            // limiter - nothing in its previous window - got twice `max`
            // before it was stopped.
            let max = self.max;
            let (value, seconds) = rate.rate_with(&key, |info| {
                let value = info.prev_samples.max(0) as f64
                    * (1.0 - info.current_interval_fraction)
                    + info.curr_samples.max(0) as f64;
                // By what stays counted: a request that is refused is
                // taken off again below.
                let counted = if value > max {
                    info.curr_samples - 1
                } else {
                    info.curr_samples
                };
                let seconds = seconds_to_reset(
                    info.interval,
                    info.prev_samples,
                    counted,
                    info.current_interval_fraction,
                );
                (value, seconds)
            });
            reset = Some(seconds);
            // A request that is turned away is taken off again, so what is
            // counted is what was let through: a client over its limit
            // goes on getting `max` per interval and not, for as long as
            // it keeps asking, nothing at all. It is counted first and
            // checked after so that requests arriving together see each
            // other.
            if value > self.max {
                rate.observe(&key, -1);
            }
            value
        } else if let Some(inflight) = &self.inflight {
            // For inflight limiting:
            // Increment counter
            // Store guard in context - when guard is dropped, counter auto-decrements
            // Added to the others, never in place of one: a second inflight
            // limit on the location used to drop the guard of the first,
            // which released its count at once and so never limited.
            let (guard, value) = inflight.incr(&key, 1);
            ctx.state.guards.push(guard);
            value as f64
        } else {
            0.0
        };

        self.note_quota(ctx, value, reset);
        if value > self.max {
            return Verdict::Exceeded(value);
        }
        Verdict::Pass
    }
}

#[async_trait]
impl Plugin for Limiter {
    /// Returns unique identifier for this limiter instance
    #[inline]
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    /// Handles incoming HTTP requests by applying configured limits
    ///
    /// # Arguments
    /// * `step` - Current plugin execution step
    /// * `session` - Mutable HTTP session
    /// * `ctx` - Mutable state context
    ///
    /// # Returns
    /// * `pingora::Result<Option<HttpResponse>>` - None to continue processing,
    ///   Some(response) with 429 status if limit exceeded
    ///
    /// # Effects
    /// * Increments and checks appropriate limit counter
    /// * Returns 429 Too Many Requests if limit exceeded
    #[inline]
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        // Only run at configured plugin step
        if step != self.plugin_step {
            return Ok(RequestPluginResult::Skipped);
        }

        match self.check(session, ctx) {
            Verdict::Pass => Ok(RequestPluginResult::Continue),
            // Over the limit: 429 Too Many Requests, unless set otherwise.
            Verdict::Exceeded(value) => {
                let mut headers: Vec<HttpHeader> =
                    self.retry_after.iter().cloned().collect();
                // The response of this plugin is not shown to its own
                // `handle_response`: the budget goes on it here.
                if self.headers
                    && let Some(quota) = &ctx.state.rate_limit
                {
                    headers.extend(quota_headers(quota));
                }
                let body = self
                    .message
                    .clone()
                    .unwrap_or_else(|| self.exceeded(value).to_string().into());
                Ok(RequestPluginResult::Respond(HttpResponse {
                    status: self.status,
                    headers: (!headers.is_empty()).then_some(headers),
                    body,
                    ..Default::default()
                }))
            },
            // Not a request too many: one that does not say who it is from.
            Verdict::MissingKey => {
                Ok(RequestPluginResult::Respond(HttpResponse {
                    status: StatusCode::BAD_REQUEST,
                    body: format!(
                        "Plugin limit, {} is required",
                        self.key_description()
                    )
                    .into(),
                    ..Default::default()
                }))
            },
        }
    }

    /// Tells the client its budget on the response of the upstream.
    #[inline]
    async fn handle_response(
        &self,
        _session: &mut Session,
        ctx: &mut Ctx,
        upstream_response: &mut ResponseHeader,
    ) -> pingora::Result<ResponsePluginResult> {
        let Some(quota) = ctx.state.rate_limit.filter(|_| self.headers) else {
            return Ok(ResponsePluginResult::Unchanged);
        };
        for (name, value) in quota_headers(&quota) {
            let _ = upstream_response.insert_header(name, value);
        }
        Ok(ResponsePluginResult::Modified)
    }

    /// And on the response another plugin answered with, a `401` after
    /// this limiter counted the request for one.
    #[inline]
    fn handles_plugin_response(&self) -> bool {
        self.headers
    }
}

register_plugin!("limit", Limiter);

#[cfg(test)]
mod tests {
    use super::*;
    use http::StatusCode;
    use pingap_config::PluginConf;
    use pingap_core::{Ctx, PluginStep};
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use std::time::Duration;
    use tokio_test::io::Builder;

    /// The context of a request from `peer`. No trusted proxies are
    /// configured in a unit test, so the peer's address is the client ip.
    fn from_peer(peer: &str) -> Ctx {
        let mut ctx = Ctx::default();
        ctx.conn.remote_addr = Some(peer.to_string());
        ctx
    }

    async fn new_session() -> Session {
        let headers = [
            "Host: github.com",
            "Referer: https://github.com/",
            "User-Agent: pingap/0.1.1",
            "Cookie: deviceId=abc",
            "Accept: application/json",
            "X-Uuid: 138q71",
            "X-Forwarded-For: 1.1.1.1, 192.168.1.2",
        ]
        .join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?key=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        session
    }

    #[test]
    fn test_limit_params() {
        let params = Limiter::try_from(
            &toml::from_str::<PluginConf>(
                r###"
type = "inflight"
tag = "cookie"
key = "deviceId"
max = 10
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!("request", params.plugin_step.to_string());
        assert_eq!(true, params.inflight.is_some());
        assert_eq!(LimitTag::Cookie, params.tag);
        assert_eq!("deviceId", params.key);

        let result = Limiter::try_from(
            &toml::from_str::<PluginConf>(
                r###"
step = "response"
type = "inflight"
tag = "cookie"
key = "deviceId"
max = 10
"###,
            )
            .unwrap(),
        );
        assert_eq!(
            "Plugin limit invalid, message: Invalid step(response), expect one of: request, proxy_upstream",
            result.err().unwrap().to_string()
        );

        // Settings that decide who is limited are checked, not defaulted.
        for (conf, expect) in [
            (
                "tag = \"cookies\"\nkey = \"a\"\nmax = 1",
                "Invalid tag(cookies)",
            ),
            ("tag = \"header\"\nmax = 1", "key is required"),
            ("type = \"inflght\"\nmax = 1", "Invalid type(inflght)"),
            ("type = \"rate\"", "max is required"),
            ("max = -1", "max must not be negative"),
            (
                "max = 1\ninterval = \"0s\"",
                "interval must be at least 1ms",
            ),
            // Regression: shorter than the counter's unit, which divided
            // by it and brought the process down on the first request.
            (
                "max = 1\ninterval = \"500us\"",
                "interval must be at least 1ms",
            ),
        ] {
            let err =
                Limiter::try_from(&toml::from_str::<PluginConf>(conf).unwrap())
                    .err()
                    .unwrap()
                    .to_string();
            assert_eq!(true, err.contains(expect), "{conf}: {err}");
        }

        // A rate limiter tells the client when to come back.
        let params = Limiter::try_from(
            &toml::from_str::<PluginConf>("max = 10\ninterval = \"30s\"")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            Some("30"),
            params
                .retry_after
                .as_ref()
                .and_then(|(_, value)| value.to_str().ok())
        );
        let params = Limiter::try_from(
            &toml::from_str::<PluginConf>("type = \"inflight\"\nmax = 10")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(true, params.retry_after.is_none());
    }

    #[tokio::test]
    async fn test_new_cookie_limiter() {
        let limiter = Limiter::new(
            &toml::from_str::<PluginConf>(
                r###"
type = "inflight"
tag = "cookie"
key = "deviceId"
max = 10
    "###,
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!(LimitTag::Cookie, limiter.tag);
        let mut ctx = Ctx {
            ..Default::default()
        };
        let session = new_session().await;

        limiter.incr(&session, &mut ctx).unwrap();
        assert_eq!(1, ctx.state.guards.len());
    }
    #[tokio::test]
    async fn test_new_req_header_limiter() {
        let limiter = Limiter::new(
            &toml::from_str::<PluginConf>(
                r###"
type = "inflight"
tag = "header"
key = "X-Uuid"
max = 10
    "###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(LimitTag::RequestHeader, limiter.tag);
        let mut ctx = Ctx {
            ..Default::default()
        };
        let session = new_session().await;

        limiter.incr(&session, &mut ctx).unwrap();
        assert_eq!(1, ctx.state.guards.len());
    }
    #[tokio::test]
    async fn test_new_query_limiter() {
        let limiter = Limiter::new(
            &toml::from_str::<PluginConf>(
                r###"
type = "inflight"
tag = "query"
key = "key"
max = 10
    "###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(LimitTag::Query, limiter.tag);
        let mut ctx = Ctx {
            ..Default::default()
        };
        let session = new_session().await;

        limiter.incr(&session, &mut ctx).unwrap();
        assert_eq!(1, ctx.state.guards.len());
    }
    #[tokio::test]
    async fn test_new_ip_limiter() {
        let limiter = Limiter::new(
            &toml::from_str::<PluginConf>(
                r###"
type = "inflight"
max = 10
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(LimitTag::Ip, limiter.tag);
        let mut ctx = from_peer("1.1.1.1");
        let session = new_session().await;

        limiter.incr(&session, &mut ctx).unwrap();
        assert_eq!(1, ctx.state.guards.len());
    }
    #[tokio::test]
    async fn test_inflight_limit() {
        let limiter = Limiter::new(
            &toml::from_str::<PluginConf>(
                r###"
type = "inflight"
max = 0
"###,
            )
            .unwrap(),
        )
        .unwrap();

        let headers = ["X-Forwarded-For: 1.1.1.1"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = limiter
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut from_peer("1.1.1.1"),
            )
            .await
            .unwrap();

        let RequestPluginResult::Respond(resp) = result else {
            panic!("result is not Respond");
        };
        assert_eq!(StatusCode::TOO_MANY_REQUESTS, resp.status);

        let limiter = Limiter::new(
            &toml::from_str::<PluginConf>(
                r###"
type = "inflight"
max = 1
"###,
            )
            .unwrap(),
        )
        .unwrap();
        let result = limiter
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut from_peer("1.1.1.1"),
            )
            .await
            .unwrap();

        assert_eq!(true, result == RequestPluginResult::Continue);
    }

    /// Regression: a request had room for one inflight guard. A second
    /// inflight limit on the location took the place of the first one's
    /// guard, which released that limiter's count while the request was
    /// still running: the first limit never limited anything.
    #[tokio::test]
    async fn test_two_inflight_limits_on_one_request() {
        let new_limiter = |tag: &str, key: &str| {
            Limiter::new(
                &toml::from_str::<PluginConf>(&format!(
                    "type = \"inflight\"\ntag = \"{tag}\"\nkey = \"{key}\"\nmax = 1"
                ))
                .unwrap(),
            )
            .unwrap()
        };
        let by_app = new_limiter("header", "X-App");
        let by_user = new_limiter("header", "X-User");
        let new_session = async || {
            let mock_io = Builder::new()
                .read(b"GET / HTTP/1.1\r\nX-App: a\r\nX-User: u\r\n\r\n")
                .build();
            let mut session = Session::new_h1(Box::new(mock_io));
            session.read_request().await.unwrap();
            session
        };

        // The first request passes both limits and holds both counts.
        let mut session = new_session().await;
        let mut first = Ctx::default();
        for limiter in [&by_app, &by_user] {
            let result = limiter
                .handle_request(PluginStep::Request, &mut session, &mut first)
                .await
                .unwrap();
            assert_eq!(true, result == RequestPluginResult::Continue);
        }
        assert_eq!(2, first.state.guards.len());

        // While it is running, a second one is over the first limit already.
        let mut session = new_session().await;
        let mut second = Ctx::default();
        let result = by_app
            .handle_request(PluginStep::Request, &mut session, &mut second)
            .await
            .unwrap();
        let RequestPluginResult::Respond(resp) = result else {
            panic!("the first limit must still be counting the first request");
        };
        assert_eq!(StatusCode::TOO_MANY_REQUESTS, resp.status);
        drop(second);

        // When the first request ends, both counts are released.
        drop(first);
        let mut session = new_session().await;
        let mut third = Ctx::default();
        for limiter in [&by_app, &by_user] {
            let result = limiter
                .handle_request(PluginStep::Request, &mut session, &mut third)
                .await
                .unwrap();
            assert_eq!(true, result == RequestPluginResult::Continue);
        }
    }

    #[tokio::test]
    async fn test_rate_limit() {
        let limiter = Limiter::new(
            &toml::from_str::<PluginConf>(
                r###"
type = "rate"
max = 1
interval = "1s"
"###,
            )
            .unwrap(),
        )
        .unwrap();

        let headers = ["X-Forwarded-For: 1.1.1.1"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = limiter
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut from_peer("1.1.1.1"),
            )
            .await
            .unwrap();

        assert_eq!(true, result == RequestPluginResult::Continue);

        let _ = limiter
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut from_peer("1.1.1.1"),
            )
            .await
            .unwrap();

        // wait for the next loop
        tokio::time::sleep(Duration::from_secs(1)).await;
        let result = limiter
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut from_peer("1.1.1.1"),
            )
            .await
            .unwrap();
        let RequestPluginResult::Respond(resp) = result else {
            panic!("result is not Respond");
        };
        assert_eq!(StatusCode::TOO_MANY_REQUESTS, resp.status);
        assert_eq!(
            Some("1"),
            resp.headers
                .as_ref()
                .and_then(|headers| headers.first())
                .and_then(|(_, value)| value.to_str().ok())
        );

        // wait for rate limiter to reset
        tokio::time::sleep(Duration::from_secs(1)).await;
        let result = limiter
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut from_peer("1.1.1.1"),
            )
            .await
            .unwrap();
        assert_eq!(true, result == RequestPluginResult::Continue);
    }

    /// How many of `total` requests in a row a limiter lets through.
    async fn admitted(
        limiter: &Limiter,
        total: usize,
        peer: &str,
        headers: impl Fn(usize) -> String,
    ) -> usize {
        let mut count = 0;
        for index in 0..total {
            let input = format!(
                "GET /vicanso/pingap HTTP/1.1\r\n{}\r\n",
                headers(index)
            );
            let mock_io = Builder::new().read(input.as_bytes()).build();
            let mut session = Session::new_h1(Box::new(mock_io));
            session.read_request().await.unwrap();
            let result = limiter
                .handle_request(
                    PluginStep::Request,
                    &mut session,
                    &mut from_peer(peer),
                )
                .await
                .unwrap();
            if result == RequestPluginResult::Continue {
                count += 1;
            }
        }
        count
    }

    fn new_rate_limiter(conf: &str) -> Limiter {
        Limiter::new(
            &toml::from_str::<PluginConf>(&format!("type = \"rate\"\n{conf}"))
                .unwrap(),
        )
        .unwrap()
    }

    /// Regression: `max` is the number of requests in an interval. The
    /// estimate took half of the current window and half of the previous
    /// one, so a client with nothing in its previous window got through
    /// twice as often before it was stopped - and with `weight = 0`,
    /// which looked at the previous window alone, every time.
    #[tokio::test]
    async fn test_rate_limit_admits_max_per_interval() {
        let no_headers = |_: usize| String::new();
        let limiter = new_rate_limiter("max = 5\ninterval = \"1m\"");
        assert_eq!(5, admitted(&limiter, 30, "1.1.1.1", no_headers).await);
        // Another client has its own count.
        assert_eq!(5, admitted(&limiter, 30, "1.1.1.2", no_headers).await);
        // What was turned away is not counted: the first client is at its
        // limit, not beyond it.
        let count = limiter
            .rate
            .as_ref()
            .unwrap()
            .rate_with(&Cow::Borrowed("1.1.1.1"), |info| {
                info.curr_samples + info.prev_samples
            });
        assert_eq!(5, count);

        // `weight` is accepted and changes nothing.
        for weight in [0, 50, 100] {
            let limiter = new_rate_limiter(&format!(
                "max = 5\ninterval = \"1m\"\nweight = {weight}"
            ));
            assert_eq!(
                5,
                admitted(&limiter, 30, "1.1.1.1", no_headers).await,
                "{weight}"
            );
        }

        // An interval shorter than a second is counted like any other;
        // `max` used to be taken per second there and the estimate per
        // interval.
        let limiter = new_rate_limiter("max = 3\ninterval = \"500ms\"");
        assert_eq!(3, admitted(&limiter, 10, "1.1.1.1", no_headers).await);
    }

    /// One request from `peer` through the limiter: whether it went on, or
    /// the response it was answered with, and what the upstream's response
    /// came back with from `handle_response`.
    async fn one_request(
        limiter: &Limiter,
        peer: &str,
        headers: &str,
    ) -> (Option<HttpResponse>, Vec<(String, String)>) {
        let input = format!("GET /vicanso/pingap HTTP/1.1\r\n{headers}\r\n");
        let mock_io = Builder::new().read(input.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let mut ctx = from_peer(peer);
        let result = limiter
            .handle_request(PluginStep::Request, &mut session, &mut ctx)
            .await
            .unwrap();
        let mut upstream_response = ResponseHeader::build(200, None).unwrap();
        limiter
            .handle_response(&mut session, &mut ctx, &mut upstream_response)
            .await
            .unwrap();
        let quota = upstream_response
            .headers
            .iter()
            .map(|(name, value)| {
                (name.to_string(), value.to_str().unwrap().to_string())
            })
            .collect();
        match result {
            RequestPluginResult::Respond(resp) => (Some(resp), quota),
            _ => (None, quota),
        }
    }

    fn header_of(resp: &HttpResponse, name: &str) -> Option<String> {
        resp.headers.iter().flatten().find_map(|(key, value)| {
            (key.as_str() == name).then(|| value.to_str().unwrap().to_string())
        })
    }

    /// `headers = true`: the client is told its budget, on what the
    /// upstream answers and on the refusal alike.
    #[tokio::test]
    async fn test_rate_limit_headers() {
        let limiter =
            new_rate_limiter("max = 3\ninterval = \"1m\"\nheaders = true");
        assert_eq!(true, limiter.handles_plugin_response());
        for remaining in ["2", "1", "0"] {
            let (resp, quota) = one_request(&limiter, "1.1.1.1", "").await;
            assert_eq!(true, resp.is_none());
            assert_eq!(3, quota.len(), "{quota:?}");
            assert_eq!(
                ("x-ratelimit-limit".to_string(), "3".to_string()),
                quota[0]
            );
            assert_eq!(
                ("x-ratelimit-remaining".to_string(), remaining.to_string()),
                quota[1]
            );
            // All of it is back once the window in progress and the next
            // have passed: between one minute and two from now.
            assert_eq!("x-ratelimit-reset", quota[2].0);
            let reset: u64 = quota[2].1.parse().unwrap();
            assert_eq!(true, (60..=120).contains(&reset), "{reset}");
        }
        // The fourth is refused, and says the same of the budget.
        let (resp, _) = one_request(&limiter, "1.1.1.1", "").await;
        let resp = resp.unwrap();
        assert_eq!(StatusCode::TOO_MANY_REQUESTS, resp.status);
        assert_eq!(Some("60".to_string()), header_of(&resp, "retry-after"));
        assert_eq!(
            Some("3".to_string()),
            header_of(&resp, "x-ratelimit-limit")
        );
        assert_eq!(
            Some("0".to_string()),
            header_of(&resp, "x-ratelimit-remaining")
        );
        assert_eq!(true, header_of(&resp, "x-ratelimit-reset").is_some());
        // Another client has all of its own.
        let (_, quota) = one_request(&limiter, "1.1.1.2", "").await;
        assert_eq!("2", quota[1].1);

        // Not asked for: nothing is added, anywhere.
        let silent = new_rate_limiter("max = 1\ninterval = \"1m\"");
        assert_eq!(false, silent.handles_plugin_response());
        let (resp, quota) = one_request(&silent, "1.1.1.1", "").await;
        assert_eq!((true, 0), (resp.is_none(), quota.len()));
        let (resp, _) = one_request(&silent, "1.1.1.1", "").await;
        assert_eq!(None, header_of(&resp.unwrap(), "x-ratelimit-limit"));

        // A limit on concurrent requests has no time to name.
        let inflight = Limiter::new(
            &toml::from_str::<PluginConf>(
                "type = \"inflight\"\nmax = 5\nheaders = true",
            )
            .unwrap(),
        )
        .unwrap();
        let (_, quota) = one_request(&inflight, "1.1.1.1", "").await;
        assert_eq!(
            vec![
                ("x-ratelimit-limit".to_string(), "5".to_string()),
                ("x-ratelimit-remaining".to_string(), "4".to_string()),
            ],
            quota
        );
    }

    /// Of two limits that report, the one with less left is what the
    /// client is told.
    #[tokio::test]
    async fn test_the_tightest_limit_is_reported() {
        let wide =
            new_rate_limiter("max = 100\ninterval = \"1m\"\nheaders = true");
        let narrow =
            new_rate_limiter("max = 2\ninterval = \"1m\"\nheaders = true");
        for limiters in [[&wide, &narrow], [&narrow, &wide]] {
            let mock_io =
                Builder::new().read(b"GET / HTTP/1.1\r\n\r\n").build();
            let mut session = Session::new_h1(Box::new(mock_io));
            session.read_request().await.unwrap();
            let mut ctx = from_peer("2.2.2.2");
            for limiter in limiters {
                limiter
                    .handle_request(PluginStep::Request, &mut session, &mut ctx)
                    .await
                    .unwrap();
            }
            assert_eq!(Some(2), ctx.state.rate_limit.map(|quota| quota.limit));
        }

        // The limit that refuses is the one the refusal is about: its
        // budget is reported, also where another has no more left ...
        let through = async |limiters: &[&Limiter], peer: &str| {
            let mock_io =
                Builder::new().read(b"GET / HTTP/1.1\r\n\r\n").build();
            let mut session = Session::new_h1(Box::new(mock_io));
            session.read_request().await.unwrap();
            let mut ctx = from_peer(peer);
            let mut refused = false;
            for limiter in limiters {
                let result = limiter
                    .handle_request(PluginStep::Request, &mut session, &mut ctx)
                    .await
                    .unwrap();
                if matches!(result, RequestPluginResult::Respond(_)) {
                    refused = true;
                    break;
                }
            }
            (refused, ctx.state.rate_limit.map(|quota| quota.limit))
        };
        let two =
            new_rate_limiter("max = 2\ninterval = \"1m\"\nheaders = true");
        let one =
            new_rate_limiter("max = 1\ninterval = \"1m\"\nheaders = true");
        assert_eq!((false, Some(1)), through(&[&two, &one], "3.3.3.3").await);
        // `two` is at 0 left after this one, and so is `one`, which refuses.
        assert_eq!((true, Some(1)), through(&[&two, &one], "3.3.3.3").await);

        // ... and nothing is, where the one that refuses does not report:
        // the budget another noted is not that of this refusal.
        let quiet = new_rate_limiter("max = 1\ninterval = \"1m\"");
        assert_eq!(
            (false, Some(100)),
            through(&[&wide, &quiet], "4.4.4.4").await
        );
        assert_eq!((true, None), through(&[&wide, &quiet], "4.4.4.4").await);
    }

    #[test]
    fn test_seconds_to_reset() {
        let minute = Duration::from_secs(60);
        // Nothing counted: nothing to wait for.
        assert_eq!(0, seconds_to_reset(minute, 0, 0, 0.5));
        // Only the window before: gone when the current one ends.
        assert_eq!(30, seconds_to_reset(minute, 4, 0, 0.5));
        // The current window fades over the whole of the next.
        assert_eq!(90, seconds_to_reset(minute, 0, 1, 0.5));
        assert_eq!(120, seconds_to_reset(minute, 3, 1, 0.0));
        // Never less than a second while something is counted.
        assert_eq!(1, seconds_to_reset(Duration::from_millis(100), 1, 1, 0.99));
    }

    /// `status` and `message` are what a refused client gets, and
    /// `missing_key = "reject"` refuses the request that names no key.
    #[tokio::test]
    async fn test_limit_rejection_is_configurable() {
        let limiter = new_rate_limiter(
            "max = 1\ninterval = \"1m\"\nstatus = 503\nmessage = \"slow down\"",
        );
        assert_eq!(
            true,
            one_request(&limiter, "1.1.1.1", "").await.0.is_none()
        );
        let resp = one_request(&limiter, "1.1.1.1", "").await.0.unwrap();
        assert_eq!(StatusCode::SERVICE_UNAVAILABLE, resp.status);
        assert_eq!("slow down", String::from_utf8_lossy(&resp.body));
        // Without them: 429 and the count.
        let limiter = new_rate_limiter("max = 1\ninterval = \"1m\"");
        one_request(&limiter, "1.1.1.1", "").await;
        let resp = one_request(&limiter, "1.1.1.1", "").await.0.unwrap();
        assert_eq!(StatusCode::TOO_MANY_REQUESTS, resp.status);
        assert_eq!(
            "Plugin limit, exceed limit 2/1",
            String::from_utf8_lossy(&resp.body)
        );

        // A request without the key: let through and not counted, unless
        // told to refuse it.
        let by_key =
            "max = 1\ninterval = \"1m\"\ntag = \"header\"\nkey = \"X-Api-Key\"";
        let lenient = new_rate_limiter(by_key);
        for _ in 0..3 {
            let (resp, _) = one_request(&lenient, "1.1.1.1", "").await;
            assert_eq!(true, resp.is_none());
        }
        let strict =
            new_rate_limiter(&format!("{by_key}\nmissing_key = \"reject\""));
        let resp = one_request(&strict, "1.1.1.1", "").await.0.unwrap();
        assert_eq!(StatusCode::BAD_REQUEST, resp.status);
        assert_eq!(
            "Plugin limit, the header X-Api-Key is required",
            String::from_utf8_lossy(&resp.body)
        );
        // With it, it is limited as before.
        let with_key = "X-Api-Key: abc\r\n";
        assert_eq!(
            true,
            one_request(&strict, "1.1.1.1", with_key).await.0.is_none()
        );
        let resp = one_request(&strict, "1.1.1.1", with_key).await.0.unwrap();
        assert_eq!(StatusCode::TOO_MANY_REQUESTS, resp.status);

        // Values that are not ones.
        let invalid = |conf: &str| {
            Limiter::new(
                &toml::from_str::<PluginConf>(&format!("max = 1\n{conf}"))
                    .unwrap(),
            )
            .err()
            .unwrap()
            .to_string()
        };
        for status in [200, 302, 399, 600, -1, 70000] {
            assert_eq!(
                "Plugin limit invalid, message: status must be between 400 and 599",
                invalid(&format!("status = {status}")),
            );
        }
        assert_eq!(
            "Plugin limit invalid, message: Invalid missing_key(deny), expect pass or reject",
            invalid("missing_key = \"deny\"")
        );
    }

    /// Regression: the client ip was whatever `X-Forwarded-For` said when
    /// no trusted proxies are configured. A new value with every request
    /// was a new client every time, and nothing was limited.
    #[tokio::test]
    async fn test_limit_by_ip_ignores_a_forged_address() {
        let limiter = new_rate_limiter("max = 5\ninterval = \"1m\"");
        let forged =
            |index: usize| format!("X-Forwarded-For: 9.9.9.{index}\r\n");
        assert_eq!(5, admitted(&limiter, 30, "1.1.1.1", forged).await);
        let forged = |index: usize| format!("X-Real-IP: 9.9.8.{index}\r\n");
        assert_eq!(0, admitted(&limiter, 30, "1.1.1.1", forged).await);
    }
}
