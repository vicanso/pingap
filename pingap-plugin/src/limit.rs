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
    get_hash_key, get_int_conf, get_plugin_factory, get_step_conf,
    get_str_conf, Error,
};
use async_trait::async_trait;
use ctor::ctor;
use http::StatusCode;
use humantime::parse_duration;
use pingap_config::{PluginCategory, PluginConf};
use pingap_core::{Ctx, HttpResponse, Plugin, PluginStep};
use pingora::proxy::Session;
use pingora_limits::inflight::Inflight;
use pingora_limits::rate::Rate;
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

type Result<T, E = Error> = std::result::Result<T, E>;

// LimitTag determines what value will be used as the rate limiting key
#[derive(PartialEq, Debug)]
pub enum LimitTag {
    Ip,            // Use client IP (from X-Forwarded-For or direct connection)
    RequestHeader, // Use value from a specified HTTP request header
    Cookie,        // Use value from a specified cookie
    Query,         // Use value from a specified URL query parameter
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

    /// Maximum number of requests/connections allowed within the interval (for rate limiting)
    /// or at the same time (for inflight limiting)
    max: isize,

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
        let step = get_step_conf(value, PluginStep::Request);

        // Parse the tag type from config, defaulting to IP-based limiting
        let tag = match get_str_conf(value, "tag").as_str() {
            "cookie" => LimitTag::Cookie,
            "header" => LimitTag::RequestHeader,
            "query" => LimitTag::Query,
            _ => LimitTag::Ip,
        };

        // Parse time interval for rate limiting
        // Format examples: "10s", "1m", "2h"
        // Default: 10 seconds if not specified
        let interval = get_str_conf(value, "interval");
        let interval = if !interval.is_empty() {
            parse_duration(&interval).map_err(|e| Error::Invalid {
                category: PluginCategory::Limit.to_string(),
                message: e.to_string(),
            })?
        } else {
            Duration::from_secs(10)
        };

        // Create either inflight or rate limiter based on config
        let mut inflight = None;
        let mut rate = None;
        if get_str_conf(value, "type") == "inflight" {
            // Inflight limiter uses atomic counters to track concurrent requests
            inflight = Some(Inflight::new());
        } else {
            // Rate limiter uses time-bucketed counters
            rate = Some(Rate::new(interval));
        }

        let params = Self {
            hash_value,
            tag,
            key: get_str_conf(value, "key"),
            max: get_int_conf(value, "max") as isize,
            inflight,
            rate,
            plugin_step: step,
        };

        // Validate plugin step - limiting only makes sense during request or upstream phases
        if ![PluginStep::Request, PluginStep::ProxyUpstream]
            .contains(&params.plugin_step)
        {
            return Err(Error::Invalid {
                category: PluginCategory::Limit.to_string(),
                message: "Limit plugin should be executed at request or proxy upstream step".to_string(),
            });
        }
        Ok(params)
    }
}

impl Limiter {
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
        debug!(params = params.to_string(), "new limit plugin");
        Self::try_from(params)
    }
    /// Increments and checks the limit counter for the current request
    ///
    /// # Arguments
    /// * `session` - The HTTP session containing request details
    /// * `ctx` - Mutable state context for storing request data
    ///
    /// # Returns
    /// * `Result<()>` - Ok if within limits, Error if limit exceeded
    ///
    /// # Effects
    /// * For rate limiting: Records request in time window
    /// * For inflight limiting: Increments counter and stores RAII guard in context
    /// * For IP-based limiting: Stores client IP in context
    pub fn incr(&self, session: &Session, ctx: &mut Ctx) -> Result<()> {
        // Extract the key value based on configured tag type
        let key = match self.tag {
            LimitTag::Query => {
                // Get value from URL query parameter
                pingap_core::get_query_value(session.req_header(), &self.key)
                    .unwrap_or_default()
                    .to_string()
            },
            LimitTag::RequestHeader => {
                // Get value from HTTP request header
                pingap_core::get_req_header_value(
                    session.req_header(),
                    &self.key,
                )
                .unwrap_or_default()
                .to_string()
            },
            LimitTag::Cookie => {
                // Get value from cookie
                pingap_core::get_cookie_value(session.req_header(), &self.key)
                    .unwrap_or_default()
                    .to_string()
            },
            _ => {
                // Get client IP from X-Forwarded-For or connection
                let client_ip = pingap_core::get_client_ip(session);
                // Store client IP in context for potential later use
                ctx.client_ip = Some(client_ip.clone());
                client_ip
            },
        };

        // Skip limiting if no key found (e.g., missing header/cookie)
        if key.is_empty() {
            return Ok(());
        }

        // Track request based on limiter type
        let value = if let Some(rate) = &self.rate {
            // For rate limiting:
            rate.observe(&key, 1); // Record this request
            let value = rate.rate(&key); // Get current rate for time window
            value.ceil() as isize
        } else if let Some(inflight) = &self.inflight {
            // For inflight limiting:
            // Increment counter
            // Store guard in context - when guard is dropped, counter auto-decrements
            let (guard, value) = inflight.incr(&key, 1);
            ctx.guard = Some(guard);
            value
        } else {
            0
        };

        // Check if limit exceeded
        if value > self.max {
            return Err(Error::Exceed {
                category: PluginCategory::Limit.to_string(),
                max: self.max,
                value,
            });
        }
        Ok(())
    }
}

#[async_trait]
impl Plugin for Limiter {
    /// Returns unique identifier for this limiter instance
    #[inline]
    fn hash_key(&self) -> String {
        self.hash_value.clone()
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
    ) -> pingora::Result<Option<HttpResponse>> {
        // Only run at configured plugin step
        if step != self.plugin_step {
            return Ok(None);
        }

        // Try to increment counter
        if let Err(e) = self.incr(session, ctx) {
            // If limit exceeded, return 429 Too Many Requests
            return Ok(Some(HttpResponse {
                status: StatusCode::TOO_MANY_REQUESTS,
                body: e.to_string().into(),
                ..Default::default()
            }));
        }

        // Continue normal request processing if within limits
        Ok(None)
    }
}

#[ctor]
fn init() {
    get_plugin_factory()
        .register("limit", |params| Ok(Arc::new(Limiter::new(params)?)));
}

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
            "Plugin limit invalid, message: Limit plugin should be executed at request or proxy upstream step",
            result.err().unwrap().to_string()
        );
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
        assert_eq!(true, ctx.guard.is_some());
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
        assert_eq!(true, ctx.guard.is_some());
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
        assert_eq!(true, ctx.guard.is_some());
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
        let mut ctx = Ctx {
            ..Default::default()
        };
        let session = new_session().await;

        limiter.incr(&session, &mut ctx).unwrap();
        assert_eq!(true, ctx.guard.is_some());
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
                &mut Ctx::default(),
            )
            .await
            .unwrap();

        assert_eq!(true, result.is_some());
        assert_eq!(StatusCode::TOO_MANY_REQUESTS, result.unwrap().status);

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
                &mut Ctx::default(),
            )
            .await
            .unwrap();

        assert_eq!(true, result.is_none());
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
                &mut Ctx::default(),
            )
            .await
            .unwrap();

        assert_eq!(true, result.is_none());

        let _ = limiter
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_secs(1)).await;

        let result = limiter
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result.is_some());
        assert_eq!(StatusCode::TOO_MANY_REQUESTS, result.unwrap().status);

        tokio::time::sleep(Duration::from_secs(1)).await;

        let result = limiter
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result.is_none());
    }
}
