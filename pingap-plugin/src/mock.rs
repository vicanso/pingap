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
    Error, get_bool_conf, get_hash_key, get_int_conf, get_int_conf_or_default,
    get_step_conf_in, get_str_conf, get_str_slice_conf,
};
use async_trait::async_trait;
use http::StatusCode;
use humantime::parse_duration;
use pingap_config::{PluginCategory, PluginConf};
use pingap_core::{
    Ctx, HttpResponse, Plugin, PluginStep, RequestPluginResult, convert_headers,
};
use pingora::proxy::Session;
use std::borrow::Cow;
use std::time::Duration;
use tokio::time::sleep;
use tracing::debug;

type Result<T, E = Error> = std::result::Result<T, E>;

/// MockResponse provides a configurable way to return mock HTTP responses for testing and development.
/// It can match specific paths and introduce artificial delays to simulate various scenarios.
pub struct MockResponse {
    /// The URL path to match against incoming requests.
    /// - If empty string: matches all paths
    /// - If set: must exactly match the request path
    ///   Example: "/api/users" will only mock requests to that exact path
    pub path: String,

    /// Determines at which point in the request lifecycle this mock should execute.
    /// Only supports two phases:
    /// - Request: Early in the cycle, before any upstream processing
    /// - ProxyUpstream: Just before the request would be sent to the upstream
    ///   server, so a cache hit is served normally and only origin-bound
    ///   requests get the mock
    pub plugin_step: PluginStep,

    /// The pre-configured HTTP response that will be returned when this mock is triggered.
    /// Contains:
    /// - status: HTTP status code (defaults to 200 OK)
    /// - headers: Optional response headers
    /// - body: Response body content
    ///   This response is constructed once during initialization for better performance
    pub resp: HttpResponse,

    /// Optional artificial delay before sending the mock response.
    /// Useful for:
    /// - Testing timeout handling
    /// - Simulating slow network conditions
    /// - Load testing with controlled response times
    ///   Format: Standard Duration (e.g., 500ms, 1s, 1m)
    pub delay: Option<Duration>,

    /// The share of the matching requests that get the mock, in percent:
    /// the others go on as if the plugin were not there. For trying out
    /// what a part of the traffic failing, or being slow, does to its
    /// clients.
    pub percentage: u8,

    /// The requests that are chosen are delayed and then go on to the
    /// upstream: latency, and no answer in place of the real one.
    pub delay_only: bool,

    /// Unique identifier for this plugin instance.
    /// - Generated from the plugin configuration
    /// - Used internally for plugin management
    /// - Not exposed publicly as it's an implementation detail
    hash_value: String,
}

impl MockResponse {
    /// Creates a new mock response handler from a plugin configuration.
    ///
    /// # Parameters
    /// - params: PluginConf containing the following optional fields:
    ///   - path: String - URL path to match
    ///   - status: int - HTTP status code (defaults to 200 OK if not specified)
    ///   - headers: []string - Response headers in "Key: Value" format
    ///   - data: string - Response body content
    ///   - delay: string - Human-readable duration (e.g., "500ms", "1s") to delay response
    ///
    /// # Returns
    /// Result<MockResponse> - Configured mock handler or error if configuration is invalid
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(
            params = pingap_config::masked_toml(params),
            "new mock plugin"
        );

        // Generate unique hash for this configuration
        let hash_value = get_hash_key(params);
        let invalid = |message: String| Error::Invalid {
            category: PluginCategory::Mock.to_string(),
            message,
        };

        // Extract all configuration parameters
        let path = get_str_conf(params, "path"); // Path to match (empty = match all)
        let status = get_int_conf(params, "status"); // HTTP status code
        let headers = get_str_slice_conf(params, "headers"); // Response headers
        let data = get_str_conf(params, "data"); // Response body

        // Parse delay duration if specified
        // Supports human-readable formats like "500ms", "1s", "1m"
        let delay = get_str_conf(params, "delay");
        // A delay of nothing is no delay: `delay_only` with it would be
        // a plugin that does nothing at all.
        let delay = if !delay.is_empty() {
            let d =
                parse_duration(&delay).map_err(|e| invalid(e.to_string()))?;
            Some(d).filter(|d| !d.is_zero())
        } else {
            None
        };

        // Every request unless it says otherwise. A share that is no
        // share is an error and not everything: a typo in what was to be
        // a tenth of the traffic is not to be all of it.
        let percentage = get_int_conf_or_default(params, "percentage", 100);
        let percentage = u8::try_from(percentage)
            .ok()
            .filter(|percentage| *percentage <= 100)
            .ok_or_else(|| {
                invalid(format!(
                    "percentage({percentage}) should be from 0 to 100"
                ))
            })?;
        let delay_only = get_bool_conf(params, "delay_only");
        if delay_only && delay.is_none() {
            return Err(invalid("delay_only needs a delay".to_string()));
        }

        // A mock exists to produce exactly what was configured, so a status
        // or header that cannot be is an error rather than a 200 without
        // headers.
        let status = if status == 0 {
            StatusCode::OK
        } else {
            u16::try_from(status)
                .ok()
                .and_then(|status| StatusCode::from_u16(status).ok())
                // An interim status is not a response: nothing would
                // follow it, and the client would go on waiting.
                .filter(|status| !status.is_informational())
                .ok_or_else(|| invalid(format!("Invalid status({status})")))?
        };
        let headers = if headers.is_empty() {
            None
        } else {
            Some(
                convert_headers(&headers)
                    .map_err(|e| invalid(format!("invalid headers: {e}")))?,
            )
        };
        let resp = HttpResponse {
            status,
            headers,
            body: data.into(),
            ..Default::default()
        };

        Ok(MockResponse {
            hash_value,
            resp,
            plugin_step: get_step_conf_in(
                params,
                &PluginCategory::Mock.to_string(),
                PluginStep::Request,
                &[PluginStep::Request, PluginStep::ProxyUpstream],
            )?,
            path,
            delay,
            percentage,
            delay_only,
        })
    }

    /// Whether this request is one of the share that is mocked.
    fn chosen(&self) -> bool {
        match self.percentage {
            100 => true,
            0 => false,
            percentage => rand::random_range(0..100u8) < percentage,
        }
    }
}

#[async_trait]
impl Plugin for MockResponse {
    /// Returns the unique identifier for this plugin instance
    #[inline]
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    /// Handles incoming requests and returns mock responses when appropriate.
    ///
    /// # Parameters
    /// - step: Current execution phase
    /// - session: Contains request details including URL path
    /// - _ctx: Ctx context (unused in mock plugin)
    ///
    /// # Returns
    /// - Ok(None) if request should proceed normally
    /// - Ok(Some(HttpResponse)) to return mock response
    /// - Err(...) if processing fails
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        _ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        // Only process if we're in the correct execution phase
        if step != self.plugin_step {
            return Ok(RequestPluginResult::Skipped);
        }

        // Check if request path matches our configured path (if any)
        if !self.path.is_empty() && session.req_header().uri.path() != self.path
        {
            return Ok(RequestPluginResult::Skipped);
        }

        if !self.chosen() {
            return Ok(RequestPluginResult::Skipped);
        }

        // Implement artificial delay if configured
        if let Some(d) = self.delay {
            sleep(d).await;
        }
        if self.delay_only {
            return Ok(RequestPluginResult::Continue);
        }

        // Return our pre-configured mock response
        Ok(RequestPluginResult::Respond(self.resp.clone()))
    }
}

register_plugin!("mock", MockResponse);

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::StatusCode;
    use pingap_config::PluginConf;
    use pingap_core::{Ctx, PluginStep};
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    /// A share of the requests, and a delay in place of an answer.
    #[tokio::test]
    async fn test_mock_percentage_and_delay_only() {
        let new = |conf: &str| {
            MockResponse::new(&toml::from_str::<PluginConf>(conf).unwrap())
        };
        let mocked = async |mock: &MockResponse| {
            let mock_io = Builder::new()
                .read(b"GET /vicanso/pingap HTTP/1.1\r\n\r\n")
                .build();
            let mut session = Session::new_h1(Box::new(mock_io));
            session.read_request().await.unwrap();
            let result = mock
                .handle_request(
                    PluginStep::Request,
                    &mut session,
                    &mut Ctx::default(),
                )
                .await
                .unwrap();
            matches!(result, RequestPluginResult::Respond(_))
        };
        let share = async |percentage: i64| {
            let mock = new(&format!("status = 503\npercentage = {percentage}"))
                .unwrap();
            let mut count = 0;
            for _ in 0..2000 {
                if mocked(&mock).await {
                    count += 1;
                }
            }
            count
        };
        // As it was without the option, and none at all.
        assert_eq!(100, new("status = 503").unwrap().percentage);
        assert_eq!(2000, share(100).await);
        assert_eq!(0, share(0).await);
        // About a tenth: 200 of 2000, give or take what chance does.
        let tenth = share(10).await;
        assert_eq!(true, (120..=290).contains(&tenth), "{tenth}");

        for (conf, message) in [
            (
                "percentage = 101",
                "percentage(101) should be from 0 to 100",
            ),
            ("percentage = -1", "percentage(-1) should be from 0 to 100"),
            ("delay_only = true", "delay_only needs a delay"),
            (
                "delay = \"0s\"\ndelay_only = true",
                "delay_only needs a delay",
            ),
        ] {
            let error = new(conf).err().unwrap().to_string();
            assert_eq!(true, error.contains(message), "{error}");
        }

        // Delayed, and then on to the upstream.
        let slow = new("delay = \"30ms\"\ndelay_only = true").unwrap();
        let mock_io = Builder::new()
            .read(b"GET /vicanso/pingap HTTP/1.1\r\n\r\n")
            .build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let started = std::time::Instant::now();
        let result = slow
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result == RequestPluginResult::Continue);
        assert_eq!(true, started.elapsed() >= Duration::from_millis(30));
    }

    /// Regression: an interim status was taken for the response to give.
    /// Nothing follows it, and the client waited for a response for good.
    #[test]
    fn test_mock_rejects_an_interim_status() {
        for status in [100, 101, 103, 199, 99, 1000] {
            let result = MockResponse::new(
                &toml::from_str::<PluginConf>(&format!("status = {status}"))
                    .unwrap(),
            );
            assert_eq!(
                true,
                result
                    .err()
                    .is_some_and(|e| e.to_string().contains("Invalid status")),
                "{status}"
            );
        }
        for status in [200, 204, 304, 404, 503] {
            let result = MockResponse::new(
                &toml::from_str::<PluginConf>(&format!("status = {status}"))
                    .unwrap(),
            );
            assert_eq!(true, result.is_ok(), "{status}");
        }
    }

    #[test]
    fn test_mock_params() {
        let params = MockResponse::new(
            &toml::from_str::<PluginConf>(
                r###"
path = "/"
status = 500
headers = [
    "Content-Type: application/json"
]
data = "{\"message\":\"Mock Service Unavailable\"}"
"###,
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!("/", params.path);
        assert_eq!("request", params.plugin_step.to_string());

        // `step` used to be parsed and then thrown away.
        let params = MockResponse::new(
            &toml::from_str::<PluginConf>(
                r###"
path = "/"
step = "proxy_upstream"
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!("proxy_upstream", params.plugin_step.to_string());

        let result = MockResponse::new(
            &toml::from_str::<PluginConf>(
                r###"
path = "/"
step = "response"
"###,
            )
            .unwrap(),
        );
        assert_eq!(
            "Plugin mock invalid, message: Invalid step(response), expect one of: request, proxy_upstream",
            result.err().unwrap().to_string()
        );

        // What cannot be produced is refused, not silently replaced.
        for (conf, expect) in [
            ("status = 99", "Invalid status(99)"),
            ("status = 1000", "Invalid status(1000)"),
            ("headers = [\"bad name: 1\"]", "invalid headers"),
        ] {
            let err =
                MockResponse::new(&toml::from_str::<PluginConf>(conf).unwrap())
                    .err()
                    .unwrap()
                    .to_string();
            assert_eq!(true, err.contains(expect), "{conf}: {err}");
        }
    }

    #[tokio::test]
    async fn test_mock_response() {
        let params = toml::from_str::<PluginConf>(
            r###"
path = "/vicanso/pingap"
status = 500
headers = [
    "Content-Type: application/json"
]
data = "{\"message\":\"Mock Service Unavailable\"}"
"###,
        )
        .unwrap();

        let mock = MockResponse::new(&params).unwrap();

        // match request path, get mock response
        let headers = ["Accept-Encoding: gzip"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let result = mock
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();

        let RequestPluginResult::Respond(resp) = result else {
            panic!("result is not Respond");
        };
        assert_eq!(StatusCode::INTERNAL_SERVER_ERROR, resp.status);
        assert_eq!(
            r###"Some([("content-type", "application/json")])"###,
            format!("{:?}", resp.headers)
        );
        assert_eq!(
            Bytes::from_static(b"{\"message\":\"Mock Service Unavailable\"}"),
            resp.body
        );

        // not match request path
        let headers = ["Accept-Encoding: gzip"].join("\r\n");
        let input_header =
            format!("GET /vicanso?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let result = mock
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result == RequestPluginResult::Skipped);
    }
}
