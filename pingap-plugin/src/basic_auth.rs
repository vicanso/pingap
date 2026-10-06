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
    Error, get_bool_conf, get_hash_key, get_str_conf, get_str_slice_conf,
};
use async_trait::async_trait;
use bytes::Bytes;
use http::HeaderValue;
use http::StatusCode;
use humantime::parse_duration;
use pingap_config::{PluginCategory, PluginConf};
use pingap_core::{
    Ctx, HTTP_HEADER_NO_STORE, HttpResponse, Plugin, PluginStep,
    RequestPluginResult, TtlLruLimit, ensure_verified_client_ip,
};
use pingap_util::base64_decode;
use pingora::proxy::Session;
use std::borrow::Cow;
use std::time::Duration;
use tokio::time::sleep;
use tracing::debug;

type Result<T, E = Error> = std::result::Result<T, E>;

/// How long failures are counted, and so the longest block, when
/// `ip_fail_window` is not set.
const DEFAULT_IP_FAIL_WINDOW: Duration = Duration::from_secs(5 * 60);
/// Client IPs whose failures are tracked at once. Beyond this the least
/// used are forgotten, which only ever lets an IP off early.
const IP_FAIL_CAPACITY: usize = 4096;

/// BasicAuth implements HTTP Basic Authentication functionality for HTTP requests.
///
/// # Security Features
/// - Validates base64-encoded credentials against a predefined list
/// - Optional rate limiting through configurable delays to prevent brute force attacks
/// - Can hide credentials from upstream services to prevent credential leakage
/// - Returns standard HTTP 401 responses with WWW-Authenticate headers
///
/// # Configuration
/// Expects configuration in TOML format with the following options:
/// - authorizations: List of base64-encoded "username:password" strings
/// - delay: Optional duration string for rate limiting (e.g., "10s")
/// - hide_credentials: Boolean to control credential forwarding
pub struct BasicAuth {
    /// The plugin execution step (should always be Request for BasicAuth)
    /// This ensures authentication happens before request processing
    plugin_step: PluginStep,

    /// The base64 `username:password` of every account, without the
    /// scheme: `admin:password` is stored as `YWRtaW46cGFzc3dvcmQ=`.
    authorizations: Vec<Vec<u8>>,

    /// When true, removes the Authorization header after successful authentication
    /// This is a security feature to prevent credential leakage to backend services
    /// Recommended to set to true unless the upstream service specifically needs credentials
    hide_credentials: bool,

    /// HTTP response returned when the Authorization header is missing
    /// Includes WWW-Authenticate header to prompt browser's authentication dialog
    /// Body contains a user-friendly message about missing authorization
    miss_authorization_resp: HttpResponse,

    /// HTTP response returned when provided credentials are invalid
    /// Also includes WWW-Authenticate header but with a different message
    /// The delay (if configured) is applied before sending this response
    unauthorized_resp: HttpResponse,

    /// Optional delay duration before responding to invalid credentials
    /// Security feature to make brute force attacks impractical
    /// Example values: "1s", "500ms", "2s"
    delay: Option<Duration>,

    /// Wrong credentials counted per client IP; `None` unless
    /// `ip_fail_limit` is set. An IP that reaches the limit is refused
    /// until its window, which starts at its first counted failure, ends.
    ip_fail_limit: Option<TtlLruLimit>,

    /// The response to a client IP that has been blocked
    too_many_failures_resp: HttpResponse,

    /// Unique hash value for the plugin instance
    /// Used for internal plugin management and caching
    /// Generated from plugin configuration to ensure consistent behavior
    hash_value: String,
}

impl TryFrom<&PluginConf> for BasicAuth {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        // Generate a unique hash for this plugin instance based on configuration
        // This ensures consistent plugin behavior across restarts
        let hash_value = get_hash_key(value);

        // Parse optional delay duration for rate limiting
        // Supports human-readable duration strings like "10s", "1m", etc.
        // Returns None if delay is not specified
        let delay = get_str_conf(value, "delay");
        let delay = if !delay.is_empty() {
            let d = parse_duration(&delay).map_err(|e| Error::Invalid {
                category: PluginCategory::BasicAuth.to_string(),
                message: e.to_string(),
            })?;
            Some(d)
        } else {
            None
        };

        // Process and validate the list of authorized credentials
        // Each credential must be a valid base64 string
        // Invalid base64 strings will cause initialization to fail
        let mut authorizations = vec![];
        for item in get_str_slice_conf(value, "authorizations").iter() {
            // Validate base64 format - this ensures we don't store invalid credentials
            let _ = base64_decode(item).map_err(|e| Error::Base64Decode {
                category: PluginCategory::BasicAuth.to_string(),
                source: e,
            })?;
            authorizations.push(item.as_bytes().to_vec());
        }

        // Ensure at least one valid authorization is configured
        if authorizations.is_empty() {
            return Err(Error::Invalid {
                category: PluginCategory::BasicAuth.to_string(),
                message: "basic authorizations can't be empty".to_string(),
            });
        }
        // Wrong passwords per client IP; 0 (the default) turns it off.
        let invalid = |message: String| Error::Invalid {
            category: PluginCategory::BasicAuth.to_string(),
            message,
        };
        let ip_fail_limit = match value.get("ip_fail_limit") {
            None => 0,
            Some(limit) => limit
                .as_integer()
                .filter(|limit| *limit >= 0)
                .ok_or_else(|| {
                    invalid(format!(
                        "ip_fail_limit({limit}) must be a non-negative integer"
                    ))
                })?,
        };
        let ip_fail_window = get_str_conf(value, "ip_fail_window");
        let ip_fail_window = if ip_fail_window.is_empty() {
            DEFAULT_IP_FAIL_WINDOW
        } else {
            let window = parse_duration(&ip_fail_window)
                .map_err(|e| invalid(format!("invalid ip_fail_window: {e}")))?;
            if window.is_zero() {
                return Err(invalid(
                    "ip_fail_window must be greater than zero".to_string(),
                ));
            }
            window
        };
        let ip_fail_limit = (ip_fail_limit > 0).then(|| {
            TtlLruLimit::new_compact(
                IP_FAIL_CAPACITY,
                ip_fail_window,
                ip_fail_limit as usize,
            )
        });

        let www_authenticate = Some(vec![(
            http::header::WWW_AUTHENTICATE,
            HeaderValue::from_static(
                r###"Basic realm="Access to the staging site""###,
            ),
        )]);

        let params = Self {
            hash_value,
            plugin_step: PluginStep::Request,
            delay,
            hide_credentials: get_bool_conf(value, "hide_credentials"),
            authorizations,
            miss_authorization_resp: HttpResponse {
                status: StatusCode::UNAUTHORIZED,
                headers: www_authenticate.clone(),
                body: Bytes::from_static(b"Authorization is missing"),
                ..Default::default()
            },
            unauthorized_resp: HttpResponse {
                status: StatusCode::UNAUTHORIZED,
                headers: www_authenticate,
                body: Bytes::from_static(b"Invalid user or password"),
                ..Default::default()
            },
            ip_fail_limit,
            too_many_failures_resp: HttpResponse {
                status: StatusCode::FORBIDDEN,
                headers: Some(vec![HTTP_HEADER_NO_STORE.clone()]),
                body: Bytes::from_static(b"Forbidden, too many failures"),
                ..Default::default()
            },
        };

        Ok(params)
    }
}

/// The credentials of a `Basic` authorization header value. The scheme is
/// case-insensitive (RFC 7235 §2.1) and whitespace may follow it; a
/// literal `Basic ` comparison used to turn `basic ...` away.
fn basic_credentials(value: &[u8]) -> Option<&[u8]> {
    let (scheme, credentials) =
        value.split_at(value.iter().position(|b| *b == b' ')?);
    scheme
        .eq_ignore_ascii_case(b"basic")
        .then(|| credentials.trim_ascii())
}

impl BasicAuth {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new basic auth plugin");
        Self::try_from(params)
    }
}

#[async_trait]
impl Plugin for BasicAuth {
    #[inline]
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    #[inline]
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        // Verify we're in the request phase - authentication must happen before processing
        if step != self.plugin_step {
            return Ok(RequestPluginResult::Skipped);
        }

        // A blocked IP is refused before its credentials are looked at, so
        // guessing stops paying off even when a guess would be right.
        //
        // Counted by an address the client cannot choose: the client ip
        // behind trusted proxies, the peer's own without them. It used to
        // be the client ip either way, which without trusted proxies is
        // whatever `X-Forwarded-For` says - a new address with every guess
        // was never blocked, and someone else's address got them blocked.
        if let Some(limit) = &self.ip_fail_limit
            && !limit.validate(ensure_verified_client_ip(session, ctx))
        {
            return Ok(RequestPluginResult::Respond(
                self.too_many_failures_resp.clone(),
            ));
        }

        // Extract and validate Authorization header
        // An empty value means the header is missing entirely
        let value = session.get_header_bytes(http::header::AUTHORIZATION);
        if value.is_empty() {
            return Ok(RequestPluginResult::Respond(
                self.miss_authorization_resp.clone(),
            ));
        }

        // Validate credentials against our authorized list, comparing in
        // constant time so a match position is not leaked via timing.
        let authorized = basic_credentials(value).is_some_and(|credentials| {
            self.authorizations
                .iter()
                .any(|auth| pingap_core::constant_time_eq(auth, credentials))
        });
        if !authorized {
            // Only wrong credentials count. A missing header does not: it is
            // how every browser starts, before the login prompt.
            if let Some(limit) = &self.ip_fail_limit {
                limit.inc(ensure_verified_client_ip(session, ctx));
            }
            // If configured, apply rate limiting delay
            // This helps prevent automated brute force attempts
            if let Some(d) = self.delay {
                sleep(d).await;
            }
            return Ok(RequestPluginResult::Respond(
                self.unauthorized_resp.clone(),
            ));
        }

        // On successful authentication, optionally remove credentials
        // This prevents credential leakage to upstream services
        if self.hide_credentials {
            session
                .req_header_mut()
                .remove_header(&http::header::AUTHORIZATION);
        }

        // Authentication successful - continue request processing
        return Ok(RequestPluginResult::Continue);
    }
}

register_plugin!("basic_auth", BasicAuth);

#[cfg(test)]
mod tests {
    use super::{BasicAuth, Plugin};
    use pingap_config::PluginConf;
    use pingap_core::{Ctx, PluginStep, RequestPluginResult};
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use std::time::Duration;
    use tokio_test::io::Builder;

    #[test]
    fn test_basic_auth_params() {
        // spellchecker:off
        let params = BasicAuth::try_from(
            &toml::from_str::<PluginConf>(
                r###"
authorizations = [
"MTIz",
"NDU2",
]
delay = "10s"
"###,
            )
            .unwrap(),
        )
        .unwrap();
        // spellchecker:on
        assert_eq!("request", params.plugin_step.to_string());
        // spellchecker:off
        assert_eq!(
            "MTIz,NDU2",
            params
                .authorizations
                .iter()
                .map(|item| std::string::String::from_utf8_lossy(item))
                .collect::<Vec<_>>()
                .join(","),
        );
        // spellchecker:on
        assert_eq!(Duration::from_secs(10), params.delay.unwrap());
        assert_eq!("AC7E9E03", params.config_key());

        let result = BasicAuth::try_from(
            &toml::from_str::<PluginConf>(
                r###"
authorizations = [
"1"
]
"###,
            )
            .unwrap(),
        );
        assert_eq!(
            "Plugin basic_auth, base64 decode error Invalid input length: 1",
            result.err().unwrap().to_string()
        );
    }

    #[tokio::test]
    async fn test_basic_auth() {
        // spellchecker:off
        let auth = BasicAuth::new(
            &toml::from_str::<PluginConf>(
                r###"
authorizations = [
    "YWRtaW46MTIzMTIz"
]
hide_credentials = true
    "###,
            )
            .unwrap(),
        )
        .unwrap();
        // spellchecker:on

        // auth success
        // spellchecker:off
        let headers = ["Authorization: Basic YWRtaW46MTIzMTIz"].join("\r\n");
        // spellchecker:on
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = auth
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result == RequestPluginResult::Continue);
        assert_eq!(
            false,
            session.req_header().headers.contains_key("Authorization")
        );

        // auth fail
        // spellchecker:off
        let headers = ["Authorization: Basic YWRtaW46MTIzMTIa"].join("\r\n");
        // spellchecker:on
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = auth
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
        assert_eq!(resp.status, http::StatusCode::UNAUTHORIZED);
    }

    /// The scheme is case-insensitive and may be followed by more than one
    /// space; another scheme is not Basic at all.
    #[test]
    fn test_basic_credentials() {
        use super::basic_credentials;
        assert_eq!(Some(&b"abc"[..]), basic_credentials(b"Basic abc"));
        assert_eq!(Some(&b"abc"[..]), basic_credentials(b"basic  abc "));
        assert_eq!(None, basic_credentials(b"Bearer abc"));
        assert_eq!(None, basic_credentials(b"Basicabc"));
    }
    #[test]
    fn test_ip_fail_limit_params() {
        // spellchecker:off
        let conf = |extra: &str| {
            toml::from_str::<PluginConf>(&format!(
                "authorizations = [\"YWRtaW46MTIzMTIz\"]\n{extra}"
            ))
            .unwrap()
        };
        // spellchecker:on
        // Off unless asked for.
        let params = BasicAuth::try_from(&conf("")).unwrap();
        assert_eq!(true, params.ip_fail_limit.is_none());
        let params = BasicAuth::try_from(&conf("ip_fail_limit = 0")).unwrap();
        assert_eq!(true, params.ip_fail_limit.is_none());
        let params = BasicAuth::try_from(&conf(
            "ip_fail_limit = 3\nip_fail_window = \"10m\"",
        ))
        .unwrap();
        assert_eq!(true, params.ip_fail_limit.is_some());

        for (extra, expect) in [
            ("ip_fail_limit = -1", "must be a non-negative integer"),
            ("ip_fail_limit = \"five\"", "must be a non-negative integer"),
            ("ip_fail_window = \"soon\"", "invalid ip_fail_window"),
            ("ip_fail_window = \"0s\"", "must be greater than zero"),
        ] {
            let err =
                BasicAuth::try_from(&conf(extra)).err().unwrap().to_string();
            assert_eq!(true, err.contains(expect), "{extra}: {err}");
        }
    }

    /// A request from the peer `client_ip`, which is what the failures are
    /// counted by when no trusted proxies are configured.
    async fn request(
        auth: &BasicAuth,
        client_ip: &str,
        authorization: Option<&str>,
    ) -> RequestPluginResult {
        request_with(auth, client_ip, "", authorization).await
    }

    /// The same, with an `X-Forwarded-For` of the client's choosing.
    async fn request_with(
        auth: &BasicAuth,
        peer: &str,
        forwarded_for: &str,
        authorization: Option<&str>,
    ) -> RequestPluginResult {
        let mut headers = vec!["Host: example.com".to_string()];
        if !forwarded_for.is_empty() {
            headers.push(format!("X-Forwarded-For: {forwarded_for}"));
        }
        if let Some(value) = authorization {
            headers.push(format!("Authorization: {value}"));
        }
        let input =
            format!("GET / HTTP/1.1\r\n{}\r\n\r\n", headers.join("\r\n"));
        let mock_io = Builder::new().read(input.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let mut ctx = Ctx::default();
        ctx.conn.remote_addr = Some(peer.to_string());
        auth.handle_request(PluginStep::Request, &mut session, &mut ctx)
            .await
            .unwrap()
    }

    fn status(result: &RequestPluginResult) -> u16 {
        match result {
            RequestPluginResult::Respond(resp) => resp.status.as_u16(),
            _ => 0,
        }
    }

    /// After `ip_fail_limit` wrong passwords an IP is refused, correct
    /// credentials included; a missing header does not count, and other
    /// IPs are unaffected.
    #[tokio::test]
    async fn test_ip_fail_limit() {
        // spellchecker:off
        let good = "Basic YWRtaW46MTIzMTIz";
        let bad = "Basic YWRtaW46MTIzMTIa";
        // spellchecker:on
        let auth = BasicAuth::new(
            &toml::from_str::<PluginConf>(&format!(
                "authorizations = [\"{}\"]\nip_fail_limit = 2\nip_fail_window = \"1m\"",
                &good["Basic ".len()..]
            ))
            .unwrap(),
        )
        .unwrap();

        // Two wrong passwords: still answered 401.
        assert_eq!(401, status(&request(&auth, "1.1.1.1", Some(bad)).await));
        assert_eq!(401, status(&request(&auth, "1.1.1.1", Some(bad)).await));
        // Now blocked, whatever it sends.
        let blocked = request(&auth, "1.1.1.1", Some(good)).await;
        assert_eq!(403, status(&blocked));
        let RequestPluginResult::Respond(resp) = blocked else {
            panic!("a blocked ip must be answered");
        };
        assert_eq!(
            b"Forbidden, too many failures".as_ref(),
            resp.body.as_ref()
        );
        assert_eq!(403, status(&request(&auth, "1.1.1.1", None).await));

        // Another IP is not affected.
        assert_eq!(
            true,
            request(&auth, "2.2.2.2", Some(good)).await
                == RequestPluginResult::Continue
        );

        // Missing credentials are the browser's first request, not a guess.
        for _ in 0..5 {
            assert_eq!(401, status(&request(&auth, "3.3.3.3", None).await));
        }
        assert_eq!(
            true,
            request(&auth, "3.3.3.3", Some(good)).await
                == RequestPluginResult::Continue
        );
    }

    /// Regression: the failures were counted by the client ip, which
    /// without trusted proxies is what `X-Forwarded-For` says. A new
    /// address with every guess was never blocked, and naming somebody
    /// else's address got that address blocked.
    #[tokio::test]
    async fn test_ip_fail_limit_ignores_a_forged_address() {
        // spellchecker:off
        let good = "Basic YWRtaW46MTIzMTIz";
        let bad = "Basic YWRtaW46MTIzMTIa";
        // spellchecker:on
        let auth = BasicAuth::new(
            &toml::from_str::<PluginConf>(&format!(
                "authorizations = [\"{}\"]\nip_fail_limit = 2\nip_fail_window = \"1m\"",
                &good["Basic ".len()..]
            ))
            .unwrap(),
        )
        .unwrap();

        // One peer guessing, under a different address each time.
        for forged in ["7.7.7.1", "7.7.7.2"] {
            assert_eq!(
                401,
                status(
                    &request_with(&auth, "1.1.1.1", forged, Some(bad)).await
                )
            );
        }
        assert_eq!(
            403,
            status(
                &request_with(&auth, "1.1.1.1", "7.7.7.3", Some(good)).await
            )
        );
        // The addresses it named are not the ones that are blocked.
        assert_eq!(
            true,
            request(&auth, "7.7.7.1", Some(good)).await
                == RequestPluginResult::Continue
        );
    }
}
