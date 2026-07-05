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
    Error, get_duration_conf, get_hash_key, get_str_conf, get_str_slice_conf,
};
use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderName, HeaderValue, StatusCode};
use pingap_config::PluginConf;
use pingap_core::{
    Ctx, HttpResponse, Plugin, PluginStep, RequestPluginResult, get_client_ip,
    get_host,
};
use pingora::proxy::Session;
use std::borrow::Cow;
use std::time::Duration;
use tracing::{debug, error};

type Result<T, E = Error> = std::result::Result<T, E>;

const CATEGORY: &str = "forward_auth";

/// ForwardAuth delegates authentication to an external HTTP service, similar to
/// nginx's `auth_request` or Traefik's ForwardAuth.
///
/// For each request it issues a `GET` to `auth_url`, forwarding the original
/// request headers (or a configured subset) plus `X-Forwarded-Method/Uri/Host/
/// For`. A `2xx` response allows the request (optionally copying selected auth
/// response headers onto the upstream request); any other status is relayed
/// back to the client verbatim (e.g. a `302` to a login page or a `401`).
///
/// # Configuration
/// - `auth_url`: external auth endpoint (required)
/// - `request_headers`: original headers to forward (empty = all)
/// - `add_headers`: auth response headers to copy onto the upstream request on success
/// - `timeout`: per-request timeout (default 10s)
pub struct ForwardAuth {
    plugin_step: PluginStep,
    client: reqwest::Client,
    auth_url: String,
    /// Original request header names to forward; empty means forward all.
    request_headers: Vec<String>,
    /// Auth-response header names to copy onto the upstream request on success.
    add_headers: Vec<String>,
    hash_value: String,
}

impl TryFrom<&PluginConf> for ForwardAuth {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);

        let auth_url = get_str_conf(value, "auth_url");
        if auth_url.is_empty() {
            return Err(Error::Invalid {
                category: CATEGORY.to_string(),
                message: "auth_url is required".to_string(),
            });
        }
        // Validate the URL up front so `-t` catches typos.
        reqwest::Url::parse(&auth_url).map_err(|e| Error::Invalid {
            category: CATEGORY.to_string(),
            message: format!("invalid auth_url: {e}"),
        })?;

        let timeout = get_duration_conf(value, "timeout")
            .unwrap_or(Duration::from_secs(10));
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| Error::Invalid {
                category: CATEGORY.to_string(),
                message: e.to_string(),
            })?;

        Ok(Self {
            hash_value,
            plugin_step: PluginStep::Request,
            client,
            auth_url,
            request_headers: get_str_slice_conf(value, "request_headers"),
            add_headers: get_str_slice_conf(value, "add_headers"),
        })
    }
}

impl ForwardAuth {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new forward auth plugin");
        Self::try_from(params)
    }
}

#[async_trait]
impl Plugin for ForwardAuth {
    #[inline]
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        _ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        if step != self.plugin_step {
            return Ok(RequestPluginResult::Skipped);
        }

        // Phase 1: build the auth subrequest from the current request. Only
        // immutable borrows here; the builder owns copies so no borrow is held
        // across the await below.
        let mut builder = self.client.get(&self.auth_url);
        {
            let req_header = session.req_header();
            for (name, value) in req_header.headers.iter() {
                if self.request_headers.is_empty()
                    || self
                        .request_headers
                        .iter()
                        .any(|h| h.eq_ignore_ascii_case(name.as_str()))
                {
                    builder = builder.header(name.as_str(), value.as_bytes());
                }
            }
            let uri = req_header
                .uri
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/");
            builder = builder
                .header("x-forwarded-method", req_header.method.as_str())
                .header("x-forwarded-uri", uri)
                .header(
                    "x-forwarded-host",
                    get_host(req_header).unwrap_or_default(),
                );
        }
        builder = builder.header("x-forwarded-for", get_client_ip(session));

        // Phase 2: call the auth service.
        let resp = match builder.send().await {
            Ok(resp) => resp,
            Err(e) => {
                error!(
                    category = CATEGORY,
                    error = %e,
                    "forward auth subrequest failed"
                );
                return Ok(RequestPluginResult::Respond(HttpResponse {
                    status: StatusCode::BAD_GATEWAY,
                    body: Bytes::from_static(b"Forward auth request failed"),
                    ..Default::default()
                }));
            },
        };

        let status = StatusCode::from_u16(resp.status().as_u16())
            .unwrap_or(StatusCode::FORBIDDEN);

        // Success: copy the configured auth-response headers onto the upstream
        // request, then continue.
        if status.is_success() {
            let mut to_add = vec![];
            for name in &self.add_headers {
                if let Some(value) = resp.headers().get(name.as_str())
                    && let (Ok(n), Ok(v)) = (
                        HeaderName::from_bytes(name.as_bytes()),
                        HeaderValue::from_bytes(value.as_bytes()),
                    )
                {
                    to_add.push((n, v));
                }
            }
            let req_header = session.req_header_mut();
            for (name, value) in to_add {
                let _ = req_header.insert_header(name, value);
            }
            return Ok(RequestPluginResult::Continue);
        }

        // Otherwise relay the auth server's decision to the client (status,
        // headers such as Location / WWW-Authenticate / Set-Cookie, and body).
        let mut headers = vec![];
        for (name, value) in resp.headers().iter() {
            // Skip framing headers that `HttpResponse` manages itself.
            if name.as_str().eq_ignore_ascii_case("content-length")
                || name.as_str().eq_ignore_ascii_case("transfer-encoding")
                || name.as_str().eq_ignore_ascii_case("connection")
            {
                continue;
            }
            if let (Ok(n), Ok(v)) = (
                HeaderName::from_bytes(name.as_str().as_bytes()),
                HeaderValue::from_bytes(value.as_bytes()),
            ) {
                headers.push((n, v));
            }
        }
        let body = resp.bytes().await.unwrap_or_default();
        Ok(RequestPluginResult::Respond(HttpResponse {
            status,
            headers: (!headers.is_empty()).then_some(headers),
            body,
            ..Default::default()
        }))
    }
}

register_plugin!("forward_auth", ForwardAuth);

#[cfg(test)]
mod tests {
    use super::ForwardAuth;
    use pingap_config::PluginConf;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_forward_auth_params() {
        // Valid config.
        let plugin = ForwardAuth::try_from(
            &toml::from_str::<PluginConf>(
                r#"
category = "forward_auth"
auth_url = "http://127.0.0.1:9000/verify"
request_headers = ["authorization", "cookie"]
add_headers = ["x-auth-user"]
timeout = "5s"
"#,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!("http://127.0.0.1:9000/verify", plugin.auth_url);
        assert_eq!("authorization,cookie", plugin.request_headers.join(","));
        assert_eq!("x-auth-user", plugin.add_headers.join(","));

        // Missing auth_url is rejected.
        let err = ForwardAuth::try_from(
            &toml::from_str::<PluginConf>(r#"category = "forward_auth""#)
                .unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(
            "Plugin forward_auth invalid, message: auth_url is required",
            err.to_string()
        );

        // Malformed auth_url is rejected.
        let err = ForwardAuth::try_from(
            &toml::from_str::<PluginConf>(
                r#"
category = "forward_auth"
auth_url = "not a url"
"#,
            )
            .unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(true, err.to_string().contains("invalid auth_url"));
    }
}
