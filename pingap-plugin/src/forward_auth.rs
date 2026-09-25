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
    Ctx, HttpResponse, Plugin, PluginStep, RequestPluginResult,
    ensure_client_ip, get_host,
};
use pingora::proxy::Session;
use std::borrow::Cow;
use std::time::Duration;
use tracing::{debug, error};

type Result<T, E = Error> = std::result::Result<T, E>;

const CATEGORY: &str = "forward_auth";

/// Original request headers that must not reach the auth service: they
/// describe the client connection or a body the bodiless `GET` subrequest
/// does not have. `Content-Length` from a `POST` used to be forwarded, so
/// the auth service waited for a body that never came, and `Host` would
/// replace the auth URL's own.
const REQUEST_HEADERS_NOT_FORWARDED: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
    "expect",
];

/// Auth response headers that are not relayed to the client: pingap frames
/// the relayed response itself, and hop-by-hop headers belong to the
/// subrequest's connection.
const RESPONSE_HEADERS_NOT_RELAYED: &[&str] = &[
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
];

fn is_listed(name: &str, list: &[&str]) -> bool {
    list.iter().any(|item| item.eq_ignore_ascii_case(name))
}

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
        // The auth service's answer is the decision, redirects included:
        // with reqwest's default policy a `302` to the login page was
        // followed, and whatever that page returned (a `200` for a login
        // form) became the verdict, letting the request through.
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
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
        ctx: &mut Ctx,
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
                if is_listed(name.as_str(), REQUEST_HEADERS_NOT_FORWARDED) {
                    continue;
                }
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
            // The scheme the client used, the way `$scheme` sees it.
            let proto = if ctx.conn.tls_version.is_some() {
                "https"
            } else {
                "http"
            };
            builder = builder
                .header("x-forwarded-method", req_header.method.as_str())
                .header("x-forwarded-uri", uri)
                .header(
                    "x-forwarded-host",
                    get_host(req_header).unwrap_or_default(),
                )
                .header("x-forwarded-proto", proto);
        }
        let client_ip = ensure_client_ip(session, ctx);
        builder = builder.header("x-forwarded-for", client_ip);

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
            if is_listed(name.as_str(), RESPONSE_HEADERS_NOT_RELAYED) {
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
    use pingap_core::{Ctx, Plugin, PluginStep, RequestPluginResult};
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_test::io::Builder;

    /// A one-request HTTP server that records the request head it received
    /// and answers with `response`.
    async fn spawn_auth_server(
        response: &'static str,
    ) -> (String, Arc<Mutex<String>>) {
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let received = Arc::new(Mutex::new(String::new()));
        let recorder = received.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let recorder = recorder.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 8192];
                    let mut head = String::new();
                    while !head.contains("\r\n\r\n") {
                        let n = stream.read(&mut buf).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        head.push_str(&String::from_utf8_lossy(&buf[..n]));
                    }
                    *recorder.lock().unwrap() = head;
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        (addr, received)
    }

    /// The auth service sees the original headers minus the ones that
    /// describe the client's connection or body, plus the forwarded set.
    #[tokio::test]
    async fn test_forward_auth_subrequest_headers() {
        let (addr, received) = spawn_auth_server(
            "HTTP/1.1 200 OK\r\nX-User-Id: 42\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        let plugin = ForwardAuth::try_from(
            &toml::from_str::<PluginConf>(&format!(
                "category = \"forward_auth\"\nauth_url = \"http://{addr}/verify\"\nadd_headers = [\"X-User-Id\"]\n"
            ))
            .unwrap(),
        )
        .unwrap();
        let input = "POST /dashboard?x=1 HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nConnection: keep-alive\r\nCookie: session=abc\r\n\r\nhello";
        let mock_io = Builder::new().read(input.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let result = plugin
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result == RequestPluginResult::Continue);
        // The success header was copied onto the upstream request.
        assert_eq!(
            "42",
            session.req_header().headers.get("X-User-Id").unwrap()
        );

        let head = received.lock().unwrap().to_ascii_lowercase();
        assert_eq!(
            true,
            head.starts_with("get /verify http/1.1\r\n"),
            "{head}"
        );
        // Each entry is matched at the start of a line, so `host:` cannot
        // be satisfied by `x-forwarded-host:`.
        for expected in [
            "cookie: session=abc",
            "x-forwarded-method: post",
            "x-forwarded-uri: /dashboard?x=1",
            "x-forwarded-host: example.com",
            "x-forwarded-proto: http",
            "x-forwarded-for: ",
            &format!("host: {addr}"),
        ] {
            assert_eq!(
                true,
                head.contains(&format!("\r\n{expected}")),
                "{expected}: {head}"
            );
        }
        for unexpected in [
            "content-length: 5",
            "connection: keep-alive",
            "host: example.com",
        ] {
            assert_eq!(
                false,
                head.contains(&format!("\r\n{unexpected}")),
                "{unexpected}: {head}"
            );
        }
    }

    /// Anything but 2xx is relayed: status, headers and body, minus the
    /// framing and hop-by-hop headers.
    #[tokio::test]
    async fn test_forward_auth_relays_rejection() {
        let (addr, _) = spawn_auth_server(
            "HTTP/1.1 302 Found\r\nLocation: /login\r\nConnection: close\r\nContent-Length: 6\r\n\r\ndenied",
        )
        .await;
        let plugin = ForwardAuth::try_from(
            &toml::from_str::<PluginConf>(&format!(
                "category = \"forward_auth\"\nauth_url = \"http://{addr}/verify\"\n"
            ))
            .unwrap(),
        )
        .unwrap();
        let mock_io = Builder::new()
            .read(b"GET /dashboard HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = plugin
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        let RequestPluginResult::Respond(resp) = result else {
            panic!("a rejection must be relayed");
        };
        assert_eq!(302, resp.status.as_u16());
        assert_eq!(b"denied".as_ref(), resp.body.as_ref());
        let headers: Vec<String> = resp
            .headers
            .unwrap_or_default()
            .iter()
            .map(|(name, value)| {
                format!("{name}: {}", value.to_str().unwrap_or_default())
            })
            .collect();
        assert_eq!(vec!["location: /login".to_string()], headers);
    }

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
