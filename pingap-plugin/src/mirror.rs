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
    Error, get_duration_conf, get_hash_key, get_int_conf_or_default,
    get_step_conf_in, get_str_conf, get_str_slice_conf,
};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use bytesize::ByteSize;
use http::header::{CONTENT_LENGTH, HOST};
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use pingap_config::PluginConf;
use pingap_core::{
    Ctx, HandleRequestBody, Plugin, PluginStep, RequestPluginResult,
    ensure_client_ip,
};
use pingora::proxy::Session;
use std::borrow::Cow;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::{debug, warn};

type Result<T, E = Error> = std::result::Result<T, E>;

const CATEGORY: &str = "mirror";
/// What a mirrored request is told by. A request that comes with it is
/// not mirrored again: two proxies that mirror to each other would send
/// one request round for ever.
const MIRROR_HEADER: &str = "x-pingap-mirror";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
/// Mirrored requests that are under way at one time, where nothing else
/// is said. Those of a target that does not answer are waited for, each
/// for the timeout, and are not to pile up without end.
const DEFAULT_MAX_INFLIGHT: usize = 100;

/// The headers of a request that are not for the mirror: they are of the
/// connection it came on, or say how its body is framed, which the copy
/// says for itself.
const HEADERS_NOT_MIRRORED: &[&str] = &[
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
    // Written here, for the client the proxy sees.
    "x-forwarded-for",
    "x-real-ip",
    "x-forwarded-proto",
];

/// Sends a copy of the requests of a location to another address, and
/// throws the answer away.
///
/// For trying a new version with the traffic the old one gets: what it
/// answers, how long it takes and whether it is there at all make no
/// difference to the client, whose request goes to the upstream as ever.
/// `traffic_splitting` divides the requests between two upstreams; this
/// sends them to both.
pub struct Mirror {
    plugin_step: PluginStep,
    client: reqwest::Client,
    /// Where the copies go: scheme, host and port, and a path that is
    /// put in front of the one of the request.
    target: String,
    /// The `Host` of the copy, where it is not to be the request's own.
    host: Option<HeaderValue>,
    /// The share of the requests that are copied, of a hundred.
    percentage: u8,
    methods: Vec<Method>,
    /// The largest body that is copied. A request with a larger one is
    /// not mirrored at all, and neither is any request with a body while
    /// this is nothing.
    max_body_size: usize,
    inflight: Arc<Semaphore>,
    /// Copies that could not be sent or were not answered, for a line in
    /// the log now and then.
    failed: Arc<AtomicU64>,
    hash_value: String,
}

impl TryFrom<&PluginConf> for Mirror {
    type Error = Error;

    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);
        let invalid = |message: String| Error::Invalid {
            category: CATEGORY.to_string(),
            message,
        };
        let target = get_str_conf(value, "target");
        let url = reqwest::Url::parse(target.trim()).map_err(|e| {
            invalid(format!(
                "target should be a url like http://10.0.0.2:8080 ({e})"
            ))
        })?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(invalid(
                "target should be an http or https url, without a query"
                    .to_string(),
            ));
        }
        // Without the slash it ends with: the path of a request starts
        // with one.
        let target = url.as_str().trim_end_matches('/').to_string();

        let host = get_str_conf(value, "host");
        let host = if host.trim().is_empty() {
            None
        } else {
            Some(HeaderValue::from_str(host.trim()).map_err(|e| {
                invalid(format!("host is not a header value: {e}"))
            })?)
        };

        let percentage = get_int_conf_or_default(value, "percentage", 100);
        let percentage = u8::try_from(percentage)
            .ok()
            .filter(|percentage| *percentage <= 100)
            .ok_or_else(|| {
                invalid(format!(
                    "percentage({percentage}) should be from 0 to 100"
                ))
            })?;

        let mut methods = vec![];
        for item in get_str_slice_conf(value, "methods") {
            let name = item.trim().to_ascii_uppercase();
            let method = Method::from_str(&name)
                .ok()
                .filter(|_| !name.is_empty())
                .ok_or_else(|| {
                    invalid(format!("methods: {item:?} is not a method"))
                })?;
            if !methods.contains(&method) {
                methods.push(method);
            }
        }
        if methods.is_empty() {
            // What does not change anything at the target, twice over.
            methods = vec![Method::GET, Method::HEAD];
        }

        let size = get_str_conf(value, "max_body_size");
        let max_body_size = if size.trim().is_empty() {
            0
        } else {
            ByteSize::from_str(size.trim())
                .map(|size| size.as_u64() as usize)
                .map_err(|e| {
                    invalid(format!("invalid max_body_size({size}): {e}"))
                })?
        };

        let timeout =
            get_duration_conf(value, "timeout").unwrap_or(DEFAULT_TIMEOUT);
        if timeout.is_zero() {
            return Err(invalid("timeout should be more than 0".to_string()));
        }
        let max_inflight = get_int_conf_or_default(
            value,
            "max_inflight",
            DEFAULT_MAX_INFLIGHT as i64,
        );
        let max_inflight = usize::try_from(max_inflight)
            .ok()
            .filter(|count| (1..=Semaphore::MAX_PERMITS).contains(count))
            .ok_or_else(|| {
                invalid(format!(
                    "max_inflight({max_inflight}) should be at least 1"
                ))
            })?;
        // What the target answers is not looked at, a redirect included.
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| invalid(e.to_string()))?;

        Ok(Self {
            plugin_step: get_step_conf_in(
                value,
                CATEGORY,
                PluginStep::Request,
                &[PluginStep::Request, PluginStep::ProxyUpstream],
            )?,
            client,
            target,
            host,
            percentage,
            methods,
            max_body_size,
            inflight: Arc::new(Semaphore::new(max_inflight)),
            failed: Arc::new(AtomicU64::new(0)),
            hash_value,
        })
    }
}

/// A copy of a request that is ready to go, but for its body.
struct Copy {
    client: reqwest::Client,
    method: Method,
    url: String,
    headers: HeaderMap,
    failed: Arc<AtomicU64>,
    /// The copies that are under way, of which this is one from the
    /// moment it is sent until it is answered.
    inflight: Arc<Semaphore>,
}

impl Copy {
    /// Sends it, from a task of its own: nobody waits for it. Unless as
    /// many as may be under way are: then this one is not sent.
    ///
    /// Its place is taken here and not when the request comes in. Taken
    /// then, a client that was slow to send its body held a place for
    /// as long as it liked, which no timeout ends, and a hundred of
    /// those were the end of mirroring.
    fn send(self, body: Option<Bytes>) {
        let Ok(permit) = self.inflight.clone().try_acquire_owned() else {
            debug!(category = CATEGORY, "too many mirrored requests in flight");
            return;
        };
        tokio::spawn(async move {
            let _permit = permit;
            let mut request = self
                .client
                .request(self.method, &self.url)
                .headers(self.headers);
            if let Some(body) = body {
                request = request.body(body);
            }
            // The answer is read to its end, so that the connection can
            // be used for the next copy, a piece at a time: none of it
            // is kept, however long it is.
            let result = async {
                let mut response = request.send().await?;
                while response.chunk().await?.is_some() {}
                Ok::<(), reqwest::Error>(())
            }
            .await;
            if let Err(e) = result {
                // A target that is down fails every copy: one line for
                // the first, the second, the fourth, the eighth...
                let failed = self.failed.fetch_add(1, Ordering::Relaxed) + 1;
                if failed.is_power_of_two() {
                    warn!(
                        category = CATEGORY,
                        // Without the url, which may carry a credential.
                        error = %e.without_url(),
                        failed,
                        "mirrored request failed"
                    );
                } else {
                    debug!(
                        category = CATEGORY,
                        error = %e.without_url(),
                        "mirrored request failed"
                    );
                }
            }
        });
    }
}

/// Keeps what goes by of the body of a request, and sends the copy once
/// it has all of it.
struct BodyCopy {
    copy: Option<Copy>,
    buffer: BytesMut,
    max: usize,
}

impl HandleRequestBody for BodyCopy {
    fn handle(
        &mut self,
        body: Option<&Bytes>,
        end_of_stream: bool,
    ) -> pingora::Result<()> {
        if self.copy.is_none() {
            return Ok(());
        }
        if let Some(body) = body {
            // More than is kept: the request is not mirrored, and what
            // was kept of it is let go.
            if self.buffer.len() + body.len() > self.max {
                self.copy = None;
                self.buffer = BytesMut::new();
                return Ok(());
            }
            self.buffer.extend_from_slice(body);
        }
        if end_of_stream && let Some(copy) = self.copy.take() {
            copy.send(Some(std::mem::take(&mut self.buffer).freeze()));
        }
        Ok(())
    }

    /// The body comes once more from its start. A copy that has been
    /// sent is not sent again, and one that was given up stays given up.
    fn restart(&mut self) {
        self.buffer.clear();
    }
}

impl Mirror {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(
            params = pingap_config::masked_toml(params),
            "new mirror plugin"
        );
        Self::try_from(params)
    }

    /// The length the request says its body has, where it says one.
    fn content_length(session: &Session) -> Option<usize> {
        session
            .req_header()
            .headers
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<usize>().ok())
    }

    /// The headers of the copy: those of the request that are not of
    /// its connection, the client as the proxy sees it, and the mark.
    fn copy_headers(&self, session: &Session, ctx: &mut Ctx) -> HeaderMap {
        let header = session.req_header();
        let mut headers = HeaderMap::with_capacity(header.headers.len() + 5);
        for (name, value) in header.headers.iter() {
            if HEADERS_NOT_MIRRORED
                .iter()
                .any(|item| item.eq_ignore_ascii_case(name.as_str()))
            {
                continue;
            }
            headers.append(name.clone(), value.clone());
        }
        // The host of the request, as the upstream gets it: the mirror
        // is a second one of those. Unless another is asked for.
        let host = self.host.clone().or_else(|| {
            header.headers.get(HOST).cloned().or_else(|| {
                header
                    .uri
                    .authority()
                    .and_then(|host| HeaderValue::from_str(host.as_str()).ok())
            })
        });
        if let Some(host) = host {
            headers.insert(HOST, host);
        }
        let proto = if ctx.conn.tls_version.is_some() {
            "https"
        } else {
            "http"
        };
        headers.insert(
            HeaderName::from_static("x-forwarded-proto"),
            HeaderValue::from_static(proto),
        );
        if let Ok(ip) = HeaderValue::from_str(ensure_client_ip(session, ctx)) {
            headers
                .insert(HeaderName::from_static("x-forwarded-for"), ip.clone());
            headers.insert(HeaderName::from_static("x-real-ip"), ip);
        }
        headers.insert(
            HeaderName::from_static(MIRROR_HEADER),
            HeaderValue::from_static("1"),
        );
        headers
    }
}

#[async_trait]
impl Plugin for Mirror {
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
        let header = session.req_header();
        if !self.methods.contains(&header.method)
            || header.headers.contains_key(MIRROR_HEADER)
        {
            return Ok(RequestPluginResult::Skipped);
        }
        let chosen = match self.percentage {
            100 => true,
            0 => false,
            percentage => rand::random_range(0..100u8) < percentage,
        };
        if !chosen {
            return Ok(RequestPluginResult::Skipped);
        }
        let has_body = !session.is_body_empty();
        if has_body
            && (self.max_body_size == 0
                || Self::content_length(session)
                    .is_some_and(|size| size > self.max_body_size))
        {
            return Ok(RequestPluginResult::Skipped);
        }
        let header = session.req_header();
        let target = header
            .uri
            .path_and_query()
            .map(|target| target.as_str())
            .unwrap_or("/");
        let copy = Copy {
            client: self.client.clone(),
            method: header.method.clone(),
            url: format!("{}{target}", self.target),
            headers: self.copy_headers(session, ctx),
            failed: self.failed.clone(),
            inflight: self.inflight.clone(),
        };
        // A body is not kept for a mirror that has all it can take: the
        // copy would be made, held for as long as the upload lasts, and
        // dropped when it is to be sent.
        if has_body && self.inflight.available_permits() == 0 {
            return Ok(RequestPluginResult::Continue);
        }
        if has_body {
            ctx.add_request_body_handler(Box::new(BodyCopy {
                copy: Some(copy),
                buffer: BytesMut::new(),
                max: self.max_body_size,
            }));
        } else {
            copy.send(None);
        }
        Ok(RequestPluginResult::Continue)
    }
}

register_plugin!("mirror", Mirror);

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_test::io::Builder;

    fn new_plugin(conf: &str) -> Result<Mirror> {
        Mirror::new(&toml::from_str::<PluginConf>(conf).unwrap())
    }

    async fn new_session(request: &str) -> Session {
        let mock_io = Builder::new().read(request.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        session
    }

    /// A target that takes one request, answers it and hands it over.
    async fn target() -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let request = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut received = vec![];
            let mut buf = [0u8; 4096];
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                received.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&received).to_string();
                let Some((head, body)) = text.split_once("\r\n\r\n") else {
                    continue;
                };
                let length = head
                    .to_lowercase()
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("content-length:").and_then(|value| {
                            value.trim().parse::<usize>().ok()
                        })
                    })
                    .unwrap_or_default();
                if n == 0 || body.len() >= length {
                    break;
                }
            }
            stream
                .write_all(
                    b"HTTP/1.1 500 Oops\r\nContent-Length: 4\r\n\r\noops",
                )
                .await
                .unwrap();
            String::from_utf8_lossy(&received).to_string()
        });
        (addr, request)
    }

    #[test]
    fn test_mirror_params() {
        let plugin = new_plugin("target = \"http://10.0.0.2:8080/\"").unwrap();
        assert_eq!("http://10.0.0.2:8080", plugin.target);
        assert_eq!(100, plugin.percentage);
        assert_eq!(vec![Method::GET, Method::HEAD], plugin.methods);
        assert_eq!(0, plugin.max_body_size);
        assert_eq!(DEFAULT_MAX_INFLIGHT, plugin.inflight.available_permits());
        assert_eq!(PluginStep::Request, plugin.plugin_step);

        let plugin = new_plugin(
            "target = \"https://shadow.test/v2\"\nhost = \"app.test\"\npercentage = 10\nmethods = [\"get\", \"POST\", \"GET\"]\nmax_body_size = \"64kb\"\nmax_inflight = 3\nstep = \"proxy_upstream\"",
        )
        .unwrap();
        assert_eq!("https://shadow.test/v2", plugin.target);
        assert_eq!("app.test", plugin.host.clone().unwrap());
        assert_eq!(10, plugin.percentage);
        assert_eq!(vec![Method::GET, Method::POST], plugin.methods);
        assert_eq!(64_000, plugin.max_body_size);
        assert_eq!(3, plugin.inflight.available_permits());
        assert_eq!(PluginStep::ProxyUpstream, plugin.plugin_step);

        for (conf, message) in [
            ("", "target should be a url"),
            (
                "target = \"shadow:8080\"",
                "target should be an http or https",
            ),
            (
                "target = \"http://shadow/?a=1\"",
                "target should be an http or https",
            ),
            (
                "target = \"http://a\"\npercentage = 101",
                "percentage(101) should be from 0 to 100",
            ),
            (
                "target = \"http://a\"\nmethods = [\"GE T\"]",
                "is not a method",
            ),
            (
                "target = \"http://a\"\nmax_body_size = \"big\"",
                "invalid max_body_size(big)",
            ),
            (
                "target = \"http://a\"\ntimeout = \"0s\"",
                "timeout should be more than 0",
            ),
            (
                "target = \"http://a\"\nmax_inflight = 0",
                "max_inflight(0) should be at least 1",
            ),
            ("target = \"http://a\"\nstep = \"response\"", "Invalid step"),
        ] {
            let error = new_plugin(conf).err().unwrap().to_string();
            assert_eq!(true, error.contains(message), "{conf}: {error}");
        }
    }

    /// A request without a body is copied at once: method, path, query
    /// and headers, with the mark, and the request goes on.
    #[tokio::test]
    async fn test_mirror_copies_a_request() {
        let (addr, received) = target().await;
        let plugin =
            new_plugin(&format!("target = \"http://{addr}/shadow\"")).unwrap();
        let mut session = new_session(
            "GET /api/users?page=2 HTTP/1.1\r\nHost: app.test\r\nX-Tenant: a\r\nConnection: keep-alive\r\nX-Forwarded-For: 1.2.3.4\r\n\r\n",
        )
        .await;
        let mut ctx = Ctx::default();
        ctx.conn.client_ip = Some("10.9.8.7".to_string());
        let result = plugin
            .handle_request(PluginStep::Request, &mut session, &mut ctx)
            .await
            .unwrap();
        assert_eq!(true, matches!(result, RequestPluginResult::Continue));
        let received = tokio::time::timeout(Duration::from_secs(5), received)
            .await
            .expect("the copy is sent")
            .unwrap()
            .to_lowercase();
        assert_eq!(
            true,
            received.starts_with("get /shadow/api/users?page=2 http/1.1\r\n"),
            "{received}"
        );
        for line in [
            "host: app.test\r\n",
            "x-tenant: a\r\n",
            "x-pingap-mirror: 1\r\n",
            "x-forwarded-for: 10.9.8.7\r\n",
            "x-real-ip: 10.9.8.7\r\n",
            "x-forwarded-proto: http\r\n",
        ] {
            assert_eq!(true, received.contains(line), "{line}: {received}");
        }
        // not what the client said of itself, nor what is of its
        // connection
        assert_eq!(false, received.contains("1.2.3.4"), "{received}");
        assert_eq!(false, received.contains("keep-alive"), "{received}");
        // The place of the copy is free again once it is answered.
        for _ in 0..100 {
            if plugin.inflight.available_permits() == DEFAULT_MAX_INFLIGHT {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(DEFAULT_MAX_INFLIGHT, plugin.inflight.available_permits());
    }

    /// Which requests are not copied.
    #[tokio::test]
    async fn test_mirror_leaves_requests_alone() {
        // Nothing listens there: a copy that was sent would fail, and is
        // counted.
        let plugin = new_plugin(
            "target = \"http://127.0.0.1:9\"\nmethods = [\"GET\", \"POST\"]\nmax_body_size = \"10b\"\ntimeout = \"1s\"",
        )
        .unwrap();
        let run = async |plugin: &Mirror, request: &str, step: PluginStep| {
            let mut session = new_session(request).await;
            let mut ctx = Ctx::default();
            let result = plugin
                .handle_request(step, &mut session, &mut ctx)
                .await
                .unwrap();
            let handlers = ctx
                .features
                .and_then(|features| features.request_body_handlers)
                .map(|handlers| handlers.len())
                .unwrap_or_default();
            (matches!(result, RequestPluginResult::Skipped), handlers)
        };
        let step = PluginStep::Request;
        // another method, another step, a request that is a copy itself
        for (request, step) in [
            ("DELETE /a HTTP/1.1\r\n\r\n", step),
            ("GET /a HTTP/1.1\r\n\r\n", PluginStep::ProxyUpstream),
            ("GET /a HTTP/1.1\r\nX-Pingap-Mirror: 1\r\n\r\n", step),
            // a body that says it is larger than what is kept
            ("POST /a HTTP/1.1\r\nContent-Length: 11\r\n\r\n", step),
        ] {
            assert_eq!(
                (true, 0),
                run(&plugin, request, step).await,
                "{request}"
            );
        }
        // A body that may be small enough is followed.
        assert_eq!(
            (false, 1),
            run(
                &plugin,
                "POST /a HTTP/1.1\r\nContent-Length: 10\r\n\r\n",
                step
            )
            .await
        );
        assert_eq!(
            (false, 1),
            run(
                &plugin,
                "POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
                step
            )
            .await
        );
        // No body is kept where none may be: only what has none is
        // copied.
        let plugin = new_plugin(
            "target = \"http://127.0.0.1:9\"\nmethods = [\"POST\"]\npercentage = 0",
        )
        .unwrap();
        assert_eq!(
            (true, 0),
            run(
                &plugin,
                "POST /a HTTP/1.1\r\nContent-Length: 1\r\n\r\n",
                step
            )
            .await
        );
        // and nothing at all of a share of none
        assert_eq!(
            (true, 0),
            run(&plugin, "POST /a HTTP/1.1\r\n\r\n", step).await
        );
    }

    /// The body is copied as it goes by, sent when it is complete, and
    /// given up when it is more than is kept.
    #[tokio::test]
    async fn test_mirror_copies_a_body() {
        let (addr, received) = target().await;
        let plugin = new_plugin(&format!(
            "target = \"http://{addr}\"\nmethods = [\"POST\"]\nmax_body_size = \"16b\""
        ))
        .unwrap();
        let handler = async |plugin: &Mirror| {
            let mut session = new_session(
                "POST /orders HTTP/1.1\r\nHost: app.test\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\n\r\n",
            )
            .await;
            let mut ctx = Ctx::default();
            plugin
                .handle_request(PluginStep::Request, &mut session, &mut ctx)
                .await
                .unwrap();
            ctx.features
                .and_then(|features| features.request_body_handlers)
                .and_then(|mut handlers| handlers.pop())
        };
        let mut copy = handler(&plugin).await.unwrap();
        // A body that is on its way holds no place among the copies that
        // are under way: a client that is slow with it held one for as
        // long as it liked.
        assert_eq!(DEFAULT_MAX_INFLIGHT, plugin.inflight.available_permits());
        // A first try at the upstream that got some of the body, and
        // then the one that gets all of it.
        copy.handle(Some(&Bytes::from_static(b"{\"id\"")), false)
            .unwrap();
        copy.restart();
        copy.handle(Some(&Bytes::from_static(b"{\"id\"")), false)
            .unwrap();
        copy.handle(Some(&Bytes::from_static(b":1}")), false)
            .unwrap();
        copy.handle(None, true).unwrap();
        let received = tokio::time::timeout(Duration::from_secs(5), received)
            .await
            .expect("the copy is sent")
            .unwrap();
        assert_eq!(
            true,
            received.starts_with("POST /orders HTTP/1.1\r\n"),
            "{received}"
        );
        assert_eq!(
            true,
            received.ends_with("\r\n\r\n{\"id\":1}"),
            "{received}"
        );
        assert_eq!(
            true,
            received.to_lowercase().contains("content-length: 8\r\n"),
            "{received}"
        );
        // Sent once: the body going by again sends nothing.
        copy.restart();
        copy.handle(Some(&Bytes::from_static(b"{\"id\":1}")), true)
            .unwrap();

        // More than is kept: given up, and nothing is sent when it ends.
        let (addr, received) = target().await;
        let plugin = new_plugin(&format!(
            "target = \"http://{addr}\"\nmethods = [\"POST\"]\nmax_body_size = \"16b\""
        ))
        .unwrap();
        let mut copy = handler(&plugin).await.unwrap();
        copy.handle(Some(&Bytes::from(vec![b'a'; 10])), false)
            .unwrap();
        copy.handle(Some(&Bytes::from(vec![b'a'; 7])), false)
            .unwrap();
        copy.handle(None, true).unwrap();
        assert_eq!(
            true,
            tokio::time::timeout(Duration::from_millis(300), received)
                .await
                .is_err()
        );
        assert_eq!(0, plugin.failed.load(Ordering::Relaxed));
    }

    /// No more copies are under way than may be: one that would be one
    /// too many is not sent, and the request goes on all the same.
    #[tokio::test]
    async fn test_mirror_max_inflight() {
        // A target that takes what it is sent and never answers.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let taken = Arc::new(AtomicU64::new(0));
        let counter = taken.clone();
        tokio::spawn(async move {
            let mut held = vec![];
            while let Ok((stream, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::Relaxed);
                held.push(stream);
            }
        });
        let plugin = new_plugin(&format!(
            "target = \"http://{addr}\"\nmax_inflight = 1\ntimeout = \"30s\"\nmethods = [\"GET\", \"POST\"]\nmax_body_size = \"1kb\""
        ))
        .unwrap();
        let request = async |plugin: &Mirror| {
            let mut session = new_session("GET /a HTTP/1.1\r\n\r\n").await;
            let result = plugin
                .handle_request(
                    PluginStep::Request,
                    &mut session,
                    &mut Ctx::default(),
                )
                .await
                .unwrap();
            matches!(result, RequestPluginResult::Continue)
        };
        assert_eq!(true, request(&plugin).await);
        for _ in 0..200 {
            if taken.load(Ordering::Relaxed) == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(1, taken.load(Ordering::Relaxed));
        assert_eq!(0, plugin.inflight.available_permits());
        // While that one is waited for, the next two are let through and
        // not copied.
        assert_eq!(true, request(&plugin).await);
        assert_eq!(true, request(&plugin).await);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(1, taken.load(Ordering::Relaxed));
        // Nor is a body kept for a copy that could not be sent.
        let mut session =
            new_session("POST /a HTTP/1.1\r\nContent-Length: 5\r\n\r\n").await;
        let mut ctx = Ctx::default();
        plugin
            .handle_request(PluginStep::Request, &mut session, &mut ctx)
            .await
            .unwrap();
        assert_eq!(
            true,
            ctx.features
                .and_then(|features| features.request_body_handlers)
                .is_none()
        );
    }
}
