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

//! WebSocket health check: an HTTP/1.1 upgrade handshake that the backend
//! must answer with `101 Switching Protocols` and a matching
//! `Sec-WebSocket-Accept` (RFC 6455 §4.2.2).
//!
//! pingora's `HttpHealthCheck` cannot be reused for this: after a 101 the
//! HTTP/1 client treats the body as close-delimited and the check drains it,
//! which blocks until the read timeout because a WebSocket server waits for
//! frames instead of closing. This check reads the response header, judges
//! it, and drops the connection without touching the body.

use super::{
    HealthCheckConf, HealthCheckSchema, new_internal_error, update_peer_options,
};
use async_trait::async_trait;
use http::StatusCode;
use pingora::connectors::http::Connector;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::lb::Backend;
use pingora::lb::health_check::{HealthCheck, HealthObserveCallback};
use pingora::protocols::ALPN;
use pingora::upstreams::peer::HttpPeer;
use sha1::{Digest, Sha1};

/// Fixed GUID the server appends to the key before hashing (RFC 6455 §1.3).
const WEBSOCKET_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub struct WebSocketHealthCheck {
    name: String,
    host: String,
    path: String,
    peer_template: HttpPeer,
    connector: Connector,
    pub consecutive_success: usize,
    pub consecutive_failure: usize,
    pub health_changed_callback: Option<HealthObserveCallback>,
}

/// The `Sec-WebSocket-Accept` value a server must return for `key`.
fn accept_key(key: &str) -> String {
    let digest = Sha1::digest(format!("{key}{WEBSOCKET_GUID}").as_bytes());
    pingap_util::base64_encode(digest)
}

/// A fresh `Sec-WebSocket-Key`: 16 random bytes, base64 encoded.
fn new_key() -> String {
    pingap_util::base64_encode(rand::random::<[u8; 16]>())
}

/// Judges the handshake response for the key that was sent.
fn validate_response(resp: &ResponseHeader, key: &str) -> pingora::Result<()> {
    if resp.status != StatusCode::SWITCHING_PROTOCOLS {
        return Err(new_internal_error(
            resp.status.as_u16(),
            format!(
                "expected 101 switching protocols, got {}",
                resp.status.as_u16()
            ),
        ));
    }
    let header = |name: &str| {
        resp.headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .trim()
            .to_string()
    };
    let upgrade = header("upgrade");
    if !upgrade.eq_ignore_ascii_case("websocket") {
        return Err(new_internal_error(
            500,
            format!("upgrade header is {upgrade:?}, not websocket"),
        ));
    }
    if header("sec-websocket-accept") != accept_key(key) {
        return Err(new_internal_error(
            500,
            "sec-websocket-accept does not match the key",
        ));
    }
    Ok(())
}

impl WebSocketHealthCheck {
    pub fn new(
        name: &str,
        conf: &HealthCheckConf,
        health_changed_callback: Option<HealthObserveCallback>,
    ) -> Self {
        let tls = conf.schema == HealthCheckSchema::Wss || conf.tls;
        let sni = if tls {
            conf.host.clone()
        } else {
            String::new()
        };
        let mut peer_template = HttpPeer::new("0.0.0.0:1", tls, sni);
        peer_template.options =
            update_peer_options(conf, peer_template.options.clone());
        // The upgrade handshake only exists on HTTP/1.1.
        peer_template.options.alpn = ALPN::H1;
        let path = if conf.path.is_empty() {
            "/".to_string()
        } else {
            conf.path.clone()
        };
        Self {
            name: name.to_string(),
            host: conf.host.clone(),
            path,
            peer_template,
            connector: Connector::new(None),
            consecutive_success: conf.consecutive_success,
            consecutive_failure: conf.consecutive_failure,
            health_changed_callback,
        }
    }

    fn build_request(&self, key: &str) -> pingora::Result<RequestHeader> {
        let mut req =
            RequestHeader::build("GET", self.path.as_bytes(), Some(5))?;
        req.append_header("Host", &self.host)?;
        req.append_header("Connection", "Upgrade")?;
        req.append_header("Upgrade", "websocket")?;
        req.append_header("Sec-WebSocket-Version", "13")?;
        req.append_header("Sec-WebSocket-Key", key)?;
        Ok(req)
    }
}

#[async_trait]
impl HealthCheck for WebSocketHealthCheck {
    async fn check(&self, target: &Backend) -> pingora::Result<()> {
        let mut peer = self.peer_template.clone();
        peer._address = target.addr.clone();
        let key = new_key();
        let req = self.build_request(&key)?;

        let (mut session, _) = self.connector.get_http_session(&peer).await?;
        session.set_write_timeout(peer.options.write_timeout);
        session.write_request_header(Box::new(req)).await?;
        session.finish_request_body().await?;
        session.set_read_timeout(peer.options.read_timeout);
        session.read_response_header().await?;
        let resp = session.response_header().ok_or_else(|| {
            new_internal_error(500, "websocket handshake has no response")
        })?;
        validate_response(resp, &key)
        // `session` drops here without reading a body or being pooled: the
        // TCP close is how the probe ends the conversation.
    }

    async fn health_status_change(&self, target: &Backend, healthy: bool) {
        if let Some(callback) = &self.health_changed_callback {
            callback.observe(target, healthy).await;
        }
    }

    fn backend_summary(&self, target: &Backend) -> String {
        format!("{}: {}", self.name, target.addr)
    }

    fn health_threshold(&self, success: bool) -> usize {
        if success {
            self.consecutive_success
        } else {
            self.consecutive_failure
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::new_health_check;
    use pretty_assertions::assert_eq;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn test_accept_key() {
        // The worked example from RFC 6455 §1.3.
        assert_eq!(
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
            accept_key("dGhlIHNhbXBsZSBub25jZQ==")
        );
        // Keys are 16 random bytes, so 24 base64 characters, and unique.
        assert_eq!(24, new_key().len());
        assert_ne!(new_key(), new_key());
    }

    #[test]
    fn test_validate_response() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let mut resp = ResponseHeader::build(101, None).unwrap();
        resp.append_header("Upgrade", "websocket").unwrap();
        resp.append_header(
            "Sec-WebSocket-Accept",
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
        )
        .unwrap();
        assert_eq!(true, validate_response(&resp, key).is_ok());

        let mut wrong_accept = ResponseHeader::build(101, None).unwrap();
        wrong_accept.append_header("Upgrade", "websocket").unwrap();
        wrong_accept
            .append_header("Sec-WebSocket-Accept", "bogus")
            .unwrap();
        let err = validate_response(&wrong_accept, key).unwrap_err();
        assert_eq!(true, err.to_string().contains("does not match"), "{err}");

        let mut no_upgrade = ResponseHeader::build(101, None).unwrap();
        no_upgrade
            .append_header(
                "Sec-WebSocket-Accept",
                "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
            )
            .unwrap();
        let err = validate_response(&no_upgrade, key).unwrap_err();
        assert_eq!(true, err.to_string().contains("not websocket"), "{err}");

        let rejected = ResponseHeader::build(400, None).unwrap();
        let err = validate_response(&rejected, key).unwrap_err();
        assert_eq!(true, err.to_string().contains("got 400"), "{err}");
    }

    type Reply = Arc<dyn Fn(&str) -> String + Send + Sync>;

    /// A fake WebSocket server: reads one request, answers with `reply(key)`
    /// and then, like a real one, waits for frames until the peer closes.
    async fn spawn_server(reply: Reply) -> String {
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let reply = reply.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let mut request = String::new();
                    while !request.contains("\r\n\r\n") {
                        let n = stream.read(&mut buf).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        request.push_str(&String::from_utf8_lossy(&buf[..n]));
                    }
                    let key = request
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("sec-websocket-key")
                                .then(|| value.trim().to_string())
                        })
                        .unwrap_or_default();
                    let _ = stream.write_all(reply(&key).as_bytes()).await;
                    let _ = stream.read(&mut buf).await;
                });
            }
        });
        addr
    }

    /// Runs one probe against `addr` and reports how long the probe alone
    /// took. Building the check is deliberately outside that window: it
    /// constructs a `Connector`, and under the rustls backend that loads the
    /// system root store - well over a second on a cold process, and nothing
    /// to do with how promptly the handshake is judged.
    async fn timed_check(
        addr: &str,
    ) -> (pingora::Result<()>, std::time::Duration) {
        let (conf, hc) = new_health_check(
            "ws",
            &format!("ws://{addr}/chat?connection_timeout=1s&read_timeout=1s"),
            None,
        )
        .unwrap();
        assert_eq!(HealthCheckSchema::Ws, conf.schema);
        assert_eq!("/chat", conf.path);
        let backend = Backend::new(addr).unwrap();
        let started = std::time::Instant::now();
        let result = hc.check(&backend).await;
        (result, started.elapsed())
    }

    async fn check(addr: &str) -> pingora::Result<()> {
        timed_check(addr).await.0
    }

    #[tokio::test]
    async fn test_websocket_health_check() {
        // A compliant server passes, and the probe returns promptly instead
        // of waiting on the read timeout for a body that never comes.
        let addr = spawn_server(Arc::new(|key: &str| {
            format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
                accept_key(key)
            )
        }))
        .await;
        let (result, elapsed) = timed_check(&addr).await;
        result.unwrap();
        assert_eq!(
            true,
            elapsed < std::time::Duration::from_millis(500),
            "probe took {elapsed:?}"
        );

        // A server that refuses the upgrade fails the check.
        let addr = spawn_server(Arc::new(|_: &str| {
            "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n".to_string()
        }))
        .await;
        let err = check(&addr).await.unwrap_err();
        assert_eq!(true, err.to_string().contains("got 400"), "{err}");

        // So does one that answers 101 with an accept value for another key.
        let addr = spawn_server(Arc::new(|_: &str| {
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n".to_string()
        }))
        .await;
        let err = check(&addr).await.unwrap_err();
        assert_eq!(true, err.to_string().contains("does not match"), "{err}");
    }
}
