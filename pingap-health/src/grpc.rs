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

//! gRPC health check: the `grpc.health.v1.Health/Check` call, spoken
//! directly over pingora's HTTP/2 client.
//!
//! The protocol's two messages have one field each, so they are encoded
//! and decoded here instead of through a generated client, and the probe
//! gets the same treatment as the HTTP one: pingora's connector, the
//! configured connection and read timeouts, TLS with the URL host as SNI
//! and no certificate verification. The tonic client this replaces had no
//! request timeout, and its `tls` flag could never work because the tonic
//! in this build carries no TLS support at all.

use super::{HealthCheckConf, new_internal_error, update_peer_options};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use http::{HeaderMap, StatusCode};
use pingora::connectors::http::Connector;
use pingora::http::RequestHeader;
use pingora::lb::Backend;
use pingora::lb::health_check::{HealthCheck, HealthObserveCallback};
use pingora::protocols::ALPN;
use pingora::protocols::http::client::HttpSession;
use pingora::upstreams::peer::HttpPeer;

/// The method of the gRPC health protocol.
const HEALTH_CHECK_PATH: &str = "/grpc.health.v1.Health/Check";
/// `HealthCheckResponse.ServingStatus.SERVING`.
const SERVING: u64 = 1;
/// A health response is a few bytes; anything past this is not one.
const MAX_RESPONSE_SIZE: usize = 4096;

pub struct GrpcHealthCheck {
    name: String,
    host: String,
    peer_template: HttpPeer,
    connector: Connector,
    /// `HealthCheckRequest { service }`, framed once.
    request: Bytes,
    /// Number of successful checks to flip from unhealthy to healthy.
    pub consecutive_success: usize,
    /// Number of failed checks to flip from healthy to unhealthy.
    pub consecutive_failure: usize,
    /// A callback that is invoked when the `healthy` status changes for a [Backend].
    pub health_changed_callback: Option<HealthObserveCallback>,
}

fn put_varint(buf: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        buf.push((value as u8) | 0x80);
        value >>= 7;
    }
    buf.push(value as u8);
}

fn get_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let byte = *buf.get(*pos)?;
        *pos += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// `HealthCheckRequest { string service = 1 }` inside a gRPC data frame: a
/// compression flag, the big-endian message length, then the message, which
/// is empty when `service` is (that asks for the overall server health).
fn encode_request(service: &str) -> Bytes {
    let mut message = Vec::with_capacity(service.len() + 11);
    if !service.is_empty() {
        // field 1, wire type 2 (length delimited)
        message.push(0x0a);
        put_varint(&mut message, service.len() as u64);
        message.extend_from_slice(service.as_bytes());
    }
    let mut frame = Vec::with_capacity(message.len() + 5);
    frame.push(0);
    frame.extend_from_slice(&(message.len() as u32).to_be_bytes());
    frame.extend_from_slice(&message);
    Bytes::from(frame)
}

/// The `status` of a `HealthCheckResponse { ServingStatus status = 1 }` in
/// a gRPC data frame: `UNKNOWN` (0) when the field is absent, `None` when
/// the bytes are not such a frame. Fields this reader does not know are
/// skipped by wire type, as protobuf requires.
fn decode_response_status(frame: &[u8]) -> Option<u64> {
    let (prefix, rest) = frame.split_at_checked(5)?;
    if prefix[0] != 0 {
        // Nothing here asks for compressed messages.
        return None;
    }
    let len = u32::from_be_bytes([prefix[1], prefix[2], prefix[3], prefix[4]])
        as usize;
    let message = rest.get(..len)?;
    let mut status = 0;
    let mut pos = 0;
    while pos < message.len() {
        let tag = get_varint(message, &mut pos)?;
        let (field, wire_type) = (tag >> 3, tag & 7);
        match wire_type {
            0 => {
                let value = get_varint(message, &mut pos)?;
                if field == 1 {
                    status = value;
                }
            },
            1 => pos += 8,
            2 => {
                let len = get_varint(message, &mut pos)? as usize;
                pos = pos.checked_add(len)?;
            },
            5 => pos += 4,
            _ => return None,
        }
    }
    (pos == message.len()).then_some(status)
}

fn serving_status_name(status: u64) -> &'static str {
    match status {
        0 => "UNKNOWN",
        1 => "SERVING",
        2 => "NOT_SERVING",
        3 => "SERVICE_UNKNOWN",
        _ => "unrecognised",
    }
}

/// The `grpc-status` and `grpc-message` of a call, when `headers` carry
/// them: the trailers normally, the response headers for a call the server
/// failed before sending a body.
fn grpc_status(headers: &HeaderMap) -> Option<(String, String)> {
    let value = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.trim().to_string())
    };
    let status = value("grpc-status")?;
    Some((status, value("grpc-message").unwrap_or_default()))
}

impl GrpcHealthCheck {
    pub fn new(
        name: &str,
        conf: &HealthCheckConf,
        health_changed_callback: Option<HealthObserveCallback>,
    ) -> Self {
        let sni = if conf.tls {
            conf.host.clone()
        } else {
            String::new()
        };
        let mut peer_template = HttpPeer::new("0.0.0.0:1", conf.tls, sni);
        peer_template.options =
            update_peer_options(conf, peer_template.options.clone());
        // gRPC is HTTP/2 only: over TLS that is what ALPN offers, in the
        // clear pingora opens the connection with the h2 preface.
        peer_template.options.alpn = ALPN::H2;
        Self {
            name: name.to_string(),
            host: conf.host.clone(),
            peer_template,
            connector: Connector::new(None),
            request: encode_request(&conf.service),
            consecutive_success: conf.consecutive_success,
            consecutive_failure: conf.consecutive_failure,
            health_changed_callback,
        }
    }

    fn build_request(
        &self,
        target: &Backend,
    ) -> pingora::Result<RequestHeader> {
        let mut req = RequestHeader::build(
            "POST",
            HEALTH_CHECK_PATH.as_bytes(),
            Some(3),
        )?;
        // pingora's HTTP/2 client turns this into `:authority`, which it
        // insists on; the backend's own address serves when the URL named
        // no host.
        if self.host.is_empty() {
            req.insert_header("Host", target.addr.to_string())?;
        } else {
            req.insert_header("Host", &self.host)?;
        }
        req.insert_header("Content-Type", "application/grpc")?;
        req.insert_header("TE", "trailers")?;
        Ok(req)
    }

    /// One call on an open session.
    async fn probe(
        &self,
        session: &mut HttpSession,
        target: &Backend,
    ) -> pingora::Result<()> {
        let req = self.build_request(target)?;
        session.set_write_timeout(self.peer_template.options.write_timeout);
        session.write_request_header(Box::new(req)).await?;
        session
            .write_request_body(self.request.clone(), true)
            .await?;
        session.set_read_timeout(self.peer_template.options.read_timeout);
        session.read_response_header().await?;

        let resp = session.response_header().ok_or_else(|| {
            new_internal_error(500, "grpc health check has no response")
        })?;
        if resp.status != StatusCode::OK {
            return Err(new_internal_error(
                resp.status.as_u16(),
                format!(
                    "grpc health check got http status {}",
                    resp.status.as_u16()
                ),
            ));
        }
        // A call the server refused comes back "trailers-only": the gRPC
        // status sits in the headers and there is no body.
        let mut status = grpc_status(&resp.headers);

        let mut body = BytesMut::new();
        while let Some(chunk) = session.read_response_body().await? {
            body.extend_from_slice(&chunk);
            if body.len() > MAX_RESPONSE_SIZE {
                return Err(new_internal_error(
                    500,
                    "grpc health check response is too large",
                ));
            }
        }
        if let HttpSession::H2(h2) = session
            && let Some(trailers) = h2.read_trailers().await?
            && let Some(trailer_status) = grpc_status(&trailers)
        {
            status = Some(trailer_status);
        }

        let Some((code, message)) = status else {
            return Err(new_internal_error(
                500,
                "grpc health check response has no grpc-status",
            ));
        };
        if code != "0" {
            return Err(new_internal_error(
                500,
                format!("grpc status {code}: {message}"),
            ));
        }
        let serving = decode_response_status(&body).ok_or_else(|| {
            new_internal_error(500, "invalid grpc health check response")
        })?;
        if serving != SERVING {
            return Err(new_internal_error(
                500,
                format!(
                    "grpc service status is {}",
                    serving_status_name(serving)
                ),
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl HealthCheck for GrpcHealthCheck {
    async fn check(&self, target: &Backend) -> pingora::Result<()> {
        let mut peer = self.peer_template.clone();
        peer._address = target.addr.clone();
        let (mut session, _) = self.connector.get_http_session(&peer).await?;
        let result = self.probe(&mut session, target).await;
        // HTTP/2 multiplexes, so pingora pools the connection by backend
        // and the next check reuses it; releasing the stream is what lets
        // the connection idle in that pool in between.
        if result.is_ok() {
            self.connector
                .release_http_session(session, &peer, peer.options.idle_timeout)
                .await;
        }
        result
    }

    async fn health_status_change(&self, target: &Backend, healthy: bool) {
        if let Some(callback) = &self.health_changed_callback {
            callback.observe(target, healthy).await;
        }
    }

    fn backend_summary(&self, target: &Backend) -> String {
        format!("{}: {}", self.name, target.addr)
    }

    /// How many *consecutive* checks flip the health of a backend: with
    /// `success` the number needed to go from unhealthy to healthy.
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
    use crate::{HealthCheckSchema, new_health_check};
    use pingora::upstreams::peer::Peer;
    use pretty_assertions::assert_eq;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tonic_health::ServingStatus;
    use tonic_health::server::{HealthReporter, health_reporter};

    #[test]
    fn test_grpc_health_check_conf() {
        let grpc_check: HealthCheckConf = "grpc://upstreamname/ping?connection_timeout=3s&success=2&failure=1&check_frequency=10s&from=nginx&reuse&tls&service=grpc".try_into().unwrap();
        assert_eq!(
            r###"HealthCheckConf { schema: Grpc, host: "upstreamname", path: "/ping?from=nginx", connection_timeout: 3s, read_timeout: 3s, check_frequency: 10s, reuse_connection: true, consecutive_success: 2, consecutive_failure: 1, service: "grpc", tls: true, parallel_check: false }"###,
            format!("{grpc_check:?}")
        );
        let grpc_check = GrpcHealthCheck::new("", &grpc_check, None);
        assert_eq!(2, grpc_check.health_threshold(true));
        assert_eq!(1, grpc_check.health_threshold(false));
        // `tls` makes it TLS with the URL host as SNI, and gRPC is h2 only.
        assert_eq!(true, grpc_check.peer_template.sni == "upstreamname");
        assert_eq!(true, grpc_check.peer_template.tls());
        assert_eq!(ALPN::H2, grpc_check.peer_template.options.alpn);
        assert_eq!(
            Some(std::time::Duration::from_secs(3)),
            grpc_check.peer_template.options.read_timeout
        );
    }

    #[test]
    fn test_varint() {
        for value in [0u64, 1, 127, 128, 300, u32::MAX as u64, u64::MAX] {
            let mut buf = vec![];
            put_varint(&mut buf, value);
            let mut pos = 0;
            assert_eq!(Some(value), get_varint(&buf, &mut pos));
            assert_eq!(buf.len(), pos);
        }
        // Truncated in the middle of a value.
        assert_eq!(None, get_varint(&[0x80], &mut 0));
    }

    #[test]
    fn test_encode_request() {
        assert_eq!(b"\x00\x00\x00\x00\x00"[..], encode_request("")[..]);
        assert_eq!(
            b"\x00\x00\x00\x00\x05\x0a\x03abc"[..],
            encode_request("abc")[..]
        );
    }

    #[test]
    fn test_decode_response_status() {
        assert_eq!(
            Some(1),
            decode_response_status(b"\x00\x00\x00\x00\x02\x08\x01")
        );
        // An empty message is the default status, UNKNOWN.
        assert_eq!(Some(0), decode_response_status(b"\x00\x00\x00\x00\x00"));
        // Fields this reader does not know are skipped: a length-delimited
        // field 2, a fixed64 field 3, then the status.
        assert_eq!(
            Some(2),
            decode_response_status(
                b"\x00\x00\x00\x00\x0f\x12\x02xy\x19\x00\x00\x00\x00\x00\x00\x00\x00\x08\x02"
            )
        );
        // Compressed, truncated, or not a frame at all.
        assert_eq!(
            None,
            decode_response_status(b"\x01\x00\x00\x00\x02\x08\x01")
        );
        assert_eq!(
            None,
            decode_response_status(b"\x00\x00\x00\x00\x09\x08\x01")
        );
        assert_eq!(None, decode_response_status(b"\x00\x00\x00\x00\x01\x08"));
        assert_eq!(None, decode_response_status(b""));
    }

    /// A real gRPC health server (tonic-health) on a free port.
    async fn spawn_health_server() -> (String, HealthReporter) {
        let (reporter, service) = health_reporter();
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming(
                    tonic::transport::server::TcpIncoming::from(listener),
                ),
        );
        (addr, reporter)
    }

    async fn check(addr: &str, query: &str) -> pingora::Result<()> {
        let (conf, hc) = new_health_check(
            "grpc",
            &format!(
                "grpc://{addr}?connection_timeout=1s&read_timeout=1s{query}"
            ),
            None,
        )
        .unwrap();
        assert_eq!(HealthCheckSchema::Grpc, conf.schema);
        hc.check(&Backend::new(addr).unwrap()).await
    }

    #[tokio::test]
    async fn test_grpc_health_check() {
        let (addr, reporter) = spawn_health_server().await;
        // The overall server, the empty service, is serving from the start;
        // a second check rides the same HTTP/2 connection.
        check(&addr, "").await.unwrap();
        check(&addr, "").await.unwrap();

        // A named service, in each of its states.
        reporter
            .set_service_status("live.Service", ServingStatus::Serving)
            .await;
        check(&addr, "&service=live.Service").await.unwrap();
        reporter
            .set_service_status("live.Service", ServingStatus::NotServing)
            .await;
        let err = check(&addr, "&service=live.Service").await.unwrap_err();
        assert_eq!(true, err.to_string().contains("NOT_SERVING"), "{err}");

        // A service the server does not know is a NOT_FOUND (5) call
        // status, which arrives trailers-only.
        let err = check(&addr, "&service=no.Such").await.unwrap_err();
        assert_eq!(true, err.to_string().contains("grpc status 5"), "{err}");
    }

    #[tokio::test]
    async fn test_grpc_health_check_rejects_non_grpc_backends() {
        // Nobody listening.
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        drop(listener);
        assert_eq!(true, check(&addr, "").await.is_err());

        // An HTTP/1.1 server, which cannot answer the h2 preface.
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf).await;
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
                        )
                        .await;
                });
            }
        });
        assert_eq!(true, check(&addr, "").await.is_err());
    }
}
