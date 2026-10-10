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

use humantime::format_duration;
use pingora::connectors::l4::Connect as L4Connect;
use pingora::lb::health_check::{
    HealthCheck, HealthObserveCallback, TcpHealthCheck,
};
use pingora::upstreams::peer::PeerOptions;
use pingora::utils::tls::CertKey;
use snafu::Snafu;
use std::sync::Arc;
use std::time::Duration;
use strum::EnumString;
use tracing::info;
static LOG_TARGET: &str = "pingap::health";

mod grpc;
mod http;
mod websocket;
pub use grpc::GrpcHealthCheck;
pub use http::HealthCheckConf;
pub use websocket::WebSocketHealthCheck;

/// Creates a new internal error
fn new_internal_error(status: u16, message: impl ToString) -> pingora::BError {
    pingora::Error::because(
        pingora::ErrorType::HTTPStatus(status),
        message.to_string(),
        pingora::Error::new(pingora::ErrorType::InternalError),
    )
}

// Add constants for default values
const DEFAULT_CONNECTION_TIMEOUT: Duration = Duration::from_secs(3);
const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(3);
const DEFAULT_CHECK_FREQUENCY: Duration = Duration::from_secs(10);
const DEFAULT_CONSECUTIVE_SUCCESS: usize = 1;
const DEFAULT_CONSECUTIVE_FAILURE: usize = 2;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Url parse error {source}, {url}"))]
    UrlParse {
        source: url::ParseError,
        url: String,
    },
    #[snafu(display("Invalid health check schema: {schema}, {message}"))]
    InvalidSchema { schema: String, message: String },
    #[snafu(display(
        "Invalid health check parameter {key}={value}: {message}"
    ))]
    InvalidParam {
        key: String,
        value: String,
        message: String,
    },
}
type Result<T, E = Error> = std::result::Result<T, E>;

fn update_peer_options(
    conf: &HealthCheckConf,
    opt: PeerOptions,
) -> PeerOptions {
    let mut options = opt;
    let timeout = Some(conf.connection_timeout);
    options.verify_hostname = false;
    options.verify_cert = false;
    options.connection_timeout = timeout;
    options.total_connection_timeout = timeout;
    options.read_timeout = Some(conf.read_timeout);
    options.write_timeout = Some(conf.read_timeout);
    // A connection is only pooled when a check releases it (`reuse`), and
    // then it has to stay there until the next check comes round. A zero
    // idle timeout used to be set here "to disable reuse": it evicted a
    // released connection at once, so `reuse` reconnected every time.
    options.idle_timeout = None;
    options
}

fn new_tcp_health_check(
    _name: &str,
    conf: &HealthCheckConf,
    health_changed_callback: Option<HealthObserveCallback>,
) -> TcpHealthCheck {
    let mut check = TcpHealthCheck::default();
    check.peer_template.options =
        update_peer_options(conf, check.peer_template.options.clone());
    check.consecutive_success = conf.consecutive_success;
    check.consecutive_failure = conf.consecutive_failure;
    check.health_changed_callback = health_changed_callback;

    check
}

pub fn new_health_check(
    name: &str,
    health_check: &str,
    health_changed_callback: Option<HealthObserveCallback>,
) -> Result<(
    HealthCheckConf,
    Box<dyn HealthCheck + Send + Sync + 'static>,
)> {
    new_health_check_with_client_cert(
        name,
        health_check,
        health_changed_callback,
        None,
    )
}

/// [`new_health_check`] for an upstream that presents a certificate to
/// its backends. An `https://` check presents it too: a backend that asks
/// its clients for one ends the handshake of a check that has none, and
/// was then never healthy.
pub fn new_health_check_with_client_cert(
    name: &str,
    health_check: &str,
    health_changed_callback: Option<HealthObserveCallback>,
    client_cert_key: Option<Arc<CertKey>>,
) -> Result<(
    HealthCheckConf,
    Box<dyn HealthCheck + Send + Sync + 'static>,
)> {
    new_health_check_with_peer(
        name,
        health_check,
        health_changed_callback,
        HealthCheckPeer {
            client_cert_key,
            ..Default::default()
        },
    )
}

/// How a connection of a check is opened, where it is not pingora's way.
pub type HealthCheckConnector = Arc<dyn L4Connect + Send + Sync>;

/// What a check takes over from the upstream whose backends it checks.
#[derive(Default, Clone)]
pub struct HealthCheckPeer {
    /// The certificate the upstream presents to its backends. An
    /// `https://` check presents it too.
    pub client_cert_key: Option<Arc<CertKey>>,
    /// How the upstream opens a connection, where it has a way of its
    /// own: with a PROXY protocol header in front. A backend that waits
    /// for that header takes a check without one for a broken client, so
    /// a check opens its connections the same way.
    ///
    /// Not a check with `check_port`: what answers on another port than
    /// the service is not the service, and is spoken to plainly.
    pub connector: Option<HealthCheckConnector>,
}

/// [`new_health_check`] for an upstream that has something to say about
/// how its backends are spoken to ([`HealthCheckPeer`]).
pub fn new_health_check_with_peer(
    name: &str,
    health_check: &str,
    health_changed_callback: Option<HealthObserveCallback>,
    peer: HealthCheckPeer,
) -> Result<(
    HealthCheckConf,
    Box<dyn HealthCheck + Send + Sync + 'static>,
)> {
    let HealthCheckPeer {
        client_cert_key,
        connector,
    } = peer;
    let health_check_conf: HealthCheckConf = if health_check.is_empty() {
        // The same check `tcp://` with no parameters gives: the documented
        // defaults. This used to be pingora's bare TCP check, which
        // flipped a backend on a single failure and came back with a
        // configuration of zero timeouts and thresholds.
        HealthCheckConf {
            schema: HealthCheckSchema::Tcp,
            connection_timeout: DEFAULT_CONNECTION_TIMEOUT,
            read_timeout: DEFAULT_READ_TIMEOUT,
            check_frequency: DEFAULT_CHECK_FREQUENCY,
            consecutive_success: DEFAULT_CONSECUTIVE_SUCCESS,
            consecutive_failure: DEFAULT_CONSECUTIVE_FAILURE,
            ..Default::default()
        }
    } else {
        health_check.try_into()?
    };
    info!(
        target: LOG_TARGET,
        name,
        schema = health_check_conf.schema.to_string(),
        host = health_check_conf.host,
        path = health_check_conf.path,
        connection_timeout =
            format_duration(health_check_conf.connection_timeout).to_string(),
        read_timeout =
            format_duration(health_check_conf.read_timeout).to_string(),
        check_frequency =
            format_duration(health_check_conf.check_frequency).to_string(),
        reuse_connection = health_check_conf.reuse_connection,
        consecutive_success = health_check_conf.consecutive_success,
        consecutive_failure = health_check_conf.consecutive_failure,
        "new health check"
    );
    let connector =
        connector.filter(|_| health_check_conf.check_port.is_none());
    let hc: Box<dyn HealthCheck + Send + Sync + 'static> =
        match health_check_conf.schema {
            HealthCheckSchema::Http | HealthCheckSchema::Https => {
                let mut check = http::new_http_health_check(
                    name,
                    &health_check_conf,
                    health_changed_callback,
                );
                if health_check_conf.schema == HealthCheckSchema::Https {
                    check.peer_template.client_cert_key = client_cert_key;
                }
                check.peer_template.options.custom_l4 = connector;
                // The body is something pingora's check does not see.
                match &health_check_conf.expect_body {
                    Some(expect_body) => Box::new(
                        http::HttpBodyHealthCheck::new(check, expect_body),
                    ),
                    None => Box::new(check),
                }
            },
            HealthCheckSchema::Grpc => Box::new(
                GrpcHealthCheck::new(
                    name,
                    &health_check_conf,
                    health_changed_callback,
                )
                .with_connector(connector),
            ),
            HealthCheckSchema::Ws | HealthCheckSchema::Wss => Box::new(
                WebSocketHealthCheck::new(
                    name,
                    &health_check_conf,
                    health_changed_callback,
                )
                .with_connector(connector),
            ),
            HealthCheckSchema::Tcp => {
                let mut check = new_tcp_health_check(
                    name,
                    &health_check_conf,
                    health_changed_callback,
                );
                check.peer_template.options.custom_l4 = connector;
                Box::new(check)
            },
        };
    Ok((health_check_conf, hc))
}

#[derive(PartialEq, Debug, Default, Clone, EnumString, strum::Display)]
#[strum(serialize_all = "snake_case")]
pub enum HealthCheckSchema {
    #[default]
    Tcp,
    Http,
    Https,
    Grpc,
    /// WebSocket upgrade handshake over plain TCP
    Ws,
    /// WebSocket upgrade handshake over TLS
    Wss,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingora::upstreams::peer::Peer;
    use pretty_assertions::assert_eq;
    use std::time::Duration;
    #[test]
    fn test_health_check_conf() {
        let tcp_check: HealthCheckConf =
            "tcp://upstreamname?connection_timeout=3s&success=2&failure=1&check_frequency=10s"
                .try_into()
                .unwrap();
        assert_eq!(
            r###"HealthCheckConf { schema: Tcp, host: "upstreamname", path: "", connection_timeout: 3s, read_timeout: 3s, check_frequency: 10s, reuse_connection: false, consecutive_success: 2, consecutive_failure: 1, service: "", tls: false, parallel_check: false, expect_status: [], check_port: None, expect_body: None }"###,
            format!("{tcp_check:?}")
        );
        let tcp_check = new_tcp_health_check("", &tcp_check, None);
        assert_eq!(1, tcp_check.consecutive_failure);
        assert_eq!(2, tcp_check.consecutive_success);
        assert_eq!(
            Duration::from_secs(3),
            tcp_check.peer_template.connection_timeout().unwrap()
        );
    }
    #[test]
    fn test_new_health_check() {
        let (conf, _) = new_health_check("upstreamname", "https://upstreamname/ping?connection_timeout=3s&read_timeout=1s&success=2&failure=1&check_frequency=10s&from=nginx&reuse", None).unwrap();
        assert_eq!(Duration::from_secs(10), conf.check_frequency);

        let err = new_health_check("upstreamname", "ftp://upstreamname", None)
            .err()
            .expect("ftp is not a health check schema");
        assert_eq!(
            true,
            err.to_string()
                .starts_with("Invalid health check schema: ftp"),
            "{err}"
        );
    }

    /// No `health_check` at all is `tcp://` with the documented defaults,
    /// not pingora's bare check that flipped a backend on one failure.
    #[test]
    fn test_default_health_check() {
        let (conf, _) = new_health_check("upstreamname", "", None).unwrap();
        assert_eq!(HealthCheckSchema::Tcp, conf.schema);
        assert_eq!(DEFAULT_CONNECTION_TIMEOUT, conf.connection_timeout);
        assert_eq!(DEFAULT_CHECK_FREQUENCY, conf.check_frequency);
        assert_eq!(DEFAULT_CONSECUTIVE_SUCCESS, conf.consecutive_success);
        assert_eq!(DEFAULT_CONSECUTIVE_FAILURE, conf.consecutive_failure);
        let tcp_check = new_tcp_health_check("", &conf, None);
        assert_eq!(DEFAULT_CONSECUTIVE_FAILURE, tcp_check.consecutive_failure);
    }

    /// Writes `HELLO\n` ahead of everything, as an upstream's own way of
    /// opening a connection writes its header.
    #[derive(Debug)]
    struct Greeting;

    #[async_trait::async_trait]
    impl L4Connect for Greeting {
        async fn connect(
            &self,
            addr: &pingora::protocols::l4::socket::SocketAddr,
        ) -> pingora::Result<pingora::protocols::l4::stream::Stream> {
            use pingora::OrErr;
            use tokio::io::AsyncWriteExt;
            let addr = addr.as_inet().expect("an address of a TCP backend");
            let mut stream = tokio::net::TcpStream::connect(addr)
                .await
                .or_err(pingora::ErrorType::ConnectError, "connect")?;
            stream
                .write_all(b"HELLO\n")
                .await
                .or_err(pingora::ErrorType::ConnectError, "greeting")?;
            Ok(stream.into())
        }
    }

    /// A check opens its connections the way the upstream does: the
    /// backend of an upstream that sends a PROXY protocol header waits
    /// for one on every connection, and a check that came without was a
    /// broken client to it - the backend was never healthy.
    #[tokio::test]
    async fn test_health_check_connects_as_the_upstream_does() {
        use pingora::lb::Backend;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // A backend that says how each connection started, and answers
        // `200` to whatever follows a greeting.
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend = listener.local_addr().unwrap().to_string();
        let (tx, mut started) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let tx = tx.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 6];
                    let greeted = stream.read_exact(&mut buf).await.is_ok()
                        && &buf == b"HELLO\n";
                    let _ = tx.send(greeted);
                    if greeted {
                        let mut rest = [0u8; 2048];
                        let _ = stream.read(&mut rest).await;
                    }
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await;
                });
            }
        });

        let peer = HealthCheckPeer {
            connector: Some(Arc::new(Greeting)),
            ..Default::default()
        };
        let params = "connection_timeout=1s&read_timeout=1s";
        for (check, healthy) in [
            (format!("tcp://health.test?{params}"), Some(true)),
            (String::new(), Some(true)),
            (format!("http://health.test/ping?{params}"), Some(true)),
            (
                format!("http://health.test/ping?expect_body=ok&{params}"),
                Some(true),
            ),
            // What answers is no gRPC or WebSocket server: the check is
            // not asked about, only how its connection started.
            (format!("grpc://health.test?{params}"), None),
            (format!("ws://health.test/ws?{params}"), None),
        ] {
            let (_, hc) =
                new_health_check_with_peer("test", &check, None, peer.clone())
                    .unwrap();
            let result = hc.check(&Backend::new(&backend).unwrap()).await;
            assert_eq!(Some(true), started.recv().await, "{check}");
            if let Some(healthy) = healthy {
                assert_eq!(healthy, result.is_ok(), "{check}: {result:?}");
            }
        }

        // Without a way of the upstream's own: pingora's, as before.
        let (_, hc) = new_health_check(
            "test",
            &format!("http://health.test/ping?{params}"),
            None,
        )
        .unwrap();
        let _ = hc.check(&Backend::new(&backend).unwrap()).await;
        assert_eq!(Some(false), started.recv().await);

        // A check that is answered on another port than the service asks
        // something that is not the service, and asks it plainly.
        let port = backend.rsplit(':').next().unwrap();
        let (_, hc) = new_health_check_with_peer(
            "test",
            &format!("http://health.test/ping?check_port={port}&{params}"),
            None,
            peer,
        )
        .unwrap();
        let _ = hc.check(&Backend::new("127.0.0.1:1").unwrap()).await;
        assert_eq!(Some(false), started.recv().await);
    }

    #[test]
    fn test_new_internal_error() {
        let err = new_internal_error(500, "test");
        assert_eq!(
            err.to_string().trim(),
            "HTTPStatus context: test cause:  InternalError"
        );
    }
}
