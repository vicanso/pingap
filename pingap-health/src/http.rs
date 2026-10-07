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
    DEFAULT_CHECK_FREQUENCY, DEFAULT_CONNECTION_TIMEOUT,
    DEFAULT_CONSECUTIVE_FAILURE, DEFAULT_CONSECUTIVE_SUCCESS,
    DEFAULT_READ_TIMEOUT, Error, HealthCheckSchema, LOG_TARGET,
    update_peer_options,
};
use humantime::parse_duration;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::lb::health_check::{HealthObserveCallback, HttpHealthCheck};
use std::time::Duration;
use tracing::error;
use url::Url;

type Result<T, E = Error> = std::result::Result<T, E>;

pub(crate) fn new_http_health_check(
    name: &str,
    conf: &HealthCheckConf,
    health_changed_callback: Option<HealthObserveCallback>,
) -> HttpHealthCheck {
    let mut check = HttpHealthCheck::new(
        &conf.host,
        conf.schema == HealthCheckSchema::Https,
    );
    check.peer_template.options =
        update_peer_options(conf, check.peer_template.options.clone());

    check.consecutive_success = conf.consecutive_success;
    check.consecutive_failure = conf.consecutive_failure;
    check.reuse_connection = conf.reuse_connection;
    check.health_changed_callback = health_changed_callback;
    // Where the check is answered on another port than the service.
    check.port_override = conf.check_port;
    // Which statuses say that the backend is fine. Without this it is
    // `200` and nothing else, which is pingora's own rule.
    if !conf.expect_status.is_empty() {
        let expected = conf.expect_status.clone();
        check.validator = Some(Box::new(move |resp: &ResponseHeader| {
            let status = resp.status.as_u16();
            if expected
                .iter()
                .any(|(from, to)| (*from..=*to).contains(&status))
            {
                return Ok(());
            }
            pingora::Error::e_explain(
                pingora::ErrorType::CustomCode("unexpected status", status),
                "during http healthcheck",
            )
        }));
    }
    let upstream_name = name.to_string();
    check.backend_summary_callback = Some(Box::new(move |backend| {
        format!("{upstream_name}: {}", backend.addr)
    }));
    // create http get request
    match RequestHeader::build("GET", conf.path.as_bytes(), None) {
        Ok(mut req) => {
            // 忽略append header fail
            if let Err(e) = req.append_header("Host", &conf.host) {
                error!(
                    target: LOG_TARGET,
                    name,
                    error = e.to_string(),
                    host = conf.host,
                    "http health check append host fail"
                );
            }
            check.req = req;
        },
        Err(e) => error!(
            target: LOG_TARGET,
            error = e.to_string(),
            "http health check fail"
        ),
    };

    check
}

#[derive(Debug, Default)]
pub struct HealthCheckConf {
    pub schema: HealthCheckSchema,
    pub host: String,
    pub path: String,
    pub connection_timeout: Duration,
    pub read_timeout: Duration,
    pub check_frequency: Duration,
    pub reuse_connection: bool,
    pub consecutive_success: usize,
    pub consecutive_failure: usize,
    pub service: String,
    pub tls: bool,
    pub parallel_check: bool,
    /// The statuses an HTTP check takes for healthy, as ranges with both
    /// ends included. Empty stands for `200` alone.
    pub expect_status: Vec<(u16, u16)>,
    /// The port an HTTP check goes to, where it is not the backend's own.
    pub check_port: Option<u16>,
}

/// `200-399,401` as ranges, both ends included.
fn parse_expect_status(
    value: &str,
) -> std::result::Result<Vec<(u16, u16)>, String> {
    let status = |text: &str| {
        text.trim()
            .parse::<u16>()
            .ok()
            .filter(|status| (100..600).contains(status))
            .ok_or_else(|| format!("{text:?} is not a status"))
    };
    let ranges = value
        .split(',')
        .map(|part| {
            let (from, to) = match part.split_once('-') {
                Some((from, to)) => (status(from)?, status(to)?),
                None => {
                    let single = status(part)?;
                    (single, single)
                },
            };
            if from > to {
                return Err(format!("{part:?} ends before it begins"));
            }
            Ok((from, to))
        })
        .collect::<std::result::Result<Vec<_>, String>>()?;
    Ok(ranges)
}

impl TryFrom<&str> for HealthCheckConf {
    type Error = Error;
    fn try_from(value: &str) -> Result<Self> {
        let value = Url::parse(value).map_err(|e| Error::UrlParse {
            source: e,
            url: value.to_string(),
        })?;

        let mut connection_timeout = DEFAULT_CONNECTION_TIMEOUT;
        let mut read_timeout = DEFAULT_READ_TIMEOUT;
        let mut check_frequency = DEFAULT_CHECK_FREQUENCY;
        let mut consecutive_success = DEFAULT_CONSECUTIVE_SUCCESS;
        let mut consecutive_failure = DEFAULT_CONSECUTIVE_FAILURE;
        let mut query_list = vec![];
        let mut reuse_connection = false;
        let mut tls = false;
        let mut parallel_check = false;
        let mut service = "".to_string();
        let mut expect_status = vec![];
        let mut check_port = None;
        // A value that does not parse is an error, not the default: with a
        // silent fallback `failure=three` or `check_frequency=5` (no unit)
        // ran the check with settings the operator never asked for.
        let invalid =
            |key: &str, value: &str, message: String| Error::InvalidParam {
                key: key.to_string(),
                value: value.to_string(),
                message,
            };
        let duration = |key: &str, value: &str| -> Result<Duration> {
            let d = parse_duration(value)
                .map_err(|e| invalid(key, value, e.to_string()))?;
            if d.is_zero() {
                return Err(invalid(
                    key,
                    value,
                    "must be greater than zero".to_string(),
                ));
            }
            Ok(d)
        };
        let count = |key: &str, value: &str| -> Result<usize> {
            match value.parse::<usize>() {
                Ok(0) => {
                    Err(invalid(key, value, "must be at least 1".to_string()))
                },
                Ok(v) => Ok(v),
                Err(e) => Err(invalid(key, value, e.to_string())),
            }
        };
        for (key, value) in value.query_pairs().into_iter() {
            match key.as_ref() {
                "connection_timeout" => {
                    connection_timeout = duration(&key, &value)?;
                },
                "read_timeout" => {
                    read_timeout = duration(&key, &value)?;
                },
                "check_frequency" => {
                    check_frequency = duration(&key, &value)?;
                },
                "success" => {
                    consecutive_success = count(&key, &value)?;
                },
                "failure" => {
                    consecutive_failure = count(&key, &value)?;
                },
                "reuse" => {
                    reuse_connection = true;
                },
                "tls" => {
                    tls = true;
                },
                "service" => {
                    service = value.to_string();
                },
                "parallel" => {
                    parallel_check = true;
                },
                "expect_status" => {
                    expect_status = parse_expect_status(&value)
                        .map_err(|message| invalid(&key, &value, message))?;
                },
                "check_port" => {
                    check_port = Some(
                        value
                            .parse::<u16>()
                            .ok()
                            .filter(|port| *port > 0)
                            .ok_or_else(|| {
                                invalid(
                                    &key,
                                    &value,
                                    "is not a port".to_string(),
                                )
                            })?,
                    );
                },
                _ => {
                    if value.is_empty() {
                        query_list.push(key.to_string());
                    } else {
                        query_list.push(format!("{key}={value}"));
                    }
                },
            };
        }
        let host = if let Some(host) = value.host() {
            host.to_string()
        } else {
            "".to_string()
        };
        let mut path = value.path().to_string();
        if !query_list.is_empty() {
            path += &format!("?{}", query_list.join("&"));
        }
        let schema =
            HealthCheckSchema::try_from(value.scheme()).map_err(|e| {
                Error::InvalidSchema {
                    schema: value.scheme().to_string(),
                    message: e.to_string(),
                }
            })?;
        // These two are read by the HTTP check alone. On another kind of
        // check they would be settings that look like they do something.
        if !matches!(schema, HealthCheckSchema::Http | HealthCheckSchema::Https)
        {
            for (key, given) in [
                ("expect_status", !expect_status.is_empty()),
                ("check_port", check_port.is_some()),
            ] {
                if given {
                    return Err(invalid(
                        key,
                        "",
                        "is for http and https checks only".to_string(),
                    ));
                }
            }
        }
        Ok(HealthCheckConf {
            schema,
            host,
            path,
            read_timeout,
            reuse_connection,
            connection_timeout,
            check_frequency,
            consecutive_success,
            consecutive_failure,
            tls,
            service,
            parallel_check,
            expect_status,
            check_port,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use pretty_assertions::assert_eq;
    use std::time::Duration;
    #[test]
    fn test_http_health_check_conf() {
        let http_check: HealthCheckConf = "https://upstreamname/ping?connection_timeout=3s&read_timeout=1s&success=2&failure=1&check_frequency=10s&from=nginx&reuse&tls&service=grpc".try_into().unwrap();
        assert_eq!(
            r###"HealthCheckConf { schema: Https, host: "upstreamname", path: "/ping?from=nginx", connection_timeout: 3s, read_timeout: 1s, check_frequency: 10s, reuse_connection: true, consecutive_success: 2, consecutive_failure: 1, service: "grpc", tls: true, parallel_check: false, expect_status: [], check_port: None }"###,
            format!("{http_check:?}")
        );
        let http_check = new_http_health_check("", &http_check, None);
        assert_eq!(1, http_check.consecutive_failure);
        assert_eq!(2, http_check.consecutive_success);
        assert_eq!(true, http_check.reuse_connection);
        assert_eq!(
            Duration::from_secs(3),
            http_check.peer_template.options.connection_timeout.unwrap()
        );
        assert_eq!(
            Duration::from_secs(1),
            http_check.peer_template.options.read_timeout.unwrap()
        );
        // Not zero: that evicted a released connection at once.
        assert_eq!(None, http_check.peer_template.options.idle_timeout);
    }

    #[test]
    fn test_invalid_params_are_rejected() {
        for (url, expect) in [
            (
                "http://h/p?connection_timeout=abc",
                "connection_timeout=abc",
            ),
            ("http://h/p?check_frequency=5", "check_frequency=5"),
            ("http://h/p?read_timeout=0s", "must be greater than zero"),
            ("http://h/p?success=two", "success=two"),
            ("http://h/p?failure=0", "must be at least 1"),
        ] {
            let err = HealthCheckConf::try_from(url).unwrap_err();
            assert_eq!(true, err.to_string().contains(expect), "{url}: {err}");
        }
    }

    /// `expect_status` says which statuses are a healthy answer, in place
    /// of `200` alone, and `check_port` where the check is answered.
    #[tokio::test]
    async fn test_expect_status_and_check_port() {
        use pingora::lb::Backend;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        assert_eq!(
            Ok(vec![(200, 399), (401, 401)]),
            parse_expect_status("200-399, 401")
        );
        for (value, expect) in [
            ("ok", "is not a status"),
            ("99", "is not a status"),
            ("200-600", "is not a status"),
            ("399-200", "ends before it begins"),
            ("200,", "is not a status"),
        ] {
            let err = parse_expect_status(value).unwrap_err();
            assert_eq!(true, err.contains(expect), "{value}: {err}");
        }
        for (url, expect) in [
            ("http://h/p?expect_status=abc", "expect_status=abc"),
            ("http://h/p?check_port=0", "is not a port"),
            ("http://h/p?check_port=70000", "is not a port"),
            // Read by the HTTP check alone.
            ("tcp://h?check_port=8081", "http and https checks only"),
            ("grpc://h?expect_status=200", "http and https checks only"),
        ] {
            let err = HealthCheckConf::try_from(url).unwrap_err();
            assert_eq!(true, err.to_string().contains(expect), "{url}: {err}");
        }
        // Not given, the check is as it was.
        let plain = HealthCheckConf::try_from("http://h/p").unwrap();
        assert_eq!(true, plain.expect_status.is_empty());
        let check = new_http_health_check("", &plain, None);
        assert_eq!(true, check.validator.is_none());
        assert_eq!(None, check.port_override);

        // A server that answers with the status its path names.
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    let head = String::from_utf8_lossy(&buf[..n]).to_string();
                    let status = head
                        .split_whitespace()
                        .nth(1)
                        .and_then(|path| {
                            path.trim_start_matches('/').parse().ok()
                        })
                        .unwrap_or(500u16);
                    let _ = stream
                        .write_all(
                            format!(
                                "HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            )
                            .as_bytes(),
                        )
                        .await;
                });
            }
        });
        let healthy = async |backend: &str, path_and_query: &str| {
            let (_, check) = crate::new_health_check(
                "http",
                &format!(
                    "http://health.test{path_and_query}connection_timeout=1s&read_timeout=1s"
                ),
                None,
            )
            .unwrap();
            check.check(&Backend::new(backend).unwrap()).await.is_ok()
        };
        let backend = format!("127.0.0.1:{port}");
        // `200` alone unless said otherwise.
        assert_eq!(true, healthy(&backend, "/200?").await);
        assert_eq!(false, healthy(&backend, "/204?").await);
        assert_eq!(false, healthy(&backend, "/302?").await);
        // What is listed, and nothing else.
        let expect = "expect_status=200-399,401&";
        for (status, expected) in [
            (200, true),
            (204, true),
            (302, true),
            (399, true),
            (401, true),
            (400, false),
            (404, false),
            (503, false),
        ] {
            assert_eq!(
                expected,
                healthy(&backend, &format!("/{status}?{expect}")).await,
                "{status}"
            );
        }
        // The check goes to the port it is told, on the backend's address:
        // the backend itself listens somewhere nothing answers.
        let elsewhere = "127.0.0.1:1";
        assert_eq!(false, healthy(elsewhere, "/200?").await);
        assert_eq!(
            true,
            healthy(elsewhere, &format!("/200?check_port={port}&")).await
        );
    }

    /// With `reuse` the second check rides the first one's connection;
    /// without it every check connects afresh.
    #[tokio::test]
    async fn test_reuse_keeps_the_connection() {
        use pingora::lb::Backend;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // A keep-alive HTTP server that counts the connections it accepts.
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let connections = Arc::new(AtomicUsize::new(0));
        let counter = connections.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let mut pending = Vec::new();
                    loop {
                        let n = stream.read(&mut buf).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        pending.extend_from_slice(&buf[..n]);
                        // One response per complete request, and only then.
                        while let Some(end) = pending
                            .windows(4)
                            .position(|window| window == b"\r\n\r\n")
                        {
                            pending.drain(..end + 4);
                            if stream
                                .write_all(
                                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
                                )
                                .await
                                .is_err()
                            {
                                return;
                            }
                        }
                    }
                });
            }
        });

        let run = |query: &'static str| {
            let addr = addr.clone();
            async move {
                let (_, hc) = crate::new_health_check(
                    "http",
                    &format!(
                        "http://{addr}/ping?connection_timeout=1s&read_timeout=1s{query}"
                    ),
                    None,
                )
                .unwrap();
                let backend = Backend::new(&addr).unwrap();
                hc.check(&backend).await.unwrap();
                hc.check(&backend).await.unwrap();
            }
        };
        run("&reuse").await;
        assert_eq!(
            1,
            connections.load(Ordering::SeqCst),
            "reuse must not reconnect"
        );
        run("").await;
        assert_eq!(3, connections.load(Ordering::SeqCst));
    }
}
