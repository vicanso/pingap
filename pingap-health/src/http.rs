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
use pingora::http::RequestHeader;
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
        Ok(HealthCheckConf {
            schema: HealthCheckSchema::try_from(value.scheme()).map_err(
                |e| Error::InvalidSchema {
                    schema: value.scheme().to_string(),
                    message: e.to_string(),
                },
            )?,
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
            r###"HealthCheckConf { schema: Https, host: "upstreamname", path: "/ping?from=nginx", connection_timeout: 3s, read_timeout: 1s, check_frequency: 10s, reuse_connection: true, consecutive_success: 2, consecutive_failure: 1, service: "grpc", tls: true, parallel_check: false }"###,
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
