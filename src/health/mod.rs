// Copyright 2024 Tree xie.
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

use crate::util;
use crate::webhook;
use async_trait::async_trait;
use http::Uri;
use humantime::parse_duration;
use pingora::http::RequestHeader;
use pingora::lb::health_check::{
    HealthCheck, HealthObserveCallback, HttpHealthCheck, TcpHealthCheck,
};
use pingora::lb::Backend;
use pingora::upstreams::peer::PeerOptions;
use snafu::{ResultExt, Snafu};
use std::time::Duration;
use strum::EnumString;
use tonic_health::{
    pb::{health_client::HealthClient, HealthCheckRequest},
    ServingStatus,
};
use tracing::{error, info};
use url::Url;
static LOG_CATEGORY: &str = "health";

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
    #[snafu(display("Tonic transport error {source}"))]
    Uri { source: http::uri::InvalidUri },
    #[snafu(display("Invalid health check schema: {schema}, {message}"))]
    InvalidSchema { schema: String, message: String },
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
    // set zero to disable reuse connection
    options.idle_timeout = Some(Duration::from_secs(0));
    options
}

fn new_tcp_health_check(name: &str, conf: &HealthCheckConf) -> TcpHealthCheck {
    let mut check = TcpHealthCheck::default();
    check.peer_template.options =
        update_peer_options(conf, check.peer_template.options.clone());
    check.consecutive_success = conf.consecutive_success;
    check.consecutive_failure = conf.consecutive_failure;
    check.health_changed_callback =
        Some(webhook::new_backend_observe_notification(name));

    check
}

fn new_http_health_check(
    name: &str,
    conf: &HealthCheckConf,
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
    check.health_changed_callback =
        Some(webhook::new_backend_observe_notification(name));
    // create http get request
    match RequestHeader::build("GET", conf.path.as_bytes(), None) {
        Ok(mut req) => {
            // 忽略append header fail
            if let Err(e) = req.append_header("Host", &conf.host) {
                error!(
                    category = LOG_CATEGORY,
                    error = e.to_string(),
                    host = conf.host,
                    "http health check append host fail"
                );
            }
            check.req = req;
        },
        Err(e) => error!(
            category = LOG_CATEGORY,
            error = e.to_string(),
            "http health check fail"
        ),
    }

    check
}

pub fn new_health_check(
    name: &str,
    health_check: &str,
) -> Result<(Box<dyn HealthCheck + Send + Sync + 'static>, Duration)> {
    let mut health_check_frequency = Duration::from_secs(10);
    let hc: Box<dyn HealthCheck + Send + Sync + 'static> =
        if health_check.is_empty() {
            let mut check = TcpHealthCheck::new();
            check.health_changed_callback =
                Some(webhook::new_backend_observe_notification(name));
            check.peer_template.options.connection_timeout =
                Some(Duration::from_secs(3));
            info!(
                category = LOG_CATEGORY,
                name,
                options = format!("{:?}", check.peer_template.options),
                "new health check"
            );
            check
        } else {
            let health_check_conf: HealthCheckConf = health_check.try_into()?;
            health_check_frequency = health_check_conf.check_frequency;
            info!(
                category = LOG_CATEGORY,
                name,
                schema = health_check_conf.schema.to_string(),
                health_check_conf = format!("{health_check_conf:?}"),
                "new http/grpc health check"
            );
            match health_check_conf.schema {
                HealthCheckSchema::Http | HealthCheckSchema::Https => {
                    Box::new(new_http_health_check(name, &health_check_conf))
                },
                HealthCheckSchema::Grpc => {
                    let check = GrpcHealthCheck::new(name, &health_check_conf)?;
                    Box::new(check)
                },
                _ => Box::new(new_tcp_health_check(name, &health_check_conf)),
            }
        };
    Ok((hc, health_check_frequency))
}

#[derive(PartialEq, Debug, Default, Clone, EnumString, strum::Display)]
#[strum(serialize_all = "snake_case")]
pub enum HealthCheckSchema {
    #[default]
    Tcp,
    Http,
    Https,
    Grpc,
}

#[derive(Debug)]
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
}

impl TryFrom<&str> for HealthCheckConf {
    type Error = Error;
    fn try_from(value: &str) -> Result<Self> {
        let value = Url::parse(value).context(UrlParseSnafu {
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
        let mut service = "".to_string();
        // HttpHealthCheck
        for (key, value) in value.query_pairs().into_iter() {
            match key.as_ref() {
                "connection_timeout" => {
                    if let Ok(d) = parse_duration(value.as_ref()) {
                        connection_timeout = d;
                    }
                },
                "read_timeout" => {
                    if let Ok(d) = parse_duration(value.as_ref()) {
                        read_timeout = d;
                    }
                },
                "check_frequency" => {
                    if let Ok(d) = parse_duration(value.as_ref()) {
                        check_frequency = d;
                    }
                },
                "success" => {
                    if let Ok(v) = value.parse::<usize>() {
                        consecutive_success = v;
                    }
                },
                "failure" => {
                    if let Ok(v) = value.parse::<usize>() {
                        consecutive_failure = v;
                    }
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
        })
    }
}

pub struct GrpcHealthCheck {
    scheme: String,
    service: String,
    origin: Uri,
    /// Number of successful checks to flip from unhealthy to healthy.
    pub consecutive_success: usize,
    /// Number of failed checks to flip from healthy to unhealthy.
    pub consecutive_failure: usize,
    /// A callback that is invoked when the `healthy` status changes for a [Backend].
    pub health_changed_callback: Option<HealthObserveCallback>,
    pub connection_timeout: Duration,
}

impl GrpcHealthCheck {
    pub fn new(name: &str, conf: &HealthCheckConf) -> Result<Self> {
        let scheme = if conf.tls {
            "https".to_string()
        } else {
            "http".to_string()
        };
        let uri = format!("{scheme}://{}", conf.host);
        let origin: Uri = uri.parse().context(UriSnafu)?;

        Ok(Self {
            scheme,
            origin,
            service: conf.service.clone(),
            consecutive_success: conf.consecutive_success,
            consecutive_failure: conf.consecutive_failure,
            connection_timeout: conf.connection_timeout,
            health_changed_callback: Some(
                webhook::new_backend_observe_notification(name),
            ),
        })
    }
}

#[async_trait]
impl HealthCheck for GrpcHealthCheck {
    async fn check(&self, target: &Backend) -> pingora::Result<()> {
        let uri = format!("{}://{}", self.scheme, target.addr);

        let conn = tonic::transport::Endpoint::from_shared(uri)
            .map_err(|e| util::new_internal_error(500, e.to_string()))?
            .origin(self.origin.clone())
            .connect_timeout(self.connection_timeout)
            .connect()
            .await
            .map_err(|e| util::new_internal_error(500, e.to_string()))?;
        let resp = HealthClient::new(conn)
            .check(HealthCheckRequest {
                service: self.service.clone(),
            })
            .await
            .map_err(|e| util::new_internal_error(500, e.to_string()))?;
        if resp.get_ref().status() != ServingStatus::Serving.into() {
            return Err(util::new_internal_error(
                500,
                "grpc server is not serving".to_string(),
            ));
        }

        Ok(())
    }

    /// Check the given backend.
    // ///
    // /// `Ok(())`` if the check passes, otherwise the check fails.
    // async fn check(&self, target: &Backend) -> Result<()>;

    // /// Called when the health changes for a [Backend].
    async fn health_status_change(&self, target: &Backend, healthy: bool) {
        if let Some(callback) = &self.health_changed_callback {
            callback.observe(target, healthy).await;
        }
    }

    // /// This function defines how many *consecutive* checks should flip the health of a backend.
    // ///
    // /// For example: with `success``: `true`: this function should return the
    // /// number of check need to flip from unhealthy to healthy.
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
    use super::{
        new_health_check, new_http_health_check, new_tcp_health_check,
        HealthCheckConf,
    };
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
            r###"HealthCheckConf { schema: Tcp, host: "upstreamname", path: "", connection_timeout: 3s, read_timeout: 3s, check_frequency: 10s, reuse_connection: false, consecutive_success: 2, consecutive_failure: 1, service: "", tls: false }"###,
            format!("{tcp_check:?}")
        );
        let tcp_check = new_tcp_health_check("", &tcp_check);
        assert_eq!(1, tcp_check.consecutive_failure);
        assert_eq!(2, tcp_check.consecutive_success);
        assert_eq!(
            Duration::from_secs(3),
            tcp_check.peer_template.connection_timeout().unwrap()
        );

        let http_check: HealthCheckConf = "https://upstreamname/ping?connection_timeout=3s&read_timeout=1s&success=2&failure=1&check_frequency=10s&from=nginx&reuse".try_into().unwrap();
        assert_eq!(
            r###"HealthCheckConf { schema: Https, host: "upstreamname", path: "/ping?from=nginx", connection_timeout: 3s, read_timeout: 1s, check_frequency: 10s, reuse_connection: true, consecutive_success: 2, consecutive_failure: 1, service: "", tls: false }"###,
            format!("{http_check:?}")
        );
        let http_check = new_http_health_check("", &http_check);
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
    }
    #[test]
    fn test_new_health_check() {
        let (_, frequency) = new_health_check("upstreamname", "https://upstreamname/ping?connection_timeout=3s&read_timeout=1s&success=2&failure=1&check_frequency=10s&from=nginx&reuse").unwrap();
        assert_eq!(Duration::from_secs(10), frequency);
    }
}
