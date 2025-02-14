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
use pingora::lb::health_check::{
    HealthCheck, HealthObserveCallback, TcpHealthCheck,
};
use pingora::upstreams::peer::PeerOptions;
use snafu::Snafu;
use std::time::Duration;
use strum::EnumString;
use tracing::info;
static LOG_CATEGORY: &str = "health";

mod grpc;
mod http;
pub use grpc::GrpcHealthCheck;
pub use http::HealthCheckConf;

/// Creates a new internal error
fn new_internal_error(status: u16, message: String) -> pingora::BError {
    pingora::Error::because(
        pingora::ErrorType::HTTPStatus(status),
        message,
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
    let mut health_check_conf = HealthCheckConf {
        schema: HealthCheckSchema::Tcp,
        check_frequency: DEFAULT_CHECK_FREQUENCY,
        ..Default::default()
    };
    let hc: Box<dyn HealthCheck + Send + Sync + 'static> = if health_check
        .is_empty()
    {
        let mut check = TcpHealthCheck::new();
        check.health_changed_callback = health_changed_callback;
        check.peer_template.options.connection_timeout =
            Some(Duration::from_secs(3));
        info!(
            category = LOG_CATEGORY,
            name,
            options = %check.peer_template.options,
            "new health check"
        );
        check
    } else {
        health_check_conf = health_check.try_into()?;
        info!(
            category = LOG_CATEGORY,
            name,
            schema = health_check_conf.schema.to_string(),
            path = health_check_conf.path,
            connection_timeout =
                format_duration(health_check_conf.connection_timeout)
                    .to_string(),
            read_timeout =
                format_duration(health_check_conf.read_timeout).to_string(),
            check_frequency =
                format_duration(health_check_conf.check_frequency).to_string(),
            reuse_connection = health_check_conf.reuse_connection,
            consecutive_success = health_check_conf.consecutive_success,
            consecutive_failure = health_check_conf.consecutive_failure,
            "new http/grpc health check"
        );
        match health_check_conf.schema {
            HealthCheckSchema::Http | HealthCheckSchema::Https => {
                Box::new(http::new_http_health_check(
                    name,
                    &health_check_conf,
                    health_changed_callback,
                ))
            },
            HealthCheckSchema::Grpc => {
                let check = GrpcHealthCheck::new(
                    name,
                    &health_check_conf,
                    health_changed_callback,
                )?;
                Box::new(check)
            },
            _ => Box::new(new_tcp_health_check(
                name,
                &health_check_conf,
                health_changed_callback,
            )),
        }
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
            r###"HealthCheckConf { schema: Tcp, host: "upstreamname", path: "", connection_timeout: 3s, read_timeout: 3s, check_frequency: 10s, reuse_connection: false, consecutive_success: 2, consecutive_failure: 1, service: "", tls: false, parallel_check: false }"###,
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
    }

    #[test]
    fn test_new_internal_error() {
        let err = new_internal_error(500, "test".to_string());
        assert_eq!(
            err.to_string().trim(),
            "HTTPStatus context: test cause:  InternalError"
        );
    }
}
