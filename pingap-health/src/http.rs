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
    update_peer_options, Error, HealthCheckSchema, DEFAULT_CHECK_FREQUENCY,
    DEFAULT_CONNECTION_TIMEOUT, DEFAULT_CONSECUTIVE_FAILURE,
    DEFAULT_CONSECUTIVE_SUCCESS, DEFAULT_READ_TIMEOUT, LOG_CATEGORY,
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
    // create http get request
    match RequestHeader::build("GET", conf.path.as_bytes(), None) {
        Ok(mut req) => {
            // 忽略append header fail
            if let Err(e) = req.append_header("Host", &conf.host) {
                error!(
                    category = LOG_CATEGORY,
                    name,
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

#[cfg(test)]
mod tests {
    use super::*;

    use pretty_assertions::assert_eq;
    use std::time::Duration;
    #[test]
    fn test_http_health_check_conf() {
        let http_check: HealthCheckConf = "https://upstreamname/ping?connection_timeout=3s&read_timeout=1s&success=2&failure=1&check_frequency=10s&from=nginx&reuse&tls&service=grpc".try_into().unwrap();
        assert_eq!(
            r###"HealthCheckConf { schema: Https, host: "upstreamname", path: "/ping?from=nginx", connection_timeout: 3s, read_timeout: 1s, check_frequency: 10s, reuse_connection: true, consecutive_success: 2, consecutive_failure: 1, service: "grpc", tls: true }"###,
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
    }
}
