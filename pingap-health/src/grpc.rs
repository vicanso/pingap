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

use super::{new_internal_error, Error, HealthCheckConf};
use async_trait::async_trait;
use http::uri::InvalidUri;
use http::Uri;
use pingora::lb::health_check::{HealthCheck, HealthObserveCallback};
use pingora::lb::Backend;
use std::time::Duration;
use tonic_health::{
    pb::{health_client::HealthClient, HealthCheckRequest},
    ServingStatus,
};

type Result<T, E = Error> = std::result::Result<T, E>;

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
    pub fn new(
        _name: &str,
        conf: &HealthCheckConf,
        health_changed_callback: Option<HealthObserveCallback>,
    ) -> Result<Self> {
        let scheme = if conf.tls {
            "https".to_string()
        } else {
            "http".to_string()
        };
        let uri = format!("{scheme}://{}", conf.host);
        let origin: Uri =
            uri.parse().map_err(|e: InvalidUri| Error::InvalidSchema {
                message: e.to_string(),
                schema: uri,
            })?;

        Ok(Self {
            scheme,
            origin,
            service: conf.service.clone(),
            consecutive_success: conf.consecutive_success,
            consecutive_failure: conf.consecutive_failure,
            connection_timeout: conf.connection_timeout,
            health_changed_callback,
        })
    }
}

#[async_trait]
impl HealthCheck for GrpcHealthCheck {
    async fn check(&self, target: &Backend) -> pingora::Result<()> {
        let uri = format!("{}://{}", self.scheme, target.addr);
        // TODO set tls config for https
        let conn = tonic::transport::Endpoint::from_shared(uri)
            .map_err(|e| new_internal_error(500, e.to_string()))?
            .origin(self.origin.clone())
            .connect_timeout(self.connection_timeout)
            .connect()
            .await
            .map_err(|e| new_internal_error(500, e.to_string()))?;
        let resp = HealthClient::new(conn)
            .check(HealthCheckRequest {
                service: self.service.clone(),
            })
            .await
            .map_err(|e| new_internal_error(500, e.to_string()))?;
        if resp.get_ref().status() != ServingStatus::Serving.into() {
            return Err(new_internal_error(500, "grpc server is not serving"));
        }

        Ok(())
    }

    /// Check the given backend.
    //
    // `Ok(())`` if the check passes, otherwise the check fails.
    // async fn check(&self, target: &Backend) -> Result<()>;
    // Called when the health changes for a [Backend].
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
    use super::*;
    use pretty_assertions::assert_eq;
    #[test]
    fn test_grpc_health_check_conf() {
        let grpc_check: HealthCheckConf = "grpc://upstreamname/ping?connection_timeout=3s&success=2&failure=1&check_frequency=10s&from=nginx&reuse&tls&service=grpc".try_into().unwrap();
        assert_eq!(
            r###"HealthCheckConf { schema: Grpc, host: "upstreamname", path: "/ping?from=nginx", connection_timeout: 3s, read_timeout: 3s, check_frequency: 10s, reuse_connection: true, consecutive_success: 2, consecutive_failure: 1, service: "grpc", tls: true, parallel_check: false }"###,
            format!("{grpc_check:?}")
        );
        let grpc_check = GrpcHealthCheck::new("", &grpc_check, None).unwrap();
        assert_eq!(2, grpc_check.health_threshold(true));
        assert_eq!(1, grpc_check.health_threshold(false));
    }
}
