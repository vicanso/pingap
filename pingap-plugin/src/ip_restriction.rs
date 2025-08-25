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
    get_hash_key, get_plugin_factory, get_str_conf, get_str_slice_conf, Error,
};
use async_trait::async_trait;
use bytes::Bytes;
use ctor::ctor;
use http::StatusCode;
use pingap_config::PluginConf;
use pingap_core::{Ctx, HttpResponse, Plugin, PluginStep, RequestPluginResult};
use pingora::proxy::Session;
use std::borrow::Cow;
use std::sync::Arc;
use tracing::debug;

type Result<T, E = Error> = std::result::Result<T, E>;

/// IpRestriction plugin provides IP-based access control for HTTP requests.
/// It can be configured to either allow or deny requests based on client IP addresses.
pub struct IpRestriction {
    plugin_step: PluginStep, // Defines when plugin runs in request lifecycle (must be Request)
    ip_rules: pingap_util::IpRules, // Contains parsed IP addresses and CIDR ranges for matching
    restriction_category: String, // "allow": whitelist mode, "deny": blacklist mode
    forbidden_resp: HttpResponse, // Customizable 403 response returned when access is denied
    hash_value: String, // Unique identifier used for plugin caching/tracking
}

impl TryFrom<&PluginConf> for IpRestriction {
    type Error = Error;
    /// Attempts to create a new IpRestriction instance from a plugin configuration.
    ///
    /// # Arguments
    /// * `value` - Plugin configuration containing IP rules, restriction type, and optional message
    ///
    /// # Returns
    /// * `Ok(IpRestriction)` - Successfully created instance
    /// * `Err(Error)` - If configuration is invalid (e.g., wrong plugin step)
    ///
    /// # Configuration Example
    /// ```toml
    /// type = "deny"
    /// ip_list = ["192.168.1.1", "10.0.0.0/24"]
    /// message = "Access denied"
    /// ```
    fn try_from(value: &PluginConf) -> Result<Self> {
        // Generate unique hash for this plugin instance
        let hash_value = get_hash_key(value);

        // Parse IP rules from configuration
        // Supports both individual IPs ("192.168.1.1") and CIDR ranges ("10.0.0.0/24")
        let ip_rules =
            pingap_util::IpRules::new(&get_str_slice_conf(value, "ip_list"));

        // Get custom error message or use default
        let mut message = get_str_conf(value, "message");
        if message.is_empty() {
            message = "Request is forbidden".to_string();
        }

        let params = Self {
            hash_value,
            plugin_step: PluginStep::Request,
            ip_rules,
            restriction_category: get_str_conf(value, "type"),
            forbidden_resp: HttpResponse {
                status: StatusCode::FORBIDDEN,
                body: Bytes::from(message),
                ..Default::default()
            },
        };

        Ok(params)
    }
}

impl IpRestriction {
    /// Creates a new IpRestriction plugin instance from the provided configuration.
    ///
    /// # Arguments
    /// * `params` - Plugin configuration parameters
    ///
    /// # Returns
    /// * `Result<Self>` - New plugin instance or error if configuration is invalid
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new ip restriction plugin");
        Self::try_from(params)
    }
}

#[async_trait]
impl Plugin for IpRestriction {
    /// Returns the unique hash key for this plugin instance.
    /// Used for caching and identifying plugin instances.
    #[inline]
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    /// Handles incoming HTTP requests by checking client IP against configured rules.
    ///
    /// # Arguments
    /// * `step` - Current plugin execution step
    /// * `session` - HTTP session containing request details
    /// * `ctx` - Request context for storing/retrieving state
    ///
    /// # Returns
    /// * `Ok(None)` - Request is allowed to proceed
    /// * `Ok(Some(HttpResponse))` - Request is denied (403) or invalid (400)
    /// * `Err(_)` - Internal error occurred during processing
    ///
    /// # Processing Flow
    /// 1. Verifies correct plugin step
    /// 2. Extracts and caches client IP
    /// 3. Checks IP against configured rules
    /// 4. Allows or denies request based on restriction type
    #[inline]
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        // Skip processing if not in correct plugin step
        if step != self.plugin_step {
            return Ok(RequestPluginResult::Skipped);
        }

        // Get client IP address, using cached value if available
        // Otherwise extract from X-Forwarded-For or remote address
        let ip = if let Some(ip) = &ctx.conn.client_ip {
            ip.to_string()
        } else {
            let ip = pingap_core::get_client_ip(session);
            ctx.conn.client_ip = Some(ip.clone()); // Cache for future use
            ip
        };

        // Check if IP matches any configured rules
        // Returns error if IP is malformed
        let found = match self.ip_rules.is_match(&ip) {
            Ok(matched) => matched,
            Err(e) => {
                return Ok(RequestPluginResult::Respond(
                    HttpResponse::bad_request(e.to_string()),
                ));
            },
        };

        // Determine if request should be allowed based on:
        // - deny mode: block if IP is found in rules (!found)
        // - allow mode: block if IP is NOT found in rules (found)
        let allow = if self.restriction_category == "deny" {
            !found
        } else {
            found
        };

        if !allow {
            // Return forbidden response with custom message if configured
            return Ok(RequestPluginResult::Respond(
                self.forbidden_resp.clone(),
            ));
        }
        // Allow request to proceed
        Ok(RequestPluginResult::Continue)
    }
}

#[ctor]
fn init() {
    get_plugin_factory().register("ip_restriction", |params| {
        Ok(Arc::new(IpRestriction::new(params)?))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::StatusCode;
    use pingap_config::PluginConf;
    use pingap_core::{ConnectionInfo, Ctx, PluginStep};
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    /// Tests IP restriction parameter parsing and validation.
    /// Verifies that:
    /// - Plugin step must be "request"
    /// - IP rules are correctly parsed
    /// - Both individual IPs and CIDR ranges are supported
    #[test]
    fn test_ip_limit_params() {
        let params = IpRestriction::try_from(
            &toml::from_str::<PluginConf>(
                r###"
ip_list = [
    "192.168.1.1",
    "10.1.1.1",
    "1.1.1.0/24",
    "2.1.1.0/24",
]
type = "deny"
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!("request", params.plugin_step.to_string());
        let description = format!("{:?}", params.ip_rules);
        assert_eq!(true, description.contains("ip_net_list"));
        assert_eq!(true, description.contains("[1.1.1.0/24, 2.1.1.0/24]"));
        assert_eq!(true, description.contains("ip_set"));
        assert_eq!(true, description.contains("10.1.1.1"));
        assert_eq!(true, description.contains("192.168.1.1"));
    }

    /// Tests IP restriction functionality.
    /// Verifies:
    /// - Deny list blocks matching IPs
    /// - Allow list permits matching IPs
    /// - CIDR range matching works correctly
    /// - IP caching in context functions properly
    /// - Correct response codes are returned
    #[tokio::test]
    async fn test_ip_limit() {
        let deny = IpRestriction::new(
            &toml::from_str::<PluginConf>(
                r###"
type = "deny"
ip_list = [
    "192.168.1.1",
    "1.1.1.0/24",
]
    "###,
            )
            .unwrap(),
        )
        .unwrap();

        let headers = ["X-Forwarded-For: 2.1.1.2"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let result = deny
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result == RequestPluginResult::Continue);

        let headers = ["X-Forwarded-For: 192.168.1.1"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let result = deny
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        let RequestPluginResult::Respond(resp) = result else {
            panic!("result is not Respond");
        };
        assert_eq!(403, resp.status.as_u16());

        let headers = ["Accept-Encoding: gzip"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let result = deny
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx {
                    conn: ConnectionInfo {
                        client_ip: Some("2.1.1.2".to_string()),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(true, result == RequestPluginResult::Continue);

        let result = deny
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx {
                    conn: ConnectionInfo {
                        client_ip: Some("1.1.1.2".to_string()),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let RequestPluginResult::Respond(resp) = result else {
            panic!("result is not Respond");
        };
        assert_eq!(StatusCode::FORBIDDEN, resp.status);

        let allow = IpRestriction::new(
            &toml::from_str::<PluginConf>(
                r###"
type = "allow"
ip_list = [
    "192.168.1.1",
    "1.1.1.0/24",
]
    "###,
            )
            .unwrap(),
        )
        .unwrap();
        let headers = ["X-Forwarded-For: 192.168.1.1"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let result = allow
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result == RequestPluginResult::Continue);
    }
}
