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
    Error, RestrictionCategory, get_hash_key, get_restriction_category_conf,
    get_str_conf, get_str_slice_conf,
};
use async_trait::async_trait;
use bytes::Bytes;
use http::StatusCode;
use pingap_config::{PluginCategory, PluginConf};
use pingap_core::{
    Ctx, HttpResponse, Plugin, PluginStep, RequestPluginResult,
    ensure_verified_client_ip,
};
use pingap_util::IpRules;
use pingora::proxy::Session;
use std::borrow::Cow;
use tracing::debug;

type Result<T, E = Error> = std::result::Result<T, E>;

/// IpRestriction plugin provides IP-based access control for HTTP requests.
/// It can be configured to either allow or deny requests based on client IP addresses.
pub struct IpRestriction {
    plugin_step: PluginStep, // Defines when plugin runs in request lifecycle (must be Request)
    ip_rules: pingap_util::IpRules, // Contains parsed IP addresses and CIDR ranges for matching
    restriction_category: RestrictionCategory, // whitelist or blacklist
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
        let ip_rules = IpRules::try_new(&get_str_slice_conf(value, "ip_list"))
            .map_err(|e| Error::Invalid {
                category: PluginCategory::IpRestriction.to_string(),
                message: e.to_string(),
            })?;

        // Get custom error message or use default
        let mut message = get_str_conf(value, "message");
        if message.is_empty() {
            message = "Request is forbidden".to_string();
        }

        let params = Self {
            hash_value,
            plugin_step: PluginStep::Request,
            ip_rules,
            restriction_category: get_restriction_category_conf(
                value,
                "ip_restriction",
            )?,
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
        debug!(
            params = pingap_config::masked_toml(params),
            "new ip restriction plugin"
        );
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

        // The address the list is checked against is one the client
        // cannot choose: its own behind trusted proxies, the peer's
        // without them. Without them `X-Forwarded-For` is simply what the
        // request says, and an allow list for `10.0.0.0/8` let in anyone
        // who sent `X-Forwarded-For: 10.1.2.3`.
        let ip = ensure_verified_client_ip(session, ctx);

        // Check if IP matches any configured rules
        // Returns error if IP is malformed
        let found = match self.ip_rules.is_match(ip) {
            Ok(matched) => matched,
            Err(e) => {
                return Ok(RequestPluginResult::Respond(
                    HttpResponse::bad_request(e.to_string()),
                ));
            },
        };

        // Determine if request should be allowed based on:
        // - deny mode: block if IP is found in rules
        // - allow mode: block if IP is NOT found in rules
        if !self.restriction_category.allows(found) {
            // Return forbidden response with custom message if configured
            return Ok(RequestPluginResult::Respond(
                self.forbidden_resp.clone(),
            ));
        }
        // Allow request to proceed
        Ok(RequestPluginResult::Continue)
    }
}

register_plugin!("ip_restriction", IpRestriction);

#[cfg(test)]
mod tests {
    use super::*;
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

    /// The status the plugin answers a request with, `None` when it lets
    /// it through. `peer` is the address of the connection, which the
    /// proxy records in the context when the request comes in.
    async fn check(
        plugin: &IpRestriction,
        peer: Option<&str>,
        headers: &str,
    ) -> Option<u16> {
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let mut ctx = Ctx {
            conn: ConnectionInfo {
                remote_addr: peer.map(|addr| addr.to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        let result = plugin
            .handle_request(PluginStep::Request, &mut session, &mut ctx)
            .await
            .unwrap();
        match result {
            RequestPluginResult::Respond(resp) => Some(resp.status.as_u16()),
            _ => None,
        }
    }

    fn new_restriction(category: &str) -> IpRestriction {
        IpRestriction::new(
            &toml::from_str::<PluginConf>(&format!(
                r###"
type = "{category}"
ip_list = [
    "192.168.1.1",
    "1.1.1.0/24",
]
    "###
            ))
            .unwrap(),
        )
        .unwrap()
    }

    /// The lists are checked against the address of the peer (no trusted
    /// proxies are configured in a unit test).
    #[tokio::test]
    async fn test_ip_limit() {
        let deny = new_restriction("deny");
        assert_eq!(None, check(&deny, Some("2.1.1.2"), "").await);
        assert_eq!(Some(403), check(&deny, Some("192.168.1.1"), "").await);
        assert_eq!(Some(403), check(&deny, Some("1.1.1.2"), "").await);

        let allow = new_restriction("allow");
        assert_eq!(None, check(&allow, Some("192.168.1.1"), "").await);
        assert_eq!(None, check(&allow, Some("1.1.1.2"), "").await);
        assert_eq!(Some(403), check(&allow, Some("2.1.1.2"), "").await);
        // No address at all is not let through either way.
        assert_eq!(Some(400), check(&allow, None, "").await);
        assert_eq!(Some(400), check(&deny, None, "").await);
    }

    /// Regression: without trusted proxies the address was whatever the
    /// request claimed. An allow list let in anyone who sent an address
    /// that is on it, and a deny list was passed by sending one that is
    /// not.
    #[tokio::test]
    async fn test_ip_limit_ignores_a_forged_address() {
        let allow = new_restriction("allow");
        for headers in [
            "X-Forwarded-For: 192.168.1.1\r\n",
            "X-Real-IP: 192.168.1.1\r\n",
            "X-Forwarded-For: 1.1.1.9, 10.0.0.1\r\n",
        ] {
            assert_eq!(
                Some(403),
                check(&allow, Some("2.1.1.2"), headers).await,
                "{headers}"
            );
        }
        // The peer is what counts, whatever else the request says.
        assert_eq!(
            None,
            check(&allow, Some("192.168.1.1"), "X-Forwarded-For: 2.1.1.2\r\n")
                .await
        );

        let deny = new_restriction("deny");
        assert_eq!(
            Some(403),
            check(&deny, Some("192.168.1.1"), "X-Forwarded-For: 2.1.1.2\r\n")
                .await
        );
    }
}
