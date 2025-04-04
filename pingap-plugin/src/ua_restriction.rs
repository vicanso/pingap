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
use pingap_core::{Ctx, HttpResponse, Plugin, PluginStep};
use pingora::proxy::Session;
use regex::Regex;
use std::sync::Arc;
use tracing::debug;

type Result<T, E = Error> = std::result::Result<T, E>;

/// UaRestriction plugin allows filtering HTTP requests based on User-Agent patterns.
/// Can be configured to either block specific user agents (deny mode) or only allow specific ones (allow mode).
///
/// # Configuration (TOML)
/// ```toml
/// ua_list = [
///   "go-http-client/1.1",           # Exact match
///   "(Twitterspider)/(\\d+)\\.(\\d+)" # Regex pattern
/// ]
/// type = "deny"    # or "allow"
/// message = "Optional custom error message"
/// ```
///
/// A plugin that filters HTTP requests based on User-Agent patterns
///
/// # Fields
///
/// * `plugin_step` - Execution phase of the plugin (must be PluginStep::Request)
///   as UA filtering only makes sense during request processing
///
/// * `ua_list` - Vector of compiled regular expressions used to match against
///   incoming User-Agent headers. Each pattern can be either an exact
///   match (e.g., "go-http-client/1.1") or a regex pattern
///   (e.g., "(Twitterspider)/(\d+)\.(\d+)")
///
/// * `restriction_category` - Determines the filtering behavior:
///   - "deny": blocks requests matching any pattern
///   - "allow": only permits requests matching at least one pattern
///
/// * `forbidden_resp` - The HTTP response returned when a request is blocked.
///   Defaults to 403 Forbidden with a configurable message
///
/// * `hash_value` - Unique identifier generated from the plugin configuration,
///   used for caching and tracking plugin instances
pub struct UaRestriction {
    plugin_step: PluginStep, // Defines when plugin runs (must be Request phase)
    ua_list: Vec<Regex>, // List of compiled regex patterns to match User-Agents
    restriction_category: String, // "deny" or "allow" - determines filtering behavior
    forbidden_resp: HttpResponse, // Custom HTTP response returned when request is blocked
    hash_value: String, // Unique identifier for plugin instance, used for caching/tracking
}

impl TryFrom<&PluginConf> for UaRestriction {
    type Error = Error;
    /// Attempts to create a new UaRestriction instance from plugin configuration.
    ///
    /// # Arguments
    /// * `value` - Plugin configuration containing ua_list, type, and optional message
    ///
    /// # Returns
    /// * `Result<Self>` - New UaRestriction instance or error if configuration is invalid
    ///
    /// # Errors
    /// * Invalid regex patterns in ua_list
    /// * Invalid plugin step (must be Request)
    fn try_from(value: &PluginConf) -> Result<Self> {
        // Generate unique hash for this plugin configuration
        let hash_value = get_hash_key(value);
        let mut ua_list = vec![];

        // Parse and compile each regex pattern from the ua_list config
        // Example config:
        // ua_list = [
        //   "go-http-client/1.1",
        //   "(Twitterspider)/(\d+)\.(\d+)"
        // ]
        for item in get_str_slice_conf(value, "ua_list").iter() {
            let reg = Regex::new(item).map_err(|e| Error::Invalid {
                category: "regex".to_string(),
                message: e.to_string(),
            })?;
            ua_list.push(reg);
        }

        // Configure custom error message or use default
        let mut message = get_str_conf(value, "message");
        if message.is_empty() {
            message = "Request is forbidden".to_string();
        }

        let params = Self {
            hash_value,
            plugin_step: PluginStep::Request,
            ua_list,
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

impl UaRestriction {
    /// Creates a new UaRestriction plugin instance from the provided configuration.
    ///
    /// # Arguments
    /// * `params` - Plugin configuration
    ///
    /// # Returns
    /// * `Result<Self>` - New plugin instance or error if configuration is invalid
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(
            params = params.to_string(),
            "new user agent restriction plugin"
        );
        Self::try_from(params)
    }
}

#[async_trait]
impl Plugin for UaRestriction {
    /// Returns the unique hash key for this plugin instance
    #[inline]
    fn hash_key(&self) -> String {
        self.hash_value.clone()
    }

    /// Handles incoming HTTP requests by checking the User-Agent against configured patterns.
    ///
    /// # Arguments
    /// * `step` - Current plugin execution step
    /// * `session` - HTTP session containing request details
    /// * `_ctx` - Plugin state context (unused)
    ///
    /// # Returns
    /// * `Ok(Some(HttpResponse))` - When request should be blocked (403 Forbidden)
    /// * `Ok(None)` - When request should be allowed to proceed
    ///
    /// # Processing Logic
    /// 1. Extracts User-Agent header from request
    /// 2. Checks UA against all configured patterns
    /// 3. In deny mode: blocks if any pattern matches
    /// 4. In allow mode: blocks if no patterns match
    #[inline]
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        _ctx: &mut Ctx,
    ) -> pingora::Result<(bool, Option<HttpResponse>)> {
        // Skip processing if not in request phase
        if step != self.plugin_step {
            return Ok((false, None));
        }

        let mut found = false;
        // Extract and check User-Agent header against patterns
        if let Some(value) = session.get_header(http::header::USER_AGENT) {
            let ua = value.to_str().unwrap_or_default();
            // Check each regex pattern until a match is found
            for item in self.ua_list.iter() {
                if !found && item.is_match(ua) {
                    found = true;
                }
            }
        }

        // Determine if request should be allowed based on mode:
        // - deny mode: block if UA matches any pattern
        // - allow mode: block if UA doesn't match any pattern
        let allow = if self.restriction_category == "deny" {
            !found // In deny mode, allow = true if no matches found
        } else {
            found // In allow mode, allow = true if match found
        };

        // Return forbidden response if request is not allowed
        if !allow {
            return Ok((true, Some(self.forbidden_resp.clone())));
        }
        Ok((true, None)) // Request allowed - continue normal processing
    }
}

#[ctor]
fn init() {
    get_plugin_factory().register("ua_restriction", |params| {
        Ok(Arc::new(UaRestriction::new(params)?))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::StatusCode;
    use pingap_config::PluginConf;
    use pingap_core::{Ctx, PluginStep};
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    /// Tests the parsing and validation of plugin configuration parameters
    #[test]
    fn test_ua_restriction_params() {
        // Example configuration in TOML format:
        // ua_list: List of regex patterns to match
        // type: "deny" to block matching UAs, "allow" to only permit matching UAs
        let params = UaRestriction::try_from(
            &toml::from_str::<PluginConf>(
                r###"
ua_list = [
"go-http-client/1.1",           # Blocks/allows exact UA string
"(Twitterspider)/(\\d+)\\.(\\d+)" # Blocks/allows Twitterspider with version numbers
]
type = "deny"  # This config will block these user agents
"###,
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!("request", params.plugin_step.to_string());
        assert_eq!(
            r#"go-http-client/1.1,(Twitterspider)/(\d+)\.(\d+)"#,
            params
                .ua_list
                .iter()
                .map(|item| item.to_string())
                .collect::<Vec<String>>()
                .join(",")
        );

        assert_eq!("deny", params.restriction_category);
    }

    /// Tests the full request handling flow including:
    /// - Allowing non-matching user agents in deny mode
    /// - Blocking matching user agents in deny mode
    /// - Pattern matching with regex
    #[tokio::test]
    async fn test_ua_restriction() {
        let deny = UaRestriction::new(
            &toml::from_str::<PluginConf>(
                r###"
ua_list = [
"go-http-client/1.1",
"(Twitterspider)/(\\d+)\\.(\\d+)"
]
type = "deny"
    "###,
            )
            .unwrap(),
        )
        .unwrap();

        let headers = ["User-Agent: pingap/1.0"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let (executed, result) = deny
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, executed);
        assert_eq!(true, result.is_none());

        let headers = ["User-Agent: go-http-client/1.1"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let (executed, result) = deny
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, executed);
        assert_eq!(true, result.is_some());
        assert_eq!(StatusCode::FORBIDDEN, result.unwrap().status);

        let headers = ["User-Agent: Twitterspider/1.1"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let (executed, result) = deny
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx {
                    client_ip: Some("1.1.1.2".to_string()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(true, executed);
        assert_eq!(true, result.is_some());
        assert_eq!(StatusCode::FORBIDDEN, result.unwrap().status);
    }
}
