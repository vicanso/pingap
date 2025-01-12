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

use super::{
    get_hash_key, get_step_conf, get_str_conf, get_str_slice_conf, Error,
    Plugin, Result,
};
use crate::config::{PluginCategory, PluginConf, PluginStep};
use crate::http_extra::HttpResponse;
use crate::state::State;
use async_trait::async_trait;
use bytes::Bytes;
use http::StatusCode;
use pingora::proxy::Session;
use substring::Substring;
use tracing::debug;

/// A plugin that controls access to resources based on the HTTP Referer header
///
/// This plugin allows implementing referer-based access control by either allowing or denying
/// requests based on their Referer header. It supports both exact domain matches and wildcard
/// prefix matching (e.g., "*.example.com").
///
/// # Configuration
/// The plugin accepts the following configuration parameters:
/// - `referer_list`: List of referer domains to match against
/// - `type`: Either "allow" or "deny" to specify the restriction type
/// - `message`: Custom message for forbidden responses (optional)
///
/// # Examples
/// ```toml
/// referer_list = [
///     "github.com",      # Exact match
///     "*.example.com",   # Wildcard prefix match
/// ]
/// type = "deny"          # Deny requests from these referrers
/// message = "Access denied by referrer policy"
/// ```
pub struct RefererRestriction {
    /// The step at which this plugin should execute (should be "request")
    plugin_step: PluginStep,
    /// List of exact domain matches (e.g., "github.com")
    referer_list: Vec<String>,
    /// List of wildcard domain suffixes (e.g., ".example.com" from "*.example.com")
    prefix_referer_list: Vec<String>,
    /// The type of restriction: "allow" or "deny"
    restriction_category: String,
    /// The HTTP response to return when access is forbidden
    forbidden_resp: HttpResponse,
    /// Unique identifier for this plugin instance
    hash_value: String,
}

impl TryFrom<&PluginConf> for RefererRestriction {
    type Error = Error;
    /// Attempts to create a RefererRestriction instance from plugin configuration
    ///
    /// # Arguments
    /// * `value` - The plugin configuration containing referer rules
    ///
    /// # Returns
    /// * `Result<Self>` - A configured RefererRestriction instance
    ///
    /// # Errors
    /// Returns an error if:
    /// - The plugin step is not set to "request"
    /// - Required configuration fields are missing
    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);
        let step = get_step_conf(value, PluginStep::Request);
        let mut referer_list = vec![];
        let mut prefix_referer_list = vec![];
        for item in get_str_slice_conf(value, "referer_list").iter() {
            if item.starts_with('*') {
                prefix_referer_list
                    .push(item.substring(1, item.len()).to_string());
            } else {
                referer_list.push(item.to_string());
            }
        }

        let mut message = get_str_conf(value, "message");
        if message.is_empty() {
            message = "Request is forbidden".to_string();
        }
        let params = Self {
            hash_value,
            plugin_step: step,
            prefix_referer_list,
            referer_list,
            restriction_category: get_str_conf(value, "type"),
            forbidden_resp: HttpResponse {
                status: StatusCode::FORBIDDEN,
                body: Bytes::from(message),
                ..Default::default()
            },
        };
        if PluginStep::Request != params.plugin_step {
            return Err(Error::Invalid {
                category: PluginCategory::RefererRestriction.to_string(),
                message: "Referer restriction plugin should be executed at request or proxy upstream step".to_string(),
            });
        }

        Ok(params)
    }
}

impl RefererRestriction {
    /// Creates a new RefererRestriction plugin instance from the provided configuration
    ///
    /// # Arguments
    /// * `params` - Plugin configuration containing:
    ///   - `referer_list`: List of domains to match against
    ///   - `type`: "allow" or "deny" to specify restriction behavior
    ///   - `message`: Optional custom forbidden message
    ///
    /// # Returns
    /// * `Result<Self>` - New RefererRestriction instance or error if configuration is invalid
    ///
    /// # Example Configuration
    /// ```toml
    /// referer_list = ["github.com", "*.example.com"]
    /// type = "deny"
    /// message = "Access denied"
    /// ```
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(
            params = params.to_string(),
            "new referer restriction plugin"
        );
        Self::try_from(params)
    }
}

#[async_trait]
impl Plugin for RefererRestriction {
    #[inline]
    /// Returns a unique hash key for this plugin instance
    ///
    /// This is used for plugin caching and identification purposes
    fn hash_key(&self) -> String {
        self.hash_value.clone()
    }

    /// Handles incoming HTTP requests by checking the Referer header against allowed/denied lists
    ///
    /// This function implements the core referer restriction logic:
    /// 1. Extracts the Referer header from the request
    /// 2. Parses the referer URL to get the host
    /// 3. Checks the host against both exact matches and wildcard prefix matches
    /// 4. Allows or denies the request based on the restriction type ("allow" or "deny")
    ///
    /// # Arguments
    /// * `step` - Current plugin execution step (must match plugin_step)
    /// * `session` - HTTP session containing request details and headers
    /// * `_ctx` - State context (unused in this plugin)
    ///
    /// # Returns
    /// * `pingora::Result<Option<HttpResponse>>` - Returns:
    ///   - `Some(HttpResponse)` with 403 Forbidden if request is blocked
    ///   - `None` if request is allowed to proceed
    ///   - Error if request processing fails
    #[inline]
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        _ctx: &mut State,
    ) -> pingora::Result<Option<HttpResponse>> {
        if step != self.plugin_step {
            return Ok(None);
        }
        let mut found = false;
        if let Some(value) = session.get_header(http::header::REFERER) {
            let referer = value.to_str().unwrap_or_default().to_string();
            let host = if let Ok(info) = url::Url::parse(&referer) {
                info.host_str().unwrap_or_default().to_string()
            } else {
                "".to_string()
            };
            if self.referer_list.contains(&host) {
                found = true;
            } else {
                found = self
                    .prefix_referer_list
                    .iter()
                    .any(|item| host.ends_with(item));
            }
        }
        let allow = if self.restriction_category == "deny" {
            !found
        } else {
            found
        };
        if !allow {
            return Ok(Some(self.forbidden_resp.clone()));
        }
        return Ok(None);
    }
}
#[cfg(test)]
mod tests {
    use super::RefererRestriction;
    use crate::state::State;
    use crate::{config::PluginConf, config::PluginStep, plugin::Plugin};
    use http::StatusCode;
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    #[test]
    fn test_referer_restriction_params() {
        let params = RefererRestriction::try_from(
            &toml::from_str::<PluginConf>(
                r###"
referer_list = [
    "github.com",
    "*.bing.cn",
]
type = "deny"
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!("request", params.plugin_step.to_string());
        assert_eq!(".bing.cn", params.prefix_referer_list.join(","));
        assert_eq!("github.com", params.referer_list.join(","));

        let result = RefererRestriction::try_from(
            &toml::from_str::<PluginConf>(
                r###"
step = "response"
referer_list = [
    "github.com",
    "*.bing.cn",
]
type = "deny"
"###,
            )
            .unwrap(),
        );
        assert_eq!("Plugin referer_restriction invalid, message: Referer restriction plugin should be executed at request or proxy upstream step", result.err().unwrap().to_string());
    }

    #[tokio::test]
    async fn test_referer_restriction() {
        let deny = RefererRestriction::new(
            &toml::from_str::<PluginConf>(
                r###"
referer_list = [
    "github.com",
    "*.bing.cn",
]
type = "deny"
    "###,
            )
            .unwrap(),
        )
        .unwrap();

        let headers = ["Referer: https://google.com/"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let result = deny
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut State::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result.is_none());

        let headers = ["Referer: https://github.com/"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let result = deny
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut State::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result.is_some());
        assert_eq!(StatusCode::FORBIDDEN, result.unwrap().status);

        let headers = ["Referer: https://test.bing.cn/"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = deny
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut State {
                    client_ip: Some("1.1.1.2".to_string()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(true, result.is_some());
        assert_eq!(StatusCode::FORBIDDEN, result.unwrap().status);
    }
}
