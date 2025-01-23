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

use super::{get_str_conf, Plugin, Result};
use crate::config::{PluginConf, PluginStep};
use crate::http_extra::HttpResponse;
use crate::plugin::get_hash_key;
use crate::state::State;
use async_trait::async_trait;
use bytes::Bytes;
use http::StatusCode;
use once_cell::sync::Lazy;
use pingora::proxy::Session;
use tracing::debug;

/// A plugin that responds with "pong" when a specific path is requested
///
/// The Ping plugin provides a simple health check endpoint that returns a "pong"
/// response when the configured path is accessed.
pub struct Ping {
    /// The URL path that triggers the ping response (e.g. "/ping")
    path: String,
    /// The execution step for this plugin (must be PluginStep::Request)
    plugin_step: PluginStep,
    /// A unique hash value identifying this plugin instance
    hash_value: String,
}

/// Response for ping requests containing "pong"
static PONG_RESPONSE: Lazy<HttpResponse> = Lazy::new(|| HttpResponse {
    status: StatusCode::OK,
    body: Bytes::from_static(b"pong"),
    ..Default::default()
});

impl Ping {
    /// Creates a new Ping plugin instance
    ///
    /// # Arguments
    /// * `params` - Plugin configuration parameters
    ///
    /// # Returns
    /// * `Result<Self>` - New Ping instance or error if configuration is invalid
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new ping plugin");
        let hash_value = get_hash_key(params);
        Ok(Self {
            hash_value,
            path: get_str_conf(params, "path"),
            plugin_step: PluginStep::Request,
        })
    }
}

#[async_trait]
impl Plugin for Ping {
    /// Returns the unique hash key for this plugin instance
    #[inline]
    fn hash_key(&self) -> String {
        self.hash_value.clone()
    }

    /// Handles incoming HTTP requests by responding with "pong" if the path matches
    ///
    /// # Arguments
    /// * `step` - Current plugin execution step
    /// * `session` - HTTP session containing request details
    /// * `_ctx` - State context (unused)
    ///
    /// # Returns
    /// * `pingora::Result<Option<HttpResponse>>` - Pong response if path matches, None otherwise
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
        if session.req_header().uri.path() == self.path {
            return Ok(Some(PONG_RESPONSE.clone()));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::Ping;
    use crate::state::State;
    use crate::{config::PluginConf, config::PluginStep, plugin::Plugin};
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    #[tokio::test]
    async fn test_ping() {
        let ping = Ping::new(
            &toml::from_str::<PluginConf>(
                r###"
path = "/ping"
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!("request", ping.plugin_step.to_string());
        assert_eq!("/ping", ping.path);

        let headers = [""].join("\r\n");
        let input_header = format!("GET /ping HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = ping
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut State::default(),
            )
            .await
            .unwrap();

        assert_eq!(true, result.is_some());
        let resp = result.unwrap();
        assert_eq!(200, resp.status.as_u16());
        assert_eq!(b"pong", resp.body.as_ref());
    }
}
