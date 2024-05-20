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

use super::{get_step_conf, get_str_conf, Error, ProxyPlugin, Result};
use crate::config::{PluginCategory, PluginConf, PluginStep};
use crate::http_extra::HttpResponse;
use crate::state::State;
use async_trait::async_trait;
use bytes::Bytes;
use http::StatusCode;
use once_cell::sync::Lazy;
use pingora::proxy::Session;

pub struct Ping {
    path: String,
    plugin_step: PluginStep,
}
static PONG_RESPONSE: Lazy<HttpResponse> = Lazy::new(|| HttpResponse {
    status: StatusCode::OK,
    body: Bytes::from_static(b"pong"),
    ..Default::default()
});

impl Ping {
    pub fn new(params: &PluginConf) -> Result<Self> {
        let step = get_step_conf(params);
        if step != PluginStep::Request {
            return Err(Error::Invalid {
                category: PluginCategory::Ping.to_string(),
                message: "Ping plugin should be executed at request step".to_string(),
            });
        }
        Ok(Self {
            path: get_str_conf(params, "path"),
            plugin_step: step,
        })
    }
}

#[async_trait]
impl ProxyPlugin for Ping {
    #[inline]
    fn step(&self) -> PluginStep {
        self.plugin_step
    }
    #[inline]
    fn category(&self) -> PluginCategory {
        PluginCategory::Ping
    }
    #[inline]
    async fn handle(
        &self,
        session: &mut Session,
        _ctx: &mut State,
    ) -> pingora::Result<Option<HttpResponse>> {
        if session.req_header().uri.path() == self.path {
            return Ok(Some(PONG_RESPONSE.clone()));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::Ping;
    use crate::config::PluginConf;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_ping_params() {
        let params = Ping::new(
            &toml::from_str::<PluginConf>(
                r###"
path = "/ping"
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!("request", params.plugin_step.to_string());
        assert_eq!("/ping", params.path);
    }
}
