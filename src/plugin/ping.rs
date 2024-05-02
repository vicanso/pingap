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

use super::ProxyPlugin;
use super::Result;
use crate::config::ProxyPluginCategory;
use crate::config::ProxyPluginStep;
use crate::http_extra::HttpResponse;
use crate::state::State;
use async_trait::async_trait;
use bytes::Bytes;
use http::StatusCode;
use once_cell::sync::Lazy;
use pingora::proxy::Session;

pub struct Ping {
    prefix: String,
    proxy_step: ProxyPluginStep,
}
static PONG_RESPONSE: Lazy<HttpResponse> = Lazy::new(|| HttpResponse {
    status: StatusCode::OK,
    body: Bytes::from_static(b"pong"),
    ..Default::default()
});

impl Ping {
    pub fn new(value: &str, proxy_step: ProxyPluginStep) -> Result<Self> {
        let mut prefix = "".to_string();
        if value.trim().len() > 1 {
            prefix = value.trim().to_string();
        }
        Ok(Self { prefix, proxy_step })
    }
}

#[async_trait]
impl ProxyPlugin for Ping {
    #[inline]
    fn step(&self) -> ProxyPluginStep {
        self.proxy_step
    }
    #[inline]
    fn category(&self) -> ProxyPluginCategory {
        ProxyPluginCategory::RedirectHttps
    }
    #[inline]
    async fn handle(
        &self,
        session: &mut Session,
        _ctx: &mut State,
    ) -> pingora::Result<Option<HttpResponse>> {
        if session.req_header().uri.path() == self.prefix {
            return Ok(Some(PONG_RESPONSE.clone()));
        }
        Ok(None)
    }
}
