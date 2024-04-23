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
use crate::http_extra::convert_headers;
use crate::http_extra::HttpResponse;
use crate::state::State;
use async_trait::async_trait;
use http::StatusCode;
use pingora::proxy::Session;

pub struct RedirectHttps {
    prefix: String,
    proxy_step: ProxyPluginStep,
}

impl RedirectHttps {
    pub fn new(value: &str, proxy_step: ProxyPluginStep) -> Result<Self> {
        let mut prefix = "".to_string();
        if value.trim().len() > 1 {
            prefix = value.trim().to_string();
        }
        Ok(Self { prefix, proxy_step })
    }
}

#[async_trait]
impl ProxyPlugin for RedirectHttps {
    #[inline]
    fn step(&self) -> ProxyPluginStep {
        self.proxy_step
    }
    #[inline]
    fn category(&self) -> ProxyPluginCategory {
        ProxyPluginCategory::RedirectHttps
    }
    #[inline]
    async fn handle(&self, session: &mut Session, ctx: &mut State) -> pingora::Result<bool> {
        if !ctx.is_tls {
            let host = if let Some(value) = session.get_header("Host") {
                value.to_str().unwrap_or_default()
            } else {
                session.req_header().uri.host().unwrap_or_default()
            };
            let location = format!(
                "Location: https://{host}{}{}",
                self.prefix,
                session.req_header().uri
            );
            let _ = HttpResponse {
                status: StatusCode::TEMPORARY_REDIRECT,
                headers: Some(convert_headers(&[location]).unwrap_or_default()),
                ..Default::default()
            }
            .send(session)
            .await?;
            return Ok(true);
        }
        Ok(false)
    }
}
