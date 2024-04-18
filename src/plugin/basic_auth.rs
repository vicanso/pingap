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
use http::HeaderValue;
use http::StatusCode;
use log::debug;
use pingora::proxy::Session;

pub struct BasicAuth {
    proxy_step: ProxyPluginStep,
    authorizations: Vec<Vec<u8>>,
    unauthorized_resp: HttpResponse,
}

impl BasicAuth {
    pub fn new(value: &str, proxy_step: ProxyPluginStep) -> Result<Self> {
        debug!("new basic auth proxy plugin, {value}, {proxy_step:?}");
        let authorizations = value
            .split(',')
            .map(|item| format!("Basic {item}").as_bytes().to_owned())
            .collect();

        Ok(Self {
            proxy_step,
            authorizations,
            unauthorized_resp: HttpResponse {
                status: StatusCode::UNAUTHORIZED,
                headers: Some(vec![(
                    http::header::WWW_AUTHENTICATE,
                    HeaderValue::from_str(r###"Basic realm="Access to the staging site""###)
                        .unwrap(),
                )]),
                ..Default::default()
            },
        })
    }
}

#[async_trait]
impl ProxyPlugin for BasicAuth {
    #[inline]
    fn step(&self) -> ProxyPluginStep {
        self.proxy_step
    }
    #[inline]
    fn category(&self) -> ProxyPluginCategory {
        ProxyPluginCategory::BasicAuth
    }
    #[inline]
    async fn handle(&self, session: &mut Session, _ctx: &mut State) -> pingora::Result<bool> {
        let value = session.get_header_bytes(http::header::AUTHORIZATION);
        if value.is_empty() || !self.authorizations.contains(&value.to_vec()) {
            self.unauthorized_resp.clone().send(session).await?;
            return Ok(true);
        }
        Ok(false)
    }
}
