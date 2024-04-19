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
use crate::http_extra::HTTP_HEADER_NAME_X_REQUEST_ID;
use crate::state::State;
use async_trait::async_trait;
use log::debug;
use nanoid::nanoid;
use pingora::proxy::Session;
use uuid::Uuid;

pub struct RequestId {
    proxy_step: ProxyPluginStep,
    algorithm: String,
    size: usize,
}

impl RequestId {
    pub fn new(value: &str, proxy_step: ProxyPluginStep) -> Result<Self> {
        debug!("new request id proxy plugin, {value}, {proxy_step:?}");
        let arr: Vec<&str> = value.split(' ').collect();
        let algorithm = arr[0].trim().to_string();
        let mut size = 8;
        if arr.len() >= 2 {
            let v = arr[1].parse::<usize>().unwrap();
            if v > 0 {
                size = v;
            }
        }
        Ok(Self {
            size,
            proxy_step,
            algorithm,
        })
    }
}

#[async_trait]
impl ProxyPlugin for RequestId {
    #[inline]
    fn step(&self) -> ProxyPluginStep {
        self.proxy_step
    }
    #[inline]
    fn category(&self) -> ProxyPluginCategory {
        ProxyPluginCategory::RequestId
    }
    #[inline]
    async fn handle(&self, session: &mut Session, ctx: &mut State) -> pingora::Result<bool> {
        let key = HTTP_HEADER_NAME_X_REQUEST_ID.clone();
        if let Some(id) = session.get_header(&key) {
            ctx.request_id = Some(id.to_str().unwrap_or_default().to_string());
            return Ok(false);
        }
        let id = match self.algorithm.as_str() {
            "nanoid" => {
                let size = self.size;
                nanoid!(size)
            }
            _ => Uuid::new_v4().to_string(),
        };
        ctx.request_id = Some(id.clone());
        let _ = session.req_header_mut().insert_header(key, &id);
        Ok(false)
    }
}
