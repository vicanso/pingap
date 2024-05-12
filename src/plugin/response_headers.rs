use std::str::FromStr;

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
use super::{Error, Result};
use crate::config::{ProxyPluginCategory, ProxyPluginStep};
use crate::http_extra::{convert_header, HttpHeader};
use crate::plugin::HttpResponse;
use crate::state::State;
use async_trait::async_trait;
use http::header::HeaderName;
use log::debug;
use pingora::proxy::Session;
use substring::Substring;

pub struct ResponseHeaders {
    proxy_step: ProxyPluginStep,
    add_headers: Vec<HttpHeader>,
    remove_headers: Vec<HeaderName>,
    set_headers: Vec<HttpHeader>,
}

impl ResponseHeaders {
    pub fn new(value: &str, proxy_step: ProxyPluginStep) -> Result<Self> {
        debug!("new stats proxy plugin, {value}, {proxy_step:?}");
        let mut add_headers = vec![];
        let mut remove_headers = vec![];
        let mut set_headers = vec![];
        for item in value.split(' ') {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            let first = item.chars().next().unwrap();
            let last = item.substring(1, item.len());
            match first {
                '+' => {
                    let header = convert_header(last).map_err(|e| Error::Invalid {
                        message: e.to_string(),
                    })?;
                    if let Some(item) = header {
                        add_headers.push(item);
                    }
                }
                '-' => {
                    let name = HeaderName::from_str(last).map_err(|e| Error::Invalid {
                        message: e.to_string(),
                    })?;
                    remove_headers.push(name);
                }
                _ => {
                    let header = convert_header(item).map_err(|e| Error::Invalid {
                        message: e.to_string(),
                    })?;
                    if let Some(item) = header {
                        set_headers.push(item);
                    }
                }
            }
        }
        Ok(Self {
            proxy_step,
            add_headers,
            remove_headers,
            set_headers,
        })
    }
}

#[async_trait]
impl ProxyPlugin for ResponseHeaders {
    #[inline]
    fn step(&self) -> ProxyPluginStep {
        self.proxy_step
    }
    #[inline]
    fn category(&self) -> ProxyPluginCategory {
        ProxyPluginCategory::ResponseHeaders
    }
    #[inline]
    async fn handle(
        &self,
        _session: &mut Session,
        ctx: &mut State,
    ) -> pingora::Result<Option<HttpResponse>> {
        // TODO find a way for better handle
        if !self.add_headers.is_empty() {
            ctx.add_headers = Some(self.add_headers.clone());
        }
        if !self.remove_headers.is_empty() {
            ctx.remove_headers = Some(self.remove_headers.clone());
        }
        if !self.set_headers.is_empty() {
            ctx.set_headers = Some(self.set_headers.clone());
        }
        Ok(None)
    }
}
