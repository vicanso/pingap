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
use crate::util;
use async_trait::async_trait;
use bytes::Bytes;
use http::StatusCode;
use ipnet::IpNet;
use log::debug;
use pingora::proxy::Session;
use std::net::IpAddr;
use std::str::FromStr;

pub struct IpLimit {
    proxy_step: ProxyPluginStep,
    ip_net_list: Vec<IpNet>,
    ip_list: Vec<String>,
    category: u8,
    forbidden_resp: HttpResponse,
}

impl IpLimit {
    pub fn new(value: &str, proxy_step: ProxyPluginStep) -> Result<Self> {
        debug!("new ip limit proxy plugin, {value}, {proxy_step:?}");
        let arr: Vec<&str> = value.split(' ').collect();
        let ip = arr[0].trim().to_string();
        let mut category = 0;
        if arr.len() >= 2 {
            let v = arr[1].parse::<u8>().unwrap();
            if v > 0 {
                category = v;
            }
        }
        let mut ip_net_list = vec![];
        let mut ip_list = vec![];
        for item in ip.split(',') {
            if let Ok(value) = IpNet::from_str(item) {
                ip_net_list.push(value);
            } else {
                ip_list.push(item.to_string());
            }
        }
        Ok(Self {
            proxy_step,
            ip_list,
            ip_net_list,
            category,
            forbidden_resp: HttpResponse {
                status: StatusCode::FORBIDDEN,
                body: Bytes::from_static(b"Request is forbidden"),
                ..Default::default()
            },
        })
    }
}

#[async_trait]
impl ProxyPlugin for IpLimit {
    #[inline]
    fn step(&self) -> ProxyPluginStep {
        self.proxy_step
    }
    #[inline]
    fn category(&self) -> ProxyPluginCategory {
        ProxyPluginCategory::IpLimit
    }
    #[inline]
    async fn handle(&self, session: &mut Session, ctx: &mut State) -> pingora::Result<bool> {
        let ip = if let Some(ip) = &ctx.client_ip {
            ip.to_string()
        } else {
            let ip = util::get_client_ip(session);
            ctx.client_ip = Some(ip.clone());
            ip
        };

        let found = if self.ip_list.contains(&ip) {
            true
        } else {
            let addr = ip
                .parse::<IpAddr>()
                .map_err(|err| util::new_internal_error(400, err.to_string()))?;
            self.ip_net_list.iter().any(|item| item.contains(&addr))
        };
        // deny ip
        let allow = if self.category > 0 { !found } else { found };
        if !allow {
            self.forbidden_resp.clone().send(session).await?;
            return Ok(true);
        }
        return Ok(false);
    }
}
