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
    get_int_conf, get_step_conf, get_str_conf, get_str_slice_conf, Error, ProxyPlugin, Result,
};
use crate::config::{PluginCategory, PluginConf, PluginStep};
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
    plugin_step: PluginStep,
    ip_net_list: Vec<IpNet>,
    ip_list: Vec<String>,
    category: u8,
    forbidden_resp: HttpResponse,
}

struct IpLimitParams {
    plugin_step: PluginStep,
    ip_net_list: Vec<IpNet>,
    ip_list: Vec<String>,
    category: u8,
}

impl TryFrom<&PluginConf> for IpLimitParams {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        let step = get_step_conf(value);
        let all_params = get_str_conf(value, "value");
        let params = if !all_params.is_empty() {
            let arr: Vec<&str> = all_params.split(' ').collect();
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
            Self {
                plugin_step: step,
                ip_list,
                ip_net_list,
                category,
            }
        } else {
            let mut ip_net_list = vec![];
            let mut ip_list = vec![];
            for item in get_str_slice_conf(value, "ip_list") {
                if let Ok(value) = IpNet::from_str(&item) {
                    ip_net_list.push(value);
                } else {
                    ip_list.push(item);
                }
            }
            Self {
                plugin_step: step,
                ip_list,
                ip_net_list,
                category: get_int_conf(value, "category") as u8,
            }
        };
        if ![PluginStep::Request, PluginStep::ProxyUpstream].contains(&params.plugin_step) {
            return Err(Error::Invalid {
                category: PluginCategory::IpLimit.to_string(),
                message: "Ip limit plugin should be executed at request or proxy upstream step"
                    .to_string(),
            });
        }
        Ok(params)
    }
}

impl IpLimit {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!("new ip limit proxy plugin, params:{params:?}");
        let params = IpLimitParams::try_from(params)?;
        Ok(Self {
            plugin_step: params.plugin_step,
            ip_list: params.ip_list,
            ip_net_list: params.ip_net_list,
            category: params.category,
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
    fn step(&self) -> PluginStep {
        self.plugin_step
    }
    #[inline]
    fn category(&self) -> PluginCategory {
        PluginCategory::IpLimit
    }
    #[inline]
    async fn handle(
        &self,
        session: &mut Session,
        ctx: &mut State,
    ) -> pingora::Result<Option<HttpResponse>> {
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
            match ip.parse::<IpAddr>() {
                Ok(addr) => self.ip_net_list.iter().any(|item| item.contains(&addr)),
                Err(e) => {
                    return Ok(Some(HttpResponse::bad_request(e.to_string().into())));
                }
            }
        };
        // deny ip
        let allow = if self.category > 0 { !found } else { found };
        if !allow {
            return Ok(Some(self.forbidden_resp.clone()));
        }
        return Ok(None);
    }
}

#[cfg(test)]
mod tests {
    use super::IpLimit;
    use crate::state::State;
    use crate::{config::PluginConf, plugin::ProxyPlugin};
    use http::StatusCode;
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    #[tokio::test]
    async fn test_ip_limit() {
        let deny = IpLimit::new(
            &toml::from_str::<PluginConf>(
                r###"
category = 1
ip_list = [
    "192.168.1.1",
    "1.1.1.0/24",
]
    "###,
            )
            .unwrap(),
        )
        .unwrap();
        let headers = ["X-Forwarded-For: 2.1.1.2"].join("\r\n");
        let input_header = format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let result = deny
            .handle(&mut session, &mut State::default())
            .await
            .unwrap();
        assert_eq!(true, result.is_none());

        let headers = ["Accept-Encoding: gzip"].join("\r\n");
        let input_header = format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let result = deny
            .handle(
                &mut session,
                &mut State {
                    client_ip: Some("2.1.1.2".to_string()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(true, result.is_none());

        let result = deny
            .handle(
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
