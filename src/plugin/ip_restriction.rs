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

use super::{get_step_conf, get_str_conf, get_str_slice_conf, Error, ProxyPlugin, Result};
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

pub struct IpRestriction {
    plugin_step: PluginStep,
    ip_net_list: Vec<IpNet>,
    ip_list: Vec<String>,
    restriction_category: String,
    forbidden_resp: HttpResponse,
}

struct IpRestrictionParams {
    plugin_step: PluginStep,
    ip_net_list: Vec<IpNet>,
    ip_list: Vec<String>,
    restriction_category: String,
    message: String,
}

impl TryFrom<&PluginConf> for IpRestrictionParams {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        let step = get_step_conf(value);

        let mut ip_net_list = vec![];
        let mut ip_list = vec![];
        for item in get_str_slice_conf(value, "ip_list") {
            if let Ok(value) = IpNet::from_str(&item) {
                ip_net_list.push(value);
            } else {
                ip_list.push(item);
            }
        }
        let params = Self {
            plugin_step: step,
            ip_list,
            ip_net_list,
            restriction_category: get_str_conf(value, "type"),
            message: get_str_conf(value, "message"),
        };
        if ![PluginStep::Request, PluginStep::ProxyUpstream].contains(&params.plugin_step) {
            return Err(Error::Invalid {
                category: PluginCategory::IpRestriction.to_string(),
                message:
                    "Ip restriction plugin should be executed at request or proxy upstream step"
                        .to_string(),
            });
        }
        Ok(params)
    }
}

impl IpRestriction {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!("new ip restriction proxy plugin, params:{params:?}");
        let params = IpRestrictionParams::try_from(params)?;
        let mut message = params.message;
        if message.is_empty() {
            message = "Request is forbidden".to_string();
        }
        Ok(Self {
            plugin_step: params.plugin_step,
            ip_list: params.ip_list,
            ip_net_list: params.ip_net_list,
            restriction_category: params.restriction_category,
            forbidden_resp: HttpResponse {
                status: StatusCode::FORBIDDEN,
                body: Bytes::from(message),
                ..Default::default()
            },
        })
    }
}

#[async_trait]
impl ProxyPlugin for IpRestriction {
    #[inline]
    fn step(&self) -> String {
        self.plugin_step.to_string()
    }
    #[inline]
    fn category(&self) -> PluginCategory {
        PluginCategory::IpRestriction
    }
    #[inline]
    async fn handle(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut State,
    ) -> pingora::Result<Option<HttpResponse>> {
        if step != self.plugin_step {
            return Ok(None);
        }
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
    use super::{IpRestriction, IpRestrictionParams};
    use crate::state::State;
    use crate::{config::PluginConf, config::PluginStep, plugin::ProxyPlugin};
    use http::StatusCode;
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    #[test]
    fn test_ip_limit_params() {
        let params = IpRestrictionParams::try_from(
            &toml::from_str::<PluginConf>(
                r###"
ip_list = [
    "192.168.1.1",
    "10.1.1.1",
    "1.1.1.0/24",
    "2.1.1.0/24",
]
type = "deny"
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!("request", params.plugin_step.to_string());
        assert_eq!("192.168.1.1,10.1.1.1", params.ip_list.join(","));
        assert_eq!(
            "1.1.1.0/24,2.1.1.0/24",
            params
                .ip_net_list
                .iter()
                .map(|item| item.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );

        let result = IpRestrictionParams::try_from(
            &toml::from_str::<PluginConf>(
                r###"
step = "upstream_response"
ip_list = [
    "192.168.1.1",
    "10.1.1.1",
    "1.1.1.0/24",
    "2.1.1.0/24",
]
type = "deny"
"###,
            )
            .unwrap(),
        );
        assert_eq!("Plugin ip_restriction invalid, message: Ip restriction plugin should be executed at request or proxy upstream step", result.err().unwrap().to_string());
    }

    #[tokio::test]
    async fn test_ip_limit() {
        let deny = IpRestriction::new(
            &toml::from_str::<PluginConf>(
                r###"
type = "deny"
ip_list = [
    "192.168.1.1",
    "1.1.1.0/24",
]
    "###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!("ip_restriction", deny.category().to_string());
        assert_eq!("request", deny.step().to_string());

        let headers = ["X-Forwarded-For: 2.1.1.2"].join("\r\n");
        let input_header = format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let result = deny
            .handle(PluginStep::Request, &mut session, &mut State::default())
            .await
            .unwrap();
        assert_eq!(true, result.is_none());

        let headers = ["X-Forwarded-For: 192.168.1.1"].join("\r\n");
        let input_header = format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let result = deny
            .handle(PluginStep::Request, &mut session, &mut State::default())
            .await
            .unwrap();
        assert_eq!(true, result.is_some());

        let headers = ["Accept-Encoding: gzip"].join("\r\n");
        let input_header = format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let result = deny
            .handle(
                PluginStep::Request,
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

        let allow = IpRestriction::new(
            &toml::from_str::<PluginConf>(
                r###"
type = "allow"
ip_list = [
    "192.168.1.1",
    "1.1.1.0/24",
]
    "###,
            )
            .unwrap(),
        )
        .unwrap();
        let headers = ["X-Forwarded-For: 192.168.1.1"].join("\r\n");
        let input_header = format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let result = allow
            .handle(PluginStep::Request, &mut session, &mut State::default())
            .await
            .unwrap();
        assert_eq!(true, result.is_none());
    }
}
