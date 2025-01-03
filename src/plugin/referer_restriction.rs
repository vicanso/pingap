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
    get_hash_key, get_step_conf, get_str_conf, get_str_slice_conf, Error,
    Plugin, Result,
};
use crate::config::{PluginCategory, PluginConf, PluginStep};
use crate::http_extra::HttpResponse;
use crate::state::State;
use async_trait::async_trait;
use bytes::Bytes;
use http::StatusCode;
use pingora::proxy::Session;
use substring::Substring;
use tracing::debug;

pub struct RefererRestriction {
    plugin_step: PluginStep,
    referer_list: Vec<String>,
    prefix_referer_list: Vec<String>,
    restriction_category: String,
    forbidden_resp: HttpResponse,
    hash_value: String,
}

impl TryFrom<&PluginConf> for RefererRestriction {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);
        let step = get_step_conf(value);
        let mut referer_list = vec![];
        let mut prefix_referer_list = vec![];
        for item in get_str_slice_conf(value, "referer_list").iter() {
            if item.starts_with('*') {
                prefix_referer_list
                    .push(item.substring(1, item.len()).to_string());
            } else {
                referer_list.push(item.to_string());
            }
        }

        let mut message = get_str_conf(value, "message");
        if message.is_empty() {
            message = "Request is forbidden".to_string();
        }
        let params = Self {
            hash_value,
            plugin_step: step,
            prefix_referer_list,
            referer_list,
            restriction_category: get_str_conf(value, "type"),
            forbidden_resp: HttpResponse {
                status: StatusCode::FORBIDDEN,
                body: Bytes::from(message),
                ..Default::default()
            },
        };
        if PluginStep::Request != params.plugin_step {
            return Err(Error::Invalid {
                category: PluginCategory::RefererRestriction.to_string(),
                message: "Referer restriction plugin should be executed at request or proxy upstream step".to_string(),
            });
        }

        Ok(params)
    }
}

impl RefererRestriction {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(
            params = params.to_string(),
            "new referer restriction plugin"
        );
        Self::try_from(params)
    }
}

#[async_trait]
impl Plugin for RefererRestriction {
    #[inline]
    fn hash_key(&self) -> String {
        self.hash_value.clone()
    }
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
        let mut found = false;
        if let Some(value) = session.get_header(http::header::REFERER) {
            let referer = value.to_str().unwrap_or_default().to_string();
            let host = if let Ok(info) = url::Url::parse(&referer) {
                info.host_str().unwrap_or_default().to_string()
            } else {
                "".to_string()
            };
            if self.referer_list.contains(&host) {
                found = true;
            } else {
                found = self
                    .prefix_referer_list
                    .iter()
                    .any(|item| host.ends_with(item));
            }
        }
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
    use super::RefererRestriction;
    use crate::state::State;
    use crate::{config::PluginConf, config::PluginStep, plugin::Plugin};
    use http::StatusCode;
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    #[test]
    fn test_referer_restriction_params() {
        let params = RefererRestriction::try_from(
            &toml::from_str::<PluginConf>(
                r###"
referer_list = [
    "github.com",
    "*.bing.cn",
]
type = "deny"
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!("request", params.plugin_step.to_string());
        assert_eq!(".bing.cn", params.prefix_referer_list.join(","));
        assert_eq!("github.com", params.referer_list.join(","));

        let result = RefererRestriction::try_from(
            &toml::from_str::<PluginConf>(
                r###"
step = "response"
referer_list = [
    "github.com",
    "*.bing.cn",
]
type = "deny"
"###,
            )
            .unwrap(),
        );
        assert_eq!("Plugin referer_restriction invalid, message: Referer restriction plugin should be executed at request or proxy upstream step", result.err().unwrap().to_string());
    }

    #[tokio::test]
    async fn test_referer_restriction() {
        let deny = RefererRestriction::new(
            &toml::from_str::<PluginConf>(
                r###"
referer_list = [
    "github.com",
    "*.bing.cn",
]
type = "deny"
    "###,
            )
            .unwrap(),
        )
        .unwrap();

        let headers = ["Referer: https://google.com/"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let result = deny
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut State::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result.is_none());

        let headers = ["Referer: https://github.com/"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let result = deny
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut State::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result.is_some());
        assert_eq!(StatusCode::FORBIDDEN, result.unwrap().status);

        let headers = ["Referer: https://test.bing.cn/"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = deny
            .handle_request(
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
    }
}
