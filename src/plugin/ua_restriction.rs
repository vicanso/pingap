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
use regex::Regex;
use tracing::debug;

pub struct UaRestriction {
    plugin_step: PluginStep,
    ua_list: Vec<Regex>,
    restriction_category: String,
    forbidden_resp: HttpResponse,
    hash_value: String,
}

impl TryFrom<&PluginConf> for UaRestriction {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);
        let step = get_step_conf(value);
        let mut ua_list = vec![];
        for item in get_str_slice_conf(value, "ua_list").iter() {
            let reg = Regex::new(item).map_err(|e| Error::Invalid {
                category: "regex".to_string(),
                message: e.to_string(),
            })?;
            ua_list.push(reg);
        }

        let mut message = get_str_conf(value, "message");
        if message.is_empty() {
            message = "Request is forbidden".to_string();
        }
        let params = Self {
            hash_value,
            plugin_step: step,
            ua_list,
            restriction_category: get_str_conf(value, "type"),
            forbidden_resp: HttpResponse {
                status: StatusCode::FORBIDDEN,
                body: Bytes::from(message),
                ..Default::default()
            },
        };
        if PluginStep::Request != params.plugin_step {
            return Err(Error::Invalid {
                category: PluginCategory::UaRestriction.to_string(),
                message: "User agent restriction plugin should be executed at request or proxy upstream step".to_string(),
            });
        }

        Ok(params)
    }
}

impl UaRestriction {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(
            params = params.to_string(),
            "new user agent restriction plugin"
        );
        Self::try_from(params)
    }
}

#[async_trait]
impl Plugin for UaRestriction {
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
        if let Some(value) = session.get_header(http::header::USER_AGENT) {
            let ua = value.to_str().unwrap_or_default();
            for item in self.ua_list.iter() {
                if !found && item.is_match(ua) {
                    found = true;
                }
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
    use super::UaRestriction;
    use crate::state::State;
    use crate::{config::PluginConf, config::PluginStep, plugin::Plugin};
    use http::StatusCode;
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    #[test]
    fn test_ua_restriction_params() {
        let params = UaRestriction::try_from(
            &toml::from_str::<PluginConf>(
                r###"
ua_list = [
"go-http-client/1.1",
"(Twitterspider)/(\\d+)\\.(\\d+)"
]
type = "deny"
"###,
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!("request", params.plugin_step.to_string());
        assert_eq!(
            r#"go-http-client/1.1,(Twitterspider)/(\d+)\.(\d+)"#,
            params
                .ua_list
                .iter()
                .map(|item| item.to_string())
                .collect::<Vec<String>>()
                .join(",")
        );

        assert_eq!("deny", params.restriction_category);
    }

    #[tokio::test]
    async fn test_ua_restriction() {
        let deny = UaRestriction::new(
            &toml::from_str::<PluginConf>(
                r###"
ua_list = [
"go-http-client/1.1",
"(Twitterspider)/(\\d+)\\.(\\d+)"
]
type = "deny"
    "###,
            )
            .unwrap(),
        )
        .unwrap();

        let headers = ["User-Agent: pingap/1.0"].join("\r\n");
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

        let headers = ["User-Agent: go-http-client/1.1"].join("\r\n");
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

        let headers = ["User-Agent: Twitterspider/1.1"].join("\r\n");
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
