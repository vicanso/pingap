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
    get_bool_conf, get_step_conf, get_str_conf, get_str_slice_conf, Error, Plugin, Result,
};
use crate::config::{PluginCategory, PluginConf, PluginStep};
use crate::http_extra::HttpResponse;
use crate::state::State;
use crate::util;
use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderName, StatusCode};
use pingora::proxy::Session;
use std::str::FromStr;
use tracing::{debug, error};

pub struct KeyAuth {
    plugin_step: PluginStep,
    header: Option<HeaderName>,
    query: Option<String>,
    keys: Vec<Vec<u8>>,
    miss_authorization_resp: HttpResponse,
    unauthorized_resp: HttpResponse,
    hide_credentials: bool,
}

impl TryFrom<&PluginConf> for KeyAuth {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        let step = get_step_conf(value);

        let query_name = get_str_conf(value, "query");
        let header_name = get_str_conf(value, "header");
        if query_name.is_empty() && header_name.is_empty() {
            return Err(Error::Invalid {
                category: PluginCategory::KeyAuth.to_string(),
                message: "Auth key is not allowed empty".to_string(),
            });
        }
        let mut query = None;
        let mut header = None;
        if !query_name.is_empty() {
            query = Some(query_name);
        } else {
            header = Some(
                HeaderName::from_str(&header_name).map_err(|e| Error::Invalid {
                    category: PluginCategory::KeyAuth.to_string(),
                    message: format!("invalid header name, {e}"),
                })?,
            );
        }
        let params = Self {
            keys: get_str_slice_conf(value, "keys")
                .iter()
                .map(|item| item.as_bytes().to_vec())
                .collect(),
            hide_credentials: get_bool_conf(value, "hide_credentials"),
            plugin_step: step,
            query,
            header,
            miss_authorization_resp: HttpResponse {
                status: StatusCode::UNAUTHORIZED,
                body: Bytes::from_static(b"Key missing"),
                ..Default::default()
            },
            unauthorized_resp: HttpResponse {
                status: StatusCode::UNAUTHORIZED,
                body: Bytes::from_static(b"Key auth fail"),
                ..Default::default()
            },
        };
        if ![PluginStep::Request, PluginStep::ProxyUpstream].contains(&params.plugin_step) {
            return Err(Error::Invalid {
                category: PluginCategory::KeyAuth.to_string(),
                message: "Key auth plugin should be executed at request or proxy upstream step"
                    .to_string(),
            });
        }
        Ok(params)
    }
}

impl KeyAuth {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new key auth plugin");
        Self::try_from(params)
    }
}

#[async_trait]
impl Plugin for KeyAuth {
    #[inline]
    fn step(&self) -> String {
        self.plugin_step.to_string()
    }
    #[inline]
    fn category(&self) -> PluginCategory {
        PluginCategory::KeyAuth
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
        let value = if let Some(key) = &self.query {
            util::get_query_value(session.req_header(), key)
                .unwrap_or_default()
                .as_bytes()
        } else {
            self.header
                .as_ref()
                .map(|v| session.get_header_bytes(v))
                .unwrap_or_default()
        };
        if value.is_empty() {
            return Ok(Some(self.miss_authorization_resp.clone()));
        }
        if !self.keys.contains(&value.to_vec()) {
            return Ok(Some(self.unauthorized_resp.clone()));
        }
        if self.hide_credentials {
            if let Some(name) = &self.header {
                session.req_header_mut().remove_header(name);
            } else if let Some(name) = &self.query {
                if let Err(e) = util::remove_query_from_header(session.req_header_mut(), name) {
                    error!(error = e.to_string(), "remove query fail");
                }
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::KeyAuth;
    use crate::state::State;
    use crate::{config::PluginConf, config::PluginStep, plugin::Plugin};
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    #[test]
    fn test_key_auth_params() {
        let params = KeyAuth::try_from(
            &toml::from_str::<PluginConf>(
                r###"
header = "X-User"
keys = [
    "123",
    "456",
]
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!("request", params.plugin_step.to_string());
        assert_eq!(true, params.header.is_some());
        if let Some(value) = params.header {
            assert_eq!("x-user", value.to_string());
        }
        assert_eq!(
            "123,456",
            params
                .keys
                .iter()
                .map(|item| std::string::String::from_utf8_lossy(item))
                .collect::<Vec<_>>()
                .join(",")
        );

        let result = KeyAuth::try_from(
            &toml::from_str::<PluginConf>(
                r###"
keys = [
    "123",
    "456",
]
"###,
            )
            .unwrap(),
        );
        assert_eq!(
            "Plugin key_auth invalid, message: Auth key is not allowed empty",
            result.err().unwrap().to_string()
        );

        let result = KeyAuth::try_from(
            &toml::from_str::<PluginConf>(
                r###"
step = "response"
header = "X-User"
keys = [
    "123",
    "456",
]
"###,
            )
            .unwrap(),
        );
        assert_eq!(
            "Plugin key_auth invalid, message: Key auth plugin should be executed at request or proxy upstream step",
            result.err().unwrap().to_string()
        );
    }

    #[tokio::test]
    async fn test_key_auth() {
        let auth = KeyAuth::new(
            &toml::from_str::<PluginConf>(
                r###"
header = "X-User"
keys = [
    "123",
    "456",
]
hide_credentials = true
"###,
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!("key_auth", auth.category().to_string());
        assert_eq!("request", auth.step().to_string());

        let headers = ["X-User: 123"].join("\r\n");
        let input_header = format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        assert_eq!(false, session.get_header_bytes("X-User").is_empty());
        let result = auth
            .handle_request(PluginStep::Request, &mut session, &mut State::default())
            .await
            .unwrap();
        assert_eq!(true, result.is_none());
        assert_eq!(true, session.get_header_bytes("X-User").is_empty());

        let headers = ["X-User: 12"].join("\r\n");
        let input_header = format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = auth
            .handle_request(PluginStep::Request, &mut session, &mut State::default())
            .await
            .unwrap();
        let resp = result.unwrap();
        assert_eq!(401, resp.status.as_u16());
        assert_eq!(
            "Key auth fail",
            std::string::String::from_utf8_lossy(resp.body.as_ref())
        );

        let headers = [""].join("\r\n");
        let input_header = format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = auth
            .handle_request(PluginStep::Request, &mut session, &mut State::default())
            .await
            .unwrap();
        let resp = result.unwrap();
        assert_eq!(401, resp.status.as_u16());
        assert_eq!(
            "Key missing",
            std::string::String::from_utf8_lossy(resp.body.as_ref())
        );

        let auth = KeyAuth::new(
            &toml::from_str::<PluginConf>(
                r###"
query = "user"
keys = [
    "123",
    "456",
]
hide_credentials = true
"###,
            )
            .unwrap(),
        )
        .unwrap();
        let headers = [""].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?user=123&type=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        assert_eq!(
            "/vicanso/pingap?user=123&type=1",
            session.req_header().uri.to_string()
        );
        let result = auth
            .handle_request(PluginStep::Request, &mut session, &mut State::default())
            .await
            .unwrap();
        assert_eq!(true, result.is_none());
        assert_eq!(
            "/vicanso/pingap?type=1",
            session.req_header().uri.to_string()
        );
    }
}
