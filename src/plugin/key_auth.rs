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
    get_bool_conf, get_step_conf, get_str_conf, get_str_slice_conf, Error, ProxyPlugin, Result,
};
use crate::config::{PluginCategory, PluginConf, PluginStep};
use crate::http_extra::HttpResponse;
use crate::state::State;
use crate::util;
use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderName, StatusCode};
use log::{debug, error};
use pingora::proxy::Session;
use std::str::FromStr;

pub struct KeyAuth {
    key_category: String,
    plugin_step: PluginStep,
    header_name: Option<HeaderName>,
    query_name: Option<String>,
    keys: Vec<Vec<u8>>,
    miss_authorization_resp: HttpResponse,
    unauthorized_resp: HttpResponse,
    hide_credentials: bool,
}

struct KeyAuthParams {
    key_category: String,
    plugin_step: PluginStep,
    header_name: Option<HeaderName>,
    query_name: Option<String>,
    keys: Vec<Vec<u8>>,
    hide_credentials: bool,
}

impl TryFrom<&PluginConf> for KeyAuthParams {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        let step = get_step_conf(value);

        let category = get_str_conf(value, "type");
        let name = get_str_conf(value, "name");
        if name.is_empty() {
            return Err(Error::Invalid {
                category: PluginCategory::KeyAuth.to_string(),
                message: "Auth key is not allowed empty".to_string(),
            });
        }
        let mut query_name = None;
        let mut header_name = None;
        if category == "query" {
            query_name = Some(name);
        } else {
            header_name = Some(HeaderName::from_str(&name).map_err(|e| Error::Invalid {
                category: PluginCategory::KeyAuth.to_string(),
                message: format!("invalid header name, {e}"),
            })?);
        }
        let params = Self {
            key_category: category,
            keys: get_str_slice_conf(value, "keys")
                .iter()
                .map(|item| item.as_bytes().to_vec())
                .collect(),
            hide_credentials: get_bool_conf(value, "hide_credentials"),
            plugin_step: step,
            query_name,
            header_name,
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
        debug!("new key auth proxy plugin, params:{params:?}");
        let params = KeyAuthParams::try_from(params)?;

        Ok(Self {
            key_category: params.key_category,
            keys: params.keys,
            plugin_step: params.plugin_step,
            query_name: params.query_name,
            header_name: params.header_name,
            hide_credentials: params.hide_credentials,
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
        })
    }
}

#[async_trait]
impl ProxyPlugin for KeyAuth {
    #[inline]
    fn step(&self) -> PluginStep {
        self.plugin_step
    }
    #[inline]
    fn category(&self) -> PluginCategory {
        PluginCategory::KeyAuth
    }
    #[inline]
    async fn handle(
        &self,
        session: &mut Session,
        _ctx: &mut State,
    ) -> pingora::Result<Option<HttpResponse>> {
        let value = if self.key_category == "query" {
            self.query_name.as_ref().map(|name| {
                util::get_query_value(session.req_header(), name)
                    .unwrap_or_default()
                    .as_bytes()
            })
        } else {
            self.header_name
                .as_ref()
                .map(|v| session.get_header_bytes(v))
        };
        if value.is_none() || value.unwrap().is_empty() {
            return Ok(Some(self.miss_authorization_resp.clone()));
        }
        if !self.keys.contains(&value.unwrap().to_vec()) {
            return Ok(Some(self.unauthorized_resp.clone()));
        }
        if self.hide_credentials {
            if let Some(name) = &self.header_name {
                session.req_header_mut().remove_header(name);
            } else if let Some(name) = &self.query_name {
                if let Err(e) = util::remove_query_from_header(session.req_header_mut(), name) {
                    error!("Remove query fail, error:{e:?}");
                }
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::{KeyAuth, KeyAuthParams};
    use crate::state::State;
    use crate::{config::PluginConf, plugin::ProxyPlugin};
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    #[test]
    fn test_key_auth_params() {
        let params = KeyAuthParams::try_from(
            &toml::from_str::<PluginConf>(
                r###"
name = "X-User"
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
        assert_eq!(true, params.header_name.is_some());
        if let Some(value) = params.header_name {
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

        let params = KeyAuthParams::try_from(
            &toml::from_str::<PluginConf>(
                r###"
name = "X-User"
type = "query"
keys = [
    "123",
    "456",
]
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!("query", params.key_category);

        let result = KeyAuthParams::try_from(
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

        let result = KeyAuthParams::try_from(
            &toml::from_str::<PluginConf>(
                r###"
step = "upstream_response"
name = "X-User"
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
name = "X-User"
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
            .handle(&mut session, &mut State::default())
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
            .handle(&mut session, &mut State::default())
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
            .handle(&mut session, &mut State::default())
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
type = "query"
name = "user"
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
            .handle(&mut session, &mut State::default())
            .await
            .unwrap();
        assert_eq!(true, result.is_none());
        assert_eq!(
            "/vicanso/pingap?type=1",
            session.req_header().uri.to_string()
        );
    }
}
