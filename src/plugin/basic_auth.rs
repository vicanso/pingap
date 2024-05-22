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

use super::{get_bool_conf, get_step_conf, get_str_slice_conf, Error, ProxyPlugin, Result};
use crate::config::{PluginCategory, PluginConf, PluginStep};
use crate::http_extra::HttpResponse;
use crate::state::State;
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use bytes::Bytes;
use http::HeaderValue;
use http::StatusCode;
use log::debug;
use pingora::proxy::Session;

struct BasicAuthParams {
    plugin_step: PluginStep,
    authorizations: Vec<Vec<u8>>,
    hide_credentials: bool,
}

impl TryFrom<&PluginConf> for BasicAuthParams {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        let step = get_step_conf(value);

        let mut authorizations = vec![];
        for item in get_str_slice_conf(value, "authorizations").iter() {
            let _ = STANDARD.decode(item).map_err(|e| Error::Base64Decode {
                category: PluginCategory::BasicAuth.to_string(),
                source: e,
            })?;
            authorizations.push(format!("Basic {item}").as_bytes().to_vec());
        }
        let params = Self {
            plugin_step: step,
            hide_credentials: get_bool_conf(value, "hide_credentials"),
            authorizations,
        };
        if ![PluginStep::Request, PluginStep::ProxyUpstream].contains(&params.plugin_step) {
            return Err(Error::Invalid {
                category: PluginCategory::BasicAuth.to_string(),
                message: "Basic auth plugin should be executed at request or proxy upstream step"
                    .to_string(),
            });
        }
        Ok(params)
    }
}

pub struct BasicAuth {
    plugin_step: PluginStep,
    authorizations: Vec<Vec<u8>>,
    hide_credentials: bool,
    miss_authorization_resp: HttpResponse,
    unauthorized_resp: HttpResponse,
}

impl BasicAuth {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!("new basic auth proxy plugin, params:{params:?}");
        let params = BasicAuthParams::try_from(params)?;

        Ok(Self {
            plugin_step: params.plugin_step,
            authorizations: params.authorizations,
            hide_credentials: params.hide_credentials,
            miss_authorization_resp: HttpResponse {
                status: StatusCode::UNAUTHORIZED,
                headers: Some(vec![(
                    http::header::WWW_AUTHENTICATE,
                    HeaderValue::from_str(r###"Basic realm="Access to the staging site""###)
                        .unwrap(),
                )]),
                body: Bytes::from_static(b"Authorization is missing"),
                ..Default::default()
            },
            unauthorized_resp: HttpResponse {
                status: StatusCode::UNAUTHORIZED,
                headers: Some(vec![(
                    http::header::WWW_AUTHENTICATE,
                    HeaderValue::from_str(r###"Basic realm="Access to the staging site""###)
                        .unwrap(),
                )]),
                body: Bytes::from_static(b"Invalid user or password"),
                ..Default::default()
            },
        })
    }
}

#[async_trait]
impl ProxyPlugin for BasicAuth {
    #[inline]
    fn step(&self) -> PluginStep {
        self.plugin_step
    }
    #[inline]
    fn category(&self) -> PluginCategory {
        PluginCategory::BasicAuth
    }
    #[inline]
    async fn handle(
        &self,
        session: &mut Session,
        _ctx: &mut State,
    ) -> pingora::Result<Option<HttpResponse>> {
        let value = session.get_header_bytes(http::header::AUTHORIZATION);
        if value.is_empty() {
            return Ok(Some(self.miss_authorization_resp.clone()));
        }
        if !self.authorizations.contains(&value.to_vec()) {
            return Ok(Some(self.unauthorized_resp.clone()));
        }
        if self.hide_credentials {
            session
                .req_header_mut()
                .remove_header(&http::header::AUTHORIZATION);
        }
        return Ok(None);
    }
}

#[cfg(test)]
mod tests {
    use super::{BasicAuth, BasicAuthParams, ProxyPlugin};
    use crate::config::PluginConf;
    use crate::state::State;
    use http::StatusCode;
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    #[test]
    fn test_basic_auth_params() {
        let params = BasicAuthParams::try_from(
            &toml::from_str::<PluginConf>(
                r###"
authorizations = [
"MTIz",
"NDU2",
]
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!("request", params.plugin_step.to_string());
        assert_eq!(
            "Basic MTIz,Basic NDU2",
            params
                .authorizations
                .iter()
                .map(|item| std::string::String::from_utf8_lossy(item))
                .collect::<Vec<_>>()
                .join(","),
        );
    }

    #[tokio::test]
    async fn test_basic_auth() {
        let auth = BasicAuth::new(
            &toml::from_str::<PluginConf>(
                r###"
authorizations = [
    "YWRtaW46MTIzMTIz"
]
    "###,
            )
            .unwrap(),
        )
        .unwrap();

        // auth success
        let headers = ["Authorization: Basic YWRtaW46MTIzMTIz"].join("\r\n");
        let input_header = format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = auth
            .handle(&mut session, &mut State::default())
            .await
            .unwrap();
        assert_eq!(true, result.is_none());

        // auth fail
        let headers = ["Authorization: Basic YWRtaW46MTIzMTIa"].join("\r\n");
        let input_header = format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = auth
            .handle(&mut session, &mut State::default())
            .await
            .unwrap();
        assert_eq!(true, result.is_some());
        assert_eq!(StatusCode::UNAUTHORIZED, result.unwrap().status);
    }
}
