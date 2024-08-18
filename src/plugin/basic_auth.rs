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
    get_bool_conf, get_hash_key, get_step_conf, get_str_conf,
    get_str_slice_conf, Error, Plugin, Result,
};
use crate::config::{PluginCategory, PluginConf, PluginStep};
use crate::http_extra::HttpResponse;
use crate::state::State;
use crate::util::base64_decode;
use async_trait::async_trait;
use bytes::Bytes;
use http::HeaderValue;
use http::StatusCode;
use humantime::parse_duration;
use pingora::proxy::Session;
use std::time::Duration;
use tokio::time::sleep;
use tracing::debug;

pub struct BasicAuth {
    plugin_step: PluginStep,
    authorizations: Vec<Vec<u8>>,
    hide_credentials: bool,
    miss_authorization_resp: HttpResponse,
    unauthorized_resp: HttpResponse,
    delay: Option<Duration>,
    hash_value: String,
}

impl TryFrom<&PluginConf> for BasicAuth {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);
        let step = get_step_conf(value);

        let delay = get_str_conf(value, "delay");
        let delay = if !delay.is_empty() {
            let d = parse_duration(&delay).map_err(|e| Error::Invalid {
                category: PluginCategory::KeyAuth.to_string(),
                message: e.to_string(),
            })?;
            Some(d)
        } else {
            None
        };
        let mut authorizations = vec![];
        for item in get_str_slice_conf(value, "authorizations").iter() {
            let _ = base64_decode(item).map_err(|e| Error::Base64Decode {
                category: PluginCategory::BasicAuth.to_string(),
                source: e,
            })?;
            authorizations.push(format!("Basic {item}").as_bytes().to_vec());
        }
        if authorizations.is_empty() {
            return Err(Error::Invalid {
                category: PluginCategory::BasicAuth.to_string(),
                message: "basic authorizations can't be empty".to_string(),
            });
        }
        let params = Self {
            hash_value,
            plugin_step: step,
            delay,
            hide_credentials: get_bool_conf(value, "hide_credentials"),
            authorizations,
            miss_authorization_resp: HttpResponse {
                status: StatusCode::UNAUTHORIZED,
                headers: Some(vec![(
                    http::header::WWW_AUTHENTICATE,
                    HeaderValue::from_str(
                        r###"Basic realm="Access to the staging site""###,
                    )
                    .unwrap(),
                )]),
                body: Bytes::from_static(b"Authorization is missing"),
                ..Default::default()
            },
            unauthorized_resp: HttpResponse {
                status: StatusCode::UNAUTHORIZED,
                headers: Some(vec![(
                    http::header::WWW_AUTHENTICATE,
                    HeaderValue::from_str(
                        r###"Basic realm="Access to the staging site""###,
                    )
                    .unwrap(),
                )]),
                body: Bytes::from_static(b"Invalid user or password"),
                ..Default::default()
            },
        };
        if ![PluginStep::Request].contains(&params.plugin_step) {
            return Err(Error::Invalid {
                category: PluginCategory::BasicAuth.to_string(),
                message: "Basic auth plugin should be executed at request step"
                    .to_string(),
            });
        }
        Ok(params)
    }
}

impl BasicAuth {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new basic auth plugin");
        Self::try_from(params)
    }
}

#[async_trait]
impl Plugin for BasicAuth {
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
        let value = session.get_header_bytes(http::header::AUTHORIZATION);
        if value.is_empty() {
            return Ok(Some(self.miss_authorization_resp.clone()));
        }
        if !self.authorizations.contains(&value.to_vec()) {
            if let Some(d) = self.delay {
                sleep(d).await;
            }
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
    use super::{BasicAuth, Plugin};
    use crate::config::{PluginConf, PluginStep};
    use crate::state::State;
    use http::StatusCode;
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    #[test]
    fn test_basic_auth_params() {
        let params = BasicAuth::try_from(
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

        let result = BasicAuth::try_from(
            &toml::from_str::<PluginConf>(
                r###"
authorizations = [
"1"
]
"###,
            )
            .unwrap(),
        );
        assert_eq!(
            "Plugin basic_auth, base64 decode error Invalid input length: 1",
            result.err().unwrap().to_string()
        );

        let result = BasicAuth::try_from(
            &toml::from_str::<PluginConf>(
                r###"
step = "response"
authorizations = [
"1234"
]
"###,
            )
            .unwrap(),
        );
        assert_eq!(
            "Plugin basic_auth invalid, message: Basic auth plugin should be executed at request step",
            result.err().unwrap().to_string()
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
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = auth
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut State::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result.is_none());

        // auth fail
        let headers = ["Authorization: Basic YWRtaW46MTIzMTIa"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = auth
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut State::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result.is_some());
        assert_eq!(StatusCode::UNAUTHORIZED, result.unwrap().status);
    }
}
