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
use crate::config::PluginCategory;
use crate::config::PluginStep;
use crate::http_extra::HttpResponse;
use crate::state::State;
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use bytes::Bytes;
use http::HeaderValue;
use http::StatusCode;
use log::debug;
use pingora::proxy::Session;

pub struct BasicAuth {
    proxy_step: PluginStep,
    authorizations: Vec<Vec<u8>>,
    miss_authorization_resp: HttpResponse,
    unauthorized_resp: HttpResponse,
}

impl BasicAuth {
    pub fn new(value: &str, proxy_step: PluginStep) -> Result<Self> {
        debug!("new basic auth proxy plugin, {value}, {proxy_step:?}");
        let mut authorizations = vec![];
        for item in value.split(' ') {
            let _ = STANDARD
                .decode(item)
                .map_err(|e| Error::Base64Decode { source: e })?;

            authorizations.push(format!("Basic {item}").as_bytes().to_owned());
        }

        Ok(Self {
            proxy_step,
            authorizations,
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
        self.proxy_step
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
        return Ok(None);
    }
}

#[cfg(test)]
mod tests {
    use super::BasicAuth;
    use crate::state::State;
    use crate::{config::PluginStep, plugin::ProxyPlugin};
    use http::StatusCode;
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    #[tokio::test]
    async fn test_basic_auth() {
        let auth = BasicAuth::new("YWRtaW46MTIzMTIz", PluginStep::ProxyUpstream).unwrap();

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
