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

use super::{get_int_conf, get_step_conf, get_str_conf, Error, Plugin, Result};
use crate::config::{PluginCategory, PluginConf, PluginStep};
use crate::http_extra::HttpResponse;
use crate::http_extra::HTTP_HEADER_NAME_X_REQUEST_ID;
use crate::state::State;
use async_trait::async_trait;
use http::HeaderName;
use nanoid::nanoid;
use pingora::proxy::Session;
use std::str::FromStr;
use tracing::debug;
use uuid::Uuid;

pub struct RequestId {
    plugin_step: PluginStep,
    algorithm: String,
    header_name: Option<HeaderName>,
    size: usize,
}

impl TryFrom<&PluginConf> for RequestId {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        let step = get_step_conf(value);
        let header_name = get_str_conf(value, "header_name");
        let header_name = if header_name.is_empty() {
            None
        } else {
            Some(
                HeaderName::from_str(&header_name).map_err(|e| Error::Invalid {
                    category: "header_name".to_string(),
                    message: e.to_string(),
                })?,
            )
        };

        let params = Self {
            plugin_step: step,
            algorithm: get_str_conf(value, "algorithm"),
            size: get_int_conf(value, "size") as usize,
            header_name,
        };
        if ![PluginStep::Request, PluginStep::ProxyUpstream].contains(&params.plugin_step) {
            return Err(Error::Invalid {
                category: PluginCategory::RequestId.to_string(),
                message: "Request id should be executed at request or proxy upstream step"
                    .to_string(),
            });
        }
        Ok(params)
    }
}

impl RequestId {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new request id plugin");
        Self::try_from(params)
    }
}

#[async_trait]
impl Plugin for RequestId {
    #[inline]
    fn step(&self) -> String {
        self.plugin_step.to_string()
    }
    #[inline]
    fn category(&self) -> PluginCategory {
        PluginCategory::RequestId
    }
    #[inline]
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut State,
    ) -> pingora::Result<Option<HttpResponse>> {
        if step != self.plugin_step {
            return Ok(None);
        }
        let key = if let Some(header) = &self.header_name {
            header.clone()
        } else {
            HTTP_HEADER_NAME_X_REQUEST_ID.clone()
        };
        if let Some(id) = session.get_header(&key) {
            ctx.request_id = Some(id.to_str().unwrap_or_default().to_string());
            return Ok(None);
        }
        let id = match self.algorithm.as_str() {
            "nanoid" => {
                let size = self.size;
                nanoid!(size)
            }
            _ => Uuid::now_v7().to_string(),
        };
        ctx.request_id = Some(id.clone());
        let _ = session.req_header_mut().insert_header(key, &id);
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::RequestId;
    use crate::state::State;
    use crate::{config::PluginConf, config::PluginStep, plugin::Plugin};
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    #[test]
    fn test_request_id_params() {
        let params = RequestId::new(
            &toml::from_str::<PluginConf>(
                r###"
algorithm = "nanoid"
size = 10
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!("nanoid", params.algorithm);
        assert_eq!(10, params.size);

        let params = RequestId::new(
            &toml::from_str::<PluginConf>(
                r###"
algorithm = "nanoid"
size = 10
header_name = "uid"
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!("uid", params.header_name.unwrap().to_string());

        let result = RequestId::new(
            &toml::from_str::<PluginConf>(
                r###"
step = "response"
algorithm = "nanoid"
size = 10
"###,
            )
            .unwrap(),
        );
        assert_eq!("Plugin request_id invalid, message: Request id should be executed at request or proxy upstream step", result.err().unwrap().to_string());
    }

    #[tokio::test]
    async fn test_request_id() {
        let id = RequestId::new(
            &toml::from_str::<PluginConf>(
                r###"
algorithm = "nanoid"
size = 10
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!("request_id", id.category().to_string());
        assert_eq!("request", id.step().to_string());

        let headers = ["X-Request-Id: 123"].join("\r\n");
        let input_header = format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let mut state = State::default();
        let result = id
            .handle_request(PluginStep::Request, &mut session, &mut state)
            .await
            .unwrap();
        assert_eq!(true, result.is_none());
        assert_eq!("123", state.request_id.unwrap_or_default());

        let headers = ["Accept-Encoding: gzip"].join("\r\n");
        let input_header = format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let mut state = State::default();
        let result = id
            .handle_request(PluginStep::Request, &mut session, &mut state)
            .await
            .unwrap();
        assert_eq!(true, result.is_none());
        assert_eq!(10, state.request_id.unwrap_or_default().len());
    }
}
