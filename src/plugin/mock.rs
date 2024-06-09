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

use super::{get_step_conf, get_str_conf, Error, ProxyPlugin, Result};
use crate::config::{PluginCategory, PluginConf, PluginStep};
use crate::http_extra::{convert_headers, HttpResponse};
use crate::plugin::{get_int_conf, get_str_slice_conf};
use crate::state::State;
use async_trait::async_trait;
use http::StatusCode;
use log::debug;
use pingora::proxy::Session;

pub struct MockResponse {
    pub path: String,
    pub plugin_step: PluginStep,
    pub resp: HttpResponse,
}

impl MockResponse {
    /// Creates a new mock response upstream, which will return a mock data.
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!("new mock proxy plugin, params:{params:?}");
        let step = get_step_conf(params);
        if ![PluginStep::Request, PluginStep::ProxyUpstream].contains(&step) {
            return Err(Error::Invalid {
                category: PluginCategory::Mock.to_string(),
                message: "Mock plugin should be executed at request or proxy upstream step"
                    .to_string(),
            });
        }

        let path = get_str_conf(params, "path");
        let status = get_int_conf(params, "status") as u16;
        let headers = get_str_slice_conf(params, "headers");
        let data = get_str_conf(params, "data");

        let mut resp = HttpResponse {
            status: StatusCode::OK,
            body: data.into(),
            ..Default::default()
        };
        if status > 0 {
            resp.status = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
        }
        if !headers.is_empty() {
            if let Ok(headers) = convert_headers(&headers) {
                resp.headers = Some(headers);
            }
        }

        Ok(MockResponse {
            resp,
            plugin_step: step,
            path,
        })
    }
}

#[async_trait]
impl ProxyPlugin for MockResponse {
    #[inline]
    fn step(&self) -> String {
        self.plugin_step.to_string()
    }
    #[inline]
    fn category(&self) -> PluginCategory {
        PluginCategory::Mock
    }
    #[inline]
    /// Sends the mock data to client.
    async fn handle(
        &self,
        step: PluginStep,
        session: &mut Session,
        _ctx: &mut State,
    ) -> pingora::Result<Option<HttpResponse>> {
        if step != self.plugin_step {
            return Ok(None);
        }
        if !self.path.is_empty() && session.req_header().uri.path() != self.path {
            return Ok(None);
        }
        Ok(Some(self.resp.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::MockResponse;
    use crate::state::State;
    use crate::{config::PluginConf, config::PluginStep, plugin::ProxyPlugin};
    use bytes::Bytes;
    use http::StatusCode;
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    #[test]
    fn test_mock_params() {
        let params = MockResponse::new(
            &toml::from_str::<PluginConf>(
                r###"
path = "/"
status = 500
headers = [
    "Content-Type: application/json"
]
data = "{\"message\":\"Mock Service Unavailable\"}"
"###,
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!("/", params.path);
        assert_eq!("request", params.step().to_string());
        assert_eq!("mock", params.category().to_string());

        let result = MockResponse::new(
            &toml::from_str::<PluginConf>(
                r###"
step = "response"
path = "/"
status = 500
headers = [
    "Content-Type: application/json"
]
data = "{\"message\":\"Mock Service Unavailable\"}"
"###,
            )
            .unwrap(),
        );
        assert_eq!("Plugin mock invalid, message: Mock plugin should be executed at request or proxy upstream step", result.err().unwrap().to_string())
    }

    #[tokio::test]
    async fn test_mock_response() {
        let params = toml::from_str::<PluginConf>(
            r###"
path = "/vicanso/pingap"
status = 500
headers = [
    "Content-Type: application/json"
]
data = "{\"message\":\"Mock Service Unavailable\"}"
"###,
        )
        .unwrap();

        let mock = MockResponse::new(&params).unwrap();

        let headers = ["Accept-Encoding: gzip"].join("\r\n");
        let input_header = format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let result = mock
            .handle(PluginStep::Request, &mut session, &mut State::default())
            .await
            .unwrap();

        assert_eq!(true, result.is_some());

        let resp = result.unwrap();
        assert_eq!(StatusCode::INTERNAL_SERVER_ERROR, resp.status);
        assert_eq!(
            r###"Some([("content-type", "application/json")])"###,
            format!("{:?}", resp.headers)
        );
        assert_eq!(
            Bytes::from_static(b"{\"message\":\"Mock Service Unavailable\"}"),
            resp.body
        );

        let headers = ["Accept-Encoding: gzip"].join("\r\n");
        let input_header = format!("GET /vicanso?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let result = mock
            .handle(PluginStep::Request, &mut session, &mut State::default())
            .await
            .unwrap();
        assert_eq!(true, result.is_none());
    }
}
