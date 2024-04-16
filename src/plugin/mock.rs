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

use super::{Error, ProxyPlugin, Result};
use crate::config::{ProxyPluginCategory, ProxyPluginStep};
use crate::http_extra::{convert_headers, HttpResponse};
use crate::state::State;
use async_trait::async_trait;
use bytes::Bytes;
use http::StatusCode;
use pingora::proxy::Session;
use serde::{Deserialize, Serialize};

#[derive(Default, Deserialize, Serialize, Clone)]
pub struct MockInfo {
    path: Option<String>,
    status: Option<u16>,
    headers: Option<Vec<String>>,
    data: String,
}

pub struct MockResponse {
    pub path: String,
    pub proxy_step: ProxyPluginStep,
    pub resp: HttpResponse,
}

impl MockResponse {
    /// Creates a new mock response upstream, which will return a mock data.
    pub fn new(value: &str, proxy_step: ProxyPluginStep) -> Result<Self> {
        let info: MockInfo = serde_json::from_str(value).map_err(|e| Error::Json { source: e })?;

        let mut resp = HttpResponse {
            status: StatusCode::OK,
            body: Bytes::from(info.data.clone()),
            ..Default::default()
        };
        if let Some(status) = info.status {
            resp.status = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
        }
        if let Some(value) = &info.headers {
            if let Ok(headers) = convert_headers(value) {
                resp.headers = Some(headers);
            }
        }

        Ok(MockResponse {
            resp,
            proxy_step,
            path: info.path.unwrap_or_default(),
        })
    }
}

#[async_trait]
impl ProxyPlugin for MockResponse {
    #[inline]
    fn step(&self) -> ProxyPluginStep {
        self.proxy_step
    }
    #[inline]
    fn category(&self) -> ProxyPluginCategory {
        ProxyPluginCategory::Mock
    }
    #[inline]
    /// Sends the mock data to client.
    async fn handle(&self, session: &mut Session, _ctx: &mut State) -> pingora::Result<bool> {
        if !self.path.is_empty() && session.req_header().uri.path() != self.path {
            return Ok(false);
        }
        let _ = self.resp.clone().send(session).await?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use crate::config::ProxyPluginStep;

    use super::MockResponse;
    use bytes::Bytes;
    use http::StatusCode;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_mock_response() {
        let resp = MockResponse::new(
            r###"{"status":500,"headers":["Content-Type: application/json"],"data":"{\"message\":\"Mock Service Unavailable\"}"}"###,
             ProxyPluginStep::RequestFilter).unwrap().resp;
        assert_eq!(StatusCode::INTERNAL_SERVER_ERROR, resp.status);
        assert_eq!(
            r###"Some([("content-type", "application/json")])"###,
            format!("{:?}", resp.headers)
        );
        assert_eq!(
            Bytes::from_static(b"{\"message\":\"Mock Service Unavailable\"}"),
            resp.body
        );
    }
}
