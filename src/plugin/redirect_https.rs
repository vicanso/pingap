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
use super::Result;
use crate::config::PluginCategory;
use crate::config::PluginStep;
use crate::http_extra::convert_headers;
use crate::http_extra::HttpResponse;
use crate::state::State;
use async_trait::async_trait;
use http::StatusCode;
use pingora::proxy::Session;

pub struct RedirectHttps {
    prefix: String,
    proxy_step: PluginStep,
}

impl RedirectHttps {
    pub fn new(value: &str, proxy_step: PluginStep) -> Result<Self> {
        let mut prefix = "".to_string();
        if value.trim().len() > 1 {
            prefix = value.trim().to_string();
        }
        Ok(Self { prefix, proxy_step })
    }
}

#[async_trait]
impl ProxyPlugin for RedirectHttps {
    #[inline]
    fn step(&self) -> PluginStep {
        self.proxy_step
    }
    #[inline]
    fn category(&self) -> PluginCategory {
        PluginCategory::RedirectHttps
    }
    #[inline]
    async fn handle(
        &self,
        session: &mut Session,
        ctx: &mut State,
    ) -> pingora::Result<Option<HttpResponse>> {
        if ctx.tls_version.is_none() {
            let host = if let Some(value) = session.get_header("Host") {
                value.to_str().unwrap_or_default()
            } else {
                session.req_header().uri.host().unwrap_or_default()
            };
            let location = format!(
                "Location: https://{host}{}{}",
                self.prefix,
                session.req_header().uri
            );
            return Ok(Some(HttpResponse {
                status: StatusCode::TEMPORARY_REDIRECT,
                headers: Some(convert_headers(&[location]).unwrap_or_default()),
                ..Default::default()
            }));
        }
        Ok(None)
    }
}
#[cfg(test)]
mod tests {
    use super::RedirectHttps;
    use crate::state::State;
    use crate::{config::PluginStep, plugin::ProxyPlugin};
    use http::StatusCode;
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    #[tokio::test]
    async fn test_redirect_https() {
        let redirect = RedirectHttps::new("/api", PluginStep::RequestFilter).unwrap();

        let headers = ["Host: github.com"].join("\r\n");
        let input_header = format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = redirect
            .handle(&mut session, &mut State::default())
            .await
            .unwrap();
        assert_eq!(true, result.is_some());
        let resp = result.unwrap();
        assert_eq!(StatusCode::TEMPORARY_REDIRECT, resp.status);
        assert_eq!(
            r###"Some([("location", "https://github.com/api/vicanso/pingap?size=1")])"###,
            format!("{:?}", resp.headers)
        );
    }
}
