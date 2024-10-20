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
    get_bool_conf, get_step_conf, get_str_conf, Error, Plugin, Result,
};
use crate::config::{PluginCategory, PluginConf, PluginStep};
use crate::http_extra::convert_headers;
use crate::http_extra::HttpResponse;
use crate::plugin::get_hash_key;
use crate::state::State;
use crate::util;
use async_trait::async_trait;
use http::StatusCode;
use pingora::proxy::Session;
use tracing::debug;

pub struct Redirect {
    prefix: String,
    http_to_https: bool,
    plugin_step: PluginStep,
    hash_value: String,
}

impl Redirect {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new redirect plugin");
        let hash_value = get_hash_key(params);
        let step = get_step_conf(params);
        if step != PluginStep::Request {
            return Err(Error::Invalid {
                category: PluginCategory::Redirect.to_string(),
                message:
                    "Redirect https plugin should be executed at request step"
                        .to_string(),
            });
        }
        let mut prefix = get_str_conf(params, "prefix");
        if prefix.len() <= 1 {
            prefix = "".to_string();
        } else if !prefix.starts_with("/") {
            prefix = format!("/{prefix}");
        }
        Ok(Self {
            hash_value,
            prefix,
            http_to_https: get_bool_conf(params, "http_to_https"),
            plugin_step: step,
        })
    }
}

#[async_trait]
impl Plugin for Redirect {
    #[inline]
    fn hash_key(&self) -> String {
        self.hash_value.clone()
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
        let schema_match = ctx.tls_version.is_some() == self.http_to_https;
        if schema_match
            && session.req_header().uri.path().starts_with(&self.prefix)
        {
            return Ok(None);
        }
        let host = util::get_host(session.req_header()).unwrap_or_default();
        let schema = if self.http_to_https { "https" } else { "http" };
        let location = format!(
            "Location: {}://{host}{}{}",
            schema,
            self.prefix,
            session.req_header().uri
        );
        Ok(Some(HttpResponse {
            status: StatusCode::TEMPORARY_REDIRECT,
            headers: Some(convert_headers(&[location]).unwrap_or_default()),
            ..Default::default()
        }))
    }
}
#[cfg(test)]
mod tests {
    use super::Redirect;
    use crate::state::State;
    use crate::{config::PluginConf, config::PluginStep, plugin::Plugin};
    use http::StatusCode;
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    #[tokio::test]
    async fn test_redirect() {
        let redirect = Redirect::new(
            &toml::from_str::<PluginConf>(
                r###"
http_to_https = true
prefix = "/api"
"###,
            )
            .unwrap(),
        )
        .unwrap();

        let headers = ["Host: github.com"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = redirect
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut State::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result.is_some());
        let resp = result.unwrap();
        assert_eq!(StatusCode::TEMPORARY_REDIRECT, resp.status);
        assert_eq!(
            r###"Some([("location", "https://github.com/api/vicanso/pingap?size=1")])"###,
            format!("{:?}", resp.headers)
        );

        let params = Redirect::new(
            &toml::from_str::<PluginConf>(
                r###"
step = "response"
http_to_https = true
prefix = "/api"
"###,
            )
            .unwrap(),
        );
        assert_eq!(
            "Plugin redirect invalid, message: Redirect https plugin should be executed at request step",
            params.err().unwrap().to_string()
        );
    }
}
