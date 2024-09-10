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

use super::{get_bool_conf, get_hash_key, get_str_conf, Error, Plugin, Result};
use crate::config::{PluginConf, PluginStep};
use crate::http_extra::HttpResponse;
use crate::state::State;
use async_trait::async_trait;
use pingora::proxy::Session;
use tracing::debug;

pub struct AcceptEncoding {
    encodings: Vec<String>,
    only_one_encoding: Option<bool>,
    hash_value: String,
    plugin_step: PluginStep,
}

impl TryFrom<&PluginConf> for AcceptEncoding {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);
        let only_one_encoding = get_bool_conf(value, "only_one_encoding");
        let mut encodings = vec![];
        for encoding in get_str_conf(value, "encodings").split(",") {
            let v = encoding.trim();
            if !v.is_empty() {
                encodings.push(v.to_string());
            }
        }

        Ok(Self {
            encodings,
            only_one_encoding: Some(only_one_encoding),
            hash_value,
            plugin_step: PluginStep::EarlyRequest,
        })
    }
}

impl AcceptEncoding {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new accept encoding plugin");
        Self::try_from(params)
    }
}

#[async_trait]
impl Plugin for AcceptEncoding {
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
        let header = session.req_header_mut();

        let Some(accept_encoding) =
            header.headers.get(http::header::ACCEPT_ENCODING)
        else {
            return Ok(None);
        };
        let accept_encoding = accept_encoding.to_str().unwrap_or_default();

        let mut new_accept_encodings = vec![];
        let only_one_encoding = self.only_one_encoding.unwrap_or_default();

        for encoding in self.encodings.iter() {
            if only_one_encoding && !new_accept_encodings.is_empty() {
                break;
            }
            if accept_encoding.contains(encoding) {
                new_accept_encodings.push(encoding.to_string());
            }
        }
        if new_accept_encodings.is_empty() {
            header.remove_header(&http::header::ACCEPT_ENCODING);
        } else {
            let _ = header.insert_header(
                http::header::ACCEPT_ENCODING,
                new_accept_encodings.join(", "),
            );
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::AcceptEncoding;
    use crate::state::State;
    use crate::{config::PluginConf, config::PluginStep, plugin::Plugin};
    use pingora::modules::http::HttpModules;
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    #[test]
    fn test_accept_encoding_params() {
        let params = AcceptEncoding::try_from(
            &toml::from_str::<PluginConf>(
                r###"
encodings = "zstd, br, gzip"
only_one_encoding = true
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!("zstd,br,gzip", params.encodings.join(","));
        assert_eq!(true, params.only_one_encoding.unwrap_or_default());
    }

    #[tokio::test]
    async fn test_accept_conding() {
        let accept_enconding = AcceptEncoding::try_from(
            &toml::from_str::<PluginConf>(
                r###"
encodings = "zstd, br, gzip"
only_one_encoding = true
"###,
            )
            .unwrap(),
        )
        .unwrap();

        // zstd
        let headers = ["Accept-Encoding: gzip, zstd"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1_with_modules(
            Box::new(mock_io),
            &HttpModules::new(),
        );
        session.read_request().await.unwrap();
        let _ = accept_enconding
            .handle_request(
                PluginStep::EarlyRequest,
                &mut session,
                &mut State::default(),
            )
            .await
            .unwrap();

        assert_eq!(
            "zstd",
            session
                .req_header()
                .headers
                .get("Accept-Encoding")
                .unwrap()
                .to_str()
                .unwrap()
        );

        // multi accept encoding
        let accept_enconding = AcceptEncoding::try_from(
            &toml::from_str::<PluginConf>(
                r###"
encodings = "zstd, br, gzip"
"###,
            )
            .unwrap(),
        )
        .unwrap();
        let headers = ["Accept-Encoding: gzip, br, zstd"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1_with_modules(
            Box::new(mock_io),
            &HttpModules::new(),
        );
        session.read_request().await.unwrap();
        let _ = accept_enconding
            .handle_request(
                PluginStep::EarlyRequest,
                &mut session,
                &mut State::default(),
            )
            .await
            .unwrap();

        assert_eq!(
            "zstd, br, gzip",
            session
                .req_header()
                .headers
                .get("Accept-Encoding")
                .unwrap()
                .to_str()
                .unwrap()
        );

        let headers = ["Accept-Encoding: snappy"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1_with_modules(
            Box::new(mock_io),
            &HttpModules::new(),
        );
        session.read_request().await.unwrap();
        let _ = accept_enconding
            .handle_request(
                PluginStep::EarlyRequest,
                &mut session,
                &mut State::default(),
            )
            .await
            .unwrap();

        assert_eq!(
            true,
            session
                .req_header()
                .headers
                .get("Accept-Encoding")
                .is_none()
        );
    }
}
