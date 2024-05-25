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

use super::{get_int_conf, get_step_conf, Error, ProxyPlugin, Result};
use crate::config::{PluginCategory, PluginConf, PluginStep};
use crate::http_extra::HttpResponse;
use crate::state::State;
use async_trait::async_trait;
use http::HeaderValue;
use log::debug;
use once_cell::sync::Lazy;
use pingora::proxy::Session;

static ZSTD_ENCODING: Lazy<HeaderValue> = Lazy::new(|| "zstd".try_into().unwrap());
static BR_ENCODING: Lazy<HeaderValue> = Lazy::new(|| "br".try_into().unwrap());
static GZIP_ENCODING: Lazy<HeaderValue> = Lazy::new(|| "gzip".try_into().unwrap());

pub struct Compression {
    gzip_level: u32,
    br_level: u32,
    zstd_level: u32,
    support_compression: bool,
    plugin_step: PluginStep,
}

struct CompressionParams {
    gzip_level: u32,
    br_level: u32,
    zstd_level: u32,
    plugin_step: PluginStep,
}

impl TryFrom<&PluginConf> for CompressionParams {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        let step = get_step_conf(value);
        let params = Self {
            gzip_level: get_int_conf(value, "gzip_level") as u32,
            br_level: get_int_conf(value, "br_level") as u32,
            zstd_level: get_int_conf(value, "zstd_level") as u32,
            plugin_step: step,
        };
        if ![PluginStep::Request, PluginStep::ProxyUpstream].contains(&params.plugin_step) {
            return Err(Error::Invalid {
                category: PluginCategory::Compression.to_string(),
                message: "Compression plugin should be executed at request or proxy upstream step"
                    .to_string(),
            });
        }
        Ok(params)
    }
}

impl Compression {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!("new compresson proxy plugin, params:{params:?}");
        let params = CompressionParams::try_from(params)?;
        let support_compression = params.gzip_level + params.br_level + params.zstd_level > 0;
        Ok(Self {
            plugin_step: params.plugin_step,
            gzip_level: params.gzip_level,
            br_level: params.br_level,
            zstd_level: params.zstd_level,
            support_compression,
        })
    }
}

#[async_trait]
impl ProxyPlugin for Compression {
    #[inline]
    fn step(&self) -> PluginStep {
        self.plugin_step
    }
    #[inline]
    fn category(&self) -> PluginCategory {
        PluginCategory::Compression
    }
    #[inline]
    async fn handle(
        &self,
        session: &mut Session,
        _ctx: &mut State,
    ) -> pingora::Result<Option<HttpResponse>> {
        if !self.support_compression {
            return Ok(None);
        }
        let header = session.req_header_mut();
        if let Some(accept_encoding) = header.headers.get(http::header::ACCEPT_ENCODING) {
            let accept_encoding = accept_encoding.to_str().unwrap_or_default();
            if accept_encoding.is_empty() {
                return Ok(None);
            }
            let level = if self.zstd_level > 0 && accept_encoding.contains("zstd") {
                let _ = header.insert_header(http::header::ACCEPT_ENCODING, ZSTD_ENCODING.clone());
                self.zstd_level
            } else if self.br_level > 0 && accept_encoding.contains("br") {
                let _ = header.insert_header(http::header::ACCEPT_ENCODING, BR_ENCODING.clone());
                self.br_level
            } else if self.gzip_level > 0 && accept_encoding.contains("gzip") {
                let _ = header.insert_header(http::header::ACCEPT_ENCODING, GZIP_ENCODING.clone());
                self.gzip_level
            } else {
                0
            };
            debug!("Compression level:{level}");
            if level > 0 {
                session.downstream_compression.adjust_decompression(true);
                session.downstream_compression.adjust_level(level);
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::Compression;
    use crate::plugin::compression::CompressionParams;
    use crate::state::State;
    use crate::{config::PluginConf, plugin::ProxyPlugin};
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    #[test]
    fn test_compression_params() {
        let params = CompressionParams::try_from(
            &toml::from_str::<PluginConf>(
                r###"
gzip_level = 9
br_level = 8
zstd_level = 6
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!("request", params.plugin_step.to_string());
        assert_eq!(9, params.gzip_level);
        assert_eq!(8, params.br_level);
        assert_eq!(6, params.zstd_level);

        let result = CompressionParams::try_from(
            &toml::from_str::<PluginConf>(
                r###"
step = "upstream_response"
gzip_level = 9
br_level = 8
zstd_level = 6
"###,
            )
            .unwrap(),
        );
        assert_eq!("Plugin compression invalid, message: Compression plugin should be executed at request or proxy upstream step", result.err().unwrap().to_string());
    }

    #[tokio::test]
    async fn test_compression() {
        let compression = Compression::new(
            &toml::from_str::<PluginConf>(
                r###"
gzip_level = 9
br_level = 8
zstd_level = 7
"###,
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!("compression", compression.category().to_string());
        assert_eq!("request", compression.step().to_string());

        // gzip
        let headers = ["Accept-Encoding: gzip"].join("\r\n");
        let input_header = format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = compression
            .handle(&mut session, &mut State::default())
            .await
            .unwrap();
        assert_eq!(true, result.is_none());
        assert_eq!(true, session.downstream_compression.is_enabled());

        // brotli
        let headers = ["Accept-Encoding: br"].join("\r\n");
        let input_header = format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = compression
            .handle(&mut session, &mut State::default())
            .await
            .unwrap();
        assert_eq!(true, result.is_none());
        assert_eq!(true, session.downstream_compression.is_enabled());

        // zstd
        let headers = ["Accept-Encoding: zstd"].join("\r\n");
        let input_header = format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = compression
            .handle(&mut session, &mut State::default())
            .await
            .unwrap();
        assert_eq!(true, result.is_none());
        assert_eq!(true, session.downstream_compression.is_enabled());

        // not support compression
        let headers = ["Accept-Encoding: none"].join("\r\n");
        let input_header = format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = compression
            .handle(&mut session, &mut State::default())
            .await
            .unwrap();
        assert_eq!(true, result.is_none());
        assert_eq!(false, session.downstream_compression.is_enabled());
    }
}
