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
use crate::config::{ProxyPluginCategory, ProxyPluginStep};
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
    proxy_step: ProxyPluginStep,
}

impl Compression {
    pub fn new(value: &str, proxy_step: ProxyPluginStep) -> Result<Self> {
        debug!("new compresson proxy plugin, {value}, {proxy_step:?}");

        let mut levels: [u32; 3] = [0, 0, 0];
        let mut support_compression = false;
        for (index, item) in value.split(' ').enumerate() {
            if index >= levels.len() {
                break;
            }
            let level = item
                .parse::<u32>()
                .map_err(|e| Error::ParseInt { source: e })?;
            if level > 0 {
                support_compression = true;
                levels[index] = level;
            }
        }
        Ok(Self {
            proxy_step,
            gzip_level: levels[0],
            br_level: levels[1],
            zstd_level: levels[2],
            support_compression,
        })
    }
}

#[async_trait]
impl ProxyPlugin for Compression {
    #[inline]
    fn step(&self) -> ProxyPluginStep {
        self.proxy_step
    }
    #[inline]
    fn category(&self) -> ProxyPluginCategory {
        ProxyPluginCategory::Compression
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
    use crate::state::State;
    use crate::{config::ProxyPluginStep, plugin::ProxyPlugin};
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    #[tokio::test]
    async fn test_basic_auth() {
        let compression = Compression::new("9 8 7", ProxyPluginStep::ProxyUpstreamFilter).unwrap();

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
