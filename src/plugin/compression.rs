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

use super::{get_bool_conf, get_hash_key, get_int_conf, Error, Plugin, Result};
use crate::config::{PluginConf, PluginStep};
use crate::http_extra::HttpResponse;
use crate::state::State;
use async_trait::async_trait;
use http::HeaderValue;
use once_cell::sync::Lazy;
use pingora::modules::http::compression::ResponseCompression;
use pingora::protocols::http::compression::Algorithm;
use pingora::proxy::Session;
use tracing::debug;

const ZSTD: &str = "zstd";
const BR: &str = "br";
const GZIP: &str = "gzip";

static ZSTD_ENCODING: Lazy<HeaderValue> =
    Lazy::new(|| ZSTD.try_into().unwrap());
static BR_ENCODING: Lazy<HeaderValue> = Lazy::new(|| BR.try_into().unwrap());
static GZIP_ENCODING: Lazy<HeaderValue> =
    Lazy::new(|| GZIP.try_into().unwrap());

pub struct Compression {
    gzip_level: u32,
    br_level: u32,
    zstd_level: u32,
    support_compression: bool,
    decompression: Option<bool>,
    plugin_step: PluginStep,
    hash_value: String,
}

impl TryFrom<&PluginConf> for Compression {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);
        let mut decompression = None;
        if value.contains_key("decompression") {
            decompression = Some(get_bool_conf(value, "decompression"));
        }
        let gzip_level = get_int_conf(value, "gzip_level") as u32;
        let br_level = get_int_conf(value, "br_level") as u32;
        let zstd_level = get_int_conf(value, "zstd_level") as u32;
        let support_compression = gzip_level + br_level + zstd_level > 0;

        let params = Self {
            hash_value,
            gzip_level,
            br_level,
            zstd_level,
            decompression,
            support_compression,
            plugin_step: PluginStep::EarlyRequest,
        };

        Ok(params)
    }
}

impl Compression {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new compresson plugin");
        Self::try_from(params)
    }
}

#[async_trait]
impl Plugin for Compression {
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
        if !self.support_compression {
            return Ok(None);
        }
        let header = session.req_header_mut();
        let Some(accept_encoding) =
            header.headers.get(http::header::ACCEPT_ENCODING)
        else {
            return Ok(None);
        };
        let accept_encoding = accept_encoding.to_str().unwrap_or_default();
        if accept_encoding.is_empty() {
            return Ok(None);
        }
        // compression order, zstd > br > gzip
        // Wait for pingora support to specify the order
        let level = if self.zstd_level > 0 && accept_encoding.contains(ZSTD) {
            let _ = header.insert_header(
                http::header::ACCEPT_ENCODING,
                ZSTD_ENCODING.clone(),
            );
            self.zstd_level
        } else if self.br_level > 0 && accept_encoding.contains(BR) {
            let _ = header.insert_header(
                http::header::ACCEPT_ENCODING,
                BR_ENCODING.clone(),
            );
            self.br_level
        } else if self.gzip_level > 0 && accept_encoding.contains(GZIP) {
            let _ = header.insert_header(
                http::header::ACCEPT_ENCODING,
                GZIP_ENCODING.clone(),
            );
            self.gzip_level
        } else {
            0
        };
        debug!(level, "compression level");
        if level == 0 {
            return Ok(None);
        }
        let Some(c) = session
            .downstream_modules_ctx
            .get_mut::<ResponseCompression>()
        else {
            return Ok(None);
        };
        if let Some(decompression) = self.decompression {
            c.adjust_decompression(decompression);
        }
        if self.zstd_level > 0 {
            c.adjust_algorithm_level(Algorithm::Zstd, self.zstd_level);
        }
        if self.br_level > 0 {
            c.adjust_algorithm_level(Algorithm::Brotli, self.br_level);
        }
        if self.gzip_level > 0 {
            c.adjust_algorithm_level(Algorithm::Gzip, self.gzip_level);
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::Compression;
    use crate::state::State;
    use crate::{config::PluginConf, config::PluginStep, plugin::Plugin};
    use pingora::modules::http::compression::{
        ResponseCompression, ResponseCompressionBuilder,
    };
    use pingora::modules::http::HttpModules;
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    #[test]
    fn test_compression_params() {
        let params = Compression::try_from(
            &toml::from_str::<PluginConf>(
                r###"
step = "early_request"
gzip_level = 9
br_level = 8
zstd_level = 6
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!("early_request", params.plugin_step.to_string());
        assert_eq!(9, params.gzip_level);
        assert_eq!(8, params.br_level);
        assert_eq!(6, params.zstd_level);
    }

    #[tokio::test]
    async fn test_compression() {
        let compression = Compression::new(
            &toml::from_str::<PluginConf>(
                r###"
step = "early_request"
gzip_level = 9
br_level = 8
zstd_level = 7
"###,
            )
            .unwrap(),
        )
        .unwrap();

        // gzip
        let headers = ["Accept-Encoding: gzip"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut modules = HttpModules::new();
        modules.add_module(ResponseCompressionBuilder::enable(0));
        let mut session =
            Session::new_h1_with_modules(Box::new(mock_io), &modules);
        session.read_request().await.unwrap();
        let result = compression
            .handle_request(
                PluginStep::EarlyRequest,
                &mut session,
                &mut State::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result.is_none());
        assert_eq!(
            true,
            session
                .downstream_modules_ctx
                .get::<ResponseCompression>()
                .unwrap()
                .is_enabled()
        );

        // brotli
        let headers = ["Accept-Encoding: br"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut modules = HttpModules::new();
        modules.add_module(ResponseCompressionBuilder::enable(0));
        let mut session =
            Session::new_h1_with_modules(Box::new(mock_io), &modules);
        session.read_request().await.unwrap();
        let result = compression
            .handle_request(
                PluginStep::EarlyRequest,
                &mut session,
                &mut State::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result.is_none());
        assert_eq!(
            true,
            session
                .downstream_modules_ctx
                .get::<ResponseCompression>()
                .unwrap()
                .is_enabled()
        );

        // zstd
        let headers = ["Accept-Encoding: zstd"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut modules = HttpModules::new();
        modules.add_module(ResponseCompressionBuilder::enable(0));
        let mut session =
            Session::new_h1_with_modules(Box::new(mock_io), &modules);
        session.read_request().await.unwrap();
        let result = compression
            .handle_request(
                PluginStep::EarlyRequest,
                &mut session,
                &mut State::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result.is_none());
        assert_eq!(
            true,
            session
                .downstream_modules_ctx
                .get::<ResponseCompression>()
                .unwrap()
                .is_enabled()
        );

        // not support compression
        let headers = ["Accept-Encoding: none"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut modules = HttpModules::new();
        modules.add_module(ResponseCompressionBuilder::enable(0));
        let mut session =
            Session::new_h1_with_modules(Box::new(mock_io), &modules);
        session.read_request().await.unwrap();
        let result = compression
            .handle_request(
                PluginStep::EarlyRequest,
                &mut session,
                &mut State::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result.is_none());
        assert_eq!(
            false,
            session
                .downstream_modules_ctx
                .get::<ResponseCompression>()
                .unwrap()
                .is_enabled()
        );
    }
}
