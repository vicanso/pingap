// Copyright 2024-2025 Tree xie.
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
    get_bool_conf, get_hash_key, get_int_conf, get_plugin_factory,
    get_str_conf, Error,
};
use async_trait::async_trait;
use bytes::Bytes;
use ctor::ctor;
use http::header::{
    ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE,
    TRANSFER_ENCODING,
};
use http::HeaderValue;
use pingap_config::PluginConf;
use pingap_core::HTTP_HEADER_TRANSFER_CHUNKED;
use pingap_core::{new_internal_error, ModifyResponseBody};
use pingap_core::{Ctx, HttpResponse, Plugin, PluginStep};
use pingora::http::ResponseHeader;
use pingora::modules::http::compression::ResponseCompression;
use pingora::protocols::http::compression::Algorithm;
use pingora::proxy::Session;
use std::str::FromStr;
use std::sync::Arc;
use tracing::debug;

type Result<T, E = Error> = std::result::Result<T, E>;

// Constants defining supported compression algorithm identifiers
const ZSTD: &str = "zstd"; // Zstandard compression
const BR: &str = "br"; // Brotli compression
const GZIP: &str = "gzip"; // Gzip compression

const FULL_BODY_COMPRESS_MODE: &str = "full";

struct Compressor {
    algorithm: Algorithm,
    level: u32,
}

impl ModifyResponseBody for Compressor {
    fn handle(&self, data: Bytes) -> pingora::Result<Bytes> {
        let compressor = self.algorithm.compressor(self.level);
        if let Some(mut compressor) = compressor {
            let data = compressor
                .encode(data.as_ref(), true)
                .map_err(|e| new_internal_error(500, e.to_string()))?;
            return Ok(data);
        }
        Err(new_internal_error(
            500,
            format!(
                "Compress algorithm {} is not supported",
                self.algorithm.as_str()
            ),
        ))
    }
    fn name(&self) -> String {
        "compression".to_string()
    }
}

/// Plugin for handling HTTP response compression
/// Supports multiple compression algorithms with configurable compression levels
pub struct Compression {
    // Compression levels for each algorithm (0-9 for gzip, 0-11 for brotli, 0-22 for zstd)
    gzip_level: u32,
    br_level: u32,
    zstd_level: u32,
    // Flag indicating if any compression algorithm is enabled (any level > 0)
    support_compression: bool,
    // Optional setting to control decompression of incoming requests
    decompression: Option<bool>,
    // Defines when this plugin runs in the request processing pipeline
    plugin_step: PluginStep,
    // Pipe mode or full body mode
    mode: String,
    // Unique identifier for caching and tracking plugin instances
    hash_value: String,
}

// Implementation to create Compression from configuration
impl TryFrom<&PluginConf> for Compression {
    type Error = Error;

    /// Attempts to create a Compression instance from plugin configuration
    ///
    /// # Arguments
    /// * `value` - Plugin configuration containing compression settings
    ///
    /// # Returns
    /// * `Result<Self>` - Configured compression plugin or error
    ///
    /// # Configuration Options
    /// * `gzip_level` - Compression level for gzip (0-9)
    /// * `br_level` - Compression level for brotli (0-11)
    /// * `zstd_level` - Compression level for zstd (0-22)
    /// * `decompression` - Optional boolean to control request decompression
    fn try_from(value: &PluginConf) -> Result<Self> {
        // Generate unique hash for this configuration
        let hash_value = get_hash_key(value);

        // Parse optional decompression setting
        let mut decompression = None;
        if value.contains_key("decompression") {
            decompression = Some(get_bool_conf(value, "decompression"));
        }

        // Get compression levels from configuration
        let gzip_level = get_int_conf(value, "gzip_level") as u32;
        let br_level = get_int_conf(value, "br_level") as u32;
        let zstd_level = get_int_conf(value, "zstd_level") as u32;
        let mode = get_str_conf(value, "mode");

        // Enable compression if any algorithm has a non-zero level
        let support_compression = gzip_level + br_level + zstd_level > 0;

        let params = Self {
            hash_value,
            gzip_level,
            br_level,
            zstd_level,
            decompression,
            support_compression,
            mode,
            // Plugin runs during early request phase
            plugin_step: PluginStep::EarlyRequest,
        };

        Ok(params)
    }
}

impl Compression {
    /// Creates a new Compression plugin instance from the provided configuration
    ///
    /// # Arguments
    /// * `params` - Plugin configuration containing compression settings
    ///
    /// # Returns
    /// * `Result<Self>` - New compression plugin instance or error
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new compression plugin");
        Self::try_from(params)
    }
    fn get_compress_level(&self, session: &Session) -> (u32, u32, u32) {
        // Extract and validate Accept-Encoding header
        let header = session.req_header();
        let Some(accept_encoding) = header.headers.get(ACCEPT_ENCODING) else {
            return (0, 0, 0);
        };
        let accept_encoding = accept_encoding.to_str().unwrap_or_default();
        if accept_encoding.is_empty() {
            return (0, 0, 0);
        }

        // Select compression algorithm based on priority and client support
        // Priority: zstd > br > gzip
        let mut zstd_level = 0;
        let mut br_level = 0;
        let mut gzip_level = 0;
        if self.zstd_level > 0 && accept_encoding.contains(ZSTD) {
            zstd_level = self.zstd_level;
        }
        if self.br_level > 0 && accept_encoding.contains(BR) {
            br_level = self.br_level;
        }
        if self.gzip_level > 0 && accept_encoding.contains(GZIP) {
            gzip_level = self.gzip_level;
        }
        (zstd_level, br_level, gzip_level)
    }
}

#[async_trait]
impl Plugin for Compression {
    /// Returns the unique hash key for this plugin instance
    /// Used for caching and identifying plugin configurations
    #[inline]
    fn hash_key(&self) -> String {
        self.hash_value.clone()
    }

    /// Processes incoming HTTP requests to configure response compression
    ///
    /// # Arguments
    /// * `step` - Current plugin processing step
    /// * `session` - HTTP session containing request/response data
    /// * `_ctx` - Ctx context (unused)
    ///
    /// # Returns
    /// * `pingora::Result<Option<HttpResponse>>` - None if successful, or HTTP response on error
    ///
    /// # Processing Steps
    /// 1. Validates plugin should run at current step
    /// 2. Checks if compression is enabled
    /// 3. Examines client's Accept-Encoding header
    /// 4. Selects best compression algorithm
    /// 5. Configures compression settings in session context
    #[inline]
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<(bool, Option<HttpResponse>)> {
        if step == PluginStep::EarlyRequest
            && self.mode == FULL_BODY_COMPRESS_MODE
        {
            let (zstd_level, br_level, gzip_level) =
                self.get_compress_level(session);
            let key = if zstd_level > 0 {
                ZSTD
            } else if br_level > 0 {
                BR
            } else if gzip_level > 0 {
                GZIP
            } else {
                ""
            };
            if !key.is_empty() {
                ctx.push_cache_key(key.to_string());
            }
        }
        // Early return conditions
        if step != self.plugin_step {
            return Ok((false, None));
        }
        if !self.support_compression {
            return Ok((false, None));
        }
        if self.mode == FULL_BODY_COMPRESS_MODE {
            return Ok((false, None));
        }
        let (zstd_level, br_level, gzip_level) =
            self.get_compress_level(session);

        debug!(zstd_level, br_level, gzip_level, "pipe compression level");

        if zstd_level == 0 && br_level == 0 && gzip_level == 0 {
            return Ok((false, None));
        }

        // Get compression context from session
        let Some(c) = session
            .downstream_modules_ctx
            .get_mut::<ResponseCompression>()
        else {
            return Ok((false, None));
        };

        // Configure decompression if specified
        if let Some(decompression) = self.decompression {
            c.adjust_decompression(decompression);
        }

        // Configure compression levels for each supported algorithm
        if zstd_level > 0 {
            c.adjust_algorithm_level(Algorithm::Zstd, zstd_level);
        }
        if br_level > 0 {
            c.adjust_algorithm_level(Algorithm::Brotli, br_level);
        }
        if gzip_level > 0 {
            c.adjust_algorithm_level(Algorithm::Gzip, gzip_level);
        }

        Ok((true, None))
    }
    fn handle_upstream_response(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut Ctx,
        upstream_response: &mut ResponseHeader,
    ) -> pingora::Result<bool> {
        if step != PluginStep::UpstreamResponse
            || !self.support_compression
            || self.mode != FULL_BODY_COMPRESS_MODE
        {
            return Ok(false);
        }
        if upstream_response.headers.contains_key(CONTENT_ENCODING) {
            return Ok(false);
        }
        let Some(content_type) = upstream_response.headers.get(CONTENT_TYPE)
        else {
            return Ok(false);
        };
        if !is_compressible_content_type(content_type) {
            return Ok(false);
        }
        let (zstd_level, br_level, gzip_level) =
            self.get_compress_level(session);
        if zstd_level == 0 && br_level == 0 && gzip_level == 0 {
            return Ok(false);
        }
        debug!(
            zstd_level,
            br_level, gzip_level, "full body compression level"
        );
        // Remove content-length since we're modifying the body
        upstream_response.remove_header(&CONTENT_LENGTH);
        // Switch to chunked transfer encoding
        let _ = upstream_response.insert_header(
            TRANSFER_ENCODING,
            HTTP_HEADER_TRANSFER_CHUNKED.1.clone(),
        );
        let encoding = if zstd_level > 0 {
            ctx.modify_upstream_response_body = Some(Box::new(Compressor {
                algorithm: Algorithm::Zstd,
                level: zstd_level,
            }));
            ZSTD
        } else if br_level > 0 {
            ctx.modify_upstream_response_body = Some(Box::new(Compressor {
                algorithm: Algorithm::Brotli,
                level: br_level,
            }));
            BR
        } else {
            ctx.modify_upstream_response_body = Some(Box::new(Compressor {
                algorithm: Algorithm::Gzip,
                level: gzip_level,
            }));
            GZIP
        };
        let _ = upstream_response.insert_header(CONTENT_ENCODING, encoding);

        Ok(false)
    }
}

fn is_compressible_content_type(content_type: &HeaderValue) -> bool {
    let Ok(content_type) = content_type.to_str() else {
        return false;
    };
    let Ok(mime) = mime_guess::Mime::from_str(content_type) else {
        return false;
    };
    match mime.essence_str() {
        "application/json" | "application/xml" | "text/html" => true,
        _ => mime.type_() == "text",
    }
}

#[ctor]
fn init() {
    get_plugin_factory().register("compression", |params| {
        Ok(Arc::new(Compression::new(params)?))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingap_config::PluginConf;
    use pingap_core::{Ctx, PluginStep};
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
        let (executed, result) = compression
            .handle_request(
                PluginStep::EarlyRequest,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, executed);
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
        let (executed, result) = compression
            .handle_request(
                PluginStep::EarlyRequest,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, executed);
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
        let (executed, result) = compression
            .handle_request(
                PluginStep::EarlyRequest,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, executed);
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
        let (executed, result) = compression
            .handle_request(
                PluginStep::EarlyRequest,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        assert_eq!(false, executed);
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
