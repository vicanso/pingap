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
    Error, accepts_encoding, get_bool_conf, get_hash_key, get_int_conf,
    get_str_conf,
};
use async_trait::async_trait;
use http::header::{
    ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE,
    TRANSFER_ENCODING, VARY,
};
use http::{HeaderValue, Method, StatusCode};
use pingap_config::{PluginCategory, PluginConf};
use pingap_core::HTTP_HEADER_TRANSFER_CHUNKED;
use pingap_core::{
    Ctx, ModifyResponseBody, Plugin, PluginStep, RequestPluginResult,
    ResponseBodyPluginResult, ResponsePluginResult, new_internal_error,
};
use pingora::http::ResponseHeader;
use pingora::modules::http::compression::ResponseCompression;
use pingora::protocols::http::compression::{Algorithm, Encode};
use pingora::proxy::Session;
use std::borrow::Cow;
use std::str::FromStr;
use tracing::debug;

type Result<T, E = Error> = std::result::Result<T, E>;

// Constants defining supported compression algorithm identifiers
const ZSTD: &str = "zstd"; // Zstandard compression
const BR: &str = "br"; // Brotli compression
const GZIP: &str = "gzip"; // Gzip compression

const UPSTREAM_RESPONSE_COMPRESS_MODE: &str = "upstream";

const PLUGIN_ID: &str = "_compress_";

struct Compressor {
    compressor: Box<dyn Encode + Send + Sync>,
}

impl Compressor {
    fn new(algorithm: Algorithm, level: u32) -> pingora::Result<Self> {
        let compressor = algorithm.compressor(level).ok_or_else(|| {
            new_internal_error(
                500,
                format!(
                    "Compress algorithm {} is not supported",
                    algorithm.as_str()
                ),
            )
        })?;
        Ok(Self { compressor })
    }
}

impl ModifyResponseBody for Compressor {
    fn handle(
        &mut self,
        _session: &Session,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
    ) -> pingora::Result<()> {
        // if body is some, replace it with the compressed data
        // the compress data will be buffer, so it may be empty some times
        let input_data =
            body.as_ref().map(|data| data.as_ref()).unwrap_or_default();
        let data = self
            .compressor
            .as_mut()
            .encode(input_data, end_of_stream)
            .map_err(|e| new_internal_error(500, e))?;
        *body = Some(data);
        Ok(())
    }
    fn name(&self) -> &str {
        "compression"
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
    // Compress the upstream response body here (`mode = "upstream"`)
    // instead of through pingora's downstream module
    upstream_mode: bool,
    // Minimum length of the response body to be compressed, only for upstream response mode
    min_length: u64,
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

        // Get compression levels from configuration. Clamped at both ends:
        // a negative level used to wrap to a huge u32 through the cast and
        // switch compression on at an absurd level.
        let level =
            |key: &str, max: i64| get_int_conf(value, key).clamp(0, max) as u32;
        let gzip_level = level("gzip_level", 9);
        let br_level = level("br_level", 11);
        let zstd_level = level("zstd_level", 22);
        // `response` is what the admin form saves for the default mode.
        let upstream_mode = match get_str_conf(value, "mode").as_str() {
            "" | "response" => false,
            UPSTREAM_RESPONSE_COMPRESS_MODE => true,
            other => {
                return Err(Error::Invalid {
                    category: PluginCategory::Compression.to_string(),
                    message: format!(
                        "Invalid mode({other}), expect response or upstream"
                    ),
                });
            },
        };

        // Enable compression if any algorithm has a non-zero level
        let support_compression = gzip_level + br_level + zstd_level > 0;

        let min_length = get_int_conf(value, "min_length").max(0) as u64;

        let params = Self {
            hash_value,
            gzip_level,
            br_level,
            zstd_level,
            decompression,
            support_compression,
            upstream_mode,
            min_length,
            // Plugin runs during early request phase
            plugin_step: PluginStep::EarlyRequest,
        };

        Ok(params)
    }
}

/// Whether the response's `Vary` already covers `Accept-Encoding` (or
/// everything).
fn varies_by_accept_encoding(headers: &http::HeaderMap) -> bool {
    headers
        .get_all(VARY)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .any(|name| name == "*" || name.eq_ignore_ascii_case("accept-encoding"))
}

/// Responses that carry no body to compress: HEAD answers, 1xx, 204, 304.
fn has_no_body(session: &Session, status: StatusCode) -> bool {
    session.req_header().method == Method::HEAD
        || status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED
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
        //
        // The match is on token boundaries and honours `q=0`, so `x-gzip` does
        // not enable gzip and `gzip;q=0` is not treated as accepted.
        let mut zstd_level = 0;
        let mut br_level = 0;
        let mut gzip_level = 0;
        if self.zstd_level > 0 && accepts_encoding(accept_encoding, ZSTD) {
            zstd_level = self.zstd_level;
        }
        if self.br_level > 0 && accepts_encoding(accept_encoding, BR) {
            br_level = self.br_level;
        }
        if self.gzip_level > 0 && accepts_encoding(accept_encoding, GZIP) {
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
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
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
    ) -> pingora::Result<RequestPluginResult> {
        if step == PluginStep::EarlyRequest {
            if self.upstream_mode {
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
            if self.decompression.unwrap_or_default()
                && let Some(c) = session
                    .downstream_modules_ctx
                    .get_mut::<ResponseCompression>()
            {
                c.adjust_decompression(true);
            }
        }
        // Early return conditions
        if step != self.plugin_step {
            return Ok(RequestPluginResult::Skipped);
        }
        if !self.support_compression || self.upstream_mode {
            return Ok(RequestPluginResult::Skipped);
        }
        let (zstd_level, br_level, gzip_level) =
            self.get_compress_level(session);

        debug!(
            zstd_level,
            br_level, gzip_level, "response compression level"
        );

        if zstd_level == 0 && br_level == 0 && gzip_level == 0 {
            return Ok(RequestPluginResult::Skipped);
        }

        // Get compression context from session
        let Some(c) = session
            .downstream_modules_ctx
            .get_mut::<ResponseCompression>()
        else {
            return Ok(RequestPluginResult::Skipped);
        };

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

        Ok(RequestPluginResult::Continue)
    }
    fn handle_upstream_response(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
        upstream_response: &mut ResponseHeader,
    ) -> pingora::Result<ResponsePluginResult> {
        if !self.support_compression || !self.upstream_mode {
            return Ok(ResponsePluginResult::Unchanged);
        }
        // Compressing nothing still emits the format's header and footer,
        // which a HEAD, 204 or 304 answer must not carry.
        if has_no_body(session, upstream_response.status) {
            return Ok(ResponsePluginResult::Unchanged);
        }
        if upstream_response.headers.contains_key(CONTENT_ENCODING) {
            return Ok(ResponsePluginResult::Unchanged);
        }
        let Some(content_type) = upstream_response.headers.get(CONTENT_TYPE)
        else {
            return Ok(ResponsePluginResult::Unchanged);
        };
        if !is_compressible_content_type(content_type) {
            return Ok(ResponsePluginResult::Unchanged);
        }
        let (zstd_level, br_level, gzip_level) =
            self.get_compress_level(session);
        if zstd_level == 0 && br_level == 0 && gzip_level == 0 {
            return Ok(ResponsePluginResult::Unchanged);
        }
        if self.min_length > 0 {
            let is_too_small = upstream_response
                .headers
                .get(CONTENT_LENGTH)
                .and_then(|header| header.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .map(|content_length| content_length < self.min_length)
                .unwrap_or(false);

            if is_too_small {
                return Ok(ResponsePluginResult::Unchanged);
            }
        }

        debug!(
            zstd_level,
            br_level, gzip_level, "upstream response body compression level"
        );
        // Remove content-length since we're modifying the body
        upstream_response.remove_header(&CONTENT_LENGTH);
        // Switch to chunked transfer encoding
        let _ = upstream_response.insert_header(
            TRANSFER_ENCODING,
            HTTP_HEADER_TRANSFER_CHUNKED.1.clone(),
        );
        let (handler, encoding) = if zstd_level > 0 {
            (
                Box::new(Compressor::new(Algorithm::Zstd, zstd_level)?),
                ZSTD,
            )
        } else if br_level > 0 {
            (Box::new(Compressor::new(Algorithm::Brotli, br_level)?), BR)
        } else {
            (
                Box::new(Compressor::new(Algorithm::Gzip, gzip_level)?),
                GZIP,
            )
        };
        ctx.add_modify_body_handler(PLUGIN_ID, handler);
        let _ = upstream_response.insert_header(CONTENT_ENCODING, encoding);

        Ok(ResponsePluginResult::Modified)
    }

    /// An encoded response was chosen on `Accept-Encoding`, so caches in
    /// front of pingap (browsers, CDNs) must key on it too. Added on the
    /// way out rather than on the upstream response, so pingap's own cache,
    /// which already keys on the chosen encoding, is not split further by
    /// every spelling of the request header; a cached compressed entry
    /// gets it on every hit the same way.
    async fn handle_response(
        &self,
        _session: &mut Session,
        _ctx: &mut Ctx,
        upstream_response: &mut ResponseHeader,
    ) -> pingora::Result<ResponsePluginResult> {
        if !self.upstream_mode
            || !upstream_response.headers.contains_key(CONTENT_ENCODING)
            || varies_by_accept_encoding(&upstream_response.headers)
        {
            return Ok(ResponsePluginResult::Unchanged);
        }
        let _ = upstream_response.append_header(VARY, "Accept-Encoding");
        Ok(ResponsePluginResult::Modified)
    }

    fn handle_upstream_response_body(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
    ) -> pingora::Result<ResponseBodyPluginResult> {
        if let Some(modifier) = ctx.get_modify_body_handler(PLUGIN_ID) {
            modifier.handle(session, body, end_of_stream)?;
            let result = if end_of_stream {
                ResponseBodyPluginResult::FullyReplaced
            } else {
                ResponseBodyPluginResult::PartialReplaced
            };
            Ok(result)
        } else {
            Ok(ResponseBodyPluginResult::Unchanged)
        }
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

register_plugin!("compression", Compression);

#[cfg(test)]
mod tests {
    use super::*;
    use pingap_config::PluginConf;
    use pingap_core::{Ctx, PluginStep, RequestPluginResult};
    use pingora::modules::http::HttpModules;
    use pingora::modules::http::compression::{
        ResponseCompression, ResponseCompressionBuilder,
    };
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

        // Levels are clamped at both ends; a negative one used to wrap.
        let params = Compression::try_from(
            &toml::from_str::<PluginConf>(
                "gzip_level = -1\nbr_level = 99\nzstd_level = 0\n",
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            (0, 11, 0),
            (params.gzip_level, params.br_level, params.zstd_level)
        );
        assert_eq!(true, params.support_compression);
        let err = Compression::try_from(
            &toml::from_str::<PluginConf>("mode = \"downstream\"").unwrap(),
        )
        .err()
        .unwrap()
        .to_string();
        assert_eq!(true, err.contains("Invalid mode(downstream)"), "{err}");
    }

    async fn new_session(input: &str) -> Session {
        let mock_io = Builder::new().read(input.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        session
    }

    /// Upstream mode compresses only responses that have a body, and adds
    /// `Vary: Accept-Encoding` on the way out.
    #[tokio::test]
    async fn test_upstream_mode_skips_bodiless_responses() {
        let compression = Compression::new(
            &toml::from_str::<PluginConf>(
                "mode = \"upstream\"\ngzip_level = 6",
            )
            .unwrap(),
        )
        .unwrap();
        let response = |status: u16| {
            let mut resp = ResponseHeader::build(status, None).unwrap();
            resp.append_header("Content-Type", "text/html").unwrap();
            resp
        };

        let mut session =
            new_session("GET / HTTP/1.1\r\nAccept-Encoding: gzip\r\n\r\n")
                .await;
        let mut ctx = Ctx::default();
        let mut resp = response(200);
        let result = compression
            .handle_upstream_response(&mut session, &mut ctx, &mut resp)
            .unwrap();
        assert_eq!(ResponsePluginResult::Modified, result);
        assert_eq!(
            Some("gzip"),
            resp.headers
                .get(CONTENT_ENCODING)
                .and_then(|v| v.to_str().ok())
        );
        let result = compression
            .handle_response(&mut session, &mut ctx, &mut resp)
            .await
            .unwrap();
        assert_eq!(ResponsePluginResult::Modified, result);
        assert_eq!(
            Some("Accept-Encoding"),
            resp.headers.get(VARY).and_then(|v| v.to_str().ok())
        );
        // Not added twice, and not on top of a `Vary: *`.
        let result = compression
            .handle_response(&mut session, &mut ctx, &mut resp)
            .await
            .unwrap();
        assert_eq!(ResponsePluginResult::Unchanged, result);
        assert_eq!(1, resp.headers.get_all(VARY).iter().count());

        for status in [204, 304, 101] {
            let mut resp = response(status);
            let result = compression
                .handle_upstream_response(
                    &mut session,
                    &mut Ctx::default(),
                    &mut resp,
                )
                .unwrap();
            assert_eq!(ResponsePluginResult::Unchanged, result, "{status}");
            assert_eq!(false, resp.headers.contains_key(CONTENT_ENCODING));
        }
        let mut session =
            new_session("HEAD / HTTP/1.1\r\nAccept-Encoding: gzip\r\n\r\n")
                .await;
        let mut resp = response(200);
        let result = compression
            .handle_upstream_response(
                &mut session,
                &mut Ctx::default(),
                &mut resp,
            )
            .unwrap();
        assert_eq!(ResponsePluginResult::Unchanged, result);
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
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result == RequestPluginResult::Continue);
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
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result == RequestPluginResult::Continue);
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
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result == RequestPluginResult::Continue);
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
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result == RequestPluginResult::Skipped);
        assert_eq!(
            false,
            session
                .downstream_modules_ctx
                .get::<ResponseCompression>()
                .unwrap()
                .is_enabled()
        );
    }

    /// Regression: the accept-encoding check used to be a substring test, so a
    /// value that merely contains an algorithm name enabled it.
    #[tokio::test]
    async fn test_compression_matches_encoding_tokens() {
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

        async fn levels(
            compression: &Compression,
            accept_encoding: &str,
        ) -> (u32, u32, u32) {
            let input_header = format!(
                "GET / HTTP/1.1\r\nAccept-Encoding: {accept_encoding}\r\n\r\n"
            );
            let mock_io = Builder::new().read(input_header.as_bytes()).build();
            let mut session = Session::new_h1(Box::new(mock_io));
            session.read_request().await.unwrap();
            compression.get_compress_level(&session)
        }

        let c = &compression;
        assert_eq!((0, 0, 9), levels(c, "gzip").await);
        assert_eq!((7, 8, 9), levels(c, "zstd, br, gzip").await);
        // `x-gzip` is a different token and must not enable gzip.
        assert_eq!((0, 0, 0), levels(c, "x-gzip").await);
        assert_eq!((0, 0, 0), levels(c, "gzipx").await);
        // An explicit q=0 means the client does not accept it.
        assert_eq!((0, 0, 0), levels(c, "gzip;q=0").await);
        assert_eq!((0, 8, 0), levels(c, "gzip;q=0, br").await);
        // A weight other than zero is still acceptable.
        assert_eq!((0, 0, 9), levels(c, "gzip;q=0.5").await);
    }
}
