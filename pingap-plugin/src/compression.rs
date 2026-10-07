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
    get_str_conf, get_str_slice_conf, is_partial_content, weaken_etag,
};
use async_trait::async_trait;
use fancy_regex::Regex;
use http::header::{
    ACCEPT_ENCODING, ACCEPT_RANGES, CACHE_CONTROL, CONTENT_ENCODING,
    CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING, VARY,
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
use std::sync::Arc;
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
    /// The name this instance keeps its body handler under, see
    /// `new_body_handler_id`.
    handler_id: String,
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
    /// The cache key components upstream mode can add: none, or one of
    /// the codings that are switched on.
    key_alternatives: Arc<Vec<Vec<String>>>,
    // Compress the upstream response body here (`mode = "upstream"`)
    // instead of through pingora's downstream module
    upstream_mode: bool,
    /// A response that says it is shorter than this is not compressed;
    /// `0` for no such floor. One that does not say how long it is, is
    /// compressed.
    min_length: u64,
    /// The content types that are compressed, as prefixes in lower case
    /// (`*` for any). `None` leaves it to the rule of the mode: pingora's
    /// in the default mode, `is_compressible_content_type` in upstream
    /// mode.
    types: Option<Vec<String>>,
    /// Requests whose path and query match are not compressed.
    skip: Option<Regex>,
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
        let invalid = |message: String| Error::Invalid {
            category: PluginCategory::Compression.to_string(),
            message,
        };
        // A list that is there and empty would compress nothing at all,
        // which is not what leaving the key out does.
        let types = if value.contains_key("types") {
            let types = get_str_slice_conf(value, "types")
                .into_iter()
                .map(|item| item.trim().to_ascii_lowercase())
                .collect::<Vec<_>>();
            if types.is_empty() || types.iter().any(String::is_empty) {
                return Err(invalid(
                    "types needs at least one content type, and none of them empty"
                        .to_string(),
                ));
            }
            Some(types)
        } else {
            None
        };
        let skip = get_str_conf(value, "skip");
        let skip = if skip.is_empty() {
            None
        } else {
            Some(Regex::new(&skip).map_err(|e| Error::Regex {
                category: PluginCategory::Compression.to_string(),
                source: Box::new(e),
            })?)
        };

        let params = Self {
            hash_value,
            handler_id: crate::new_body_handler_id(PLUGIN_ID),
            gzip_level,
            br_level,
            zstd_level,
            decompression,
            support_compression,
            upstream_mode,
            key_alternatives: Arc::new(
                std::iter::once(vec![])
                    .chain(
                        [
                            (ZSTD, zstd_level),
                            (BR, br_level),
                            (GZIP, gzip_level),
                        ]
                        .into_iter()
                        .filter(|(_, level)| *level > 0)
                        .map(|(coding, _)| vec![coding.to_string()]),
                    )
                    .collect(),
            ),
            min_length,
            types,
            skip,
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

/// Responses that are passed on as they are: an event stream, and
/// whatever the upstream marks `Cache-Control: no-transform`.
///
/// A compressor hands out its output when its buffer is full or the body
/// ends, so the events of a `text/event-stream` - a few bytes each, sent
/// as they happen - all reached the client together when the stream
/// closed. `no-transform` forbids changing the content coding outright
/// (RFC 9111 5.2.2.6).
fn must_not_transform(headers: &http::HeaderMap) -> bool {
    let is_event_stream = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|mime| {
            mime.trim().eq_ignore_ascii_case("text/event-stream")
        });
    is_event_stream || has_no_transform(headers)
}

/// Whether the response says `Cache-Control: no-transform`.
fn has_no_transform(headers: &http::HeaderMap) -> bool {
    headers
        .get_all(CACHE_CONTROL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|directive| directive.trim().eq_ignore_ascii_case("no-transform"))
}

/// Whether the content type of the response starts with one of `types`,
/// which are in lower case. Parameters (`; charset=utf-8`) are not a part
/// of it, and a response that names no type matches nothing, `*`
/// included: neither mode compresses what it knows nothing about.
fn matches_types(types: &[String], headers: &http::HeaderMap) -> bool {
    let Some(mime) = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .filter(|mime| !mime.is_empty())
    else {
        return false;
    };
    types.iter().any(|prefix| {
        prefix == "*"
            || mime.as_bytes().get(..prefix.len()).is_some_and(|head| {
                head.eq_ignore_ascii_case(prefix.as_bytes())
            })
    })
}

/// Whether the response says it is shorter than `min_length`. One that
/// does not say how long it is, is not too short.
fn is_shorter_than(min_length: u64, headers: &http::HeaderMap) -> bool {
    min_length > 0
        && headers
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<u64>().ok())
            .is_some_and(|content_length| content_length < min_length)
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
        debug!(
            params = pingap_config::masked_toml(params),
            "new compression plugin"
        );
        Self::try_from(params)
    }
    /// Whether the request is one of those `skip` takes out.
    ///
    /// By the path and query the client asked for, and not what a rewrite
    /// of the location made of them. Upstream mode needs the answer
    /// twice, for the cache key and for the response, and does not ask
    /// twice: see `chosen_levels`.
    fn is_skipped(&self, session: &Session, ctx: &Ctx) -> bool {
        let Some(skip) = &self.skip else {
            return false;
        };
        let uri = ctx
            .features
            .as_ref()
            .and_then(|features| features.original_uri.as_ref())
            .unwrap_or(&session.req_header().uri);
        let target = uri
            .path_and_query()
            .map_or(uri.path(), |value| value.as_str());
        skip.is_match(target).unwrap_or_default()
    }
    fn get_compress_level(
        &self,
        session: &Session,
        ctx: &Ctx,
    ) -> (u32, u32, u32) {
        if self.is_skipped(session, ctx) {
            return (0, 0, 0);
        }
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

impl Compression {
    /// The coding upstream mode compresses the response with, as levels:
    /// the one that was settled when the request came in and is in its
    /// cache key.
    ///
    /// Not decided again from the request as it is by now. A location may
    /// have rewritten the path that `skip` goes by, `key_auth` taken its
    /// parameter out of the query, another plugin replaced
    /// `Accept-Encoding`: with a second answer that differed from the
    /// first, a compressed response was stored under the key of the
    /// clients that take no coding, and served to them.
    fn chosen_levels(&self, session: &Session, ctx: &Ctx) -> (u32, u32, u32) {
        match ctx.get_plugin_note(&self.handler_id) {
            Some(ZSTD) => (self.zstd_level, 0, 0),
            Some(BR) => (0, self.br_level, 0),
            Some(GZIP) => (0, 0, self.gzip_level),
            Some(_) => (0, 0, 0),
            // The request step did not run for this request.
            None => self.get_compress_level(session, ctx),
        }
    }
}

/// `accept_encoding` with `coding` moved to the front, or `None` when it
/// is there already. The entry keeps its parameters, the others their
/// order.
fn prefer_encoding(accept_encoding: &str, coding: &str) -> Option<String> {
    let is_coding = |item: &&str| {
        item.split(';')
            .next()
            .is_some_and(|name| name.trim().eq_ignore_ascii_case(coding))
    };
    let items = || {
        accept_encoding
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
    };
    let position = items().position(|item| is_coding(&item))?;
    if position == 0 {
        return None;
    }
    let mut value = String::with_capacity(accept_encoding.len() + 2);
    value.push_str(items().nth(position)?);
    for item in items().filter(|item| !is_coding(item)) {
        value.push_str(", ");
        value.push_str(item);
    }
    Some(value)
}

#[async_trait]
impl Plugin for Compression {
    /// Returns the unique hash key for this plugin instance
    /// Used for caching and identifying plugin configurations
    #[inline]
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    /// In the default mode pingora compresses what a plugin answers with
    /// as well - the files of `directory` above all - so `types` and
    /// `min_length` have to be asked about those too, or the fonts and
    /// documents of a static site are compressed with a list that names
    /// only text. All `handle_response` does in that mode is switch the
    /// compression off.
    #[inline]
    fn handles_plugin_response(&self) -> bool {
        !self.upstream_mode
            && self.support_compression
            && (self.types.is_some() || self.min_length > 0)
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
            // Nothing of this with no level switched on: the plugin is
            // there for something else, decompression say.
            if self.upstream_mode && self.support_compression {
                let (zstd_level, br_level, gzip_level) =
                    self.get_compress_level(session, ctx);
                let key = if zstd_level > 0 {
                    ZSTD
                } else if br_level > 0 {
                    BR
                } else if gzip_level > 0 {
                    GZIP
                } else {
                    ""
                };
                // Settled here, once: the cache key below says it, and
                // the response is compressed by it.
                ctx.set_plugin_note(&self.handler_id, key);
                // The coding is a part of the cache key, one of those a
                // request can ask for: a `PURGE`, which asks for none,
                // removes the entry of each.
                let current = if key.is_empty() {
                    vec![]
                } else {
                    vec![key.to_string()]
                };
                ctx.push_cache_key_variant(
                    current,
                    self.key_alternatives.clone(),
                );
                // The upstream is asked for the coding this plugin settled
                // on and no other. With the client's header passed on, an
                // upstream that compresses by itself answered in a coding
                // of its own choosing - brotli, to a client that takes
                // both - and that response was stored under the key of
                // the coding chosen here, for clients that take only that
                // one. With no coding chosen the header is the client's
                // business and the upstream's, see `handle_upstream_response`.
                let header = session.req_header_mut();
                if !key.is_empty()
                    && header
                        .headers
                        .get(ACCEPT_ENCODING)
                        .is_some_and(|value| value.as_bytes() != key.as_bytes())
                {
                    let _ = header.insert_header(ACCEPT_ENCODING, key);
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
            self.get_compress_level(session, ctx);

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

        // One algorithm, by the fixed priority, and it is put first in
        // `Accept-Encoding`: pingora compresses with the first coding of
        // that header it knows and looks no further. A browser lists gzip
        // first, so with all three enabled it got gzip, and with only
        // zstd or brotli enabled it got nothing. Order has no meaning in
        // the header, so the upstream is told the same as before.
        let (coding, algorithm, level) = if zstd_level > 0 {
            (ZSTD, Algorithm::Zstd, zstd_level)
        } else if br_level > 0 {
            (BR, Algorithm::Brotli, br_level)
        } else {
            (GZIP, Algorithm::Gzip, gzip_level)
        };
        c.adjust_algorithm_level(algorithm, level);
        let preferred = session
            .req_header()
            .headers
            .get(ACCEPT_ENCODING)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| prefer_encoding(value, coding));
        if let Some(value) = preferred {
            let _ = session
                .req_header_mut()
                .insert_header(ACCEPT_ENCODING, value);
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
        let (zstd_level, br_level, gzip_level) =
            self.chosen_levels(session, ctx);
        let chosen = zstd_level > 0 || br_level > 0 || gzip_level > 0;
        if upstream_response.headers.contains_key(CONTENT_ENCODING) {
            // Compressed by the upstream, for a client this plugin has no
            // coding for, so by what that client's header says. The key
            // has no coding in it then, and the next client under the same
            // key may take none at all: unless the upstream says so itself
            // the response is marked as depending on the header, and the
            // cache keeps the answers to different headers apart.
            if !chosen && !varies_by_accept_encoding(&upstream_response.headers)
            {
                let _ =
                    upstream_response.append_header(VARY, "Accept-Encoding");
                return Ok(ResponsePluginResult::Modified);
            }
            return Ok(ResponsePluginResult::Unchanged);
        }
        if must_not_transform(&upstream_response.headers)
            || is_partial_content(upstream_response)
        {
            return Ok(ResponsePluginResult::Unchanged);
        }
        // The configured types where there are some, the fixed list
        // where there are none.
        let compressible = match &self.types {
            Some(types) => matches_types(types, &upstream_response.headers),
            None => upstream_response
                .headers
                .get(CONTENT_TYPE)
                .is_some_and(is_compressible_content_type),
        };
        if !compressible {
            return Ok(ResponsePluginResult::Unchanged);
        }
        if !chosen {
            return Ok(ResponsePluginResult::Unchanged);
        }
        if is_shorter_than(self.min_length, &upstream_response.headers) {
            return Ok(ResponsePluginResult::Unchanged);
        }

        debug!(
            zstd_level,
            br_level, gzip_level, "upstream response body compression level"
        );
        // Remove content-length since we're modifying the body
        upstream_response.remove_header(&CONTENT_LENGTH);
        // Ranges of these bytes are not ranges of what the upstream has.
        // The `ETag` stays as the upstream gave it, for the cache to
        // revalidate with; it is weakened on the way out, in
        // `handle_response`.
        upstream_response.remove_header(&ACCEPT_RANGES);
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
        ctx.add_modify_body_handler(&self.handler_id, handler);
        let _ = upstream_response.insert_header(CONTENT_ENCODING, encoding);

        Ok(ResponsePluginResult::Modified)
    }

    /// An encoded response was chosen on `Accept-Encoding`, so caches in
    /// front of pingap (browsers, CDNs) must key on it too. Added on the
    /// way out rather than on the upstream response, so pingap's own cache,
    /// which already keys on the chosen encoding, is not split further by
    /// every spelling of the request header; a cached compressed entry
    /// gets it on every hit the same way.
    ///
    /// In the default mode the compression is pingora's, which decides by
    /// the response header right after this hook: a response that is not
    /// to be transformed has it switched off here, and so has one that
    /// `types` or `min_length` leave out. pingora's own rule (text,
    /// `application/*`, `font/*` and a few more, none with `zip` in it,
    /// nothing under twenty bytes) still applies to what is left: the
    /// list can narrow it, not widen it.
    async fn handle_response(
        &self,
        session: &mut Session,
        _ctx: &mut Ctx,
        upstream_response: &mut ResponseHeader,
    ) -> pingora::Result<ResponsePluginResult> {
        if !self.upstream_mode {
            // `adjust_level` panics once the module has gone on to the
            // body, so it is only called while it is still at the header.
            let headers = &upstream_response.headers;
            let left_out = must_not_transform(headers)
                || self
                    .types
                    .as_ref()
                    .is_some_and(|types| !matches_types(types, headers))
                || is_shorter_than(self.min_length, headers);
            if self.support_compression
                && left_out
                && let Some(c) = session
                    .downstream_modules_ctx
                    .get_mut::<ResponseCompression>()
                && c.is_header_phase()
            {
                c.adjust_level(0);
                // `no-transform` covers the other direction as well: a
                // response that comes compressed is passed on compressed,
                // also with `decompression` on.
                if has_no_transform(&upstream_response.headers) {
                    c.adjust_decompression(false);
                }
            }
            return Ok(ResponsePluginResult::Unchanged);
        }
        if !upstream_response.headers.contains_key(CONTENT_ENCODING) {
            return Ok(ResponsePluginResult::Unchanged);
        }
        // The upstream's strong `ETag` names the bytes it sent, and these
        // are their compressed form: the validator is made a weak one, as
        // nginx and pingora's own compression do it. Here, on the way to
        // the client and for a response from the cache as well, and not on
        // the response that is stored: the cache revalidates with the
        // validator as the upstream gave it, and takes the upstream's
        // again from every `304`.
        let weakened = weaken_etag(upstream_response);
        if varies_by_accept_encoding(&upstream_response.headers) {
            return Ok(if weakened {
                ResponsePluginResult::Modified
            } else {
                ResponsePluginResult::Unchanged
            });
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
        if let Some(modifier) = ctx.get_modify_body_handler(&self.handler_id) {
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

    fn new_compression(conf: &str) -> Compression {
        Compression::new(&toml::from_str::<PluginConf>(conf).unwrap()).unwrap()
    }

    /// A session of the default mode, with pingora's compression module
    /// the way the proxy adds it.
    async fn new_module_session(input: &str) -> Session {
        let mock_io = Builder::new().read(input.as_bytes()).build();
        let mut modules = HttpModules::new();
        modules.add_module(ResponseCompressionBuilder::enable(0));
        let mut session =
            Session::new_h1_with_modules(Box::new(mock_io), &modules);
        session.read_request().await.unwrap();
        session
    }

    fn module_enabled(session: &Session) -> bool {
        session
            .downstream_modules_ctx
            .get::<ResponseCompression>()
            .unwrap()
            .is_enabled()
    }

    fn response(
        content_type: &str,
        content_length: Option<u64>,
    ) -> ResponseHeader {
        let mut resp = ResponseHeader::build(200, None).unwrap();
        if !content_type.is_empty() {
            resp.append_header("Content-Type", content_type).unwrap();
        }
        if let Some(content_length) = content_length {
            resp.append_header("Content-Length", content_length.to_string())
                .unwrap();
        }
        resp
    }

    #[test]
    fn test_matches_types() {
        let types = |items: &[&str]| -> Vec<String> {
            items.iter().map(|item| item.to_string()).collect()
        };
        let matches = |items: &[&str], content_type: &str| {
            matches_types(&types(items), &response(content_type, None).headers)
        };
        let text = ["text/", "application/json", "image/svg+xml"];
        assert_eq!(true, matches(&text, "text/html"));
        assert_eq!(true, matches(&text, "Text/CSS; charset=utf-8"));
        assert_eq!(true, matches(&text, "application/json"));
        assert_eq!(true, matches(&text, " application/json ;charset=utf-8"));
        assert_eq!(true, matches(&text, "image/svg+xml"));
        // A prefix, so what begins the same is taken along.
        assert_eq!(true, matches(&text, "application/json-seq"));
        assert_eq!(false, matches(&text, "image/png"));
        assert_eq!(false, matches(&text, "application/octet-stream"));
        assert_eq!(false, matches(&text, "text"));
        // The parameters are not a part of the type.
        assert_eq!(false, matches(&["charset"], "text/html; charset=utf-8"));
        // Anything that names a type, and nothing that names none.
        assert_eq!(true, matches(&["*"], "video/mp4"));
        assert_eq!(false, matches(&["*"], ""));
        assert_eq!(false, matches(&text, ""));

        assert_eq!(
            true,
            is_shorter_than(1024, &response("text/html", Some(1023)).headers)
        );
        assert_eq!(
            false,
            is_shorter_than(1024, &response("text/html", Some(1024)).headers)
        );
        // A response that does not say how long it is, is not too short,
        // and neither is any without a floor.
        assert_eq!(
            false,
            is_shorter_than(1024, &response("text/html", None).headers)
        );
        assert_eq!(
            false,
            is_shorter_than(0, &response("text/html", Some(1)).headers)
        );
    }

    #[test]
    fn test_compression_rule_params() {
        let compression = new_compression(
            "gzip_level = 6\ntypes = [\" Text/ \", \"application/JSON\"]\nmin_length = 512\nskip = \"^/download/\"",
        );
        assert_eq!(
            Some(vec!["text/".to_string(), "application/json".to_string()]),
            compression.types
        );
        assert_eq!(512, compression.min_length);
        assert_eq!(true, compression.skip.is_some());
        // The responses of other plugins are looked at only in the default
        // mode, and only with a rule that is about the response.
        assert_eq!(true, compression.handles_plugin_response());
        for (conf, asks) in [
            ("gzip_level = 6", false),
            ("gzip_level = 6\nskip = \"^/download/\"", false),
            ("gzip_level = 6\nmin_length = 512", true),
            ("gzip_level = 6\ntypes = [\"text/\"]", true),
            ("types = [\"text/\"]", false),
            (
                "mode = \"upstream\"\ngzip_level = 6\ntypes = [\"text/\"]",
                false,
            ),
        ] {
            assert_eq!(
                asks,
                new_compression(conf).handles_plugin_response(),
                "{conf}"
            );
        }

        let error = |conf: &str| {
            Compression::new(&toml::from_str::<PluginConf>(conf).unwrap())
                .err()
                .unwrap()
                .to_string()
        };
        for conf in ["types = []", "types = [\"text/\", \" \"]"] {
            assert_eq!(
                "Plugin compression invalid, message: types needs at least one content type, and none of them empty",
                error(conf),
                "{conf}"
            );
        }
        assert_eq!(
            true,
            error("skip = \"(\"")
                .starts_with("Plugin compression, regex error ")
        );
    }

    /// `types`, `min_length` and `skip` in upstream mode, where the plugin
    /// compresses by itself.
    #[tokio::test]
    async fn test_upstream_mode_types_min_length_and_skip() {
        const REQUEST: &str =
            "GET /api/users?page=1 HTTP/1.1\r\nAccept-Encoding: gzip\r\n\r\n";
        async fn compressed(
            compression: &Compression,
            request: &str,
            ctx: &mut Ctx,
            mut resp: ResponseHeader,
        ) -> bool {
            let mut session = new_session(request).await;
            compression
                .handle_upstream_response(&mut session, ctx, &mut resp)
                .unwrap();
            resp.headers.contains_key(CONTENT_ENCODING)
        }

        // Without `types` it is the fixed list, as before.
        let fixed = new_compression("mode = \"upstream\"\ngzip_level = 6");
        for (content_type, expected) in [
            ("text/css", true),
            ("application/json", true),
            ("application/javascript", false),
            ("image/svg+xml", false),
        ] {
            assert_eq!(
                expected,
                compressed(
                    &fixed,
                    REQUEST,
                    &mut Ctx::default(),
                    response(content_type, None)
                )
                .await,
                "{content_type}"
            );
        }

        // With `types` it is what the list says, and nothing else.
        let listed = new_compression(
            "mode = \"upstream\"\ngzip_level = 6\ntypes = [\"application/javascript\", \"image/svg\"]\nmin_length = 100",
        );
        for (content_type, content_length, expected) in [
            ("application/javascript", None, true),
            ("image/svg+xml; charset=utf-8", Some(100), true),
            ("text/css", None, false),
            ("application/json", None, false),
            ("", None, false),
            // Listed, and said to be too short.
            ("application/javascript", Some(99), false),
        ] {
            assert_eq!(
                expected,
                compressed(
                    &listed,
                    REQUEST,
                    &mut Ctx::default(),
                    response(content_type, content_length)
                )
                .await,
                "{content_type} {content_length:?}"
            );
        }

        // `skip` is asked about the path and query of the request.
        let skipping = new_compression(
            "mode = \"upstream\"\ngzip_level = 6\nskip = \"^/api/|[?&]raw=1\"",
        );
        for (target, expected) in [
            ("/api/users", false),
            ("/web/index.html", true),
            ("/web/index.html?raw=1", false),
            ("/web/api/users", true),
        ] {
            let request = format!(
                "GET {target} HTTP/1.1\r\nAccept-Encoding: gzip\r\n\r\n"
            );
            assert_eq!(
                expected,
                compressed(
                    &skipping,
                    &request,
                    &mut Ctx::default(),
                    response("text/html", None)
                )
                .await,
                "{target}"
            );
        }

        // A request that is skipped is one that takes no coding: the
        // cache key says so, and the client's header is left as it came.
        let mut session = new_session(
            "GET /api/users HTTP/1.1\r\nAccept-Encoding: gzip, br\r\n\r\n",
        )
        .await;
        let mut ctx = Ctx::default();
        skipping
            .handle_request(PluginStep::EarlyRequest, &mut session, &mut ctx)
            .await
            .unwrap();
        assert_eq!(
            "gzip, br",
            session.req_header().headers.get(ACCEPT_ENCODING).unwrap()
        );
        let keys = ctx.cache.as_ref().and_then(|cache| cache.keys.clone());
        assert_eq!(Some(vec![]), keys);

        // The location rewrote the path between the two times the plugin
        // asks: the answer is the one for what the client asked for, both
        // times. By the rewritten path the response was compressed and
        // stored under the key of the clients that take no coding.
        let mut session = new_session(
            "GET /internal/users HTTP/1.1\r\nAccept-Encoding: gzip\r\n\r\n",
        )
        .await;
        let mut ctx = Ctx::default();
        ctx.features.get_or_insert_default().original_uri =
            Some("/api/users".parse().unwrap());
        let mut resp = response("text/html", None);
        skipping
            .handle_upstream_response(&mut session, &mut ctx, &mut resp)
            .unwrap();
        assert_eq!(false, resp.headers.contains_key(CONTENT_ENCODING));
    }

    /// Regression: upstream mode decided twice, for the cache key when
    /// the request came in and for the body when the response did, each
    /// time from the request as it was then. In between `key_auth` takes
    /// its parameter out of the query, and another plugin may replace
    /// `Accept-Encoding`: with `skip` matching the first and not the
    /// second, a gzip body was stored under the key of the clients that
    /// take no coding.
    #[tokio::test]
    async fn test_upstream_mode_decides_once() {
        let compression = new_compression(
            "mode = \"upstream\"\ngzip_level = 6\nskip = \"[?&]sig=\"",
        );
        // Skipped by its query, which is gone by the time of the response.
        let mut session = new_session(
            "GET /file?sig=abc HTTP/1.1\r\nAccept-Encoding: gzip\r\n\r\n",
        )
        .await;
        let mut ctx = Ctx::default();
        compression
            .handle_request(PluginStep::EarlyRequest, &mut session, &mut ctx)
            .await
            .unwrap();
        assert_eq!(
            Some(vec![]),
            ctx.cache.as_ref().and_then(|cache| cache.keys.clone())
        );
        session.req_header_mut().set_uri("/file".parse().unwrap());
        let mut resp = response("text/html", None);
        compression
            .handle_upstream_response(&mut session, &mut ctx, &mut resp)
            .unwrap();
        assert_eq!(false, resp.headers.contains_key(CONTENT_ENCODING));

        // The other way round: gzip is in the key, and the header that
        // asked for it has been replaced since.
        let mut session =
            new_session("GET /file HTTP/1.1\r\nAccept-Encoding: gzip\r\n\r\n")
                .await;
        let mut ctx = Ctx::default();
        compression
            .handle_request(PluginStep::EarlyRequest, &mut session, &mut ctx)
            .await
            .unwrap();
        assert_eq!(
            Some(vec!["gzip".to_string()]),
            ctx.cache.as_ref().and_then(|cache| cache.keys.clone())
        );
        session
            .req_header_mut()
            .insert_header(ACCEPT_ENCODING, "identity")
            .unwrap();
        session
            .req_header_mut()
            .set_uri("/file?sig=abc".parse().unwrap());
        let mut resp = response("text/html", None);
        compression
            .handle_upstream_response(&mut session, &mut ctx, &mut resp)
            .unwrap();
        assert_eq!("gzip", resp.headers.get(CONTENT_ENCODING).unwrap());
    }

    /// The same three in the default mode, where pingora compresses and
    /// the plugin can only tell it not to.
    #[tokio::test]
    async fn test_response_mode_types_min_length_and_skip() {
        async fn enabled(
            compression: &Compression,
            target: &str,
            mut resp: ResponseHeader,
        ) -> bool {
            let mut session = new_module_session(&format!(
                "GET {target} HTTP/1.1\r\nAccept-Encoding: gzip\r\n\r\n"
            ))
            .await;
            let mut ctx = Ctx::default();
            compression
                .handle_request(
                    PluginStep::EarlyRequest,
                    &mut session,
                    &mut ctx,
                )
                .await
                .unwrap();
            compression
                .handle_response(&mut session, &mut ctx, &mut resp)
                .await
                .unwrap();
            module_enabled(&session)
        }

        // No rule: the plugin switches nothing off, whatever the type and
        // the length. What is compressed is pingora's to say.
        let plain = new_compression("gzip_level = 6");
        assert_eq!(
            true,
            enabled(&plain, "/a.woff2", response("font/woff2", Some(10))).await
        );

        let ruled = new_compression(
            "gzip_level = 6\ntypes = [\"text/\", \"application/json\"]\nmin_length = 100\nskip = \"^/download/\"",
        );
        for (target, content_type, content_length, expected) in [
            ("/", "text/html; charset=utf-8", Some(4096), true),
            ("/api", "application/json", None, true),
            ("/doc.pdf", "application/pdf", Some(4096), false),
            ("/font.woff2", "font/woff2", None, false),
            ("/", "", Some(4096), false),
            // Of a listed type, and said to be too short.
            ("/", "text/html", Some(99), false),
            ("/", "text/html", Some(100), true),
            // Taken out by its path, whatever it is.
            ("/download/report.html", "text/html", Some(4096), false),
        ] {
            assert_eq!(
                expected,
                enabled(&ruled, target, response(content_type, content_length))
                    .await,
                "{target} {content_type} {content_length:?}"
            );
        }
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

    /// Regression: upstream mode compressed the part of a body a range
    /// request got, under the `Content-Range` of the uncompressed bytes,
    /// and left the upstream's strong `ETag` and `Accept-Ranges` on a
    /// body they no longer described.
    #[tokio::test]
    async fn test_upstream_mode_and_the_validators() {
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
            resp.append_header("ETag", "\"v1\"").unwrap();
            resp.append_header("Accept-Ranges", "bytes").unwrap();
            resp
        };
        let mut session =
            new_session("GET / HTTP/1.1\r\nAccept-Encoding: gzip\r\n\r\n")
                .await;

        // A part of the body is passed on as it is.
        let mut part = response(206);
        part.append_header("Content-Range", "bytes 0-99/4000")
            .unwrap();
        let result = compression
            .handle_upstream_response(
                &mut session,
                &mut Ctx::default(),
                &mut part,
            )
            .unwrap();
        assert_eq!(ResponsePluginResult::Unchanged, result);
        assert_eq!(false, part.headers.contains_key(CONTENT_ENCODING));
        assert_eq!("\"v1\"", part.headers.get("ETag").unwrap());

        // The whole of it is compressed, and says no more of itself than
        // is still true.
        let mut whole = response(200);
        let result = compression
            .handle_upstream_response(
                &mut session,
                &mut Ctx::default(),
                &mut whole,
            )
            .unwrap();
        assert_eq!(ResponsePluginResult::Modified, result);
        assert_eq!(false, whole.headers.contains_key("Accept-Ranges"));
        // The validator is the upstream's in what the cache stores, and
        // a weak one in what the client gets - also from the cache, and
        // again after the cache took the upstream's from a `304`.
        assert_eq!("\"v1\"", whole.headers.get("ETag").unwrap());
        for _ in 0..2 {
            let mut sent = whole.clone();
            compression
                .handle_response(&mut session, &mut Ctx::default(), &mut sent)
                .await
                .unwrap();
            assert_eq!("W/\"v1\"", sent.headers.get("ETag").unwrap());
        }
        // One that was not compressed keeps its validator.
        let mut plain = response(200);
        compression
            .handle_response(&mut session, &mut Ctx::default(), &mut plain)
            .await
            .unwrap();
        assert_eq!("\"v1\"", plain.headers.get("ETag").unwrap());
    }

    /// Regression: upstream mode passed the client's `Accept-Encoding`
    /// on. An upstream that compresses answered in the coding it liked
    /// best, and with a cache that answer was stored under the key of
    /// the coding this plugin had chosen.
    #[tokio::test]
    async fn test_upstream_mode_asks_for_the_coding_it_chose() {
        let compression = Compression::new(
            &toml::from_str::<PluginConf>(
                "mode = \"upstream\"\ngzip_level = 6",
            )
            .unwrap(),
        )
        .unwrap();
        let asked = async |accept_encoding: &str| {
            let mut session = new_session(&format!(
                "GET / HTTP/1.1\r\n{accept_encoding}\r\n"
            ))
            .await;
            let mut ctx = Ctx::default();
            compression
                .handle_request(
                    PluginStep::EarlyRequest,
                    &mut session,
                    &mut ctx,
                )
                .await
                .unwrap();
            let value = session
                .req_header()
                .headers
                .get(ACCEPT_ENCODING)
                .map(|value| value.to_str().unwrap().to_string());
            let keys = ctx.cache.and_then(|cache| cache.keys);
            (value, keys)
        };
        assert_eq!(
            (Some("gzip".to_string()), Some(vec!["gzip".to_string()])),
            asked("Accept-Encoding: br, gzip, zstd\r\n").await
        );
        assert_eq!(
            (Some("gzip".to_string()), Some(vec!["gzip".to_string()])),
            asked("Accept-Encoding: gzip\r\n").await
        );
        // Nothing this plugin compresses with: the header is left as it
        // came, and nothing is added to the key.
        assert_eq!(
            (Some("br".to_string()), Some(vec![])),
            asked("Accept-Encoding: br\r\n").await
        );
        assert_eq!((None, Some(vec![])), asked("").await);

        // An upstream that then compresses for that client has its answer
        // kept apart from the answers to other headers.
        let mut session =
            new_session("GET / HTTP/1.1\r\nAccept-Encoding: br\r\n\r\n").await;
        let mut resp = ResponseHeader::build(200, None).unwrap();
        resp.append_header("Content-Type", "text/html").unwrap();
        resp.append_header("Content-Encoding", "br").unwrap();
        let result = compression
            .handle_upstream_response(
                &mut session,
                &mut Ctx::default(),
                &mut resp,
            )
            .unwrap();
        assert_eq!(ResponsePluginResult::Modified, result);
        assert_eq!("Accept-Encoding", resp.headers.get(VARY).unwrap());

        // With no level switched on the plugin keeps out of all of it.
        let idle = Compression::new(
            &toml::from_str::<PluginConf>(
                "mode = \"upstream\"\ndecompression = true",
            )
            .unwrap(),
        )
        .unwrap();
        let mut session =
            new_session("GET / HTTP/1.1\r\nAccept-Encoding: gzip, br\r\n\r\n")
                .await;
        let mut ctx = Ctx::default();
        idle.handle_request(PluginStep::EarlyRequest, &mut session, &mut ctx)
            .await
            .unwrap();
        assert_eq!(
            "gzip, br",
            session.req_header().headers.get(ACCEPT_ENCODING).unwrap()
        );
        assert_eq!(true, ctx.cache.is_none());
    }

    /// Regression: an event stream was compressed like any other text,
    /// and a compressor hands its output over when its buffer is full or
    /// the body ends: the events arrived together, at the end. Neither it
    /// nor a response marked `no-transform` is touched now, in either mode.
    #[tokio::test]
    async fn test_compression_leaves_streams_and_no_transform() {
        let response = |content_type: &str, cache_control: &str| {
            let mut resp = ResponseHeader::build(200, None).unwrap();
            resp.append_header("Content-Type", content_type).unwrap();
            if !cache_control.is_empty() {
                resp.append_header("Cache-Control", cache_control).unwrap();
            }
            resp
        };
        let cases = [
            ("text/event-stream", "", false),
            ("Text/Event-Stream; charset=utf-8", "", false),
            ("text/html", "public, No-Transform", false),
            ("text/html", "no-cache", true),
            ("text/html", "", true),
        ];

        // The upstream mode compresses by itself.
        let upstream = Compression::new(
            &toml::from_str::<PluginConf>(
                "mode = \"upstream\"\ngzip_level = 6",
            )
            .unwrap(),
        )
        .unwrap();
        for (content_type, cache_control, compressed) in cases {
            let mut session =
                new_session("GET / HTTP/1.1\r\nAccept-Encoding: gzip\r\n\r\n")
                    .await;
            let mut resp = response(content_type, cache_control);
            upstream
                .handle_upstream_response(
                    &mut session,
                    &mut Ctx::default(),
                    &mut resp,
                )
                .unwrap();
            assert_eq!(
                compressed,
                resp.headers.contains_key(CONTENT_ENCODING),
                "{content_type} {cache_control}"
            );
        }

        // The default mode leaves it to pingora, which is told not to.
        let downstream = Compression::new(
            &toml::from_str::<PluginConf>("gzip_level = 6").unwrap(),
        )
        .unwrap();
        for (content_type, cache_control, compressed) in cases {
            let mock_io = Builder::new()
                .read(b"GET / HTTP/1.1\r\nAccept-Encoding: gzip\r\n\r\n")
                .build();
            let mut modules = HttpModules::new();
            modules.add_module(ResponseCompressionBuilder::enable(0));
            let mut session =
                Session::new_h1_with_modules(Box::new(mock_io), &modules);
            session.read_request().await.unwrap();
            let mut ctx = Ctx::default();
            downstream
                .handle_request(
                    PluginStep::EarlyRequest,
                    &mut session,
                    &mut ctx,
                )
                .await
                .unwrap();
            let mut resp = response(content_type, cache_control);
            downstream
                .handle_response(&mut session, &mut ctx, &mut resp)
                .await
                .unwrap();
            assert_eq!(
                compressed,
                session
                    .downstream_modules_ctx
                    .get::<ResponseCompression>()
                    .unwrap()
                    .is_enabled(),
                "{content_type} {cache_control}"
            );
        }
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

    #[test]
    fn test_prefer_encoding() {
        let prefer = |value: &str, coding: &str| {
            prefer_encoding(value, coding).unwrap_or_else(|| value.to_string())
        };
        assert_eq!(
            "zstd, gzip, deflate, br",
            prefer("gzip, deflate, br, zstd", "zstd")
        );
        // Already first: left as it is.
        assert_eq!(None, prefer_encoding("zstd, gzip", "zstd"));
        assert_eq!(None, prefer_encoding("gzip", "gzip"));
        // The entry keeps its weight, and its spelling.
        assert_eq!("br;q=0.9, gzip;q=0", prefer("gzip;q=0, br;q=0.9", "br"));
        assert_eq!("ZSTD, gzip", prefer("gzip,ZSTD", "zstd"));
        // Not listed: nothing to move.
        assert_eq!(None, prefer_encoding("gzip, x-br", "br"));
    }

    /// Regression: pingora compresses with the first coding the client
    /// lists. A browser lists gzip first, so the priority of the plugin
    /// did not hold, and with gzip disabled nothing was compressed.
    #[tokio::test]
    async fn test_compression_puts_its_choice_first() {
        let accept_encoding_after = async |conf: &str, accept: &str| {
            let compression = Compression::try_from(
                &toml::from_str::<PluginConf>(conf).unwrap(),
            )
            .unwrap();
            let input_header =
                format!("GET / HTTP/1.1\r\nAccept-Encoding: {accept}\r\n\r\n");
            let mock_io = Builder::new().read(input_header.as_bytes()).build();
            let mut modules = HttpModules::new();
            modules.add_module(ResponseCompressionBuilder::enable(0));
            let mut session =
                Session::new_h1_with_modules(Box::new(mock_io), &modules);
            session.read_request().await.unwrap();
            compression
                .handle_request(
                    PluginStep::EarlyRequest,
                    &mut session,
                    &mut Ctx::default(),
                )
                .await
                .unwrap();
            session
                .req_header()
                .headers
                .get("Accept-Encoding")
                .unwrap()
                .to_str()
                .unwrap()
                .to_string()
        };
        let browser = "gzip, deflate, br, zstd";
        let all = "gzip_level = 6\nbr_level = 6\nzstd_level = 3";
        assert_eq!(
            "zstd, gzip, deflate, br",
            accept_encoding_after(all, browser).await
        );
        assert_eq!(
            "br, gzip, deflate, zstd",
            accept_encoding_after("br_level = 6", browser).await
        );
        // A coding the client refuses is not chosen.
        assert_eq!(
            "br, gzip, zstd;q=0",
            accept_encoding_after(all, "gzip, br, zstd;q=0").await
        );
        // Nothing enabled that the client takes: untouched.
        assert_eq!(
            "gzip",
            accept_encoding_after("zstd_level = 3", "gzip").await
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
            compression.get_compress_level(&session, &Ctx::default())
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
