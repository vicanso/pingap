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

use super::{get_bool_conf, get_hash_key, get_int_conf, Error, Plugin, Result};
use crate::http_extra::HttpResponse;
use crate::state::State;
use async_trait::async_trait;
use pingap_config::{PluginConf, PluginStep};
use pingora::modules::http::compression::ResponseCompression;
use pingora::protocols::http::compression::Algorithm;
use pingora::proxy::Session;
use tracing::debug;

// Constants defining supported compression algorithm identifiers
const ZSTD: &str = "zstd"; // Zstandard compression
const BR: &str = "br"; // Brotli compression
const GZIP: &str = "gzip"; // Gzip compression

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

        // Enable compression if any algorithm has a non-zero level
        let support_compression = gzip_level + br_level + zstd_level > 0;

        let params = Self {
            hash_value,
            gzip_level,
            br_level,
            zstd_level,
            decompression,
            support_compression,
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
    /// * `_ctx` - State context (unused)
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
        _ctx: &mut State,
    ) -> pingora::Result<Option<HttpResponse>> {
        // Early return conditions
        if step != self.plugin_step {
            return Ok(None);
        }
        if !self.support_compression {
            return Ok(None);
        }

        // Extract and validate Accept-Encoding header
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

        // Select compression algorithm based on priority and client support
        // Priority: zstd > br > gzip
        let level = if self.zstd_level > 0 && accept_encoding.contains(ZSTD) {
            self.zstd_level
        } else if self.br_level > 0 && accept_encoding.contains(BR) {
            self.br_level
        } else if self.gzip_level > 0 && accept_encoding.contains(GZIP) {
            self.gzip_level
        } else {
            0
        };
        debug!(level, "compression level");
        if level == 0 {
            return Ok(None);
        }

        // Get compression context from session
        let Some(c) = session
            .downstream_modules_ctx
            .get_mut::<ResponseCompression>()
        else {
            return Ok(None);
        };

        // Configure decompression if specified
        if let Some(decompression) = self.decompression {
            c.adjust_decompression(decompression);
        }

        // Configure compression levels for each supported algorithm
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
    use crate::plugin::Plugin;
    use crate::state::State;
    use pingap_config::{PluginConf, PluginStep};
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
