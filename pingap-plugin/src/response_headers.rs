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
use super::{get_hash_key, get_plugin_factory, get_str_slice_conf, Error};
use async_trait::async_trait;
use ctor::ctor;
use http::header::HeaderName;
use pingap_config::{PluginCategory, PluginConf};
use pingap_core::{
    convert_header, convert_header_value, Ctx, HttpHeader, Plugin,
    ResponsePluginResult,
};
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use std::borrow::Cow;
use std::str::FromStr;
use std::sync::Arc;
use tracing::debug;

type Result<T, E = Error> = std::result::Result<T, E>;

/// ResponseHeaders plugin handles HTTP response header modifications.
/// It provides functionality to add, remove, set, and rename response headers
/// based on configuration provided in TOML format.
pub struct ResponseHeaders {
    /// Headers to be appended to the response
    /// - Allows multiple values for the same header name
    /// - Preserves any existing header values
    /// - Format: Vec of (header_name, header_value) pairs
    ///   Example: [("x-service", "1"), ("x-service", "2")]
    add_headers: Vec<HttpHeader>,

    /// Headers to be completely removed from the response
    /// - Removes all values for specified header names
    /// - Headers are removed regardless of their values
    ///   Example: ["content-type", "x-powered-by"]
    remove_headers: Vec<HeaderName>,

    /// Headers to be set with specific values
    /// - Overwrites any existing values for the header
    /// - If header doesn't exist, it will be created
    /// - Format: Vec of (header_name, header_value) pairs
    ///   Example: [("x-response-id", "123")]
    set_headers: Vec<HttpHeader>,

    /// Headers to be renamed while preserving their values
    /// - Format: Vec of (original_name, new_name) tuples
    /// - Values are moved from original name to new name
    /// - If new name already exists, values are appended
    ///   Example: [("x-old-header", "x-new-header")]
    rename_headers: Vec<(HeaderName, HeaderName)>,

    /// Headers to be set only if they don't already exist in the response
    /// - Only sets the header if it's not present
    /// - Does not modify existing header values
    /// - Format: Vec of (header_name, header_value) pairs
    ///   Example: [("x-default-header", "default-value")]
    set_headers_not_exists: Vec<HttpHeader>,

    /// Unique identifier for this plugin instance
    /// Generated from the plugin configuration to track changes
    hash_value: String,
}

impl TryFrom<&PluginConf> for ResponseHeaders {
    type Error = Error;

    /// Attempts to create a ResponseHeaders plugin from a plugin configuration.
    ///
    /// # Arguments
    /// * `value` - The plugin configuration containing header modification rules
    ///
    /// # Returns
    /// * `Ok(ResponseHeaders)` - Successfully created plugin instance
    /// * `Err(Error)` - If configuration is invalid or step is not "response"
    ///
    /// # Configuration Format
    /// ```toml
    /// step = "response"
    /// add_headers = ["Header-Name:Value"]
    /// remove_headers = ["Header-Name"]
    /// set_headers = ["Header-Name:Value"]
    /// rename_headers = ["Old-Name:New-Name"]
    /// ```
    fn try_from(value: &PluginConf) -> Result<Self> {
        // Generate unique hash for this plugin configuration
        let hash_value = get_hash_key(value);

        // Parse add_headers from config
        // Format: "Header-Name:header value"
        let mut add_headers = vec![];
        for item in get_str_slice_conf(value, "add_headers").iter() {
            let header = convert_header(item).map_err(|e| Error::Invalid {
                category: PluginCategory::ResponseHeaders.to_string(),
                message: e.to_string(),
            })?;
            if let Some(item) = header {
                add_headers.push(item);
            }
        }

        let mut set_headers = vec![];
        for item in get_str_slice_conf(value, "set_headers").iter() {
            let header = convert_header(item).map_err(|e| Error::Invalid {
                category: PluginCategory::ResponseHeaders.to_string(),
                message: e.to_string(),
            })?;
            if let Some(item) = header {
                set_headers.push(item);
            }
        }
        let mut remove_headers = vec![];
        for item in get_str_slice_conf(value, "remove_headers").iter() {
            let item =
                HeaderName::from_str(item).map_err(|e| Error::Invalid {
                    category: PluginCategory::ResponseHeaders.to_string(),
                    message: e.to_string(),
                })?;
            remove_headers.push(item);
        }
        let mut rename_headers = vec![];
        for item in get_str_slice_conf(value, "rename_headers").iter() {
            if let Some((k, v)) =
                item.split_once(':').map(|(k, v)| (k.trim(), v.trim()))
            {
                let original_name =
                    HeaderName::from_str(k).map_err(|e| Error::Invalid {
                        category: PluginCategory::ResponseHeaders.to_string(),
                        message: e.to_string(),
                    })?;
                let new_name =
                    HeaderName::from_str(v).map_err(|e| Error::Invalid {
                        category: PluginCategory::ResponseHeaders.to_string(),
                        message: e.to_string(),
                    })?;
                rename_headers.push((original_name, new_name));
            }
        }
        let mut set_headers_not_exists = vec![];
        for item in get_str_slice_conf(value, "set_headers_not_exists").iter() {
            let header = convert_header(item).map_err(|e| Error::Invalid {
                category: PluginCategory::ResponseHeaders.to_string(),
                message: e.to_string(),
            })?;
            if let Some(item) = header {
                set_headers_not_exists.push(item);
            }
        }

        let params = Self {
            hash_value,
            add_headers,
            set_headers,
            remove_headers,
            rename_headers,
            set_headers_not_exists,
        };

        Ok(params)
    }
}

impl ResponseHeaders {
    /// Creates a new ResponseHeaders plugin instance from the given configuration.
    ///
    /// # Arguments
    /// * `params` - Plugin configuration containing header modification rules
    ///
    /// # Returns
    /// * `Ok(ResponseHeaders)` - Successfully created plugin instance
    /// * `Err(Error)` - If configuration is invalid
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new stats plugin");
        Self::try_from(params)
    }
}

#[async_trait]
impl Plugin for ResponseHeaders {
    /// Returns the unique hash key for this plugin instance.
    #[inline]
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    /// Handles response header modifications during the response phase.
    ///
    /// # Arguments
    /// * `session` - Current HTTP session
    /// * `ctx` - Plugin state context
    /// * `upstream_response` - Response headers to modify
    ///
    /// # Processing Order
    /// 1. Add new headers (preserving existing values)
    /// 2. Remove specified headers
    /// 3. Set headers (overwriting existing values)
    /// 4. Rename headers (moving values to new names)
    ///
    /// # Returns
    /// * `Ok(())` - Headers processed successfully
    /// * `Err(...)` - If a critical error occurs
    ///
    /// Note: Individual header operation failures are ignored to ensure
    /// the response can still be processed.
    #[inline]
    async fn handle_response(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
        upstream_response: &mut ResponseHeader,
    ) -> pingora::Result<ResponsePluginResult> {
        // Headers are processed in a specific order to ensure predictable behavior:
        // 1. Add new headers (allows multiple values)
        //    - Uses append_header which preserves existing values
        //    - Supports dynamic value substitution via convert_header_value
        // 2. Remove specified headers
        //    - Completely removes headers regardless of value
        // 3. Set headers (overwrites existing values)
        //    - Uses insert_header which replaces any existing values
        //    - Supports dynamic value substitution via convert_header_value
        // 4. Rename headers (moves values to new header name)
        //    - Removes original header and moves its value to new name
        //    - If new name already exists, value is appended

        // Add new headers (append mode)
        for (name, value) in &self.add_headers {
            // Try to convert any dynamic values in header
            if let Some(value) = convert_header_value(value, session, ctx) {
                let _ = upstream_response.append_header(name, value);
            } else {
                // Use original value if conversion fails
                let _ = upstream_response.append_header(name, value);
            }
        }

        // Remove specified headers
        for name in &self.remove_headers {
            let _ = upstream_response.remove_header(name);
        }

        // Set headers (overwrite mode)
        for (name, value) in &self.set_headers {
            if let Some(value) = convert_header_value(value, session, ctx) {
                let _ = upstream_response.insert_header(name, value);
            } else {
                let _ = upstream_response.insert_header(name, value);
            }
        }

        // Set headers that don't exist (conditional set)
        for (name, value) in &self.set_headers_not_exists {
            if !upstream_response.headers.contains_key(name) {
                if let Some(value) = convert_header_value(value, session, ctx) {
                    let _ = upstream_response.insert_header(name, value);
                } else {
                    let _ = upstream_response.insert_header(name, value);
                }
            }
        }

        // Rename headers (move values to new name)
        for (original_name, new_name) in &self.rename_headers {
            if let Some(value) = upstream_response.remove_header(original_name)
            {
                let _ = upstream_response.append_header(new_name, value);
            }
        }
        Ok(ResponsePluginResult::Modified)
    }
}

#[ctor]
fn init() {
    get_plugin_factory().register("response_headers", |params| {
        Ok(Arc::new(ResponseHeaders::new(params)?))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingap_config::PluginConf;
    use pingap_core::Ctx;
    use pingora::http::ResponseHeader;
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    /// Tests parsing of plugin configuration parameters.
    ///
    /// Verifies:
    /// - Valid configuration is parsed correctly
    /// - Headers are properly formatted
    /// - Invalid step returns appropriate error
    #[test]
    fn test_response_headers_params() {
        let params = ResponseHeaders::try_from(
            &toml::from_str::<PluginConf>(
                r###"
step = "response"
add_headers = [
"X-Service:1",
"X-Service:2",
]
set_headers = [
"X-Response-Id:123"
]
remove_headers = [
"Content-Type"
]
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            r#"[("x-service", "1"), ("x-service", "2")]"#,
            format!("{:?}", params.add_headers)
        );
        assert_eq!(
            r#"[("x-response-id", "123")]"#,
            format!("{:?}", params.set_headers)
        );
        assert_eq!(
            r#"["content-type"]"#,
            format!("{:?}", params.remove_headers)
        );
    }

    /// Tests header modification functionality.
    ///
    /// Verifies:
    /// - Headers are added correctly
    /// - Headers are removed as specified
    /// - Headers are set with new values
    /// - Response contains expected final headers
    #[tokio::test]
    async fn test_response_headers() {
        let response_headers = ResponseHeaders::new(
            &toml::from_str::<PluginConf>(
                r###"
step = "response"
add_headers = [
    "X-Service:1",
    "X-Service:2",
]
set_headers = [
    "X-Response-Id:123"
]
remove_headers = [
    "Content-Type"
]
set_headers_not_exists = [
    "X-Response-Id:abc",
    "X-Tag:userTag",
]
    "###,
            )
            .unwrap(),
        )
        .unwrap();

        let headers = ["Accept-Encoding: gzip"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let mut upstream_response =
            ResponseHeader::build_no_case(200, None).unwrap();

        upstream_response
            .append_header("Content-Type", "application/json")
            .unwrap();

        response_headers
            .handle_response(
                &mut session,
                &mut Ctx::default(),
                &mut upstream_response,
            )
            .await
            .unwrap();

        assert_eq!(
            r###"ResponseHeader { base: Parts { status: 200, version: HTTP/1.1, headers: {"x-service": "1", "x-service": "2", "x-response-id": "123", "x-tag": "userTag"} }, header_name_map: None, reason_phrase: None }"###,
            format!("{upstream_response:?}")
        )
    }
}
