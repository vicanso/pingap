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
    get_hash_key, get_int_conf, get_plugin_factory, get_step_conf,
    get_str_conf, Error,
};
use async_trait::async_trait;
use ctor::ctor;
use http::HeaderName;
use nanoid::nanoid;
use pingap_config::{PluginCategory, PluginConf};
use pingap_core::{
    Ctx, Plugin, PluginStep, RequestPluginResult, HTTP_HEADER_NAME_X_REQUEST_ID,
};
use pingora::proxy::Session;
use std::borrow::Cow;
use std::str::FromStr;
use std::sync::Arc;
use tracing::debug;
use uuid::Uuid;

type Result<T, E = Error> = std::result::Result<T, E>;

/// Represents a plugin that handles request ID generation and management.
/// This plugin can either use existing request IDs from incoming requests
/// or generate new ones using configurable algorithms.
pub struct RequestId {
    // Determines when the plugin executes in the request lifecycle
    // Can be either Request (early in the pipeline) or ProxyUpstream (before forwarding)
    plugin_step: PluginStep,

    // The algorithm used for generating request IDs:
    // - "nanoid": Generates collision-resistant IDs with configurable length
    // - Any other value: Uses UUID v7 (time-based UUID with better sequential properties)
    algorithm: String,

    // Optional custom header name for the request ID
    // If None, defaults to X-Request-ID
    // Must be a valid HTTP header name when specified
    header_name: Option<HeaderName>,

    // Size parameter for nanoid generation
    // Only used when algorithm = "nanoid"
    // Determines the length of the generated ID
    size: usize,

    // Unique hash value for this plugin instance
    // Used to identify and potentially cache plugin configurations
    hash_value: String,
}

impl TryFrom<&PluginConf> for RequestId {
    type Error = Error;

    /// Attempts to create a RequestId plugin from the provided configuration.
    ///
    /// # Arguments
    /// * `value` - The plugin configuration containing settings for the request ID handling
    ///
    /// # Returns
    /// * `Ok(RequestId)` - Successfully created plugin instance
    /// * `Err(Error)` - If configuration is invalid (e.g., invalid header name or step)
    ///
    /// # Configuration Options
    /// * `header_name` - Custom header name for the request ID (optional)
    /// * `algorithm` - ID generation algorithm ("nanoid" or UUID v7)
    /// * `size` - Length of generated nanoid (if using nanoid algorithm)
    /// * `step` - Plugin execution step (must be Request or ProxyUpstream)
    fn try_from(value: &PluginConf) -> Result<Self> {
        // Generate a unique hash key for this plugin instance based on its configuration
        let hash_value = get_hash_key(value);
        // Extract the execution step from configuration
        let step = get_step_conf(value, PluginStep::Request);

        // Parse and validate the custom header name if provided
        // An empty string means use the default X-Request-Id header
        let header_name = get_str_conf(value, "header_name");
        let header_name = if header_name.is_empty() {
            None
        } else {
            // Attempt to parse the header name, ensuring it's valid HTTP header syntax
            Some(HeaderName::from_str(&header_name).map_err(|e| {
                Error::Invalid {
                    category: "header_name".to_string(),
                    message: e.to_string(),
                }
            })?)
        };
        let mut size = get_int_conf(value, "size") as usize;
        if size == 0 {
            size = 8;
        }

        let params = Self {
            hash_value,
            plugin_step: step,
            algorithm: get_str_conf(value, "algorithm"),
            size,
            header_name,
        };

        // Validate execution step - request IDs should be set early in the pipeline
        // Either during initial request processing or just before forwarding to upstream
        if ![PluginStep::Request, PluginStep::ProxyUpstream]
            .contains(&params.plugin_step)
        {
            return Err(Error::Invalid {
                category: PluginCategory::RequestId.to_string(),
                message: "Request id should be executed at request or proxy upstream step".to_string(),
            });
        }
        Ok(params)
    }
}

impl RequestId {
    /// Creates a new RequestId plugin instance from the provided configuration.
    ///
    /// # Arguments
    /// * `params` - Plugin configuration parameters
    ///
    /// # Returns
    /// * `Result<RequestId>` - The created plugin instance or an error if configuration is invalid
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new request id plugin");
        Self::try_from(params)
    }
}

#[async_trait]
impl Plugin for RequestId {
    /// Returns the unique hash key identifying this plugin instance.
    /// Used for caching and plugin identification purposes.
    #[inline]
    fn hash_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    /// Handles incoming requests by managing request IDs.
    ///
    /// # Arguments
    /// * `step` - Current execution step in the request pipeline
    /// * `session` - Mutable reference to the current session
    /// * `ctx` - Mutable reference to the request context state
    ///
    /// # Returns
    /// * `Ok(None)` - Continue normal request processing
    /// * `Ok(Some(HttpResponse))` - Return early with the provided response
    /// * `Err(_)` - If an error occurs during processing
    ///
    /// # Behavior
    /// 1. Returns early if not at configured execution step
    /// 2. Uses existing request ID if present in headers
    /// 3. Generates new ID using configured algorithm if needed
    /// 4. Stores ID in both context and request headers
    #[inline]
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        // Early return if we're not at the configured execution step
        if step != self.plugin_step {
            return Ok(RequestPluginResult::Skipped);
        }

        // Determine which header name to use for the request ID
        // Either the custom configured name or the default X-Request-ID
        let key = if let Some(header) = &self.header_name {
            header.clone()
        } else {
            HTTP_HEADER_NAME_X_REQUEST_ID.clone()
        };

        // Check if request already has an ID header
        // If it does, store it in context and continue processing
        // This preserves request IDs across service boundaries
        if let Some(id) = session.get_header(&key) {
            ctx.state.request_id =
                Some(id.to_str().unwrap_or_default().to_string());
            return Ok(RequestPluginResult::Continue);
        }

        // Generate new request ID based on configured algorithm
        let id = match self.algorithm.as_str() {
            "nanoid" => {
                // nanoid generates shorter, URL-safe unique IDs
                // Good for scenarios where ID length matters
                let size = self.size;
                nanoid!(size)
            },
            _ => {
                // UUID v7 is time-based and provides good sequential properties
                // Better for debugging and log analysis as they're naturally ordered
                Uuid::now_v7().to_string()
            },
        };

        // Store the generated ID in both context and request headers
        // Context storage makes it available to other parts of the application
        // Header insertion ensures it's forwarded to upstream services
        ctx.state.request_id = Some(id.clone());
        let _ = session.req_header_mut().insert_header(key, &id);
        Ok(RequestPluginResult::Continue)
    }
}

#[ctor]
fn init() {
    get_plugin_factory()
        .register("request_id", |params| Ok(Arc::new(RequestId::new(params)?)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingap_config::PluginConf;
    use pingap_core::{Ctx, PluginStep};
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    /// Tests the creation of RequestId plugin with various configurations.
    /// Verifies proper handling of algorithm, size, and header name settings.
    #[test]
    fn test_request_id_params() {
        let params = RequestId::new(
            &toml::from_str::<PluginConf>(
                r###"
algorithm = "nanoid"
size = 10
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!("nanoid", params.algorithm);
        assert_eq!(10, params.size);

        let params = RequestId::new(
            &toml::from_str::<PluginConf>(
                r###"
algorithm = "nanoid"
size = 10
header_name = "uid"
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!("uid", params.header_name.unwrap().to_string());

        let result = RequestId::new(
            &toml::from_str::<PluginConf>(
                r###"
step = "response"
algorithm = "nanoid"
size = 10
"###,
            )
            .unwrap(),
        );
        assert_eq!(
            "Plugin request_id invalid, message: Request id should be executed at request or proxy upstream step",
            result.err().unwrap().to_string()
        );
    }

    /// Tests the request handling functionality of the RequestId plugin.
    /// Verifies:
    /// 1. Preservation of existing request IDs
    /// 2. Generation of new IDs when none exist
    /// 3. Proper ID length when using nanoid
    #[tokio::test]
    async fn test_request_id() {
        let id = RequestId::new(
            &toml::from_str::<PluginConf>(
                r###"
algorithm = "nanoid"
size = 10
"###,
            )
            .unwrap(),
        )
        .unwrap();

        let headers = ["X-Request-Id: 123"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let mut state = Ctx::default();
        let result = id
            .handle_request(PluginStep::Request, &mut session, &mut state)
            .await
            .unwrap();
        assert_eq!(true, result == RequestPluginResult::Continue);
        assert_eq!("123", state.state.request_id.unwrap_or_default());

        let headers = ["Accept-Encoding: gzip"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let mut state = Ctx::default();
        let result = id
            .handle_request(PluginStep::Request, &mut session, &mut state)
            .await
            .unwrap();
        assert_eq!(true, result == RequestPluginResult::Continue);
        assert_eq!(10, state.state.request_id.unwrap_or_default().len());
    }
}
