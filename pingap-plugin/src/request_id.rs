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
    Error, get_hash_key, get_int_conf_or_default, get_step_conf_in,
    get_str_conf,
};
use async_trait::async_trait;
use http::HeaderName;
use nanoid::nanoid;
use pingap_config::{PluginCategory, PluginConf};
use pingap_core::{
    Ctx, HTTP_HEADER_NAME_X_REQUEST_ID, Plugin, PluginStep, RequestPluginResult,
};
use pingora::proxy::Session;
use std::borrow::Cow;
use std::str::FromStr;
use tracing::debug;
use uuid::Uuid;

type Result<T, E = Error> = std::result::Result<T, E>;

/// How a fresh id is generated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdAlgorithm {
    /// UUID v7, time-ordered.
    Uuid,
    /// nanoid of `size` characters, URL safe.
    Nanoid,
}

/// The longest nanoid accepted; well past any tracing need, and a bound on
/// what `size` can allocate per request.
const MAX_NANOID_SIZE: i64 = 64;

/// Represents a plugin that handles request ID generation and management.
/// This plugin can either use existing request IDs from incoming requests
/// or generate new ones using configurable algorithms.
pub struct RequestId {
    // Determines when the plugin executes in the request lifecycle
    // Can be either Request (early in the pipeline) or ProxyUpstream (before forwarding)
    plugin_step: PluginStep,

    // The algorithm used for generating request IDs
    algorithm: IdAlgorithm,

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
        let category = PluginCategory::RequestId.to_string();
        let invalid = |message: String| Error::Invalid {
            category: category.clone(),
            message,
        };
        // Request IDs should be set early in the pipeline: during initial
        // request processing or just before forwarding to upstream.
        let step = get_step_conf_in(
            value,
            &category,
            PluginStep::Request,
            &[PluginStep::Request, PluginStep::ProxyUpstream],
        )?;

        // Parse and validate the custom header name if provided
        // An empty string means use the default X-Request-Id header
        let header_name = get_str_conf(value, "header_name");
        let header_name =
            if header_name.is_empty() {
                None
            } else {
                // Attempt to parse the header name, ensuring it's valid HTTP header syntax
                Some(HeaderName::from_str(&header_name).map_err(|e| {
                    invalid(format!("invalid header_name: {e}"))
                })?)
            };
        let algorithm = match get_str_conf(value, "algorithm").as_str() {
            "" | "uuid" => IdAlgorithm::Uuid,
            "nanoid" => IdAlgorithm::Nanoid,
            other => {
                return Err(invalid(format!(
                    "Invalid algorithm({other}), expect uuid or nanoid"
                )));
            },
        };
        // A negative size used to wrap through the cast into a nanoid of
        // billions of characters, allocated on the first request.
        let size = get_int_conf_or_default(value, "size", 8);
        if !(1..=MAX_NANOID_SIZE).contains(&size) {
            return Err(invalid(format!(
                "size({size}) must be between 1 and {MAX_NANOID_SIZE}"
            )));
        }

        Ok(Self {
            hash_value,
            plugin_step: step,
            algorithm,
            size: size as usize,
            header_name,
        })
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
    fn config_key(&self) -> Cow<'_, str> {
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
            header
        } else {
            &HTTP_HEADER_NAME_X_REQUEST_ID
        };

        // Check if request already has an ID header
        // If it does, store it in context and continue processing
        // This preserves request IDs across service boundaries
        if let Some(id) = session.get_header(key) {
            ctx.state.request_id =
                Some(id.to_str().unwrap_or_default().to_string());
            return Ok(RequestPluginResult::Continue);
        }

        // Generate new request ID based on configured algorithm
        let id = match self.algorithm {
            // nanoid generates shorter, URL-safe unique IDs
            // Good for scenarios where ID length matters
            IdAlgorithm::Nanoid => nanoid!(self.size),
            // UUID v7 is time-based and provides good sequential properties
            // Better for debugging and log analysis as they're naturally ordered
            IdAlgorithm::Uuid => Uuid::now_v7().to_string(),
        };

        // Store the generated ID in both context and request headers
        // Context storage makes it available to other parts of the application
        // Header insertion ensures it's forwarded to upstream services
        ctx.state.request_id = Some(id.clone());
        let _ = session.req_header_mut().insert_header(key, &id);
        Ok(RequestPluginResult::Continue)
    }
}

register_plugin!("request_id", RequestId);

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
        assert_eq!(IdAlgorithm::Nanoid, params.algorithm);
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
            "Plugin request_id invalid, message: Invalid step(response), expect one of: request, proxy_upstream",
            result.err().unwrap().to_string()
        );

        for (conf, expect) in [
            ("algorithm = \"ulid\"", "Invalid algorithm(ulid)"),
            ("size = -1", "size(-1) must be between 1 and 64"),
            ("size = 0", "size(0) must be between"),
            ("size = 65", "size(65) must be between"),
            ("header_name = \"bad name\"", "invalid header_name"),
        ] {
            let err =
                RequestId::new(&toml::from_str::<PluginConf>(conf).unwrap())
                    .err()
                    .unwrap()
                    .to_string();
            assert_eq!(true, err.contains(expect), "{conf}: {err}");
        }
        let params = RequestId::new(
            &toml::from_str::<PluginConf>("algorithm = \"uuid\"").unwrap(),
        )
        .unwrap();
        assert_eq!(IdAlgorithm::Uuid, params.algorithm);
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
