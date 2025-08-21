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

use super::{Ctx, HttpResponse};
use async_trait::async_trait;
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use std::borrow::Cow;
use strum::EnumString;

#[derive(
    PartialEq, Debug, Default, Clone, Copy, EnumString, strum::Display,
)]
#[strum(serialize_all = "snake_case")]
pub enum PluginStep {
    EarlyRequest,
    #[default]
    Request,
    ProxyUpstream,
    UpstreamResponse,
    Response,
}

/// A more expressive return type for `handle_request`.
/// It clearly states the plugin's decision.
pub enum RequestPluginResult {
    /// The plugin did not run or took no action.
    Skipped,
    /// The plugin ran and modified the request; processing should continue.
    Continue,
    /// The plugin has decided to terminate the request and send an immediate response.
    Respond(HttpResponse),
}

// Manually implement the PartialEq trait for RequestPluginResult
impl PartialEq for RequestPluginResult {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            // Two Skipped variants are always equal.
            (RequestPluginResult::Skipped, RequestPluginResult::Skipped) => {
                true
            },

            // Two Continue variants are always equal.
            (RequestPluginResult::Continue, RequestPluginResult::Continue) => {
                true
            },

            // Any other combination is not equal.
            _ => false,
        }
    }
}

/// Core trait that defines the interface all plugins must implement.
///
/// Plugins can handle both requests and responses at different processing steps.
/// The default implementations do nothing and return Ok.
#[async_trait]
pub trait Plugin: Sync + Send {
    /// Returns a unique key that identifies this specific plugin instance.
    ///
    /// # Purpose
    /// - Can be used for caching plugin results
    /// - Helps differentiate between multiple instances of the same plugin type
    /// - Useful for tracking and debugging
    ///
    /// # Default
    /// Returns an empty string by default, which means no specific instance identification.
    fn hash_key(&self) -> Cow<'_, str> {
        Cow::Borrowed("")
    }

    /// Processes an HTTP request at a specified lifecycle step.
    ///
    /// # Parameters
    /// * `_step` - Current processing step in the request lifecycle (e.g., pre-routing, post-routing)
    /// * `_session` - Mutable reference to the HTTP session containing request data
    /// * `_ctx` - Mutable reference to the request context for storing state
    ///
    /// # Returns
    /// * `Ok((executed, response))` where:
    ///   * `executed` - Boolean flag:
    ///     - `true`: Plugin performed meaningful logic for this request
    ///     - `false`: Plugin was skipped or did nothing for this request
    ///   * `response` - Optional HTTP response:
    ///     - `Some(response)`: Terminates request processing and returns this response to client
    ///     - `None`: Allows request to continue to next plugin or upstream
    /// * `Err` - Returns error if plugin processing failed
    async fn handle_request(
        &self,
        _step: PluginStep,
        _session: &mut Session,
        _ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        Ok(RequestPluginResult::Skipped)
    }

    /// Processes an HTTP response at a specified lifecycle step.
    ///
    /// # Parameters
    /// * `_step` - Current processing step in the response lifecycle
    /// * `_session` - Mutable reference to the HTTP session
    /// * `_ctx` - Mutable reference to the request context
    /// * `_upstream_response` - Mutable reference to the upstream response header
    ///
    /// # Returns
    /// * `Ok(modified)` - Boolean flag:
    ///   - `true`: Plugin modified the response in some way
    ///   - `false`: Plugin did not modify the response
    /// * `Err` - Returns error if plugin processing failed
    async fn handle_response(
        &self,
        _step: PluginStep,
        _session: &mut Session,
        _ctx: &mut Ctx,
        _upstream_response: &mut ResponseHeader,
    ) -> pingora::Result<bool> {
        Ok(false)
    }
    fn handle_upstream_response(
        &self,
        _step: PluginStep,
        _session: &mut Session,
        _ctx: &mut Ctx,
        _upstream_response: &mut ResponseHeader,
    ) -> pingora::Result<bool> {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_step() {
        let step = "early_request".parse::<PluginStep>().unwrap();
        assert_eq!(step, PluginStep::EarlyRequest);
        assert_eq!(step.to_string(), "early_request");

        let step = "request".parse::<PluginStep>().unwrap();
        assert_eq!(step, PluginStep::Request);
        assert_eq!(step.to_string(), "request");

        let step = "proxy_upstream".parse::<PluginStep>().unwrap();
        assert_eq!(step, PluginStep::ProxyUpstream);
        assert_eq!(step.to_string(), "proxy_upstream");

        let step = "response".parse::<PluginStep>().unwrap();
        assert_eq!(step, PluginStep::Response);
        assert_eq!(step.to_string(), "response");
    }
}
