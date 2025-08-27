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
use bytes::Bytes;
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

/// Represents the action a plugin takes on a response.
#[derive(Debug, PartialEq, Eq)]
pub enum ResponsePluginResult {
    /// The plugin did not change the response.
    Unchanged,
    /// The plugin modified the response (e.g., headers or body).
    Modified,
    // TODO
    // FullyReplaced(HttpResponse),
}

// Represents the action a plugin task on a response
#[derive(Debug, PartialEq, Eq)]
pub enum ResponseBodyPluginResult {
    Unchanged,
    PartialReplaced(Option<Bytes>),
    FullyReplaced(Option<Bytes>),
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
    fn config_key(&self) -> Cow<'_, str> {
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
    /// * `Ok(result)` where:
    ///   * `result` - The result of the plugin's action on the request
    ///     - `Skipped`: Plugin did not run or took no action
    ///     - `Continue`: Plugin ran and modified the request; processing should continue
    ///     - `Respond(response)`: Plugin has decided to terminate the request and send an immediate response
    ///   * `response` - Optional HTTP response:
    ///     - `Some(response)`: Terminates request processing and returns this response to client
    ///     - `None`: Allows request to continue to next plugin or upstream
    /// * `Err` - Returns error if plugin processing failed
    #[inline]
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
    /// * `_session` - Mutable reference to the HTTP session
    /// * `_ctx` - Mutable reference to the request context
    /// * `_upstream_response` - Mutable reference to the upstream response header
    ///
    /// # Returns
    /// * `Ok(result)` - The result of the plugin's action on the response
    ///   - `Unchanged`: Plugin did not modify the response
    ///   - `Modified`: Plugin modified the response in some way
    /// * `Err` - Returns error if plugin processing failed
    #[inline]
    async fn handle_response(
        &self,
        _session: &mut Session,
        _ctx: &mut Ctx,
        _upstream_response: &mut ResponseHeader,
    ) -> pingora::Result<ResponsePluginResult> {
        Ok(ResponsePluginResult::Unchanged)
    }

    /// Processes an HTTP response body at a specified lifecycle step.
    ///
    /// # Parameters
    /// * `_step` - Current processing step in the response body lifecycle
    /// * `_session` - Mutable reference to the HTTP session
    /// * `_ctx` - Mutable reference to the request context
    /// * `_body` - Mutable reference to the response body
    /// * `_end_of_stream` - Boolean flag:
    ///   - `true`: The end of the response body has been reached
    ///   - `false`: The response body is still being received
    ///
    /// # Returns
    /// * `Ok(result)` - The result of the plugin's action on the response body
    ///   - `Unchanged`: Plugin did not modify the response body
    ///   - `PartialReplaced(new_body)`: Plugin replaced a part of the response body
    ///   - `FullyReplaced(new_body)`: Plugin replaced the response body with a new one
    /// * `Err` - Returns error if plugin processing failed
    #[inline]
    fn handle_response_body(
        &self,
        _session: &mut Session,
        _ctx: &mut Ctx,
        _body: &mut Option<bytes::Bytes>,
        _end_of_stream: bool,
    ) -> pingora::Result<ResponseBodyPluginResult> {
        Ok(ResponseBodyPluginResult::Unchanged)
    }

    /// Processes an upstream response at a specified lifecycle step.
    ///
    /// # Parameters
    /// * `_step` - Current processing step in the upstream response lifecycle
    /// * `_session` - Mutable reference to the HTTP session
    /// * `_ctx` - Mutable reference to the request context
    /// * `_upstream_response` - Mutable reference to the upstream response header
    ///
    /// # Returns
    /// * `Ok(result)` - The result of the plugin's action on the response
    ///   - `Unchanged`: Plugin did not modify the response
    ///   - `Modified`: Plugin modified the response in some way
    /// * `Err` - Returns error if plugin processing failed
    #[inline]
    fn handle_upstream_response(
        &self,
        _session: &mut Session,
        _ctx: &mut Ctx,
        _upstream_response: &mut ResponseHeader,
    ) -> pingora::Result<ResponsePluginResult> {
        Ok(ResponsePluginResult::Unchanged)
    }

    /// Processes an upstream response body at a specified lifecycle step.
    ///
    /// # Parameters
    /// * `_step` - Current processing step in the upstream response body lifecycle
    /// * `_session` - Mutable reference to the HTTP session
    /// * `_ctx` - Mutable reference to the request context
    /// * `_body` - Mutable reference to the upstream response body
    /// * `_end_of_stream` - Boolean flag:
    ///   - `true`: The end of the upstream response body has been reached
    ///   - `false`: The upstream response body is still being received
    ///
    /// # Returns
    /// * `Ok(result)` - The result of the plugin's action on the response body
    ///   - `Unchanged`: Plugin did not modify the response body
    ///   - `PartialReplaced(new_body)`: Plugin replaced a part of the response body
    ///   - `FullyReplaced(new_body)`: Plugin replaced the response body with a new one
    /// * `Err` - Returns error if plugin processing failed
    #[inline]
    fn handle_upstream_response_body(
        &self,
        _session: &mut Session,
        _ctx: &mut Ctx,
        _body: &mut Option<bytes::Bytes>,
        _end_of_stream: bool,
    ) -> pingora::Result<ResponseBodyPluginResult> {
        Ok(ResponseBodyPluginResult::Unchanged)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

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

    #[test]
    fn test_request_plugin_result() {
        let skip1 = RequestPluginResult::Skipped;
        let skip2 = RequestPluginResult::Skipped;
        assert_eq!(true, skip1 == skip2);

        let continue1 = RequestPluginResult::Continue;
        let continue2 = RequestPluginResult::Continue;
        assert_eq!(true, continue1 == continue2);

        let respond1 = RequestPluginResult::Respond(HttpResponse::no_content());
        let respond2 = RequestPluginResult::Respond(HttpResponse::no_content());
        assert_eq!(false, respond1 == respond2);
    }
}
