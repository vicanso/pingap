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
    Response,
}

/// Core trait that defines the interface all plugins must implement.
///
/// Plugins can handle both requests and responses at different processing steps.
/// The default implementations do nothing and return Ok.
#[async_trait]
pub trait Plugin: Sync + Send {
    fn hash_key(&self) -> String {
        "".to_string()
    }
    async fn handle_request(
        &self,
        _step: PluginStep,
        _session: &mut Session,
        _ctx: &mut Ctx,
    ) -> pingora::Result<Option<HttpResponse>> {
        Ok(None)
    }
    async fn handle_response(
        &self,
        _step: PluginStep,
        _session: &mut Session,
        _ctx: &mut Ctx,
        _upstream_response: &mut ResponseHeader,
    ) -> pingora::Result<()> {
        Ok(())
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
