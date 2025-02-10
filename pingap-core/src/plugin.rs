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

use super::{Ctx, Error, HttpResponse};
use async_trait::async_trait;
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use serde::{Deserialize, Serialize, Serializer};
use std::str::FromStr;
use strum::EnumString;

type Result<T, E = Error> = std::result::Result<T, E>;

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

impl Serialize for PluginStep {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().as_ref())
    }
}

impl<'de> Deserialize<'de> for PluginStep {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value: String = serde::Deserialize::deserialize(deserializer)?;
        let category =
            PluginStep::from_str(&value).unwrap_or(PluginStep::default());

        Ok(category)
    }
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
