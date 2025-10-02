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
    get_bool_conf, get_hash_key, get_int_conf, get_plugin_factory,
    get_str_conf, Error,
};
use async_trait::async_trait;
use ctor::ctor;
use pingap_config::{PluginCategory, PluginConf};
use pingap_core::get_cookie_value;
use pingap_core::{Ctx, Plugin, PluginStep, RequestPluginResult};
use pingora::proxy::Session;
use rand::{rng, Rng};
use std::borrow::Cow;
use std::sync::Arc;
use tracing::debug;

type Result<T, E = Error> = std::result::Result<T, E>;

pub struct TrafficSplitting {
    plugin_step: PluginStep,
    hash_value: String,
    /// The upstream traffic targeting
    upstream: String,
    /// The weight of traffic targeting
    weight: u8,
    /// Whether to use stickiness
    stickiness: bool,
    /// The sticky cookie for traffic targeting
    sticky_cookie: String,
}

impl TryFrom<&PluginConf> for TrafficSplitting {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        let upstream = get_str_conf(value, "upstream");
        if upstream.is_empty() {
            return Err(Error::Invalid {
                category: PluginCategory::TrafficSplitting.to_string(),
                message: "upstream is not allowed empty".to_string(),
            });
        }
        let weight = get_int_conf(value, "weight").min(100) as u8;
        let stickiness = get_bool_conf(value, "stickiness");
        let sticky_cookie = get_str_conf(value, "sticky_cookie");
        if stickiness && sticky_cookie.is_empty() {
            return Err(Error::Invalid {
                category: PluginCategory::TrafficSplitting.to_string(),
                message: "sticky_cookie is not allowed empty".to_string(),
            });
        }
        Ok(Self {
            hash_value: get_hash_key(value),
            plugin_step: PluginStep::Request,
            upstream,
            weight,
            stickiness,
            sticky_cookie,
        })
    }
}

impl TrafficSplitting {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new traffic splitting plugin");
        TrafficSplitting::try_from(params)
    }
}

#[async_trait]
impl Plugin for TrafficSplitting {
    /// Returns the unique hash key for this plugin instance
    #[inline]
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    /// Handles incoming HTTP requests for traffic splitting
    ///
    /// # Arguments
    /// * `step` - Current plugin execution step
    /// * `session` - HTTP session containing request details
    /// * `ctx` - Ctx context for sharing data between plugins
    ///
    /// # Returns
    /// * `Ok(Some(HttpResponse))` - For immediate responses (e.g., PURGE operations)
    /// * `Ok(None)` - To continue normal request processing
    #[inline]
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        if step != self.plugin_step {
            return Ok(RequestPluginResult::Skipped);
        }
        // if stickiness is enabled, use cookie value to calculate roll value
        // if stickiness is disabled, use random number to calculate roll value
        let roll_value = if self.stickiness {
            get_cookie_value(session.req_header(), &self.sticky_cookie)
                .map(|cookie| (crc32fast::hash(cookie.as_bytes()) % 100) as u8)
                // if cookie not exist, return a value that will never hit
                .unwrap_or(u8::MAX)
        } else {
            rng().random_range(..100)
        };

        // if roll_value is less than or equal to weight, hit, need to switch upstream
        if roll_value <= self.weight {
            ctx.upstream.name = self.upstream.clone();
        }

        Ok(RequestPluginResult::Continue)
    }
}

#[ctor]
fn init() {
    get_plugin_factory().register("traffic_splitting", |params| {
        Ok(Arc::new(TrafficSplitting::new(params)?))
    });
}
