// Copyright 2024 Tree xie.
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

use super::{get_step_conf, get_str_conf, Error, ResponsePlugin, Result};
use crate::config::{PluginCategory, PluginConf, PluginStep};
use crate::state::State;
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use log::debug;
use pingora::http::ResponseHeader;
use pingora::proxy::Session;

struct JwtSignParams {
    plugin_step: PluginStep,
    secret: String,
    algorithm: String,
}

impl TryFrom<&PluginConf> for JwtSignParams {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        let step = get_step_conf(value);
        let params = Self {
            plugin_step: step,
            secret: get_str_conf(value, "secret"),
            algorithm: get_str_conf(value, "algorithm"),
        };

        if params.secret.is_empty() {
            return Err(Error::Invalid {
                category: PluginCategory::JwtSign.to_string(),
                message: "Jwt secret is not allowed empty".to_string(),
            });
        }

        if ![PluginStep::UpstreamResponse].contains(&params.plugin_step) {
            return Err(Error::Invalid {
                category: PluginCategory::JwtSign.to_string(),
                message: "Jwt auth plugin should be executed at request or proxy upstream step"
                    .to_string(),
            });
        }

        Ok(params)
    }
}

pub struct JwtSign {
    plugin_step: PluginStep,
    secret: String,
    algorithm: String,
}

impl JwtSign {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!("new jwt sign response plugin, params:{params:?}");
        let params = JwtSignParams::try_from(params)?;

        Ok(Self {
            plugin_step: params.plugin_step,
            secret: params.secret,
            algorithm: params.algorithm,
        })
    }
}

#[async_trait]
impl ResponsePlugin for JwtSign {
    #[inline]
    fn step(&self) -> String {
        self.plugin_step.to_string()
    }
    #[inline]
    fn category(&self) -> PluginCategory {
        PluginCategory::ResponseHeaders
    }
    #[inline]
    async fn handle(
        &self,
        step: PluginStep,
        _session: &mut Session,
        _ctx: &mut State,
        upstream_response: &mut ResponseHeader,
    ) -> pingora::Result<()> {
        if step != self.plugin_step {
            return Ok(());
        }
        let is_hs512 = self.algorithm == "HS512";
        let alg = if is_hs512 { "HS512" } else { "HS256" };
        let header =
            URL_SAFE_NO_PAD.encode(r#"{"alg": "{"#.to_owned() + alg + r#""}","typ": "JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(b"");
        let content = format!("{header}.{payload}");
        let secret = self.secret.as_bytes();
        let sign = if is_hs512 {
            let hash = hmac_sha512::HMAC::mac(content.as_bytes(), secret);
            URL_SAFE_NO_PAD.encode(hash)
        } else {
            let hash = hmac_sha256::HMAC::mac(content.as_bytes(), secret);
            URL_SAFE_NO_PAD.encode(hash)
        };
        let _ = upstream_response.insert_header("X-Jwt", format!("{content}.{sign}"));
        Ok(())
    }
}
