// Copyright 2026 Zsombor Gegesy.
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

#[cfg(feature = "geo")]
use super::{
    Error, get_hash_key, get_plugin_factory, get_str_conf, get_str_slice_conf,
};
use async_trait::async_trait;
use bytes::Bytes;
use ctor::ctor;
use http::StatusCode;
use pingap_config::PluginConf;
use pingap_core::{
    Ctx, HttpResponse, Plugin, PluginStep, RequestPluginResult, get_client_ip,
};
use pingora::proxy::Session;
use std::borrow::Cow;
use std::net::IpAddr;
use std::sync::Arc;
use tor_geoip::GeoipDb;
use tracing::{debug, info};

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestrictionCategory {
    Deny,
    Allow,
    Reporting,
}

impl TryFrom<&str> for RestrictionCategory {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "deny" => Ok(RestrictionCategory::Deny),
            "allow" => Ok(RestrictionCategory::Allow),
            "reporting" => Ok(RestrictionCategory::Reporting),
            _ => Err(format!("invalid restriction category: {value}")),
        }
    }
}

pub struct GeoRestriction {
    plugin_step: PluginStep,
    country_codes: Vec<String>,
    restriction_category: RestrictionCategory,
    forbidden_resp: HttpResponse,
    hash_value: String,
    geo_db: Arc<GeoipDb>,
}

impl TryFrom<&PluginConf> for GeoRestriction {
    type Error = Error;

    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);

        let raw_codes = get_str_slice_conf(value, "country_codes");
        let country_codes: Vec<String> = raw_codes
            .iter()
            .flat_map(|s| s.split(|c| c == ' ' || c == ','))
            .filter(|s| !s.is_empty())
            .map(|s| s.trim().to_uppercase())
            .collect();

        for code in &country_codes {
            if code.len() != 2 || !code.chars().all(|c| c.is_ascii_alphabetic())
            {
                return Err(Error::Invalid {
                    category: "geo_restriction".to_string(),
                    message: format!(
                        "invalid country code '{}': must be exactly 2 ASCII letters",
                        code
                    ),
                });
            }
        }

        let mut message = get_str_conf(value, "message");
        if message.is_empty() {
            message = "Access from your country is not allowed".to_string();
        }

        let category_str = get_str_conf(value, "type");
        let restriction_category =
            category_str.as_str().try_into().map_err(|e: String| {
                Error::Invalid {
                    category: "geo_restriction".to_string(),
                    message: e,
                }
            })?;

        let params = Self {
            hash_value,
            plugin_step: PluginStep::Request,
            country_codes,
            restriction_category,
            forbidden_resp: HttpResponse {
                status: StatusCode::FORBIDDEN,
                body: Bytes::from(message),
                ..Default::default()
            },
            geo_db: GeoipDb::new_embedded(),
        };

        Ok(params)
    }
}

impl GeoRestriction {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new geo restriction plugin");
        let result = Self::try_from(params)?;
        info!(
            country_codes = ?result.country_codes,
            restriction_category = ?result.restriction_category,
            "geo restriction plugin configured"
        );
        Ok(result)
    }
}

#[async_trait]
impl Plugin for GeoRestriction {
    #[inline]
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

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

        let ip = ctx
            .conn
            .client_ip
            .get_or_insert_with(|| get_client_ip(session));

        let ip_addr: IpAddr = match ip.parse() {
            Ok(addr) => addr,
            Err(_) => {
                return Ok(RequestPluginResult::Continue);
            },
        };

        let country_code = self
            .geo_db
            .lookup_country_code(ip_addr)
            .map(|cc| cc.to_string());

        let country_code_str = country_code.as_deref().unwrap_or("??");

        if self.restriction_category == RestrictionCategory::Reporting {
            info!(ip = %ip, country = %country_code_str, "geoip lookup");
            return Ok(RequestPluginResult::Continue);
        }

        let found = self.country_codes.iter().any(|cc| cc == country_code_str);

        let allow = if self.restriction_category == RestrictionCategory::Deny {
            !found
        } else {
            found
        };

        if !allow {
            return Ok(RequestPluginResult::Respond(
                self.forbidden_resp.clone(),
            ));
        }

        Ok(RequestPluginResult::Continue)
    }
}

#[ctor]
fn init() {
    get_plugin_factory().register("geo_restriction", |params| {
        Ok(Arc::new(GeoRestriction::new(params)?))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingap_config::PluginConf;
    use pingap_core::Ctx;
    use pingora::proxy::Session;
    use tokio_test::io::Builder;

    #[test]
    fn test_geo_restriction_params() {
        let params = GeoRestriction::try_from(
            &toml::from_str::<PluginConf>(
                r###"
country_codes = ["CN", "US"]
type = "deny"
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!("request", params.plugin_step.to_string());
        assert_eq!(vec!["CN", "US"], params.country_codes);
        assert_eq!(RestrictionCategory::Deny, params.restriction_category);
    }

    #[tokio::test]
    async fn test_geo_restriction_continue() {
        let geo = GeoRestriction::new(
            &toml::from_str::<PluginConf>(
                r###"
type = "deny"
country_codes = ["CN", "RU"]
message = "Country not allowed"
"###,
            )
            .unwrap(),
        )
        .unwrap();

        let headers = ["X-Forwarded-For: 8.8.8.8"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let result = geo
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result == RequestPluginResult::Continue);
    }
}
