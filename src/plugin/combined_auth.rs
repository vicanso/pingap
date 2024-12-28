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

use super::{
    get_hash_key, get_int_conf, get_step_conf, get_str_conf,
    get_str_slice_conf, Error, Plugin, Result,
};
use crate::config::{PluginCategory, PluginConf, PluginStep};
use crate::http_extra::{HttpResponse, HTTP_HEADER_NO_STORE};
use crate::state::State;
use crate::util;
use ahash::AHashMap;
use async_trait::async_trait;
use bytes::Bytes;
use hex::ToHex;
use http::StatusCode;
use pingora::proxy::Session;
use sha2::{Digest, Sha256};
use tracing::debug;

struct AuthParam {
    ip_rules: Option<util::IpRules>,
    secret: String,
    deviation: i64,
}

pub struct CombinedAuth {
    hash_value: String,
    plugin_step: PluginStep,
    auths: AHashMap<String, AuthParam>,
}

impl TryFrom<&PluginConf> for CombinedAuth {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);
        let step = get_step_conf(value);

        let category = "combined_auth".to_string();

        let Some(authorizations) = value.get("authorizations") else {
            return Err(Error::Invalid {
                category,
                message: "authorizations is empty".to_string(),
            });
        };
        let Some(authorizations) = authorizations.as_array() else {
            return Err(Error::Invalid {
                category,
                message: "authorizations is not array".to_string(),
            });
        };
        let mut auths = AHashMap::new();
        for item in authorizations.iter() {
            let Some(value) = item.as_table() else {
                continue;
            };
            let app_id = get_str_conf(value, "app_id");
            if app_id.is_empty() {
                continue;
            }
            let mut ip_rules = None;
            let ip_list = get_str_slice_conf(value, "ip_list");
            if !ip_list.is_empty() {
                ip_rules = Some(util::IpRules::new(&ip_list));
            }
            auths.insert(
                app_id,
                AuthParam {
                    ip_rules,
                    secret: get_str_conf(value, "secret"),
                    deviation: get_int_conf(value, "deviation"),
                },
            );
        }
        if PluginStep::Request != step {
            return Err(Error::Invalid {
                category: PluginCategory::CombinedAuth.to_string(),
                message:
                    "Combined auth plugin should be executed at request step"
                        .to_string(),
            });
        }

        Ok(Self {
            plugin_step: step,
            hash_value,
            auths,
        })
    }
}

impl CombinedAuth {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new combined auth plugin");
        Self::try_from(params)
    }
    fn validate(&self, session: &Session) -> Result<()> {
        let category = "combined_auth";
        // validate timestamp
        let req_header = session.req_header();
        let Some(app_id) = util::get_query_value(req_header, "app_id") else {
            return Err(Error::Invalid {
                category: category.to_string(),
                message: "app id is empty".to_string(),
            });
        };
        let Some(auth_param) = self.auths.get(app_id) else {
            return Err(Error::Invalid {
                category: category.to_string(),
                message: "app id is invalid".to_string(),
            });
        };
        // not validate for super secret
        if auth_param.secret == "*" {
            return Ok(());
        }
        // validate ip
        if let Some(ip_rules) = &auth_param.ip_rules {
            let ip = util::get_client_ip(session);
            if !ip_rules.matched(&ip).unwrap_or_default() {
                return Err(Error::Invalid {
                    category: category.to_string(),
                    message: "ip is invalid".to_string(),
                });
            }
        }

        let ts = util::get_query_value(req_header, "ts").unwrap_or_default();
        if ts.is_empty() {
            return Err(Error::Invalid {
                category: category.to_string(),
                message: "timestamp is empty".to_string(),
            });
        }
        let value = ts.parse::<i64>().map_err(|e| Error::Invalid {
            category: category.to_string(),
            message: e.to_string(),
        })?;
        let now = util::now().as_secs() as i64;
        if (now - value).abs() > auth_param.deviation {
            return Err(Error::Invalid {
                category: category.to_string(),
                message: "timestamp deviation is invalid".to_string(),
            });
        }
        let digest =
            util::get_query_value(req_header, "digest").unwrap_or_default();
        if digest.is_empty() {
            return Err(Error::Invalid {
                category: category.to_string(),
                message: "digest is empty".to_string(),
            });
        }

        let mut hasher = Sha256::new();
        hasher.update(format!("{}:{ts}", auth_param.secret).as_bytes());
        let hash256 = hasher.finalize();
        if digest.to_lowercase() != hash256.encode_hex::<String>() {
            return Err(Error::Invalid {
                category: category.to_string(),
                message: "digest is invalid".to_string(),
            });
        }
        Ok(())
    }
}
#[async_trait]
impl Plugin for CombinedAuth {
    #[inline]
    fn hash_key(&self) -> String {
        self.hash_value.clone()
    }
    #[inline]
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        _ctx: &mut State,
    ) -> pingora::Result<Option<HttpResponse>> {
        if step != self.plugin_step {
            return Ok(None);
        }
        if let Err(e) = self.validate(session) {
            return Ok(Some(HttpResponse {
                status: StatusCode::UNAUTHORIZED,
                headers: Some(vec![HTTP_HEADER_NO_STORE.clone()]),
                body: Bytes::from(e.to_string()),
                ..Default::default()
            }));
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthParam, CombinedAuth};
    use crate::config::PluginStep;
    use crate::util;
    use ahash::AHashMap;
    use hex::ToHex;
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use sha2::{Digest, Sha256};
    use tokio_test::io::Builder;

    #[tokio::test]
    async fn test_combined_auth() {
        let mut auths = AHashMap::new();
        let secret = "abcd";
        auths.insert(
            "pingap".to_string(),
            AuthParam {
                ip_rules: Some(util::IpRules::new(&vec![
                    "127.0.0.1".to_string(),
                    "192.168.1.0/24".to_string(),
                ])),
                secret: secret.to_string(),
                deviation: 60,
            },
        );
        let combined_auth = CombinedAuth {
            plugin_step: PluginStep::Request,
            hash_value: "".to_string(),
            auths,
        };

        // no app id
        let headers = [""].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = combined_auth.validate(&session);
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Plugin combined_auth invalid, message: app id is empty",
            result.unwrap_err().to_string()
        );

        // app id is invalid
        let headers = [""].join("\r\n");
        let input_header = format!(
            "GET /vicanso/pingap?app_id=abc HTTP/1.1\r\n{headers}\r\n\r\n"
        );
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = combined_auth.validate(&session);
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Plugin combined_auth invalid, message: app id is invalid",
            result.unwrap_err().to_string()
        );

        // ip is invalid
        let headers = ["X-Forwarded-For: 1.1.1.1"].join("\r\n");
        let input_header = format!(
            "GET /vicanso/pingap?app_id=pingap HTTP/1.1\r\n{headers}\r\n\r\n"
        );
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = combined_auth.validate(&session);
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Plugin combined_auth invalid, message: ip is invalid",
            result.unwrap_err().to_string()
        );

        // timestamp is empty
        let headers = ["X-Forwarded-For: 192.168.1.10"].join("\r\n");
        let input_header = format!(
            "GET /vicanso/pingap?app_id=pingap HTTP/1.1\r\n{headers}\r\n\r\n"
        );
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = combined_auth.validate(&session);
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Plugin combined_auth invalid, message: timestamp is empty",
            result.unwrap_err().to_string()
        );

        // timestamp is invalid
        let headers = ["X-Forwarded-For: 192.168.1.10"].join("\r\n");
        let input_header = format!(
            "GET /vicanso/pingap?app_id=pingap&ts=123 HTTP/1.1\r\n{headers}\r\n\r\n"
        );
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = combined_auth.validate(&session);
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Plugin combined_auth invalid, message: timestamp deviation is invalid",
            result.unwrap_err().to_string()
        );

        // digest is empty
        let headers = ["X-Forwarded-For: 192.168.1.10"].join("\r\n");
        let ts = util::now().as_secs() as i64;
        let input_header = format!(
            "GET /vicanso/pingap?app_id=pingap&ts={ts} HTTP/1.1\r\n{headers}\r\n\r\n"
        );
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = combined_auth.validate(&session);
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Plugin combined_auth invalid, message: digest is empty",
            result.unwrap_err().to_string()
        );

        // digest is invalid
        let headers = ["X-Forwarded-For: 192.168.1.10"].join("\r\n");
        let ts = util::now().as_secs() as i64;
        let input_header = format!(
            "GET /vicanso/pingap?app_id=pingap&ts={ts}&digest=abc HTTP/1.1\r\n{headers}\r\n\r\n"
        );
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = combined_auth.validate(&session);
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Plugin combined_auth invalid, message: digest is invalid",
            result.unwrap_err().to_string()
        );

        let headers = ["X-Forwarded-For: 192.168.1.10"].join("\r\n");
        let ts = util::now().as_secs() as i64;
        let mut hasher = Sha256::new();
        hasher.update(format!("{secret}:{ts}",).as_bytes());
        let hash256 = hasher.finalize();
        let digest = hash256.encode_hex::<String>();
        let input_header = format!(
            "GET /vicanso/pingap?app_id=pingap&ts={ts}&digest={digest} HTTP/1.1\r\n{headers}\r\n\r\n"
        );
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = combined_auth.validate(&session);
        assert_eq!(true, result.is_ok());
    }
}
