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

use super::{get_step_conf, get_str_conf, Error, ProxyPlugin, Result};
use crate::config::{PluginCategory, PluginConf, PluginStep};
use crate::http_extra::HttpResponse;
use crate::state::State;
use crate::util;
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use bytes::Bytes;
use http::StatusCode;
use log::debug;
use pingora::proxy::Session;
use serde::{Deserialize, Serialize};
use substring::Substring;

struct JwtAuthParams {
    plugin_step: PluginStep,
    secret: String,
    header: Option<String>,
    query: Option<String>,
    cookie: Option<String>,
}

impl TryFrom<&PluginConf> for JwtAuthParams {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        let step = get_step_conf(value);

        let header = get_str_conf(value, "header");
        let query = get_str_conf(value, "query");
        let cookie = get_str_conf(value, "cookie");
        if header.is_empty() && query.is_empty() && cookie.is_empty() {
            return Err(Error::Invalid {
                category: PluginCategory::JwtAuth.to_string(),
                message: "Jwt key or key type is not allowed empty".to_string(),
            });
        }
        let header = if header.is_empty() {
            None
        } else {
            Some(header)
        };
        let query = if query.is_empty() { None } else { Some(query) };
        let cookie = if cookie.is_empty() {
            None
        } else {
            Some(cookie)
        };
        let params = Self {
            plugin_step: step,
            secret: get_str_conf(value, "secret"),
            header,
            query,
            cookie,
        };

        if params.secret.is_empty() {
            return Err(Error::Invalid {
                category: PluginCategory::JwtAuth.to_string(),
                message: "Jwt secret is not allowed empty".to_string(),
            });
        }

        if ![PluginStep::Request, PluginStep::ProxyUpstream].contains(&params.plugin_step) {
            return Err(Error::Invalid {
                category: PluginCategory::JwtAuth.to_string(),
                message: "Jwt auth plugin should be executed at request or proxy upstream step"
                    .to_string(),
            });
        }

        Ok(params)
    }
}

pub struct JwtAuth {
    plugin_step: PluginStep,
    secret: String,
    header: Option<String>,
    query: Option<String>,
    cookie: Option<String>,
    unauthorized_resp: HttpResponse,
}

impl JwtAuth {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!("new jwt auth proxy plugin, params:{params:?}");
        let params = JwtAuthParams::try_from(params)?;

        Ok(Self {
            plugin_step: params.plugin_step,
            secret: params.secret,
            header: params.header,
            query: params.query,
            cookie: params.cookie,
            unauthorized_resp: HttpResponse {
                status: StatusCode::UNAUTHORIZED,
                body: Bytes::from_static(b"Invalid or expired jwt"),
                ..Default::default()
            },
        })
    }
}

#[derive(Debug, Default, Deserialize, Clone, Serialize)]
struct JwtHeader {
    alg: String,
    typ: String,
}

#[async_trait]
impl ProxyPlugin for JwtAuth {
    #[inline]
    fn step(&self) -> PluginStep {
        self.plugin_step
    }
    #[inline]
    fn category(&self) -> PluginCategory {
        PluginCategory::JwtAuth
    }
    #[inline]
    async fn handle(
        &self,
        step: PluginStep,
        session: &mut Session,
        _ctx: &mut State,
    ) -> pingora::Result<Option<HttpResponse>> {
        if step != self.plugin_step {
            return Ok(None);
        }
        let req_header = session.req_header();
        let value = if let Some(key) = &self.header {
            let value = util::get_req_header_value(req_header, key).unwrap_or_default();
            let bearer = "Bearer ";
            if value.starts_with(bearer) {
                value.substring(bearer.len(), value.len())
            } else {
                value
            }
        } else if let Some(key) = &self.cookie {
            util::get_cookie_value(req_header, key).unwrap_or_default()
        } else if let Some(key) = &self.query {
            util::get_query_value(req_header, key).unwrap_or_default()
        } else {
            ""
        };
        if value.is_empty() {
            let mut resp = self.unauthorized_resp.clone();
            resp.body = Bytes::from_static(b"Jwt authorization is missing");
            return Ok(Some(resp));
        }
        let arr: Vec<&str> = value.split('.').collect();
        if arr.len() != 3 {
            let mut resp = self.unauthorized_resp.clone();
            resp.body = Bytes::from_static(b"Jwt authorization format is invalid");
            return Ok(Some(resp));
        }
        let jwt_header = serde_json::from_slice::<JwtHeader>(
            &URL_SAFE_NO_PAD.decode(arr[0]).unwrap_or_default(),
        )
        .unwrap_or_default();
        let content = format!("{}.{}", arr[0], arr[1]);
        let secret = self.secret.as_bytes();
        let valid = match jwt_header.alg.as_str() {
            "HS512" => {
                let hash = hmac_sha512::HMAC::mac(content.as_bytes(), secret);
                URL_SAFE_NO_PAD.encode(hash) == arr[2]
            }
            _ => {
                let hash = hmac_sha256::HMAC::mac(content.as_bytes(), secret);
                URL_SAFE_NO_PAD.encode(hash) == arr[2]
            }
        };
        if !valid {
            let mut resp = self.unauthorized_resp.clone();
            resp.body = Bytes::from_static(b"Jwt authorization is invalid");
            return Ok(Some(resp));
        }
        let value: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(arr[1]).unwrap_or_default())
                .unwrap_or_default();
        if let Some(exp) = value.get("exp") {
            if exp.as_u64().unwrap_or_default() < util::now().as_secs() {
                let mut resp = self.unauthorized_resp.clone();
                resp.body = Bytes::from_static(b"Jwt authorization is expired");
                return Ok(Some(resp));
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::{JwtAuth, JwtAuthParams};
    use crate::config::{PluginConf, PluginStep};
    use crate::plugin::ProxyPlugin;
    use crate::state::State;
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    #[test]
    fn test_jwt_auth_params() {
        let params = JwtAuthParams::try_from(
            &toml::from_str::<PluginConf>(
                r###"
secret = "123123"
cookie = "jwt"
"###,
            )
            .unwrap(),
        )
        .unwrap();

        let result = JwtAuthParams::try_from(
            &toml::from_str::<PluginConf>(
                r###"
step = "upstream_response"
secret = "123123"
cookie = "jwt"
"###,
            )
            .unwrap(),
        );
        assert_eq!(
            "Plugin jwt_auth invalid, message: Jwt auth plugin should be executed at request or proxy upstream step",
            result.err().unwrap().to_string()
        );

        assert_eq!("jwt", params.cookie.unwrap_or_default());
        assert_eq!("123123", params.secret);

        let result = JwtAuthParams::try_from(
            &toml::from_str::<PluginConf>(
                r###"
cookie = "jwt"
"###,
            )
            .unwrap(),
        );

        assert_eq!(
            "Plugin jwt_auth invalid, message: Jwt secret is not allowed empty",
            result.err().unwrap().to_string()
        );

        let result = JwtAuthParams::try_from(
            &toml::from_str::<PluginConf>(
                r###"
secret = "123123"
"###,
            )
            .unwrap(),
        );

        assert_eq!(
            "Plugin jwt_auth invalid, message: Jwt key or key type is not allowed empty",
            result.err().unwrap().to_string()
        );
    }

    #[tokio::test]
    async fn test_jwt_auth() {
        let auth = JwtAuth::new(
            &toml::from_str::<PluginConf>(
                r###"
secret = "123123"
header = "Authorization"
"###,
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!("jwt_auth", auth.category().to_string());
        assert_eq!("request", auth.step().to_string());

        // auth success(hs256)
        let headers = ["Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiIsImFkbWluIjp0cnVlLCJleHAiOjIzNDgwNTUyNjV9.j6sYJ2dCCSxskwPmvHM7WniGCbkT30z2BrjfsuQLFJc"].join("\r\n");
        let input_header = format!("GET / HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = auth
            .handle(PluginStep::Request, &mut session, &mut State::default())
            .await
            .unwrap();

        assert_eq!(true, result.is_none());

        // auth success(hs512)
        let headers = ["Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiIsImFkbWluIjp0cnVlLCJleHAiOjIzNDgwNTUyNjV9.HxFVxDd5ZiLsD1dWW1AywWMERhqk0Ck9IsdBHyD_1zap3w-waVOmFq0Yt1fWaYmh8HDtXLN6vlTd0HHYIYEGUw"].join("\r\n");
        let input_header = format!("GET / HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = auth
            .handle(PluginStep::Request, &mut session, &mut State::default())
            .await
            .unwrap();

        assert_eq!(true, result.is_none());

        // no auth token
        let headers = [""].join("\r\n");
        let input_header = format!("GET / HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let resp = auth
            .handle(PluginStep::Request, &mut session, &mut State::default())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(401, resp.status.as_u16());
        assert_eq!(
            "Jwt authorization is missing",
            std::string::String::from_utf8_lossy(resp.body.as_ref())
        );

        // auth format invalid
        let headers = ["Authorization: Bearer a.b"].join("\r\n");
        let input_header = format!("GET / HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let resp = auth
            .handle(PluginStep::Request, &mut session, &mut State::default())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(401, resp.status.as_u16());
        assert_eq!(
            "Jwt authorization format is invalid",
            std::string::String::from_utf8_lossy(resp.body.as_ref())
        );

        let headers = ["Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiIsImFkbWluIjp0cnVlLCJleHAiOjE3MTcwODQ4MDB9.zz7VHuqt9t6UGLNr5RZdfzvqMDEei"].join("\r\n");
        let input_header = format!("GET / HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let resp = auth
            .handle(PluginStep::Request, &mut session, &mut State::default())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(401, resp.status.as_u16());
        assert_eq!(
            "Jwt authorization is invalid",
            std::string::String::from_utf8_lossy(resp.body.as_ref())
        );

        // expired
        let headers = ["Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiIsImFkbWluIjp0cnVlLCJleHAiOjE3MTY5MDMyNjV9.PRS-PZafcGsV_rCL8QQfJdOJAvL5fOI_Z14N16JEcng"].join("\r\n");
        let input_header = format!("GET / HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let resp = auth
            .handle(PluginStep::Request, &mut session, &mut State::default())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(401, resp.status.as_u16());
        assert_eq!(
            "Jwt authorization is expired",
            std::string::String::from_utf8_lossy(resp.body.as_ref())
        );
    }
}
