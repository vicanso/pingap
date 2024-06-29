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

use super::{get_step_conf, get_str_conf, Error, Plugin, Result};
use crate::config::{PluginCategory, PluginConf, PluginStep};
use crate::http_extra::{HttpResponse, HTTP_HEADER_NO_STORE};
use crate::state::State;
use crate::util;
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use bytes::Bytes;
use cookie::Cookie;
use http::{header, HeaderValue, Method, StatusCode};
use humantime::parse_duration;
use nanoid::nanoid;
use pingora::proxy::Session;
use sha2::{Digest, Sha256};
use tracing::debug;

pub struct Csrf {
    plugin_step: PluginStep,
    token_path: String,
    key: String,
    name: String,
    // ttl seconds
    ttl: u64,
    unauthorized_resp: HttpResponse,
}

impl TryFrom<&PluginConf> for Csrf {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        let step = get_step_conf(value);

        let mut params = Self {
            plugin_step: step,
            name: get_str_conf(value, "name"),
            token_path: get_str_conf(value, "token_path"),
            key: get_str_conf(value, "key"),
            ttl: 0,
            unauthorized_resp: HttpResponse {
                status: StatusCode::UNAUTHORIZED,
                body: Bytes::from("Csrf token is empty or invalid"),
                ..Default::default()
            },
        };
        if params.name.is_empty() {
            params.name = "x-csrf-token".to_string();
        }
        let ttl = get_str_conf(value, "ttl");
        if !ttl.is_empty() {
            let ttl = parse_duration(&ttl).map_err(|e| Error::Invalid {
                category: PluginCategory::Csrf.to_string(),
                message: e.to_string(),
            })?;
            params.ttl = ttl.as_secs();
        }

        if params.token_path.is_empty() {
            return Err(Error::Invalid {
                category: PluginCategory::Csrf.to_string(),
                message: "Token path is not allowed empty".to_string(),
            });
        }
        if params.key.is_empty() {
            return Err(Error::Invalid {
                category: PluginCategory::Csrf.to_string(),
                message: "Key is not allowed empty".to_string(),
            });
        }

        if ![PluginStep::Request].contains(&params.plugin_step) {
            return Err(Error::Invalid {
                category: PluginCategory::Csrf.to_string(),
                message: "Csrf plugin should be executed at request or proxy upstream step".to_string(),
            });
        }

        Ok(params)
    }
}

impl Csrf {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new csrf plugin");
        Csrf::try_from(params)
    }
}

fn generate_token(key: &str) -> String {
    let id = nanoid!(12);
    let prefix = format!("{id}.{:x}", util::now().as_secs());
    let mut hasher = Sha256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(key.as_bytes());
    let hash256 = hasher.finalize();
    format!("{prefix}.{}", STANDARD.encode(hash256))
}

fn validate_token(key: &str, ttl: u64, value: &str) -> bool {
    let arr: Vec<&str> = value.split('.').collect();
    if arr.len() != 3 {
        return false;
    }

    if ttl > 0 {
        let now = util::now().as_secs();
        if now - u64::from_str_radix(arr[1], 16).unwrap_or_default() > ttl {
            return false;
        }
    }

    let mut hasher = Sha256::new();
    hasher.update(format!("{}.{}", arr[0], arr[1]).as_bytes());
    hasher.update(key.as_bytes());
    let hash256 = hasher.finalize();
    if arr[2] != STANDARD.encode(hash256) {
        return false;
    }
    true
}

#[async_trait]
impl Plugin for Csrf {
    #[inline]
    fn step(&self) -> String {
        self.plugin_step.to_string()
    }
    #[inline]
    fn category(&self) -> PluginCategory {
        PluginCategory::Csrf
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
        if session.req_header().uri.path() == self.token_path {
            let token = generate_token(&self.key);
            let mut builder = Cookie::build((&self.name, &token)).path("/");
            if self.ttl > 0 {
                builder = builder
                    .max_age(cookie::time::Duration::seconds(self.ttl as i64));
            };

            let set_cookie = (
                header::SET_COOKIE,
                HeaderValue::from_str(&builder.build().to_string()).map_err(
                    |e| util::new_internal_error(400, e.to_string()),
                )?,
            );

            let resp = HttpResponse {
                status: StatusCode::NO_CONTENT,
                headers: Some(vec![HTTP_HEADER_NO_STORE.clone(), set_cookie]),
                ..Default::default()
            };

            return Ok(Some(resp));
        }

        if [Method::GET, Method::HEAD, Method::OPTIONS]
            .contains(&session.req_header().method)
        {
            return Ok(None);
        }

        let value = session.get_header_bytes(&self.name);
        if value.is_empty() {
            return Ok(Some(self.unauthorized_resp.clone()));
        }

        let value = std::string::String::from_utf8_lossy(value);

        if value
            != util::get_cookie_value(session.req_header(), &self.name)
                .unwrap_or_default()
            || !validate_token(&self.key, self.ttl, &value)
        {
            return Ok(Some(self.unauthorized_resp.clone()));
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::{generate_token, validate_token, Csrf};
    use crate::config::{PluginConf, PluginStep};
    use crate::plugin::Plugin;
    use crate::state::State;
    use cookie::Cookie;
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use std::str::FromStr;
    use tokio_test::io::Builder;

    #[test]
    fn test_csrf_params() {
        let params = Csrf::try_from(
            &toml::from_str::<PluginConf>(
                r###"
token_path = "/csrf-token"
key = "WjrXUG47wu"
ttl = "1h"
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!("/csrf-token", params.token_path);
        assert_eq!("WjrXUG47wu", params.key);
        assert_eq!(3600, params.ttl);

        let result = Csrf::try_from(
            &toml::from_str::<PluginConf>(
                r###"
token_path = "/csrf-token"
key = "WjrXUG47wu"
ttl = "1a"
"###,
            )
            .unwrap(),
        );
        assert_eq!(
            r#"Plugin csrf invalid, message: unknown time unit "a", supported units: ns, us, ms, sec, min, hours, days, weeks, months, years (and few variations)"#,
            result.err().unwrap().to_string()
        );

        let result = Csrf::try_from(
            &toml::from_str::<PluginConf>(
                r###"
key = "WjrXUG47wu"
"###,
            )
            .unwrap(),
        );
        assert_eq!(
            "Plugin csrf invalid, message: Token path is not allowed empty",
            result.err().unwrap().to_string()
        );

        let result = Csrf::try_from(
            &toml::from_str::<PluginConf>(
                r###"
token_path = "/csrf-token"
"###,
            )
            .unwrap(),
        );
        assert_eq!(
            "Plugin csrf invalid, message: Key is not allowed empty",
            result.err().unwrap().to_string()
        );

        let result = Csrf::try_from(
            &toml::from_str::<PluginConf>(
                r###"
step = "response"
token_path = "/csrf-token"
key = "WjrXUG47wu"
ttl = "1h"
"###,
            )
            .unwrap(),
        );
        assert_eq!(
            "Plugin csrf invalid, message: Csrf plugin should be executed at request or proxy upstream step",
            result.err().unwrap().to_string()
        );
    }

    #[test]
    fn test_generate_token() {
        let key = "123";
        let value = generate_token(key);
        assert_eq!(true, validate_token(key, 10, &value));
        assert_eq!(false, validate_token(key, 10, &format!("{value}:1")));
    }

    #[tokio::test]
    async fn test_csrf() {
        let csrf = Csrf::new(
            &toml::from_str::<PluginConf>(
                r###"
token_path = "/csrf-token"
key = "WjrXUG47wu"
ttl = "1h"
    "###,
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!("request", csrf.step().to_string());
        assert_eq!("csrf", csrf.category().to_string());

        let headers = [""].join("\r\n");
        let input_header =
            format!("GET /csrf-token HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let resp = csrf
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut State::default(),
            )
            .await
            .unwrap()
            .unwrap();
        let binding = resp.headers.unwrap();
        let cookie = binding[1].1.to_str().unwrap();
        let c = Cookie::from_str(cookie).unwrap();
        assert_eq!("x-csrf-token", c.name());
        assert_eq!(66, c.value().len());

        let headers = [format!("x-csrf-token:{}", "123")].join("\r\n");
        let input_header = format!("POST / HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let resp = csrf
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut State::default(),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(401, resp.status.as_u16());

        let headers = [
            format!("x-csrf-token: {}", c.value()),
            format!("Cookie: x-csrf-token={}", c.value()),
        ]
        .join("\r\n");
        let input_header = format!("POST / HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let result = csrf
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut State::default(),
            )
            .await
            .unwrap();

        assert_eq!(true, result.is_none());
    }
}
