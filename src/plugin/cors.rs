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

use super::{get_bool_conf, get_step_conf, get_str_conf, Error, Plugin, Result};
use crate::config::{PluginCategory, PluginConf, PluginStep};
use crate::http_extra::{convert_header_value, HttpHeader, HttpResponse};
use crate::state::State;
use crate::util;
use async_trait::async_trait;
use bytes::Bytes;
use http::{header, HeaderValue};
use humantime::parse_duration;
use log::debug;
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use regex::Regex;
use std::time::Duration;

pub struct Cors {
    plugin_step: PluginStep,
    path: Option<Regex>,
    allow_origin: HeaderValue,
    headers: Vec<HttpHeader>,
}

struct CorsParams {
    plugin_step: PluginStep,
    path: Option<Regex>,
    allow_origin: String,
    allow_methods: String,
    allow_headers: String,
    max_age: Duration,
    allow_credentials: bool,
    expose_headers: String,
}

impl TryFrom<&PluginConf> for CorsParams {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        let step = get_step_conf(value);

        let max_age = get_str_conf(value, "max_age");
        let max_age = if !max_age.is_empty() {
            parse_duration(&max_age).map_err(|e| Error::Invalid {
                category: PluginCategory::Cors.to_string(),
                message: e.to_string(),
            })?
        } else {
            Duration::from_secs(3600)
        };
        let path = get_str_conf(value, "path");
        let path = if path.is_empty() {
            None
        } else {
            let reg = Regex::new(&path).map_err(|e| Error::Invalid {
                category: PluginCategory::Cors.to_string(),
                message: e.to_string(),
            })?;
            Some(reg)
        };
        let params = Self {
            plugin_step: step,
            path,
            allow_origin: get_str_conf(value, "allow_origin"),
            allow_methods: get_str_conf(value, "allow_methods"),
            allow_headers: get_str_conf(value, "allow_headers"),
            max_age,
            allow_credentials: get_bool_conf(value, "allow_credentials"),
            expose_headers: get_str_conf(value, "expose_headers"),
        };
        if params.plugin_step != PluginStep::Request {
            return Err(Error::Invalid {
                category: PluginCategory::Cors.to_string(),
                message: "Cors plugin should be executed at request step".to_string(),
            });
        }

        Ok(params)
    }
}

impl Cors {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!("new cors plugin, params: {params:?}");
        let params = CorsParams::try_from(params)?;
        let allow_origin = if params.allow_origin.is_empty() {
            "*".to_string()
        } else {
            params.allow_origin
        };
        let allow_methods = if params.allow_methods.is_empty() {
            "GET, POST, PUT, PATCH, DELETE, OPTIONS".to_string()
        } else {
            params.allow_methods
        };
        let format_header_value = |value: &str| -> Result<HeaderValue> {
            HeaderValue::from_str(value).map_err(|e| Error::Invalid {
                category: PluginCategory::Cors.to_string(),
                message: e.to_string(),
            })
        };

        let mut headers = vec![(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            format_header_value(&allow_methods)?,
        )];
        if !params.allow_headers.is_empty() {
            headers.push((
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                format_header_value(&params.allow_headers)?,
            ));
        }
        if !params.max_age.is_zero() {
            headers.push((
                header::ACCESS_CONTROL_MAX_AGE,
                format_header_value(&params.max_age.as_secs().to_string())?,
            ));
        }
        if params.allow_credentials {
            headers.push((
                header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                format_header_value("true")?,
            ));
        }
        if !params.expose_headers.is_empty() {
            headers.push((
                header::ACCESS_CONTROL_EXPOSE_HEADERS,
                format_header_value(&params.expose_headers)?,
            ));
        }

        Ok(Self {
            plugin_step: params.plugin_step,
            path: params.path,
            allow_origin: format_header_value(&allow_origin)?,
            headers,
        })
    }
    fn get_headers(&self, session: &mut Session, ctx: &mut State) -> Result<Vec<HttpHeader>> {
        let origin =
            convert_header_value(&self.allow_origin, session, ctx).ok_or(Error::Invalid {
                category: PluginCategory::Cors.to_string(),
                message: "Allow origin is invalid".to_string(),
            })?;
        let mut headers = self.headers.clone();
        headers.push((header::ACCESS_CONTROL_ALLOW_ORIGIN, origin));
        Ok(headers)
    }
}

#[async_trait]
impl Plugin for Cors {
    #[inline]
    fn step(&self) -> String {
        self.plugin_step.to_string()
    }
    #[inline]
    fn category(&self) -> PluginCategory {
        PluginCategory::Cors
    }
    #[inline]
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut State,
    ) -> pingora::Result<Option<HttpResponse>> {
        if step != self.plugin_step {
            return Ok(None);
        }
        if let Some(reg) = &self.path {
            // not match path
            if !reg.is_match(session.req_header().uri.path()) {
                return Ok(None);
            }
        }
        if http::Method::OPTIONS == session.req_header().method {
            let headers = self
                .get_headers(session, ctx)
                .map_err(|e| util::new_internal_error(400, e.to_string()))?;
            let mut resp = HttpResponse::no_content();
            resp.headers = Some(headers);
            return Ok(Some(resp));
        }
        Ok(None)
    }
    async fn handle_response(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut State,
        upstream_response: &mut ResponseHeader,
    ) -> pingora::Result<Option<Bytes>> {
        if step != PluginStep::Response {
            return Ok(None);
        }
        if let Some(reg) = &self.path {
            // not match path
            if !reg.is_match(session.req_header().uri.path()) {
                return Ok(None);
            }
        }
        if session.get_header(header::ORIGIN).is_none() {
            return Ok(None);
        }

        let headers = self
            .get_headers(session, ctx)
            .map_err(|e| util::new_internal_error(400, e.to_string()))?;
        for (name, value) in &headers {
            let _ = upstream_response.insert_header(name, value);
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::{Cors, CorsParams};
    use crate::{
        config::{PluginConf, PluginStep},
        plugin::Plugin,
        state::State,
    };
    use pingora::{http::ResponseHeader, proxy::Session};
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    #[test]
    fn test_cors_params() {
        let params = CorsParams::try_from(
            &toml::from_str::<PluginConf>(
                r###"
path = "^/api"
allow_methods = "GET"
allow_origin = "$http_origin"
allow_credentials = true
allow_headers = "Content-Type, X-User-Id"
max_age = "60m"
        "###,
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!("request", params.plugin_step.to_string());

        assert_eq!("^/api", params.path.unwrap().to_string());
        assert_eq!("GET", params.allow_methods);
        assert_eq!("$http_origin", params.allow_origin);
        assert_eq!("Content-Type, X-User-Id", params.allow_headers);
        assert_eq!(true, params.allow_credentials);
        assert_eq!(3600, params.max_age.as_secs());
    }
    #[tokio::test]
    async fn test_cors() {
        let headers = ["X-User: 123", "Origin: https://pingap.io"].join("\r\n");
        let input_header = format!("OPTIONS /api/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let cors = Cors::new(
            &toml::from_str::<PluginConf>(
                r###"
path = "^/api"
allow_methods = "GET"
allow_origin = "$http_origin"
allow_credentials = true
allow_headers = "Content-Type, X-User-Id"
expose_headers = "Content-Encoding, Kuma-Revision"
max_age = "60m"
    "###,
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!("request", cors.step().to_string());
        assert_eq!("cors", cors.category().to_string());

        let resp = cors
            .handle_request(PluginStep::Request, &mut session, &mut State::default())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(204, resp.status.as_u16());
        assert_eq!(
            r#"[("access-control-allow-methods", "GET"), ("access-control-allow-headers", "Content-Type, X-User-Id"), ("access-control-max-age", "3600"), ("access-control-allow-credentials", "true"), ("access-control-expose-headers", "Content-Encoding, Kuma-Revision"), ("access-control-allow-origin", "https://pingap.io")]"#,
            format!("{:?}", resp.headers.unwrap())
        );

        let mut header = ResponseHeader::build(200, None).unwrap();

        cors.handle_response(
            PluginStep::Response,
            &mut session,
            &mut State::default(),
            &mut header,
        )
        .await
        .unwrap();

        assert_eq!(
            r#"{"access-control-allow-methods": "GET", "access-control-allow-headers": "Content-Type, X-User-Id", "access-control-max-age": "3600", "access-control-allow-credentials": "true", "access-control-expose-headers": "Content-Encoding, Kuma-Revision", "access-control-allow-origin": "https://pingap.io"}"#,
            format!("{:?}", header.headers)
        );
    }
}
