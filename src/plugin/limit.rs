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

use super::{get_int_conf, get_step_conf, get_str_conf, Error, Plugin, Result};
use crate::config::{PluginCategory, PluginConf, PluginStep};
use crate::http_extra::HttpResponse;
use crate::state::State;
use crate::util;
use async_trait::async_trait;
use http::StatusCode;
use humantime::parse_duration;
use pingora::proxy::Session;
use pingora_limits::inflight::Inflight;
use pingora_limits::rate::Rate;
use std::time::Duration;
use tracing::debug;

#[derive(PartialEq, Debug)]
pub enum LimitTag {
    Ip,
    RequestHeader,
    Cookie,
    Query,
}

pub struct Limiter {
    tag: LimitTag,
    max: isize,
    key: String,
    inflight: Option<Inflight>,
    rate: Option<Rate>,
    plugin_step: PluginStep,
}

impl TryFrom<&PluginConf> for Limiter {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        let step = get_step_conf(value);

        let tag = match get_str_conf(value, "tag").as_str() {
            "cookie" => LimitTag::Cookie,
            "header" => LimitTag::RequestHeader,
            "query" => LimitTag::Query,
            _ => LimitTag::Ip,
        };
        let interval = get_str_conf(value, "interval");
        let interval = if !interval.is_empty() {
            parse_duration(&interval).map_err(|e| Error::Invalid {
                category: PluginCategory::Limit.to_string(),
                message: e.to_string(),
            })?
        } else {
            Duration::from_secs(10)
        };
        let mut inflight = None;
        let mut rate = None;
        if get_str_conf(value, "type") == "inflight" {
            inflight = Some(Inflight::new());
        } else {
            rate = Some(Rate::new(interval));
        }

        let params = Self {
            tag,
            key: get_str_conf(value, "key"),
            max: get_int_conf(value, "max") as isize,
            inflight,
            rate,
            plugin_step: step,
        };
        if ![PluginStep::Request, PluginStep::ProxyUpstream].contains(&params.plugin_step) {
            return Err(Error::Invalid {
                category: PluginCategory::Limit.to_string(),
                message: "Limit plugin should be executed at request or proxy upstream step"
                    .to_string(),
            });
        }
        Ok(params)
    }
}

impl Limiter {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new limit plugin");
        Self::try_from(params)
    }
    /// Increment `key` by 1. If value gt max, an error will be return.
    /// Otherwise returns a Guard. It may set the client ip to context.
    pub fn incr(&self, session: &Session, ctx: &mut State) -> Result<()> {
        let key = match self.tag {
            LimitTag::Query => util::get_query_value(session.req_header(), &self.key)
                .unwrap_or_default()
                .to_string(),
            LimitTag::RequestHeader => util::get_req_header_value(session.req_header(), &self.key)
                .unwrap_or_default()
                .to_string(),
            LimitTag::Cookie => util::get_cookie_value(session.req_header(), &self.key)
                .unwrap_or_default()
                .to_string(),
            _ => {
                let client_ip = util::get_client_ip(session);
                ctx.client_ip = Some(client_ip.clone());
                client_ip
            }
        };
        if key.is_empty() {
            return Ok(());
        }
        let value = if let Some(rate) = &self.rate {
            rate.observe(&key, 1);
            let value = rate.rate(&key);
            value as isize
        } else if let Some(inflight) = &self.inflight {
            let (guard, value) = inflight.incr(&key, 1);
            ctx.guard = Some(guard);
            value
        } else {
            0
        };
        if value > self.max {
            return Err(Error::Exceed {
                category: PluginCategory::Limit.to_string(),
                max: self.max,
                value,
            });
        }
        Ok(())
    }
}
#[async_trait]
impl Plugin for Limiter {
    #[inline]
    fn step(&self) -> String {
        self.plugin_step.to_string()
    }
    #[inline]
    fn category(&self) -> PluginCategory {
        PluginCategory::Limit
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
        if let Err(e) = self.incr(session, ctx) {
            return Ok(Some(HttpResponse {
                status: StatusCode::TOO_MANY_REQUESTS,
                body: e.to_string().into(),
                ..Default::default()
            }));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::{LimitTag, Limiter};
    use crate::{config::PluginConf, config::PluginStep, plugin::Plugin, state::State};
    use http::StatusCode;
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use std::time::Duration;
    use tokio_test::io::Builder;

    async fn new_session() -> Session {
        let headers = [
            "Host: github.com",
            "Referer: https://github.com/",
            "User-Agent: pingap/0.1.1",
            "Cookie: deviceId=abc",
            "Accept: application/json",
            "X-Uuid: 138q71",
            "X-Forwarded-For: 1.1.1.1, 192.168.1.2",
        ]
        .join("\r\n");
        let input_header = format!("GET /vicanso/pingap?key=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        session
    }

    #[test]
    fn test_limit_params() {
        let params = Limiter::try_from(
            &toml::from_str::<PluginConf>(
                r###"
type = "inflight"
tag = "cookie"
key = "deviceId"
max = 10
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!("request", params.plugin_step.to_string());
        assert_eq!(true, params.inflight.is_some());
        assert_eq!(LimitTag::Cookie, params.tag);
        assert_eq!("deviceId", params.key);

        let result = Limiter::try_from(
            &toml::from_str::<PluginConf>(
                r###"
step = "response"
type = "inflight"
tag = "cookie"
key = "deviceId"
max = 10
"###,
            )
            .unwrap(),
        );
        assert_eq!("Plugin limit invalid, message: Limit plugin should be executed at request or proxy upstream step", result.err().unwrap().to_string());
    }

    #[tokio::test]
    async fn test_new_cookie_limiter() {
        let limiter = Limiter::new(
            &toml::from_str::<PluginConf>(
                r###"
type = "inflight"
tag = "cookie"
key = "deviceId"
max = 10
    "###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!("limit", limiter.category().to_string());
        assert_eq!("request", limiter.step().to_string());

        assert_eq!(LimitTag::Cookie, limiter.tag);
        let mut ctx = State {
            ..Default::default()
        };
        let session = new_session().await;

        limiter.incr(&session, &mut ctx).unwrap();
        assert_eq!(true, ctx.guard.is_some());
    }
    #[tokio::test]
    async fn test_new_req_header_limiter() {
        let limiter = Limiter::new(
            &toml::from_str::<PluginConf>(
                r###"
type = "inflight"
tag = "header"
key = "X-Uuid"
max = 10
    "###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(LimitTag::RequestHeader, limiter.tag);
        let mut ctx = State {
            ..Default::default()
        };
        let session = new_session().await;

        limiter.incr(&session, &mut ctx).unwrap();
        assert_eq!(true, ctx.guard.is_some());
    }
    #[tokio::test]
    async fn test_new_query_limiter() {
        let limiter = Limiter::new(
            &toml::from_str::<PluginConf>(
                r###"
type = "inflight"
tag = "query"
key = "key"
max = 10
    "###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(LimitTag::Query, limiter.tag);
        let mut ctx = State {
            ..Default::default()
        };
        let session = new_session().await;

        limiter.incr(&session, &mut ctx).unwrap();
        assert_eq!(true, ctx.guard.is_some());
    }
    #[tokio::test]
    async fn test_new_ip_limiter() {
        let limiter = Limiter::new(
            &toml::from_str::<PluginConf>(
                r###"
type = "inflight"
max = 10
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(LimitTag::Ip, limiter.tag);
        let mut ctx = State {
            ..Default::default()
        };
        let session = new_session().await;

        limiter.incr(&session, &mut ctx).unwrap();
        assert_eq!(true, ctx.guard.is_some());
    }
    #[tokio::test]
    async fn test_inflight_limit() {
        let limiter = Limiter::new(
            &toml::from_str::<PluginConf>(
                r###"
type = "inflight"
max = 0
"###,
            )
            .unwrap(),
        )
        .unwrap();

        let headers = ["X-Forwarded-For: 1.1.1.1"].join("\r\n");
        let input_header = format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = limiter
            .handle_request(PluginStep::Request, &mut session, &mut State::default())
            .await
            .unwrap();

        assert_eq!(true, result.is_some());
        assert_eq!(StatusCode::TOO_MANY_REQUESTS, result.unwrap().status);

        let limiter = Limiter::new(
            &toml::from_str::<PluginConf>(
                r###"
type = "inflight"
max = 1
"###,
            )
            .unwrap(),
        )
        .unwrap();
        let result = limiter
            .handle_request(PluginStep::Request, &mut session, &mut State::default())
            .await
            .unwrap();

        assert_eq!(true, result.is_none());
    }

    #[tokio::test]
    async fn test_rate_limit() {
        let limiter = Limiter::new(
            &toml::from_str::<PluginConf>(
                r###"
type = "rate"
max = 1
interval = "1s"
"###,
            )
            .unwrap(),
        )
        .unwrap();

        let headers = ["X-Forwarded-For: 1.1.1.1"].join("\r\n");
        let input_header = format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = limiter
            .handle_request(PluginStep::Request, &mut session, &mut State::default())
            .await
            .unwrap();

        assert_eq!(true, result.is_none());

        let _ = limiter
            .handle_request(PluginStep::Request, &mut session, &mut State::default())
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_secs(1)).await;

        let result = limiter
            .handle_request(PluginStep::Request, &mut session, &mut State::default())
            .await
            .unwrap();
        assert_eq!(true, result.is_some());
        assert_eq!(StatusCode::TOO_MANY_REQUESTS, result.unwrap().status);

        tokio::time::sleep(Duration::from_secs(1)).await;

        let result = limiter
            .handle_request(PluginStep::Request, &mut session, &mut State::default())
            .await
            .unwrap();
        assert_eq!(true, result.is_none());
    }
}
