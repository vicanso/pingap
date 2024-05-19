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

use super::{get_int_conf, get_step_conf, get_str_conf, Error, ProxyPlugin, Result};
use crate::config::{PluginCategory, PluginConf, PluginStep};
use crate::http_extra::HttpResponse;
use crate::state::State;
use crate::util;
use async_trait::async_trait;
use http::StatusCode;
use humantime::parse_duration;
use log::debug;
use pingora::proxy::Session;
use pingora_limits::inflight::Inflight;
use pingora_limits::rate::Rate;
use std::time::Duration;

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
    value: String,
    inflight: Option<Inflight>,
    rate: Option<Rate>,
    plugin_step: PluginStep,
}

struct LimiterParams {
    category: String,
    tag: LimitTag,
    max: isize,
    value: String,
    interval: Duration,
    plugin_step: PluginStep,
}

impl TryFrom<&PluginConf> for LimiterParams {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        let step = get_step_conf(value);

        let tag = match get_str_conf(value, "key").as_str() {
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
        let params = Self {
            tag,
            category: get_str_conf(value, "category"),
            value: get_str_conf(value, "value"),
            max: get_int_conf(value, "max") as isize,
            interval,
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
        debug!("new limit proxy plugin, params:{params:?}");
        let params = LimiterParams::try_from(params)?;
        let mut inflight = None;
        let mut rate = None;
        if params.category == "inflight" {
            inflight = Some(Inflight::new());
        } else {
            rate = Some(Rate::new(params.interval));
        }

        Ok(Self {
            tag: params.tag,
            plugin_step: params.plugin_step,
            max: params.max,
            value: params.value,
            inflight,
            rate,
        })
    }
    /// Increment `key` by 1. If value gt max, an error will be return.
    /// Otherwise returns a Guard. It may set the client ip to context.
    pub fn incr(&self, session: &Session, ctx: &mut State) -> Result<()> {
        let key = match self.tag {
            LimitTag::Query => util::get_query_value(session.req_header(), &self.value)
                .unwrap_or_default()
                .to_string(),
            LimitTag::RequestHeader => {
                util::get_req_header_value(session.req_header(), &self.value)
                    .unwrap_or_default()
                    .to_string()
            }
            LimitTag::Cookie => util::get_cookie_value(session.req_header(), &self.value)
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
impl ProxyPlugin for Limiter {
    #[inline]
    fn step(&self) -> PluginStep {
        self.plugin_step
    }
    #[inline]
    fn category(&self) -> PluginCategory {
        PluginCategory::Limit
    }
    #[inline]
    async fn handle(
        &self,
        session: &mut Session,
        ctx: &mut State,
    ) -> pingora::Result<Option<HttpResponse>> {
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
    use crate::{
        config::PluginConf,
        plugin::{limit::LimiterParams, ProxyPlugin},
        state::State,
    };
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
        let params = LimiterParams::try_from(
            &toml::from_str::<PluginConf>(
                r###"
category = "inflight"
key = "cookie"
value = "deviceId"
max = 10
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!("request", params.plugin_step.to_string());
        assert_eq!("inflight", params.category);
        assert_eq!(LimitTag::Cookie, params.tag);
        assert_eq!("deviceId", params.value);
        assert_eq!(Duration::from_secs(10), params.interval);
    }

    #[tokio::test]
    async fn test_new_cookie_limiter() {
        let limiter = Limiter::new(
            &toml::from_str::<PluginConf>(
                r###"
category = "inflight"
key = "cookie"
value = "deviceId"
max = 10
    "###,
            )
            .unwrap(),
        )
        .unwrap();
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
category = "inflight"
key = "header"
value = "X-Uuid"
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
category = "inflight"
key = "query"
value = "key"
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
category = "inflight"
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
category = "inflight"
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
            .handle(&mut session, &mut State::default())
            .await
            .unwrap();

        assert_eq!(true, result.is_some());
        assert_eq!(StatusCode::TOO_MANY_REQUESTS, result.unwrap().status);

        let limiter = Limiter::new(
            &toml::from_str::<PluginConf>(
                r###"
category = "inflight"
max = 1
"###,
            )
            .unwrap(),
        )
        .unwrap();
        let result = limiter
            .handle(&mut session, &mut State::default())
            .await
            .unwrap();

        assert_eq!(true, result.is_none());
    }

    #[tokio::test]
    async fn test_rate_limit() {
        let limiter = Limiter::new(
            &toml::from_str::<PluginConf>(
                r###"
category = "rate"
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
            .handle(&mut session, &mut State::default())
            .await
            .unwrap();

        assert_eq!(true, result.is_none());

        let _ = limiter
            .handle(&mut session, &mut State::default())
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_secs(1)).await;

        let result = limiter
            .handle(&mut session, &mut State::default())
            .await
            .unwrap();
        assert_eq!(true, result.is_some());
        assert_eq!(StatusCode::TOO_MANY_REQUESTS, result.unwrap().status);

        tokio::time::sleep(Duration::from_secs(1)).await;

        let result = limiter
            .handle(&mut session, &mut State::default())
            .await
            .unwrap();
        assert_eq!(true, result.is_none());
    }
}
