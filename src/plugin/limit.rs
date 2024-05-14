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

use super::ProxyPlugin;
use super::{Error, Result};
use crate::config::{PluginCategory, PluginStep};
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
    proxy_step: PluginStep,
}

impl Limiter {
    pub fn new(value: &str, proxy_step: PluginStep) -> Result<Self> {
        debug!("new limit proxy plugin, {value}, {proxy_step:?}");
        if ![PluginStep::Request, PluginStep::ProxyUpstream].contains(&proxy_step) {
            return Err(Error::Invalid {
                category: PluginCategory::Limit.to_string(),
                message: "Limit plugin should be executed at request or proxy upstream step"
                    .to_string(),
            });
        }
        let (category, limit_value) = value.split_once(' ').ok_or(Error::Invalid {
            category: PluginCategory::Limit.to_string(),
            message: value.to_string(),
        })?;

        let mut tag = LimitTag::Ip;
        let mut key_value = "".to_string();
        let mut max = 0;
        let mut interval = Duration::from_secs(10);
        for item in limit_value.split('&') {
            let (key, value) = item.split_once('=').ok_or(Error::Invalid {
                category: PluginCategory::Limit.to_string(),
                message: item.to_string(),
            })?;
            match key {
                "key" => {
                    tag = match value {
                        "cookie" => LimitTag::Cookie,
                        "header" => LimitTag::RequestHeader,
                        "query" => LimitTag::Query,
                        _ => LimitTag::Ip,
                    };
                }
                "value" => key_value = value.to_string(),
                "max" => {
                    max = value.parse::<isize>().map_err(|e| Error::Invalid {
                        category: PluginCategory::Limit.to_string(),
                        message: e.to_string(),
                    })?;
                }
                "interval" => {
                    interval = parse_duration(value).map_err(|e| Error::Invalid {
                        category: PluginCategory::Limit.to_string(),
                        message: e.to_string(),
                    })?;
                }
                _ => {}
            };
        }
        let mut inflight = None;
        let mut rate = None;
        if category == "inflight" {
            inflight = Some(Inflight::new());
        } else {
            rate = Some(Rate::new(interval));
        }

        Ok(Self {
            tag,
            proxy_step,
            max,
            value: key_value,
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
        self.proxy_step
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
    use crate::{config::PluginStep, plugin::ProxyPlugin, state::State};
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
    #[tokio::test]
    async fn test_new_cookie_limiter() {
        let limiter = Limiter::new(
            "inflight key=cookie&value=deviceId&max=10",
            PluginStep::Request,
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
            "inflight key=header&value=X-Uuid&max=10",
            PluginStep::Request,
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
        let limiter =
            Limiter::new("inflight key=query&value=key&max=10", PluginStep::Request).unwrap();
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
        let limiter = Limiter::new("inflight max=10", PluginStep::Request).unwrap();
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
        let limiter = Limiter::new("inflight max=0", PluginStep::Request).unwrap();

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

        let limiter = Limiter::new("inflight max=1", PluginStep::Request).unwrap();
        let result = limiter
            .handle(&mut session, &mut State::default())
            .await
            .unwrap();

        assert_eq!(true, result.is_none());
    }

    #[tokio::test]
    async fn test_rate_limit() {
        let limiter = Limiter::new("rate max=1&interval=1s", PluginStep::Request).unwrap();

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
