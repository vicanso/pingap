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

use crate::state::State;
use crate::utils;
use pingora::proxy::Session;
use pingora_limits::inflight::Inflight;
use snafu::{ResultExt, Snafu};
use std::num::ParseIntError;
use substring::Substring;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Invalid {message}"))]
    Invalid { message: String },
    #[snafu(display("Parse int {source}"))]
    ParseInt { source: ParseIntError },
    #[snafu(display("Exceed limit {value}/{max}"))]
    Exceed { max: isize, value: isize },
}
type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(PartialEq)]
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
    inflight: Inflight,
}

impl Limiter {
    pub fn new(value: &str) -> Result<Limiter> {
        let (key, max) = value.split_once(' ').ok_or(Error::Invalid {
            message: value.to_string(),
        })?;
        let max = max.parse::<u32>().context(ParseIntSnafu)?;
        if key.len() < 2 {
            return Err(Error::Invalid {
                message: key.to_string(),
            });
        }
        let key = key.substring(1, key.len() - 1);
        let ch = key.substring(0, 1);
        let value = key.substring(1, key.len());
        let tag = match ch {
            "~" => LimitTag::Cookie,
            ">" => LimitTag::RequestHeader,
            "?" => LimitTag::Query,
            _ => LimitTag::Ip,
        };

        Ok(Limiter {
            tag,
            max: max as isize,
            value: value.to_string(),
            inflight: Inflight::new(),
        })
    }
    /// Increment `key` by 1. If value gt max, an error will be return.
    /// Otherwise returns a Guard.
    pub fn incr(&self, session: &Session, ctx: &mut State) -> Result<()> {
        let key = match self.tag {
            LimitTag::Query => utils::get_query_value(session.req_header(), &self.value)
                .unwrap_or_default()
                .to_string(),
            LimitTag::RequestHeader => {
                utils::get_req_header_value(session.req_header(), &self.value)
                    .unwrap_or_default()
                    .to_string()
            }
            LimitTag::Cookie => utils::get_cookie_value(session.req_header(), &self.value)
                .unwrap_or_default()
                .to_string(),
            _ => {
                let client_ip = utils::get_client_ip(session);
                ctx.client_ip = Some(client_ip.clone());
                client_ip
            }
        };
        if key.is_empty() {
            return Ok(());
        }
        let (guard, value) = self.inflight.incr(key, 1);
        if value > self.max {
            return Err(Error::Exceed {
                max: self.max,
                value,
            });
        }
        ctx.guard = Some(guard);
        Ok(())
    }
}
