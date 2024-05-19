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
use crate::http_extra::{HttpResponse, HTTP_HEADER_CONTENT_JSON};
use crate::state::{get_hostname, get_start_time, State};
use crate::util;
use async_trait::async_trait;
use bytesize::ByteSize;
use http::StatusCode;
use log::debug;
use memory_stats::memory_stats;
use pingora::proxy::Session;
use serde::Serialize;
use std::time::Duration;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Serialize)]
struct ServerStats {
    processing: i32,
    accepted: u64,
    hostname: String,
    physical_mem_mb: usize,
    physical_mem: String,
    version: String,
    start_time: u64,
    uptime: String,
}
pub struct Stats {
    path: String,
    plugin_step: PluginStep,
}

struct StatsParams {
    path: String,
    plugin_step: PluginStep,
}
impl TryFrom<&PluginConf> for StatsParams {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        let step = get_step_conf(value);

        let params = Self {
            plugin_step: step,
            path: get_str_conf(value, "path"),
        };
        if ![PluginStep::Request, PluginStep::ProxyUpstream].contains(&params.plugin_step) {
            return Err(Error::Invalid {
                category: PluginCategory::Stats.to_string(),
                message: "Stats plugin should be executed at request or proxy upstream step"
                    .to_string(),
            });
        }
        Ok(params)
    }
}

impl Stats {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!("new stats proxy plugin, params:{params:?}");
        let params = StatsParams::try_from(params)?;

        Ok(Self {
            plugin_step: params.plugin_step,
            path: params.path,
        })
    }
}

#[async_trait]
impl ProxyPlugin for Stats {
    #[inline]
    fn step(&self) -> PluginStep {
        self.plugin_step
    }
    #[inline]
    fn category(&self) -> PluginCategory {
        PluginCategory::Stats
    }
    #[inline]
    async fn handle(
        &self,
        session: &mut Session,
        ctx: &mut State,
    ) -> pingora::Result<Option<HttpResponse>> {
        if session.req_header().uri.path() == self.path {
            let mut physical_mem = 0;
            if let Some(value) = memory_stats() {
                physical_mem = value.physical_mem;
            }
            let uptime: humantime::Duration =
                Duration::from_secs(util::now().as_secs() - get_start_time()).into();
            let buf = serde_json::to_vec(&ServerStats {
                accepted: ctx.accepted,
                processing: ctx.processing,
                hostname: get_hostname(),
                physical_mem: ByteSize(physical_mem as u64).to_string_as(true),
                physical_mem_mb: physical_mem / (1024 * 1024),
                version: VERSION.to_string(),
                start_time: get_start_time(),
                uptime: uptime.to_string(),
            })
            .unwrap_or_default();
            return Ok(Some(HttpResponse {
                status: StatusCode::OK,
                body: buf.into(),
                headers: Some(vec![HTTP_HEADER_CONTENT_JSON.clone()]),
                ..Default::default()
            }));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::Stats;
    use crate::state::State;
    use crate::{config::PluginConf, plugin::ProxyPlugin};
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    #[tokio::test]
    async fn test_stats() {
        let stats = Stats::new(
            &toml::from_str::<PluginConf>(
                r###"
            path = "/stats"
        "###,
            )
            .unwrap(),
        )
        .unwrap();

        let headers = ["Accept-Encoding: gzip"].join("\r\n");
        let input_header = format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let result = stats
            .handle(&mut session, &mut State::default())
            .await
            .unwrap();
        assert_eq!(true, result.is_none());

        let headers = ["Accept-Encoding: gzip"].join("\r\n");
        let input_header = format!("GET /stats HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let result = stats
            .handle(&mut session, &mut State::default())
            .await
            .unwrap();
        assert_eq!(true, result.is_some());
    }
}
