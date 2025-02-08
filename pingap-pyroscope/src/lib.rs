// Copyright 2024-2025 Tree xie.
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

use async_trait::async_trait;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use pyroscope::{
    pyroscope::PyroscopeAgentRunning, PyroscopeAgent, PyroscopeError,
};
use pyroscope_pprofrs::{pprof_backend, PprofConfig};
use snafu::{ResultExt, Snafu};
use substring::Substring;
use tracing::{error, info};
use url::Url;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Url parse error {source}, {url}"))]
    UrlParse {
        source: url::ParseError,
        url: String,
    },
    #[snafu(display("Pyroscope error {source}"))]
    Pyroscope { source: PyroscopeError },
}
type Result<T, E = Error> = std::result::Result<T, E>;

pub struct AgentService {
    url: String,
}

pub fn new_agent_service(value: &str) -> AgentService {
    AgentService {
        url: value.to_string(),
    }
}

#[async_trait]
impl BackgroundService for AgentService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        match start_pyroscope(&self.url) {
            Ok(agent_running) => {
                let _ = shutdown.changed().await;
                let agent_ready = agent_running.stop().unwrap();
                agent_ready.shutdown();
            },
            Err(e) => {
                error!("start pyroscope error: {}", e);
            },
        }
    }
}

fn start_pyroscope(
    value: &str,
) -> Result<PyroscopeAgent<PyroscopeAgentRunning>> {
    let mut connect_url = value.to_string();
    let url_info = Url::parse(value).context(UrlParseSnafu {
        url: value.to_string(),
    })?;
    let mut application_name = "pingap".to_string();
    let mut user = "".to_string();
    let mut password = "".to_string();
    let mut sample_rate = 100;
    let mut tags = vec![];
    let format_tag_value = |value: &str| {
        if value.starts_with("$") {
            std::env::var(value.substring(1, value.len()))
                .unwrap_or(value.to_string())
        } else {
            value.to_string()
        }
    };
    let tag_key_prefix = "tag:";
    for (key, value) in url_info.query_pairs().into_iter() {
        match key.as_ref() {
            "app" => application_name = value.to_string(),
            "user" => user = value.to_string(),
            "password" => password = value.to_string(),
            "sample_rate" => {
                if let Ok(v) = value.parse::<u32>() {
                    sample_rate = v;
                }
            },
            _ if key.starts_with(tag_key_prefix) => {
                let tag_value = format_tag_value(&value);
                let key =
                    key.substring(tag_key_prefix.len(), key.len()).to_string();
                tags.push((key.to_string(), tag_value));
            },
            _ => {},
        };
    }
    if let Some(query) = url_info.query() {
        connect_url = connect_url.replace(&format!("?{query}"), "");
    }

    let mut agent = PyroscopeAgent::builder(&connect_url, &application_name);
    if !user.is_empty() {
        agent = agent.basic_auth(user, password);
    }
    let client = agent
        .backend(pprof_backend(
            PprofConfig::new()
                .sample_rate(sample_rate)
                .report_thread_id()
                .report_thread_name(),
        ))
        .tags(tags.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect())
        .build()
        .context(PyroscopeSnafu)?;
    info!(
        application_name = application_name,
        sample_rate = sample_rate,
        url = connect_url,
        tags = tags
            .iter()
            .map(|(k, v)| format!("{k}:{v}"))
            .collect::<Vec<String>>()
            .join(","),
        "connect to pyroscope",
    );
    client.start().context(PyroscopeSnafu)
}
