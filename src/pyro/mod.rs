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

use log::info;
use pyroscope::{pyroscope::PyroscopeAgentRunning, PyroscopeAgent, PyroscopeError};
use pyroscope_pprofrs::{pprof_backend, PprofConfig};
use snafu::{ResultExt, Snafu};
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

pub fn start_pyroscope(value: &str) -> Result<PyroscopeAgent<PyroscopeAgentRunning>> {
    let mut connect_url = value.to_string();
    let url_info = Url::parse(value).context(UrlParseSnafu {
        url: value.to_string(),
    })?;
    let mut application_name = "pingap".to_string();
    let mut user = "".to_string();
    let mut password = "".to_string();
    let mut samplerate = 100;
    for (key, value) in url_info.query_pairs().into_iter() {
        match key.as_ref() {
            "app" => application_name = value.to_string(),
            "user" => user = value.to_string(),
            "password" => password = value.to_string(),
            "samplerate" => {
                if let Ok(v) = value.parse::<u32>() {
                    samplerate = v;
                }
            }
            _ => {}
        };
    }
    if let Some(query) = url_info.query() {
        connect_url = connect_url.replace(query, "");
    }

    let mut agent = PyroscopeAgent::builder(&connect_url, &application_name);
    if !user.is_empty() {
        agent = agent.basic_auth(user, password);
    }
    let client = agent
        .backend(pprof_backend(PprofConfig::new().sample_rate(samplerate)))
        // .tags([("app", "Rust"), ("TagB", "ValueB")].to_vec())
        .build()
        .context(PyroscopeSnafu)?;
    info!("Connect to pyroscope, app:{application_name}, url:{connect_url}");
    client.start().context(PyroscopeSnafu)
}
