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

use crate::config::{PluginCategory, PluginConf, PluginStep};
use crate::http_extra::HttpResponse;
use crate::state::State;
use async_trait::async_trait;
use once_cell::sync::OnceCell;
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use snafu::Snafu;
use std::collections::HashMap;
use std::str::FromStr;

mod admin;
mod basic_auth;
mod cache;
mod compression;
mod csrf;
mod directory;
mod ip_restriction;
mod jwt_auth;
mod jwt_sign;
mod key_auth;
mod limit;
mod mock;
mod ping;
mod redirect;
mod referer_restriction;
mod request_id;
mod response_headers;
mod stats;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Plugin {category} invalid, message: {message}"))]
    Invalid { category: String, message: String },
    #[snafu(display("Plugin {category}, exceed limit {value}/{max}"))]
    Exceed {
        category: String,
        max: isize,
        value: isize,
    },
    #[snafu(display("Plugin {category}, base64 decode error {source}"))]
    Base64Decode {
        category: String,
        source: base64::DecodeError,
    },
}
type Result<T, E = Error> = std::result::Result<T, E>;

#[async_trait]
pub trait ProxyPlugin: Sync + Send {
    fn category(&self) -> PluginCategory;
    fn step(&self) -> PluginStep;
    async fn handle(
        &self,
        _session: &mut Session,
        _ctx: &mut State,
    ) -> pingora::Result<Option<HttpResponse>> {
        Ok(None)
    }
}

pub trait ResponsePlugin: Sync + Send {
    fn category(&self) -> PluginCategory;
    fn step(&self) -> PluginStep;
    fn handle(
        &self,
        _session: &mut Session,
        _ctx: &mut State,
        _upstream_response: &mut ResponseHeader,
    ) {
    }
}

pub fn get_builtin_proxy_plugins() -> Vec<(String, PluginConf)> {
    vec![
        // default level, gzip:6 br:6 zstd:3
        (
            "pingap:compression".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "compression"
gzip_level = 6
br_level = 6
zstd_level = 6
remark = "Compression for http, support zstd:3, br:6, gzip:6"
"###,
            )
            .unwrap(),
        ),
        (
            "pingap:ping".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "ping"
path = "/ping"
remark = "Ping pong"
"###,
            )
            .unwrap(),
        ),
        (
            "pingap:stats".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "stats"
path = "/stats"
remark = "Get stats of server"
"###,
            )
            .unwrap(),
        ),
        (
            "pingap:requestId".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "request_id"
remark = "Generate a request id for service"
"###,
            )
            .unwrap(),
        ),
    ]
}

type Plugins = (
    HashMap<String, Box<dyn ProxyPlugin>>,
    HashMap<String, Box<dyn ResponsePlugin>>,
);

static PLUGINS: OnceCell<Plugins> = OnceCell::new();

pub fn parse_plugins(confs: Vec<(String, PluginConf)>) -> Result<Plugins> {
    let mut proxy_plugins: HashMap<String, Box<dyn ProxyPlugin>> = HashMap::new();
    let mut response_plugins: HashMap<String, Box<dyn ResponsePlugin>> = HashMap::new();
    for (name, conf) in confs.iter() {
        let name = name.to_string();
        let category = conf.get("category");
        if category.is_none() {
            return Err(Error::Invalid {
                category: "".to_string(),
                message: "Category can not be empty".to_string(),
            });
        }
        let category = PluginCategory::from_str(category.unwrap().as_str().unwrap_or_default())
            .unwrap_or_default();
        match category {
            PluginCategory::Limit => {
                let l = limit::Limiter::new(conf)?;
                proxy_plugins.insert(name, Box::new(l));
            }
            PluginCategory::Compression => {
                let c = compression::Compression::new(conf)?;
                proxy_plugins.insert(name, Box::new(c));
            }
            PluginCategory::Stats => {
                let s = stats::Stats::new(conf)?;
                proxy_plugins.insert(name, Box::new(s));
            }
            PluginCategory::Admin => {
                let a = admin::AdminServe::new(conf)?;
                proxy_plugins.insert(name, Box::new(a));
            }
            PluginCategory::Directory => {
                let d = directory::Directory::new(conf)?;
                proxy_plugins.insert(name, Box::new(d));
            }
            PluginCategory::Mock => {
                let m = mock::MockResponse::new(conf)?;
                proxy_plugins.insert(name, Box::new(m));
            }
            PluginCategory::RequestId => {
                let r = request_id::RequestId::new(conf)?;
                proxy_plugins.insert(name, Box::new(r));
            }
            PluginCategory::IpRestriction => {
                let l = ip_restriction::IpRestriction::new(conf)?;
                proxy_plugins.insert(name, Box::new(l));
            }
            PluginCategory::KeyAuth => {
                let k = key_auth::KeyAuth::new(conf)?;
                proxy_plugins.insert(name, Box::new(k));
            }
            PluginCategory::BasicAuth => {
                let b = basic_auth::BasicAuth::new(conf)?;
                proxy_plugins.insert(name, Box::new(b));
            }
            PluginCategory::Cache => {
                let c = cache::Cache::new(conf)?;
                proxy_plugins.insert(name, Box::new(c));
            }
            PluginCategory::Redirect => {
                let r = redirect::Redirect::new(conf)?;
                proxy_plugins.insert(name, Box::new(r));
            }
            PluginCategory::Ping => {
                let p = ping::Ping::new(conf)?;
                proxy_plugins.insert(name, Box::new(p));
            }
            PluginCategory::ResponseHeaders => {
                let r = response_headers::ResponseHeaders::new(conf)?;
                response_plugins.insert(name, Box::new(r));
            }
            PluginCategory::RefererRestriction => {
                let r = referer_restriction::RefererRestriction::new(conf)?;
                proxy_plugins.insert(name, Box::new(r));
            }
            PluginCategory::Csrf => {
                let c = csrf::Csrf::new(conf)?;
                proxy_plugins.insert(name, Box::new(c));
            }
            PluginCategory::JwtAuth => {
                let j = jwt_auth::JwtAuth::new(conf)?;
                proxy_plugins.insert(name, Box::new(j));
            }
            PluginCategory::JwtSign => {
                let j = jwt_sign::JwtSign::new(conf)?;
                response_plugins.insert(name, Box::new(j));
            }
        };
    }

    Ok((proxy_plugins, response_plugins))
}

pub fn init_plugins(confs: Vec<(String, PluginConf)>) -> Result<()> {
    PLUGINS.get_or_try_init(|| {
        let data = &mut confs.clone();
        data.extend(get_builtin_proxy_plugins());
        parse_plugins(data.to_vec())
    })?;
    Ok(())
}

#[inline]
pub fn get_proxy_plugin(name: &str) -> Option<&dyn ProxyPlugin> {
    if let Some((proxy_plugins, _)) = PLUGINS.get() {
        if let Some(plugin) = proxy_plugins.get(name) {
            return Some(plugin.as_ref());
        }
    }
    None
}

#[inline]
pub fn get_response_plugin(name: &str) -> Option<&dyn ResponsePlugin> {
    if let Some((_, response_plugins)) = PLUGINS.get() {
        if let Some(plugin) = response_plugins.get(name) {
            return Some(plugin.as_ref());
        }
    }
    None
}

pub fn list_plugins() -> Option<&'static Plugins> {
    PLUGINS.get()
}

pub(crate) fn get_str_conf(value: &PluginConf, key: &str) -> String {
    if let Some(value) = value.get(key) {
        value.as_str().unwrap_or_default().to_string()
    } else {
        "".to_string()
    }
}

pub(crate) fn get_int_conf(value: &PluginConf, key: &str) -> i64 {
    if let Some(value) = value.get(key) {
        value.as_integer().unwrap_or_default()
    } else {
        0
    }
}

pub(crate) fn get_bool_conf(value: &PluginConf, key: &str) -> bool {
    if let Some(value) = value.get(key) {
        value.as_bool().unwrap_or_default()
    } else {
        false
    }
}

pub(crate) fn get_str_slice_conf(value: &PluginConf, key: &str) -> Vec<String> {
    if let Some(value) = value.get(key) {
        if let Some(values) = value.as_array() {
            return values
                .iter()
                .map(|item| item.as_str().unwrap_or_default().to_string())
                .collect();
        }
    }
    vec![]
}

pub(crate) fn get_step_conf(value: &PluginConf) -> PluginStep {
    PluginStep::from_str(get_str_conf(value, "step").as_str()).unwrap_or_default()
}

#[test]
pub fn initialize_test_plugins() {
    let _ = init_plugins(vec![
        (
            "test:mock".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "mock"
path = "/mock"
status = 999
data = "abc"
"###,
            )
            .unwrap(),
        ),
        (
            "test:add_headers".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "response_headers"
step = "upstream_response"
add_headers = [
"X-Service:1",
"X-Service:2",
]
set_headers = [
"X-Response-Id:123"
]
remove_headers = [
"Content-Type"
]
"###,
            )
            .unwrap(),
        ),
    ]);
}
