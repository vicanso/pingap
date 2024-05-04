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

use super::{ProxyPlugin, Result};
use crate::config::{
    self, save_config, BasicConf, LocationConf, ProxyPluginCategory, ProxyPluginConf,
    ProxyPluginStep, ServerConf, UpstreamConf,
};
use crate::config::{
    PingapConf, CATEGORY_LOCATION, CATEGORY_PROXY_PLUGIN, CATEGORY_SERVER, CATEGORY_UPSTREAM,
};
use crate::http_extra::{HttpResponse, HTTP_HEADER_WWW_AUTHENTICATE};
use crate::state::get_start_time;
use crate::state::{restart_now, State};
use crate::util::{self, get_pkg_version};
use async_trait::async_trait;
use bytes::Bytes;
use bytes::{BufMut, BytesMut};
use bytesize::ByteSize;
use hex::encode;
use http::Method;
use http::{header, HeaderValue, StatusCode};
use log::{debug, error};
use memory_stats::memory_stats;
use pingora::http::RequestHeader;
use pingora::proxy::Session;
use rust_embed::EmbeddedFile;
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use substring::Substring;

#[derive(RustEmbed)]
#[folder = "dist/"]
struct AdminAsset;

pub struct EmbeddedStaticFile(pub Option<EmbeddedFile>, pub u32);

impl From<EmbeddedStaticFile> for HttpResponse {
    fn from(value: EmbeddedStaticFile) -> Self {
        if value.0.is_none() {
            return HttpResponse::not_found("Not Found".into());
        }
        // value 0 is some
        let file = value.0.unwrap();
        // hash为基于内容生成
        let str = &encode(file.metadata.sha256_hash())[0..8];
        let mime_type = file.metadata.mimetype();
        // 长度+hash的一部分
        let entity_tag = format!(r#""{:x}-{str}""#, file.data.len());
        // 因为html对于网页是入口，避免缓存后更新不及时
        // 因此设置为0
        // 其它js,css会添加版本号，因此无影响
        let max_age = if mime_type.contains("text/html") {
            0
        } else {
            value.1
        };

        let mut headers = vec![];
        if let Ok(value) = HeaderValue::from_str(mime_type) {
            headers.push((header::CONTENT_TYPE, value));
        }
        if let Ok(value) = HeaderValue::from_str(&entity_tag) {
            headers.push((header::ETAG, value));
        }

        HttpResponse {
            status: StatusCode::OK,
            body: Bytes::copy_from_slice(&file.data),
            max_age: Some(max_age),
            headers: Some(headers),
            ..Default::default()
        }
    }
}

pub struct AdminServe {
    pub path: String,
    pub authorization: String,
    pub proxy_step: ProxyPluginStep,
}
impl AdminServe {
    pub fn new(value: &str, proxy_step: ProxyPluginStep) -> Result<Self> {
        debug!("new admin server proxy plugin, {value}, {proxy_step:?}");
        let arr: Vec<&str> = value.split(' ').collect();
        let mut authorization = "".to_string();
        if arr.len() >= 2 {
            authorization = arr[1].trim().to_string();
        }
        Ok(Self {
            path: arr[0].trim().to_string(),
            proxy_step,
            authorization,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct ErrorResponse {
    message: String,
}

#[derive(Serialize, Deserialize)]
struct BasicInfo {
    start_time: u64,
    version: String,
    memory: String,
    arch: String,
    config_hash: String,
}

impl AdminServe {
    fn auth_validate(&self, req_header: &RequestHeader) -> bool {
        if self.authorization.is_empty() {
            return true;
        }
        let value = util::get_req_header_value(req_header, "Authorization").unwrap_or_default();
        if value.is_empty() {
            return false;
        }
        if value != format!("Basic {}", self.authorization) {
            return false;
        }
        true
    }
    async fn load_config(&self) -> pingora::Result<PingapConf> {
        let conf = config::load_config(&config::get_config_path(), true)
            .await
            .map_err(|e| {
                error!("failed to load config: {e}");
                util::new_internal_error(400, e.to_string())
            })?;
        conf.validate().map_err(|e| {
            error!("failed to validate config: {e}");
            util::new_internal_error(400, e.to_string())
        })?;
        Ok(conf)
    }
    async fn get_config(&self, category: &str) -> pingora::Result<HttpResponse> {
        let conf = self.load_config().await?;
        let resp = match category {
            CATEGORY_UPSTREAM => HttpResponse::try_from_json(&conf.upstreams)?,
            CATEGORY_LOCATION => HttpResponse::try_from_json(&conf.locations)?,
            CATEGORY_SERVER => HttpResponse::try_from_json(&conf.servers)?,
            CATEGORY_PROXY_PLUGIN => HttpResponse::try_from_json(&conf.proxy_plugins)?,
            _ => HttpResponse::try_from_json(&conf)?,
        };
        Ok(resp)
    }

    async fn remove_config(&self, category: &str, name: &str) -> pingora::Result<HttpResponse> {
        let mut conf = self.load_config().await?;
        conf.remove(category, name).map_err(|e| {
            error!("failed to validate config: {e}");
            util::new_internal_error(400, e.to_string())
        })?;
        save_config(&config::get_config_path(), &conf, category)
            .await
            .map_err(|e| {
                error!("failed to save config: {e}");
                util::new_internal_error(400, e.to_string())
            })?;
        Ok(HttpResponse::no_content())
    }
    async fn update_config(
        &self,
        session: &mut Session,
        category: &str,
        name: &str,
    ) -> pingora::Result<HttpResponse> {
        let mut buf = BytesMut::with_capacity(4096);
        while let Some(value) = session.read_request_body().await? {
            buf.put(value.as_ref());
        }
        let key = name.to_string();
        let mut conf = self.load_config().await?;
        match category {
            CATEGORY_UPSTREAM => {
                let upstream: UpstreamConf = serde_json::from_slice(&buf).map_err(|e| {
                    error!("failed to deserialize upstream: {e}");
                    util::new_internal_error(400, e.to_string())
                })?;
                conf.upstreams.insert(key, upstream);
            }
            CATEGORY_LOCATION => {
                let location: LocationConf = serde_json::from_slice(&buf).map_err(|e| {
                    error!("failed to deserialize location: {e}");
                    util::new_internal_error(400, e.to_string())
                })?;
                conf.locations.insert(key, location);
            }
            CATEGORY_SERVER => {
                let server: ServerConf = serde_json::from_slice(&buf).map_err(|e| {
                    error!("failed to deserialize server: {e}");
                    util::new_internal_error(400, e.to_string())
                })?;
                conf.servers.insert(key, server);
            }
            CATEGORY_PROXY_PLUGIN => {
                let plugin: ProxyPluginConf = serde_json::from_slice(&buf).map_err(|e| {
                    error!("failed to deserialize proxy plugin: {e}");
                    util::new_internal_error(400, e.to_string())
                })?;
                conf.proxy_plugins.insert(key, plugin);
            }
            _ => {
                let basic_conf: BasicConf = serde_json::from_slice(&buf).map_err(|e| {
                    error!("failed to basic info: {e}");
                    util::new_internal_error(400, e.to_string())
                })?;
                conf.basic = basic_conf;
            }
        };
        save_config(&config::get_config_path(), &conf, category)
            .await
            .map_err(|e| {
                error!("failed to save config: {e}");
                util::new_internal_error(400, e.to_string())
            })?;
        Ok(HttpResponse::no_content())
    }
}

fn get_method_path(session: &Session) -> (Method, String) {
    let req_header = session.req_header();
    let method = req_header.method.clone();
    let path = req_header.uri.path();
    (method, path.to_string())
}

#[async_trait]
impl ProxyPlugin for AdminServe {
    #[inline]
    fn step(&self) -> ProxyPluginStep {
        self.proxy_step
    }
    #[inline]
    fn category(&self) -> ProxyPluginCategory {
        ProxyPluginCategory::Admin
    }
    async fn handle(
        &self,
        session: &mut Session,
        _ctx: &mut State,
    ) -> pingora::Result<Option<HttpResponse>> {
        if !session.req_header().uri.path().starts_with(&self.path) {
            return Ok(None);
        }
        let header = session.req_header_mut();
        if !self.auth_validate(header) {
            return Ok(Some(HttpResponse {
                status: StatusCode::UNAUTHORIZED,
                headers: Some(vec![HTTP_HEADER_WWW_AUTHENTICATE.clone()]),
                ..Default::default()
            }));
        }
        let path = header.uri.path();
        let mut new_path = path.substring(self.path.len(), path.len()).to_string();
        if let Some(query) = header.uri.query() {
            new_path = format!("{new_path}?{query}");
        }
        // TODO parse error
        if let Ok(uri) = new_path.parse::<http::Uri>() {
            header.set_uri(uri);
        }

        let (method, mut path) = get_method_path(session);
        let api_prefix = "/api";
        if path.starts_with(api_prefix) {
            path = path.substring(api_prefix.len(), path.len()).to_string();
        }
        let params: Vec<&str> = path.split('/').collect();
        let mut category = "";
        if params.len() >= 3 {
            category = params[2];
        }
        let resp = if path.starts_with("/configs") {
            match method {
                Method::POST => {
                    if params.len() < 4 {
                        Err(pingora::Error::new_str("Url is invalid(no name)"))
                    } else {
                        self.update_config(session, category, params[3]).await
                    }
                }
                Method::DELETE => {
                    if params.len() < 4 {
                        Err(pingora::Error::new_str("Url is invalid(no name)"))
                    } else {
                        self.remove_config(category, params[3]).await
                    }
                }
                _ => self.get_config(category).await,
            }
            .unwrap_or_else(|err| {
                HttpResponse::try_from_json_status(
                    &ErrorResponse {
                        message: err.to_string(),
                    },
                    StatusCode::INTERNAL_SERVER_ERROR,
                )
                .unwrap_or(HttpResponse::unknown_error("Json serde fail".into()))
            })
        } else if path == "/basic" {
            let mut memory = "".to_string();
            if let Some(value) = memory_stats() {
                memory = ByteSize(value.physical_mem as u64).to_string_as(true);
            }
            let arch = if cfg!(any(target_arch = "arm", target_arch = "aarch64")) {
                "arm64"
            } else {
                "x86"
            };

            HttpResponse::try_from_json(&BasicInfo {
                start_time: get_start_time(),
                version: get_pkg_version().to_string(),
                arch: arch.to_string(),
                config_hash: config::get_config_hash(),
                memory,
            })
            .unwrap_or(HttpResponse::unknown_error("Json serde fail".into()))
        } else if path == "/restart" && method == Method::POST {
            if let Err(e) = restart_now() {
                error!("Restart fail: {e}");
                HttpResponse::bad_request(e.to_string().into())
            } else {
                HttpResponse::no_content()
            }
        } else {
            let mut file = path.substring(1, path.len());
            if file.is_empty() {
                file = "index.html";
            }
            EmbeddedStaticFile(AdminAsset::get(file), 365 * 24 * 3600).into()
        };
        Ok(Some(resp))
    }
}
