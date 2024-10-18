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

use super::{
    get_hash_key, get_int_conf, get_step_conf, get_str_conf,
    get_str_slice_conf, Error, Plugin, Result,
};
use crate::config::{
    self, get_current_config, save_config, BasicConf, CertificateConf,
    LocationConf, PluginCategory, PluginConf, PluginStep, ServerConf,
    UpstreamConf, CATEGORY_CERTIFICATE,
};
use crate::config::{
    PingapConf, CATEGORY_LOCATION, CATEGORY_PLUGIN, CATEGORY_SERVER,
    CATEGORY_UPSTREAM,
};
use crate::http_extra::{HttpResponse, HTTP_HEADER_WWW_AUTHENTICATE};
use crate::limit::TtlLruLimit;
use crate::state::{get_processing_accepted, get_start_time, get_system_info};
use crate::state::{restart_now, State};
use crate::util::{self, base64_decode};
use async_trait::async_trait;
use bytes::Bytes;
use bytes::{BufMut, BytesMut};
use flate2::write::GzEncoder;
use flate2::Compression;
use hex::encode;
use http::Method;
use http::{header, HeaderValue, StatusCode};
use pingora::http::RequestHeader;
use pingora::proxy::Session;
use rust_embed::EmbeddedFile;
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::time::Duration;
use substring::Substring;
use tracing::{debug, error};

#[derive(RustEmbed)]
#[folder = "dist/"]
struct AdminAsset;

pub struct EmbeddedStaticFile(pub Option<EmbeddedFile>, pub Duration);

impl From<EmbeddedStaticFile> for HttpResponse {
    fn from(value: EmbeddedStaticFile) -> Self {
        let Some(file) = value.0 else {
            return HttpResponse::not_found("Not Found".into());
        };
        // generate content hash
        let str = &encode(file.metadata.sha256_hash())[0..8];
        let mime_type = file.metadata.mimetype();
        // cut hash and file length as etag
        let entity_tag = format!(r#""{:x}-{str}""#, file.data.len());
        // html set no-cache
        let max_age = if mime_type.contains("text/html") {
            0
        } else {
            value.1.as_secs()
        };

        let mut headers = vec![];
        if let Ok(value) = HeaderValue::from_str(mime_type) {
            headers.push((header::CONTENT_TYPE, value));
        }
        if let Ok(value) = HeaderValue::from_str(&entity_tag) {
            headers.push((header::ETAG, value));
        }

        let mut gzip_body = None;
        if file.data.len() > 1024 {
            let mut d = GzEncoder::new(vec![], Compression::best());
            let _ = d.write_all(&file.data);
            if let Ok(w) = d.finish() {
                gzip_body = Some(Bytes::copy_from_slice(w.as_ref()));
                if let Ok(value) = HeaderValue::from_str("gzip") {
                    headers.push((header::CONTENT_ENCODING, value));
                }
            }
        }
        let body = if let Some(data) = gzip_body {
            data
        } else {
            Bytes::copy_from_slice(&file.data)
        };

        HttpResponse {
            status: StatusCode::OK,
            body,
            max_age: Some(max_age as u32),
            headers: Some(headers),
            ..Default::default()
        }
    }
}

pub struct AdminServe {
    pub path: String,
    pub authorizations: Vec<Vec<u8>>,
    pub plugin_step: PluginStep,
    hash_value: String,
    ip_fail_limit: TtlLruLimit,
}

#[derive(Serialize, Deserialize)]
struct ErrorResponse {
    message: String,
}

#[derive(Serialize, Deserialize)]
struct BasicInfo {
    start_time: u64,
    version: String,
    rustc_version: String,
    kernel: String,
    config_hash: String,
    pid: String,
    user: String,
    group: String,
    threads: usize,
    processing: i32,
    accepted: u64,
    memory_mb: usize,
    memory: String,
    arch: String,
    cpus: usize,
    physical_cpus: usize,
    total_memory: String,
    used_memory: String,
    enabled_full: bool,
}

impl TryFrom<&PluginConf> for AdminServe {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);
        let mut authorizations = vec![];
        for item in get_str_slice_conf(value, "authorizations").iter() {
            if item.is_empty() {
                continue;
            }
            let _ = base64_decode(item).map_err(|e| Error::Base64Decode {
                category: PluginCategory::BasicAuth.to_string(),
                source: e,
            })?;
            authorizations.push(format!("Basic {item}").as_bytes().to_vec());
        }
        let mut ip_fail_limit = get_int_conf(value, "ip_fail_limit");
        if ip_fail_limit <= 0 {
            ip_fail_limit = 10;
        }
        let params = AdminServe {
            hash_value,
            plugin_step: get_step_conf(value),
            path: get_str_conf(value, "path"),
            ip_fail_limit: TtlLruLimit::new(
                512,
                Duration::from_secs(5 * 60),
                ip_fail_limit as usize,
            ),
            authorizations,
        };
        if ![PluginStep::Request, PluginStep::ProxyUpstream]
            .contains(&params.plugin_step)
        {
            return Err(Error::Invalid {
                category: PluginCategory::Admin.to_string(),
                message: "Admin serve plugin should be executed at request or proxy upstream step".to_string(),
            });
        }

        Ok(params)
    }
}

impl AdminServe {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new admin server plugin");
        let serve = AdminServe::try_from(params)?;

        Ok(serve)
    }
    fn auth_validate(&self, req_header: &RequestHeader) -> bool {
        if self.authorizations.is_empty() {
            return true;
        }
        let value = util::get_req_header_value(req_header, "Authorization")
            .unwrap_or_default();
        if value.is_empty() {
            return false;
        }
        self.authorizations.contains(&value.as_bytes().to_vec())
    }
    async fn load_config(&self) -> pingora::Result<PingapConf> {
        let conf = config::load_config(true).await.map_err(|e| {
            error!("failed to load config: {e}");
            util::new_internal_error(400, e.to_string())
        })?;
        conf.validate().map_err(|e| {
            error!("failed to validate config: {e}");
            util::new_internal_error(400, e.to_string())
        })?;
        Ok(conf)
    }
    async fn get_config(
        &self,
        category: &str,
    ) -> pingora::Result<HttpResponse> {
        let conf = self.load_config().await?;
        if category == "toml" {
            let data = toml::to_string_pretty(&conf)
                .map_err(|e| util::new_internal_error(400, e.to_string()))?;
            return Ok(HttpResponse {
                status: StatusCode::OK,
                body: data.into(),
                ..Default::default()
            });
        }
        let resp = match category {
            CATEGORY_UPSTREAM => HttpResponse::try_from_json(&conf.upstreams)?,
            CATEGORY_LOCATION => HttpResponse::try_from_json(&conf.locations)?,
            CATEGORY_SERVER => HttpResponse::try_from_json(&conf.servers)?,
            CATEGORY_PLUGIN => HttpResponse::try_from_json(&conf.plugins)?,
            CATEGORY_CERTIFICATE => {
                HttpResponse::try_from_json(&conf.certificates)?
            },
            _ => HttpResponse::try_from_json(&conf)?,
        };
        Ok(resp)
    }

    async fn remove_config(
        &self,
        category: &str,
        name: &str,
    ) -> pingora::Result<HttpResponse> {
        let mut conf = self.load_config().await?;
        conf.remove(category, name).map_err(|e| {
            error!(error = e.to_string(), "validate config fail");
            util::new_internal_error(400, e.to_string())
        })?;
        save_config(&conf, category).await.map_err(|e| {
            error!(error = e.to_string(), "save config fail");
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
                let upstream: UpstreamConf = serde_json::from_slice(&buf)
                    .map_err(|e| {
                        error!(
                            error = e.to_string(),
                            "descrialize upstream fail"
                        );
                        util::new_internal_error(400, e.to_string())
                    })?;
                conf.upstreams.insert(key, upstream);
            },
            CATEGORY_LOCATION => {
                let location: LocationConf = serde_json::from_slice(&buf)
                    .map_err(|e| {
                        error!(
                            error = e.to_string(),
                            "descrialize location fail"
                        );
                        util::new_internal_error(400, e.to_string())
                    })?;
                conf.locations.insert(key, location);
            },
            CATEGORY_SERVER => {
                let server: ServerConf =
                    serde_json::from_slice(&buf).map_err(|e| {
                        error!(
                            error = e.to_string(),
                            "descrialize server fail"
                        );
                        util::new_internal_error(400, e.to_string())
                    })?;
                conf.servers.insert(key, server);
            },
            CATEGORY_PLUGIN => {
                let plugin: PluginConf =
                    serde_json::from_slice(&buf).map_err(|e| {
                        error!(
                            error = e.to_string(),
                            "descrialize plugin fail"
                        );
                        util::new_internal_error(400, e.to_string())
                    })?;
                conf.plugins.insert(key, plugin);
            },
            CATEGORY_CERTIFICATE => {
                let certificate: CertificateConf = serde_json::from_slice(&buf)
                    .map_err(|e| {
                        error!(
                            error = e.to_string(),
                            "descrialize certificate fail"
                        );
                        util::new_internal_error(400, e.to_string())
                    })?;
                conf.certificates.insert(key, certificate);
            },
            _ => {
                let basic_conf: BasicConf = serde_json::from_slice(&buf)
                    .map_err(|e| {
                        error!(error = e.to_string(), "descrialize basic fail");
                        util::new_internal_error(400, e.to_string())
                    })?;
                conf.basic = basic_conf;
            },
        };
        save_config(&conf, category).await.map_err(|e| {
            error!(error = e.to_string(), "save config fail");
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
impl Plugin for AdminServe {
    #[inline]
    fn hash_key(&self) -> String {
        self.hash_value.clone()
    }
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        _ctx: &mut State,
    ) -> pingora::Result<Option<HttpResponse>> {
        if self.plugin_step != step {
            return Ok(None);
        }
        let ip = util::get_client_ip(session);
        if !self.ip_fail_limit.validate(&ip).await {
            return Ok(Some(HttpResponse {
                status: StatusCode::FORBIDDEN,
                body: Bytes::from_static(b"Forbidden, too many failures"),
                ..Default::default()
            }));
        }
        if !session.req_header().uri.path().starts_with(&self.path) {
            return Ok(None);
        }
        let header = session.req_header_mut();
        if !self.auth_validate(header) {
            self.ip_fail_limit.inc(&ip).await;
            return Ok(Some(HttpResponse {
                status: StatusCode::UNAUTHORIZED,
                headers: Some(vec![HTTP_HEADER_WWW_AUTHENTICATE.clone()]),
                ..Default::default()
            }));
        }
        let path = header.uri.path();
        let mut new_path =
            path.substring(self.path.len(), path.len()).to_string();
        if let Some(query) = header.uri.query() {
            new_path = format!("{new_path}?{query}");
        }
        // ignore parse error
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
                },
                Method::DELETE => {
                    if params.len() < 4 {
                        Err(pingora::Error::new_str("Url is invalid(no name)"))
                    } else {
                        self.remove_config(category, params[3]).await
                    }
                },
                _ => self.get_config(category).await,
            }
            .unwrap_or_else(|err| {
                HttpResponse::try_from_json_status(
                    &ErrorResponse {
                        message: err.to_string(),
                    },
                    StatusCode::INTERNAL_SERVER_ERROR,
                )
                .unwrap_or(HttpResponse::unknown_error(
                    "Json serde fail".into(),
                ))
            })
        } else if path == "/basic" {
            let system_info = get_system_info();
            let current_config = get_current_config();
            let data = tokio::fs::read(current_config.basic.get_pid_file())
                .await
                .unwrap_or_default();
            let pid = std::string::String::from_utf8_lossy(&data)
                .trim()
                .to_string();
            let mut threads = 0;
            let cpu_count = num_cpus::get();
            let mut default_threads = current_config.basic.threads.unwrap_or(1);
            if default_threads == 0 {
                default_threads = cpu_count;
            }
            for (_, server) in current_config.servers.iter() {
                let count = server.threads.unwrap_or(1);
                if count == 0 {
                    threads += default_threads;
                } else {
                    threads += count;
                }
            }
            let (processing, accepted) = get_processing_accepted();
            cfg_if::cfg_if! {
                if #[cfg(feature = "full")] {
                    let enabled_full = true;
                } else {
                    let enabled_full = false;
                }
            }

            HttpResponse::try_from_json(&BasicInfo {
                start_time: get_start_time(),
                version: util::get_pkg_version().to_string(),
                rustc_version: util::get_rustc_version(),
                config_hash: config::get_config_hash(),
                user: current_config.basic.user.clone().unwrap_or_default(),
                group: current_config.basic.group.clone().unwrap_or_default(),
                pid,
                threads,
                accepted,
                processing,
                kernel: system_info.kernel,
                memory_mb: system_info.memory_mb,
                memory: system_info.memory,
                arch: system_info.arch,
                cpus: system_info.cpus,
                physical_cpus: system_info.physical_cpus,
                total_memory: system_info.total_memory,
                used_memory: system_info.used_memory,
                enabled_full,
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
            EmbeddedStaticFile(
                AdminAsset::get(file),
                Duration::from_secs(365 * 24 * 3600),
            )
            .into()
        };
        Ok(Some(resp))
    }
}

#[cfg(test)]
mod tests {
    use super::{AdminAsset, AdminServe, EmbeddedStaticFile};
    use crate::{config::PluginConf, http_extra::HttpResponse};
    use pretty_assertions::assert_eq;
    use std::time::Duration;

    #[test]
    fn test_admin_params() {
        let params = AdminServe::try_from(
            &toml::from_str::<PluginConf>(
                r#"
    category = "admin"
    path = "/"
    authorizations = [
        "YWRtaW46MTIzMTIz",
        "cGluZ2FwOjEyMzEyMw=="
    ]
    "#,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            "Basic YWRtaW46MTIzMTIz,Basic cGluZ2FwOjEyMzEyMw==",
            params
                .authorizations
                .iter()
                .map(|item| std::string::String::from_utf8_lossy(item))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert_eq!("request", params.plugin_step.to_string());
        assert_eq!("/", params.path);

        let result = AdminServe::try_from(
            &toml::from_str::<PluginConf>(
                r#"
    category = "admin"
    path = "/"
    authorizations = [
        "123",
    ]
    "#,
            )
            .unwrap(),
        );

        assert_eq!(
            "Plugin basic_auth, base64 decode error Invalid padding",
            result.err().unwrap().to_string()
        );

        let result = AdminServe::try_from(
            &toml::from_str::<PluginConf>(
                r#"
    step = "response"
    category = "admin"
    path = "/"
    authorizations = [
        "YWRtaW46MTIzMTIz",
        "cGluZ2FwOjEyMzEyMw=="
    ]
    "#,
            )
            .unwrap(),
        );
        assert_eq!(
            "Plugin admin invalid, message: Admin serve plugin should be executed at request or proxy upstream step",
            result.err().unwrap().to_string()
        );
    }

    #[test]
    fn test_embeded_static_file() {
        let file = AdminAsset::get("index.html").unwrap();
        let resp: HttpResponse =
            EmbeddedStaticFile(Some(file), Duration::from_secs(60)).into();
        assert_eq!(true, !resp.body.is_empty());
        assert_eq!(200, resp.status.as_u16());
        assert_eq!(0, resp.max_age.unwrap_or_default());
        assert_eq!(
            r#"("content-type", "text/html")"#,
            format!("{:?}", resp.headers.unwrap_or_default()[0])
        );

        let resp: HttpResponse =
            EmbeddedStaticFile(None, Duration::from_secs(60)).into();
        assert_eq!(404, resp.status.as_u16())
    }
}
