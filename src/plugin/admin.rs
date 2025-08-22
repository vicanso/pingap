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

use super::{get_hash_key, get_int_conf, get_str_conf, get_str_slice_conf};
use crate::process::{get_start_time, restart_now};
use async_trait::async_trait;
use bytes::Bytes;
use bytes::{BufMut, BytesMut};
use ctor::ctor;
use flate2::write::GzEncoder;
use flate2::Compression;
use hex::encode;
use hex::ToHex;
use http::Method;
use http::{header, HeaderValue, StatusCode};
use humantime::parse_duration;
use pingap_certificate::get_certificate_info_list;
use pingap_config::{
    self, get_current_config, save_config, BasicConf, CertificateConf,
    LoadConfigOptions, LocationConf, PluginCategory, PluginConf, ServerConf,
    StorageConf, UpstreamConf, CATEGORY_CERTIFICATE, CATEGORY_STORAGE,
};
use pingap_config::{
    PingapConf, CATEGORY_LOCATION, CATEGORY_PLUGIN, CATEGORY_SERVER,
    CATEGORY_UPSTREAM,
};
use pingap_core::{
    Ctx, HttpResponse, Plugin, PluginStep, RequestPluginResult, TtlLruLimit,
};
use pingap_performance::get_process_system_info;
use pingap_performance::get_processing_accepted;
use pingap_plugin::{get_plugin_factory, Error};
use pingap_upstream::{get_upstream_healthy_status, UpstreamHealthyStatus};
use pingap_util::base64_decode;
use pingora::http::RequestHeader;
use pingora::proxy::Session;
use regex::Regex;
use rust_embed::EmbeddedFile;
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;
use substring::Substring;
use tracing::{debug, error};
use urlencoding::decode;

type Result<T> = std::result::Result<T, Error>;

#[derive(RustEmbed)]
#[folder = "dist/"]
struct AdminAsset;

pub struct EmbeddedStaticFile(pub Option<EmbeddedFile>, pub Duration);

impl From<EmbeddedStaticFile> for HttpResponse {
    fn from(value: EmbeddedStaticFile) -> Self {
        let Some(file) = value.0 else {
            return HttpResponse::not_found("Not Found");
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
    pub authorizations: Vec<(String, String)>,
    pub plugin_step: PluginStep,
    max_age: Duration,
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
    features: Vec<String>,
    fd_count: usize,
    tcp_count: usize,
    tcp6_count: usize,
    supported_plugins: Vec<String>,
    upstream_healthy_status: HashMap<String, UpstreamHealthyStatus>,
}

#[derive(Serialize, Deserialize)]
struct TomlJson {
    pub full: String,
    pub original: String,
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
            let data =
                base64_decode(item).map_err(|e| Error::Base64Decode {
                    category: PluginCategory::BasicAuth.to_string(),
                    source: e,
                })?;
            if let Some((user, pass)) =
                std::string::String::from_utf8_lossy(&data).split_once(':')
            {
                authorizations.push((user.to_string(), pass.to_string()));
            }
        }
        let mut ip_fail_limit = get_int_conf(value, "ip_fail_limit");
        if ip_fail_limit <= 0 {
            ip_fail_limit = 10;
        }
        let max_age_value = &get_str_conf(value, "max_age");
        let mut max_age = Duration::from_secs(2 * 24 * 3600);
        if !max_age_value.is_empty() {
            max_age = parse_duration(max_age_value).map_err(|e| {
                Error::ParseDuration {
                    category: "admin".to_string(),
                    source: e,
                }
            })?;
        }
        let mut path = get_str_conf(value, "path");
        if path.len() > 1 && path.ends_with("/") {
            path = path.substring(0, path.len() - 1).to_string();
        }

        let params = AdminServe {
            hash_value,
            max_age,
            plugin_step: PluginStep::Request,
            path,
            ip_fail_limit: TtlLruLimit::new_compact(
                512,
                Duration::from_secs(5 * 60),
                ip_fail_limit as usize,
            ),
            authorizations,
        };

        Ok(params)
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct AesParams {
    category: String,
    key: String,
    data: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct AesResp {
    value: String,
}

async fn get_request_body(session: &mut Session) -> pingora::Result<BytesMut> {
    let mut buf = BytesMut::with_capacity(4096);
    while let Some(value) = session.read_request_body().await? {
        buf.put(value.as_ref());
    }
    Ok(buf)
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
        let path = req_header.uri.path();
        if path.len() <= 1
            || Regex::new(r#".(js|css|png)$"#).unwrap().is_match(path)
        {
            return true;
        }
        let value =
            pingap_core::get_req_header_value(req_header, "Authorization")
                .unwrap_or_default();
        if value.is_empty() {
            return false;
        }
        let Some((token, ts)) = value.split_once(':') else {
            return false;
        };
        let offset = pingap_core::now_sec() as i64
            - ts.parse::<i64>().unwrap_or_default();
        if offset.abs() > self.max_age.as_secs() as i64 {
            return false;
        }

        for (user, pass) in self.authorizations.iter() {
            let mut hasher = Sha256::new();
            hasher.update(format!("{user}:{pass}:{ts}").as_bytes());
            let hash256 = hasher.finalize();
            if hash256.encode_hex::<String>() == token {
                return true;
            }
        }
        false
    }
    async fn load_config(
        &self,
        replace_include: bool,
    ) -> pingora::Result<PingapConf> {
        let conf = pingap_config::load_config(LoadConfigOptions {
            replace_include,
            admin: true,
        })
        .await
        .map_err(|e| {
            error!("failed to load config: {e}");
            pingap_core::new_internal_error(400, e.to_string())
        })?;
        Ok(conf)
    }
    async fn get_config(
        &self,
        category: &str,
    ) -> pingora::Result<HttpResponse> {
        let conf = self.load_config(false).await?;
        if category == "toml" {
            let full_conf = self.load_config(true).await?;
            let mut full_toml =
                toml::to_string_pretty(&full_conf).map_err(|e| {
                    pingap_core::new_internal_error(400, e.to_string())
                })?;
            if let Ok(value) = pingap_util::toml_omit_empty_value(&full_toml) {
                full_toml = value;
            };
            let mut original_toml =
                toml::to_string_pretty(&conf).map_err(|e| {
                    pingap_core::new_internal_error(400, e.to_string())
                })?;
            if let Ok(value) =
                pingap_util::toml_omit_empty_value(&original_toml)
            {
                original_toml = value;
            };
            return HttpResponse::try_from_json(&TomlJson {
                full: full_toml,
                original: original_toml,
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
        let mut conf = self.load_config(false).await?;
        conf.remove(category, name).map_err(|e| {
            error!(error = e.to_string(), "validate config fail");
            pingap_core::new_internal_error(400, e.to_string())
        })?;
        save_config(&conf, category, Some(name))
            .await
            .map_err(|e| {
                error!(error = e.to_string(), "save config fail");
                pingap_core::new_internal_error(400, e.to_string())
            })?;
        Ok(HttpResponse::no_content())
    }
    async fn update_config(
        &self,
        session: &mut Session,
        category: &str,
        name: &str,
    ) -> pingora::Result<HttpResponse> {
        if name.is_empty() {
            return Err(pingap_core::new_internal_error(
                400,
                "name is empty".to_string(),
            ));
        }
        let buf = get_request_body(session).await?;
        let key = name.to_string();
        let mut conf = self.load_config(false).await?;
        match category {
            CATEGORY_UPSTREAM => {
                let upstream: UpstreamConf = serde_json::from_slice(&buf)
                    .map_err(|e| {
                        error!(
                            error = e.to_string(),
                            "descrialize upstream fail"
                        );
                        pingap_core::new_internal_error(400, e.to_string())
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
                        pingap_core::new_internal_error(400, e.to_string())
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
                        pingap_core::new_internal_error(400, e.to_string())
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
                        pingap_core::new_internal_error(400, e.to_string())
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
                        pingap_core::new_internal_error(400, e.to_string())
                    })?;
                conf.certificates.insert(key, certificate);
            },
            CATEGORY_STORAGE => {
                let storage: StorageConf = serde_json::from_slice(&buf)
                    .map_err(|e| {
                        error!(
                            error = e.to_string(),
                            "descrialize storage fail"
                        );
                        pingap_core::new_internal_error(400, e.to_string())
                    })?;
                conf.storages.insert(key, storage);
            },
            _ => {
                let basic_conf: BasicConf = serde_json::from_slice(&buf)
                    .map_err(|e| {
                        error!(error = e.to_string(), "descrialize basic fail");
                        pingap_core::new_internal_error(400, e.to_string())
                    })?;
                conf.basic = basic_conf;
            },
        };
        save_config(&conf, category, Some(name))
            .await
            .map_err(|e| {
                error!(error = e.to_string(), "save config fail");
                pingap_core::new_internal_error(400, e.to_string())
            })?;
        Ok(HttpResponse::no_content())
    }
    async fn import_config(
        &self,
        session: &mut Session,
    ) -> pingora::Result<HttpResponse> {
        let buf = get_request_body(session).await?;
        let conf = PingapConf::new(&buf, false).map_err(|e| {
            error!(error = e.to_string(), "import config fail");
            pingap_core::new_internal_error(400, e.to_string())
        })?;
        if let Some(storage) = pingap_config::get_config_storage() {
            pingap_config::sync_config(&conf, storage)
                .await
                .map_err(|e| {
                    error!(error = e.to_string(), "import config fail");
                    pingap_core::new_internal_error(400, e.to_string())
                })?;
        }
        Ok(HttpResponse::no_content())
    }
}

fn get_method_path(session: &Session) -> (Method, String) {
    let req_header = session.req_header();
    let method = req_header.method.clone();
    let path = req_header.uri.path();
    (method, path.to_string())
}

async fn handle_request_admin(
    plugin: &AdminServe,
    session: &mut Session,
    _ctx: &mut Ctx,
) -> pingora::Result<Option<HttpResponse>> {
    let ip = pingap_core::get_client_ip(session);
    if !plugin.ip_fail_limit.check_and_inc(&ip) {
        return Ok(Some(HttpResponse {
            status: StatusCode::FORBIDDEN,
            body: Bytes::from_static(b"Forbidden, too many failures"),
            ..Default::default()
        }));
    }

    let header = session.req_header_mut();
    let path = header.uri.path();
    let mut new_path =
        path.substring(plugin.path.len(), path.len()).to_string();
    if plugin.path.len() > 1 && new_path.is_empty() {
        new_path = format!("{path}/");
        if let Some(query) = header.uri.query() {
            new_path = format!("{new_path}?{query}");
        }
        let resp = HttpResponse::redirect(&new_path)?;
        return Ok(Some(resp));
    }
    if let Some(query) = header.uri.query() {
        new_path = format!("{new_path}?{query}");
    }
    // ignore parse error
    if let Ok(uri) = new_path.parse::<http::Uri>() {
        header.set_uri(uri);
    }
    if !plugin.auth_validate(header) {
        return Ok(Some(HttpResponse {
            status: StatusCode::UNAUTHORIZED,
            ..Default::default()
        }));
    }

    let (method, mut path) = get_method_path(session);
    let api_prefix = "/api";
    if path.starts_with(api_prefix) {
        path = path.substring(api_prefix.len(), path.len()).to_string();
    }
    let params: Vec<String> = path
        .split('/')
        .map(|item| decode(item).unwrap_or_default().to_string())
        .collect();
    let mut category = "";
    if params.len() >= 3 {
        category = &params[2];
    }
    let resp = if path.starts_with("/configs") {
        match method {
            Method::POST => {
                if category == "import" {
                    plugin.import_config(session).await
                } else if params.len() < 4 {
                    Err(pingora::Error::new_str("Url is invalid(no name)"))
                } else {
                    plugin.update_config(session, category, &params[3]).await
                }
            },
            Method::DELETE => {
                if params.len() < 4 {
                    Err(pingora::Error::new_str("Url is invalid(no name)"))
                } else {
                    plugin.remove_config(category, &params[3]).await
                }
            },
            _ => plugin.get_config(category).await,
        }
        .unwrap_or_else(|err| {
            HttpResponse::try_from_json_status(
                &ErrorResponse {
                    message: err.to_string(),
                },
                StatusCode::INTERNAL_SERVER_ERROR,
            )
            .unwrap_or(HttpResponse::unknown_error("Json serde fail"))
        })
    } else if path == "/basic" {
        let current_config = get_current_config();
        let info = get_process_system_info();

        let (processing, accepted) = get_processing_accepted();

        let mut basic_info = BasicInfo {
            start_time: get_start_time(),
            version: pingap_util::get_pkg_version().to_string(),
            rustc_version: pingap_util::get_rustc_version(),
            config_hash: pingap_config::get_config_hash(),
            user: current_config.basic.user.clone().unwrap_or_default(),
            group: current_config.basic.group.clone().unwrap_or_default(),
            pid: info.pid.to_string(),
            threads: info.threads,
            accepted,
            processing,
            kernel: info.kernel,
            memory_mb: info.memory_mb,
            memory: info.memory,
            arch: info.arch,
            cpus: info.cpus,
            physical_cpus: info.physical_cpus,
            total_memory: info.total_memory,
            used_memory: info.used_memory,
            features: vec![],
            fd_count: info.fd_count,
            tcp_count: info.tcp_count,
            tcp6_count: info.tcp6_count,
            supported_plugins: get_plugin_factory().supported_plugins(),
            upstream_healthy_status: get_upstream_healthy_status(),
        };
        basic_info.features.push("default".to_string());

        cfg_if::cfg_if! {
            if #[cfg(feature = "tracing")] {
                basic_info.features.push("tracing".to_string());
            }
        }
        cfg_if::cfg_if! {
            if #[cfg(feature = "full")] {
                basic_info.features.push("full".to_string());
            }
        }
        cfg_if::cfg_if! {
            if #[cfg(feature = "pyro")] {
                basic_info.features.push("pyroscope".to_string());
            }
        }

        HttpResponse::try_from_json(&basic_info)
            .unwrap_or(HttpResponse::unknown_error("Json serde fail"))
    } else if path == "/restart" && method == Method::POST {
        if let Err(e) = restart_now().await {
            error!("Restart fail: {e}");
            HttpResponse::bad_request(e.to_string())
        } else {
            HttpResponse::no_content()
        }
    } else if path == "/aes" {
        let buf = get_request_body(session).await?;
        let params: AesParams = serde_json::from_slice(buf.as_ref())
            .map_err(|e| pingap_core::new_internal_error(400, e.to_string()))?;
        let value = if params.category == "encrypt" {
            pingap_util::aes_encrypt(&params.key, &params.data)
        } else {
            pingap_util::aes_decrypt(&params.key, &params.data)
        }
        .map_err(|e| pingap_core::new_internal_error(400, e.to_string()))?;
        HttpResponse::try_from_json(&AesResp { value })
            .unwrap_or(HttpResponse::unknown_error("Json serde fail"))
    } else if path == "/certificates" {
        let mut infos = HashMap::new();
        for (name, info) in get_certificate_info_list() {
            infos.insert(name, info);
        }
        HttpResponse::try_from_json(&infos)
            .unwrap_or(HttpResponse::unknown_error("Json serde fail"))
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

#[async_trait]
impl Plugin for AdminServe {
    #[inline]
    fn hash_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        _ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        if self.plugin_step != step {
            return Ok(RequestPluginResult::Skipped);
        }
        if !session.req_header().uri.path().starts_with(&self.path) {
            return Ok(RequestPluginResult::Skipped);
        }
        let resp = handle_request_admin(self, session, _ctx).await?;
        if let Some(resp) = resp {
            return Ok(RequestPluginResult::Respond(resp));
        }
        Ok(RequestPluginResult::Continue)
    }
}

#[ctor]
fn init() {
    get_plugin_factory()
        .register("admin", |params| Ok(Arc::new(AdminServe::new(params)?)));
}

#[cfg(test)]
mod tests {
    use super::{AdminAsset, AdminServe, EmbeddedStaticFile};
    use pingap_config::PluginConf;
    use pingap_core::HttpResponse;
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
            "admin:123123,pingap:123123",
            params
                .authorizations
                .iter()
                .map(|item| format!("{}:{}", item.0, item.1))
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
    }

    #[test]
    fn test_embedded_static_file() {
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
