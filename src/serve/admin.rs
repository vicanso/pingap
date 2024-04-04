use super::embedded_file::EmbeddedStaticFile;
use super::Serve;
use crate::config::PingapConf;
use crate::config::{self, get_start_time, save_config, LocationConf, ServerConf, UpstreamConf};
use crate::http_extra::HttpResponse;
use crate::state::State;
use crate::utils::get_pkg_version;
use async_trait::async_trait;
use bytesize::ByteSize;
use http::{Method, StatusCode};
use log::error;
use memory_stats::memory_stats;
use once_cell::sync::Lazy;
use pingora::proxy::Session;
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use substring::Substring;

#[derive(RustEmbed)]
#[folder = "dist/"]
struct AdminAsset;

pub struct AdminServe {}
pub static ADMIN_SERVE: Lazy<&AdminServe> = Lazy::new(|| &AdminServe {});

#[derive(Serialize, Deserialize)]
struct ErrorResponse {
    message: String,
}

#[derive(Serialize, Deserialize)]
struct BasicConfParams {
    error_template: Option<String>,
    pid_file: Option<String>,
    upgrade_sock: Option<String>,
    user: Option<String>,
    group: Option<String>,
    threads: Option<usize>,
    work_stealing: Option<bool>,
}

#[derive(Serialize, Deserialize)]
struct BasicInfo {
    start_time: u64,
    version: String,
    memory: String,
}

const CATEGORY_UPSTREAM: &str = "upstream";
const CATEGORY_LOCATION: &str = "location";
const CATEGORY_SERVER: &str = "server";

impl AdminServe {
    fn load_config(&self) -> pingora::Result<PingapConf> {
        let conf = config::load_config(&config::get_config_path(), true).map_err(|e| {
            error!("failed to load config: {e}");
            pingora::Error::new_str("Load config fail")
        })?;
        conf.validate().map_err(|e| {
            error!("failed to validate config: {e}");
            pingora::Error::new_str("Validate config fail")
        })?;
        Ok(conf)
    }
    async fn get_config(&self, category: &str) -> pingora::Result<HttpResponse> {
        let conf = self.load_config()?;
        let resp = match category {
            CATEGORY_UPSTREAM => HttpResponse::try_from_json(&conf.upstreams)?,
            CATEGORY_LOCATION => HttpResponse::try_from_json(&conf.locations)?,
            CATEGORY_SERVER => HttpResponse::try_from_json(&conf.servers)?,
            _ => HttpResponse::try_from_json(&conf)?,
        };
        Ok(resp)
    }

    async fn remove_config(&self, category: &str, name: &str) -> pingora::Result<HttpResponse> {
        let mut conf = self.load_config()?;

        match category {
            CATEGORY_UPSTREAM => {
                conf.upstreams.remove(name);
            }
            CATEGORY_LOCATION => {
                conf.locations.remove(name);
            }
            CATEGORY_SERVER => {
                conf.servers.remove(name);
            }
            _ => {}
        };
        save_config(&config::get_config_path(), &mut conf).map_err(|e| {
            error!("failed to save config: {e}");
            pingora::Error::new_str("Save config fail")
        })?;
        Ok(HttpResponse::no_content())
    }
    async fn update_config(
        &self,
        session: &mut Session,
        category: &str,
        name: &str,
    ) -> pingora::Result<HttpResponse> {
        let buf = session.read_request_body().await?.unwrap_or_default();
        let key = name.to_string();
        let mut conf = self.load_config()?;
        match category {
            CATEGORY_UPSTREAM => {
                let upstream: UpstreamConf = serde_json::from_slice(&buf).map_err(|e| {
                    error!("failed to deserialize upstream: {e}");
                    pingora::Error::new_str("Upstream config invalid")
                })?;
                conf.upstreams.insert(key, upstream);
            }
            CATEGORY_LOCATION => {
                let location: LocationConf = serde_json::from_slice(&buf).map_err(|e| {
                    error!("failed to deserialize location: {e}");
                    pingora::Error::new_str("Location config invalid")
                })?;
                conf.locations.insert(key, location);
            }
            CATEGORY_SERVER => {
                let server: ServerConf = serde_json::from_slice(&buf).map_err(|e| {
                    error!("failed to deserialize server: {e}");
                    pingora::Error::new_str("Server config invalid")
                })?;
                conf.servers.insert(key, server);
            }
            _ => {
                let basic_conf: BasicConfParams = serde_json::from_slice(&buf).map_err(|e| {
                    error!("failed to basic info: {e}");
                    pingora::Error::new_str("Basic config invalid")
                })?;
                conf.error_template = basic_conf.error_template.unwrap_or_default();
                conf.pid_file = basic_conf.pid_file;
                conf.upgrade_sock = basic_conf.upgrade_sock;
                conf.user = basic_conf.user;
                conf.group = basic_conf.group;
                conf.threads = basic_conf.threads;
                conf.work_stealing = basic_conf.work_stealing;
            }
        };
        save_config(&config::get_config_path(), &mut conf).map_err(|e| {
            error!("failed to save config: {e}");
            pingora::Error::new_str("Save config fail")
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
impl Serve for AdminServe {
    async fn handle(&self, session: &mut Session, ctx: &mut State) -> pingora::Result<bool> {
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
                .unwrap_or(HttpResponse::unknown_error())
            })
        } else if path == "/basic" {
            let mut memory = "".to_string();
            if let Some(value) = memory_stats() {
                memory = ByteSize(value.physical_mem as u64).to_string_as(true);
            }

            HttpResponse::try_from_json(&BasicInfo {
                start_time: get_start_time(),
                version: get_pkg_version().to_string(),
                memory,
            })
            .unwrap_or(HttpResponse::unknown_error())
        } else {
            let mut file = path.substring(1, path.len());
            if file.is_empty() {
                file = "index.html";
            }
            EmbeddedStaticFile(AdminAsset::get(file), 365 * 24 * 3600).into()
        };
        ctx.response_body_size = resp.send(session).await?;
        Ok(true)
    }
}
