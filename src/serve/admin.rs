use super::Serve;
use crate::config::{self, save_config, LocationConf, ServerConf, UpstreamConf};
use crate::state::State;
use crate::{cache::HttpResponse, config::PingapConf};
use async_trait::async_trait;
use http::Method;
use log::error;
use once_cell::sync::Lazy;
use pingora::proxy::Session;
use serde::{Deserialize, Serialize};

pub struct AdminServe {}

pub static ADMIN_SERVE: Lazy<&AdminServe> = Lazy::new(|| &AdminServe {});

#[derive(Serialize, Deserialize)]
struct ErrorResponse {
    message: String,
}

#[derive(Serialize, Deserialize)]
struct BasicConfParams {
    error_template: String,
    pid_file: Option<String>,
    upgrade_sock: Option<String>,
    user: Option<String>,
    group: Option<String>,
    threads: Option<usize>,
    work_stealing: Option<bool>,
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
        save_config(&config::get_config_path(), &conf).map_err(|e| {
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
                conf.error_template = basic_conf.error_template;
                conf.pid_file = basic_conf.pid_file;
                conf.upgrade_sock = basic_conf.upgrade_sock;
                conf.user = basic_conf.user;
                conf.group = basic_conf.group;
                conf.threads = basic_conf.threads;
                conf.work_stealing = basic_conf.work_stealing;
            }
        };
        save_config(&config::get_config_path(), &conf).map_err(|e| {
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
        let (method, path) = get_method_path(session);
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
                HttpResponse::try_from_json(&ErrorResponse {
                    message: err.to_string(),
                })
                .unwrap_or(HttpResponse::unknown_error())
            })
        } else {
            HttpResponse::not_found()
        };
        ctx.response_body_size = resp.send(session).await?;
        Ok(true)
    }
}
