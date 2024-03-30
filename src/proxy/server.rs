use super::logger::Parser;
use super::{Location, Upstream};
use crate::cache;
use crate::config::{LocationConf, PingapConf, UpstreamConf};
use crate::serve::Serve;
use crate::serve::ADMIN_SERVE;
use crate::state::State;
use crate::utils;
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use bytes::Bytes;
use http::StatusCode;
use log::{error, info};
use once_cell::sync::Lazy;
use pingora::http::ResponseHeader;
use pingora::listeners::TlsSettings;
use pingora::protocols::http::error_resp;
use pingora::protocols::Digest;
use pingora::proxy::{http_proxy_service, HttpProxy};
use pingora::server::configuration;
use pingora::services::background::GenBackgroundService;
use pingora::services::listening::Service;
use pingora::services::Service as IService;
use pingora::upstreams::peer::Peer;
use pingora::{
    proxy::{ProxyHttp, Session},
    upstreams::peer::HttpPeer,
};
use serde::Serialize;
use snafu::{ResultExt, Snafu};
use std::collections::HashMap;
use std::fs;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::Arc;
use substring::Substring;

static ERROR_TEMPLATE: &str = include_str!("../../error.html");

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Toml de error {}, {content}", source.to_string()))]
    TomlDe {
        source: toml::de::Error,
        content: String,
    },
    #[snafu(display("Error {category} {message}"))]
    Common { category: String, message: String },
    #[snafu(display("Io {source}"))]
    Io { source: std::io::Error },
}
type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Default)]
pub struct ServerConf {
    pub name: String,
    pub addr: String,
    pub admin: bool,
    pub stats_path: Option<String>,
    pub admin_path: Option<String>,
    pub access_log: Option<String>,
    pub upstreams: Vec<(String, UpstreamConf)>,
    pub locations: Vec<(String, LocationConf)>,
    pub tls_cert: Option<Vec<u8>>,
    pub tls_key: Option<Vec<u8>>,
    pub error_template: String,
}

impl From<PingapConf> for Vec<ServerConf> {
    fn from(conf: PingapConf) -> Self {
        let mut upstreams = vec![];
        for (name, item) in conf.upstreams {
            upstreams.push((name, item));
        }
        let mut locations = vec![];
        for (name, item) in conf.locations {
            locations.push((name, item));
        }
        // sort location by weight
        locations.sort_by_key(|b| std::cmp::Reverse(b.1.get_weight()));
        let mut servers = vec![];
        for (name, item) in conf.servers {
            let valid_locations = item.locations.unwrap_or_default();
            let mut valid_upstreams = vec![];
            // filter location of server
            let mut filter_locations = vec![];
            for item in locations.iter() {
                if valid_locations.contains(&item.0) {
                    valid_upstreams.push(item.1.upstream.clone());
                    filter_locations.push(item.clone())
                }
            }
            // filter upstream of server locations
            let mut filter_upstreams = vec![];
            for item in upstreams.iter() {
                if valid_upstreams.contains(&item.0) {
                    filter_upstreams.push(item.clone())
                }
            }
            let mut tls_cert = None;
            let mut tls_key = None;
            // load config validate base64
            // so ignore error
            if let Some(value) = &item.tls_cert {
                let buf = STANDARD.decode(value).unwrap_or_default();
                tls_cert = Some(buf);
            }
            if let Some(value) = &item.tls_key {
                let buf = STANDARD.decode(value).unwrap_or_default();
                tls_key = Some(buf);
            }

            let error_template = if conf.error_template.is_empty() {
                ERROR_TEMPLATE.to_string()
            } else {
                conf.error_template.clone()
            };

            servers.push(ServerConf {
                name,
                tls_cert,
                tls_key,
                admin: false,
                stats_path: item.stats_path,
                admin_path: item.admin_path,
                addr: item.addr,
                access_log: item.access_log,
                upstreams: filter_upstreams,
                locations: filter_locations,
                error_template,
            });
        }

        servers
    }
}

impl ServerConf {
    pub fn validate(&self) -> Result<()> {
        // TODO validate
        Ok(())
    }
}

pub struct Server {
    admin: bool,
    addr: String,
    accepted: AtomicU64,
    processing: AtomicI32,
    locations: Vec<Location>,
    log_parser: Option<Parser>,
    error_template: String,
    stats_path: Option<String>,
    admin_path: Option<String>,
    tls_cert: Option<Vec<u8>>,
    tls_key: Option<Vec<u8>>,
}

static HOST_NAME: Lazy<String> = Lazy::new(|| {
    hostname::get()
        .unwrap_or_default()
        .to_str()
        .unwrap_or_default()
        .to_string()
});

#[derive(Serialize)]
struct ServerStats {
    processing: i32,
    accepted: u64,
    hostname: String,
}

pub struct ServerServices {
    pub lb: Service<HttpProxy<Server>>,
    pub bg_services: Vec<Box<dyn IService>>,
}

impl Server {
    pub fn new(conf: ServerConf) -> Result<Self> {
        let mut upstreams = vec![];
        let in_used_upstreams: Vec<_> = conf
            .locations
            .iter()
            .map(|item| item.1.upstream.clone())
            .collect();
        for item in conf.upstreams.iter() {
            // ignore not in used
            if !in_used_upstreams.contains(&item.0) {
                continue;
            }
            let up = Upstream::new(&item.0, &item.1).map_err(|err| Error::Common {
                category: "upstream".to_string(),
                message: err.to_string(),
            })?;
            upstreams.push(Arc::new(up));
        }
        let mut locations = vec![];
        for item in conf.locations.iter() {
            locations.push(
                Location::new(&item.0, &item.1, upstreams.clone()).map_err(|err| {
                    Error::Common {
                        category: "location".to_string(),
                        message: err.to_string(),
                    }
                })?,
            );
        }
        let mut p = None;
        if let Some(access_log) = conf.access_log {
            p = Some(Parser::from(access_log.as_str()));
        }

        Ok(Server {
            admin: conf.admin,
            accepted: AtomicU64::new(0),
            processing: AtomicI32::new(0),
            stats_path: conf.stats_path,
            admin_path: conf.admin_path,
            addr: conf.addr,
            log_parser: p,
            locations,
            error_template: conf.error_template,
            tls_key: conf.tls_key,
            tls_cert: conf.tls_cert,
        })
    }
    pub fn run(self, conf: &Arc<configuration::ServerConf>) -> Result<ServerServices> {
        let addr = self.addr.clone();
        let mut bg_services: Vec<Box<dyn IService>> = vec![];
        for item in self.locations.iter() {
            let name = format!("BG {}", item.upstream.name);
            if let Some(up) = item.upstream.get_round_robind() {
                bg_services.push(Box::new(GenBackgroundService::new(name.clone(), up)));
            }
            if let Some(up) = item.upstream.get_consistent() {
                bg_services.push(Box::new(GenBackgroundService::new(name, up)));
            }
        }
        // tls
        let tls_cert = self.tls_cert.clone();
        let tls_key = self.tls_key.clone();

        let mut lb = http_proxy_service(conf, self);
        // add tls
        if tls_cert.is_some() {
            let dir = tempfile::tempdir().context(IoSnafu)?;
            let cert_path = dir.path().join("tls-cert");
            let key_path = dir.path().join("tls-key");
            fs::write(cert_path.clone(), tls_cert.unwrap_or_default()).context(IoSnafu)?;
            fs::write(key_path.clone(), tls_key.unwrap_or_default()).context(IoSnafu)?;
            let mut tls_settings = TlsSettings::intermediate(
                cert_path.to_str().ok_or(Error::Common {
                    category: "tmpdir".to_string(),
                    message: cert_path.to_string_lossy().to_string(),
                })?,
                key_path.to_str().ok_or(Error::Common {
                    category: "tmpdir".to_string(),
                    message: key_path.to_string_lossy().to_string(),
                })?,
            )
            .map_err(|err| Error::Common {
                category: "tls".to_string(),
                message: err.to_string(),
            })?;
            tls_settings.enable_h2();
            lb.add_tls_with_settings(&addr, None, tls_settings);
        } else {
            lb.add_tcp(&addr);
        }
        Ok(ServerServices { lb, bg_services })
    }
    fn get_stats_response(&self) -> cache::HttpResponse {
        let buf = serde_json::to_vec(&ServerStats {
            accepted: self.accepted.load(Ordering::Relaxed),
            processing: self.processing.load(Ordering::Relaxed),
            hostname: HOST_NAME.to_string(),
        })
        .unwrap_or_default();

        cache::HttpResponse {
            status: StatusCode::OK,
            body: Bytes::from(buf),
            headers: Some(vec![cache::HTTP_HEADER_CONTENT_JSON.clone()]),
            ..Default::default()
        }
    }
}

static LOCATION_NOT_FOUND: &str = "Location not found";

#[async_trait]
impl ProxyHttp for Server {
    type CTX = State;
    fn new_ctx(&self) -> Self::CTX {
        State::default()
    }
    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        ctx.processing = self.processing.fetch_add(1, Ordering::Relaxed);
        self.accepted.fetch_add(1, Ordering::Relaxed);
        if session.is_http2() {
            ctx.http_version = 2;
        }

        let header = session.req_header_mut();
        let path = header.uri.path();
        let host = header.uri.host().unwrap_or_default();

        if let Some(stats_path) = &self.stats_path {
            if stats_path == path {
                let size = self
                    .get_stats_response()
                    .send(session)
                    .await
                    .unwrap_or_else(|e| {
                        error!("failed to send error response to downstream: {e}");
                        0
                    });
                ctx.status = Some(StatusCode::OK);
                ctx.response_body_size = size;
                return Ok(true);
            }
        }

        // admin server
        if self.admin {
            let result = ADMIN_SERVE.handle(session, ctx).await?;
            return Ok(result);
        }

        // admin path
        if let Some(admin_path) = &self.admin_path {
            if path.starts_with(admin_path) {
                let mut new_path = path.substring(admin_path.len(), path.len()).to_string();
                if let Some(query) = header.uri.query() {
                    new_path = format!("{new_path}?{query}");
                }
                // TODO parse error
                if let Ok(uri) = new_path.parse::<http::Uri>() {
                    header.set_uri(uri);
                }
                let result = ADMIN_SERVE.handle(session, ctx).await?;
                return Ok(result);
            }
        }

        let (location_index, _) = self
            .locations
            .iter()
            .enumerate()
            .find(|(_, item)| item.matched(host, path))
            .ok_or_else(|| pingora::Error::new_str(LOCATION_NOT_FOUND))?;
        ctx.location_index = Some(location_index);
        // TODO get response from cache
        // check location support cache

        Ok(false)
    }
    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut State,
    ) -> pingora::Result<Box<HttpPeer>> {
        let header = session.req_header_mut();
        let path = header.uri.path();
        let location_index = ctx
            .location_index
            .ok_or_else(|| pingora::Error::new_str(LOCATION_NOT_FOUND))?;
        let lo = self
            .locations
            .get(location_index)
            .ok_or_else(|| pingora::Error::new_str(LOCATION_NOT_FOUND))?;

        if let Some(mut new_path) = lo.rewrite(path) {
            if let Some(query) = header.uri.query() {
                new_path = format!("{new_path}?{query}");
            }
            // TODO parse error
            let _ = new_path.parse::<http::Uri>().map(|uri| header.set_uri(uri));
        }
        lo.insert_proxy_headers(header);
        let peer = lo
            .upstream
            .new_http_peer(ctx, header)
            .ok_or(pingora::Error::new_str("Upstream not found"))?;
        Ok(Box::new(peer))
    }
    async fn connected_to_upstream(
        &self,
        _session: &mut Session,
        reused: bool,
        peer: &HttpPeer,
        _fd: std::os::unix::io::RawFd,
        _digest: Option<&Digest>,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        ctx.reused = reused;
        ctx.upstream_address = peer.address().to_string();
        Ok(())
    }
    fn upstream_response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) {
        if ctx.status.is_none() {
            ctx.status = Some(upstream_response.status);
        }
        if let Some(index) = ctx.location_index {
            if let Some(lo) = self.locations.get(index) {
                lo.insert_headers(upstream_response)
            }
        }
        if let Some(p) = &self.log_parser {
            let mut m = HashMap::new();
            for key in p.response_headers.iter() {
                upstream_response.headers.get(key).map(|value| {
                    m.insert(
                        key.to_string(),
                        value.to_str().unwrap_or_default().to_string(),
                    )
                });
            }
            ctx.response_headers = Some(m);
        }
    }
    fn upstream_response_body_filter(
        &self,
        _session: &mut Session,
        body: &Option<bytes::Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) {
        if let Some(body) = body {
            ctx.response_body_size += body.len();
        }
    }

    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &pingora::Error,
        ctx: &mut Self::CTX,
    ) -> u16
    where
        Self::CTX: Send + Sync,
    {
        let server_session = session.as_mut();

        let code = match e.etype() {
            pingora::HTTPStatus(code) => *code,
            _ => match e.esource() {
                pingora::ErrorSource::Upstream => 502,
                pingora::ErrorSource::Downstream => match e.etype() {
                    pingora::ErrorType::WriteError | pingora::ErrorType::ReadError => 500,
                    // client close the connection
                    pingora::ErrorType::ConnectionClosed => 499,
                    _ => 400,
                },
                pingora::ErrorSource::Internal | pingora::ErrorSource::Unset => 500,
            },
        };
        // TODO better error handler
        let mut resp = match code {
            502 => error_resp::HTTP_502_RESPONSE.clone(),
            400 => error_resp::HTTP_400_RESPONSE.clone(),
            _ => error_resp::gen_error_response(code),
        };

        let content = self
            .error_template
            .replace("{{version}}", utils::get_pkg_version())
            .replace("{{content}}", &e.to_string());
        let buf = Bytes::from(content);
        ctx.response_body_size = buf.len();
        let _ = resp.insert_header(http::header::CONTENT_TYPE, "text/html; charset=utf-8");
        let _ = resp.insert_header(http::header::CONTENT_LENGTH, buf.len().to_string());

        // TODO: we shouldn't be closing downstream connections on internally generated errors
        // and possibly other upstream connect() errors (connection refused, timeout, etc)
        //
        // This change is only here because we DO NOT re-use downstream connections
        // today on these errors and we should signal to the client that pingora is dropping it
        // rather than a misleading the client with 'keep-alive'
        server_session.set_keepalive(None);

        server_session
            .write_response_header(Box::new(resp))
            .await
            .unwrap_or_else(|e| {
                error!("failed to send error response to downstream: {e}");
            });

        let _ = server_session.write_response_body(buf).await;
        if ctx.status.is_none() {
            if let Ok(status) = StatusCode::from_u16(code) {
                ctx.status = Some(status);
            }
        }
        code
    }
    async fn logging(&self, session: &mut Session, _e: Option<&pingora::Error>, ctx: &mut Self::CTX)
    where
        Self::CTX: Send + Sync,
    {
        self.processing.fetch_add(-1, Ordering::Relaxed);

        if let Some(p) = &self.log_parser {
            ctx.response_size = session.body_bytes_sent();
            info!("{}", p.format(session.req_header(), ctx));
        }
    }
}
