use super::logger::Parser;
use super::state::State;
use super::{Location, Upstream};
use crate::config::{LocationConf, PingapConf, UpstreamConf};
use async_trait::async_trait;
use log::info;
use pingora::http::ResponseHeader;
use pingora::proxy::{http_proxy_service, HttpProxy};
use pingora::server::configuration;
use pingora::services::background::GenBackgroundService;
use pingora::services::listening::Service;
use pingora::services::Service as IService;
use pingora::{
    proxy::{ProxyHttp, Session},
    upstreams::peer::HttpPeer,
};
use snafu::Snafu;
use std::sync::Arc;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Toml de error {}, {content}", source.to_string()))]
    TomlDe {
        source: toml::de::Error,
        content: String,
    },
    #[snafu(display("Error {category} {message}"))]
    Common { category: String, message: String },
}
type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Default)]
pub struct ServerConf {
    pub name: String,
    pub addr: String,
    pub access_log: Option<String>,
    pub upstreams: Vec<(String, UpstreamConf)>,
    pub locations: Vec<(String, LocationConf)>,
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
        locations.sort_by_key(|b| std::cmp::Reverse(get_weight(&b.1)));
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

            servers.push(ServerConf {
                name,
                addr: item.addr,
                access_log: item.access_log,
                upstreams: filter_upstreams,
                locations: filter_locations,
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
    addr: String,
    locations: Vec<Location>,
    log_parser: Option<Parser>,
}

pub struct ServerServices {
    pub lb: Service<HttpProxy<Server>>,
    pub bg_services: Vec<Box<dyn IService>>,
}

pub fn get_weight(conf: &LocationConf) -> u8 {
    // path starts with
    // = 8
    // prefix(default) 4
    // ~ 2
    // host exist 1
    let mut weighted: u8 = 0;
    if let Some(path) = &conf.path {
        if path.starts_with('=') {
            weighted += 8;
        } else if path.starts_with('~') {
            weighted += 2;
        } else {
            weighted += 4;
        }
    };
    if conf.host.is_some() {
        weighted += 1;
    }
    weighted
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
            addr: conf.addr,
            log_parser: p,
            locations,
        })
    }
    pub fn run(self, conf: &Arc<configuration::ServerConf>) -> ServerServices {
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

        let mut lb = http_proxy_service(conf, self);
        lb.add_tcp(&addr);
        ServerServices { lb, bg_services }
    }
}

#[async_trait]
impl ProxyHttp for Server {
    type CTX = State;
    fn new_ctx(&self) -> Self::CTX {
        State::default()
    }
    async fn upstream_peer(
        &self,
        session: &mut Session,
        _ctx: &mut State,
    ) -> pingora::Result<Box<HttpPeer>> {
        let header = session.req_header_mut();
        let path = header.uri.path();
        let host = header.uri.host().unwrap_or_default();

        let lo = self
            .locations
            .iter()
            .find(|item| item.matched(path, host))
            .ok_or(pingora::Error::new_str("Location not found"))?;
        if let Some(mut new_path) = lo.rewrite(path) {
            if let Some(query) = header.uri.query() {
                new_path = format!("{new_path}?{query}");
            }
            // TODO parse error
            if let Ok(uri) = new_path.parse::<http::Uri>() {
                header.set_uri(uri);
            }
        }
        if let Some(arr) = lo.get_proxy_headers() {
            for (k, v) in arr {
                // v validate for HeaderValue, so always no error
                let _ = header.insert_header(k, v.to_vec());
            }
        }
        let peer = lo
            .upstream
            .new_http_peer(header)
            .ok_or(pingora::Error::new_str("Upstream not found"))?;
        Ok(Box::new(peer))
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
    }

    async fn logging(&self, session: &mut Session, _e: Option<&pingora::Error>, ctx: &mut Self::CTX)
    where
        Self::CTX: Send + Sync,
    {
        if let Some(p) = &self.log_parser {
            info!("{}", p.format(session, ctx));
        }
    }
}
