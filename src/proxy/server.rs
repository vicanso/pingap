use super::{Location, LocationConf, Upstream, UpstreamConf};
use crate::config::Config;
use async_trait::async_trait;
use log::info;
use pingora::proxy::{http_proxy_service, HttpProxy};
use pingora::server::configuration;
use pingora::services::background::GenBackgroundService;
use pingora::services::listening::Service;
use pingora::services::Service as IService;
use pingora::{
    proxy::{ProxyHttp, Session},
    upstreams::peer::HttpPeer,
};
use serde::Deserialize;
use snafu::{ResultExt, Snafu};
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
    pub upstreams: Vec<UpstreamConf>,
    pub locations: Vec<LocationConf>,
}

#[derive(Deserialize, Debug)]
struct ServerTomlConf {
    name: String,
    addr: String,
    locations: Option<Vec<String>>,
}

impl TryFrom<Config> for Vec<ServerConf> {
    type Error = Error;
    fn try_from(conf: Config) -> Result<Self> {
        let mut upstreams = vec![];
        for item in conf.upstreams.iter() {
            let up: UpstreamConf = toml::from_str(item).context(TomlDeSnafu {
                content: item.clone(),
            })?;
            upstreams.push(up);
        }
        let mut locations = vec![];
        // TODO sort location
        for item in conf.locations.iter() {
            let lo: LocationConf = toml::from_str(item).context(TomlDeSnafu {
                content: item.clone(),
            })?;
            locations.push(lo);
        }
        let mut servers = vec![];
        for item in conf.servers.iter() {
            let se: ServerTomlConf = toml::from_str(item).context(TomlDeSnafu {
                content: item.clone(),
            })?;
            let valid_locations = se.locations.unwrap_or_default();
            let mut valid_upstreams = vec![];
            // filter location of server
            let mut filter_locations = vec![];
            for item in locations.iter() {
                if valid_locations.contains(&item.name) {
                    valid_upstreams.push(item.upstream.clone());
                    filter_locations.push(item.clone())
                }
            }
            // filter upstream of server locations
            let mut filter_upstreams = vec![];
            for item in upstreams.iter() {
                if valid_upstreams.contains(&item.name) {
                    filter_upstreams.push(item.clone())
                }
            }

            servers.push(ServerConf {
                name: se.name,
                addr: se.addr,
                upstreams: filter_upstreams,
                locations: filter_locations,
            });
        }

        Ok(servers)
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
            .map(|item| item.upstream.clone())
            .collect();
        for item in conf.upstreams.iter() {
            // ignore not in used
            if !in_used_upstreams.contains(&item.name) {
                continue;
            }
            let up = Upstream::new(item).map_err(|err| Error::Common {
                category: "upstream".to_string(),
                message: err.to_string(),
            })?;
            upstreams.push(Arc::new(up));
        }
        let mut locations = vec![];
        for item in conf.locations.iter() {
            locations.push(Location::new(item, upstreams.clone()).map_err(|err| {
                Error::Common {
                    category: "location".to_string(),
                    message: err.to_string(),
                }
            })?);
        }

        Ok(Server {
            addr: conf.addr,
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
    type CTX = ();
    fn new_ctx(&self) -> Self::CTX {
        info!("new ctx");
    }
    async fn upstream_peer(
        &self,
        session: &mut Session,
        _ctx: &mut (),
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
        let peer = lo
            .upstream
            .new_http_peer(header)
            .ok_or(pingora::Error::new_str("Upstream not found"))?;
        Ok(Box::new(peer))
    }
}
