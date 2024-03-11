use std::sync::Arc;

use super::Location;
use async_trait::async_trait;
use log::info;
use pingora::lb::selection::{Consistent, RoundRobin};
use pingora::lb::LoadBalancer;
use pingora::proxy::{http_proxy_service, HttpProxy};
use pingora::server::configuration;
use pingora::services::background::GenBackgroundService;
use pingora::services::listening::Service;
use pingora::Result;
use pingora::{
    proxy::{ProxyHttp, Session},
    upstreams::peer::HttpPeer,
};

#[derive(Debug, Default)]
pub struct ServerConf {
    pub addr: String,
}

pub struct Server {
    addr: String,
    locations: Vec<Location>,
}

pub struct ServerServices {
    pub lb: Service<HttpProxy<Server>>,
    pub round_robin_services: Vec<GenBackgroundService<LoadBalancer<RoundRobin>>>,
    pub consistent_services: Vec<GenBackgroundService<LoadBalancer<Consistent>>>,
}

impl Server {
    pub fn new(conf: ServerConf, locations: Vec<Location>) -> Self {
        Server {
            addr: conf.addr.clone(),
            locations,
        }
    }
    pub fn run(self, conf: &Arc<configuration::ServerConf>) -> ServerServices {
        let addr = self.addr.clone();
        let mut round_robin_services = vec![];
        let mut consistent_services = vec![];
        for item in self.locations.iter() {
            let name = format!("BG {}", item.upstream.name);
            if let Some(up) = item.upstream.get_round_robind() {
                round_robin_services.push(GenBackgroundService::new(name.clone(), up));
            }
            if let Some(up) = item.upstream.get_consistent() {
                consistent_services.push(GenBackgroundService::new(name, up));
            }
        }
        let mut lb = http_proxy_service(conf, self);
        lb.add_tcp(&addr);
        ServerServices {
            lb,
            round_robin_services,
            consistent_services,
        }
    }
}

#[async_trait]
impl ProxyHttp for Server {
    type CTX = ();
    fn new_ctx(&self) -> Self::CTX {
        info!("new ctx");
    }
    async fn upstream_peer(&self, session: &mut Session, _ctx: &mut ()) -> Result<Box<HttpPeer>> {
        let uri = &session.req_header().uri;

        let lo = self
            .locations
            .iter()
            .find(|item| item.matched(uri.path(), uri.host().unwrap_or_default()))
            .ok_or(crate::error::Error::Invalid {
                category: "server".to_string(),
                message: "Location not found".to_string(),
            })?;
        // TODO add key generate
        let peer = lo
            .upstream
            .new_http_peer(b"")
            .ok_or(crate::error::Error::Invalid {
                category: "server".to_string(),
                message: "Location not found".to_string(),
            })?;
        Ok(Box::new(peer))
    }
}
