// use async_trait::async_trait;
// use log::info;
// use pingora::prelude::*;
use std::sync::Arc;

use pingora::apps::HttpServerApp;
use pingora::proxy::http_proxy_service;
use pingora::server;
use pingora::server::configuration::Opt;
use pingora::services::background::{background_service, BackgroundService};

use crate::proxy::{Location, LocationConf, Upstream, UpstreamConf};
use crate::proxy::{Server as ProxyServer, ServerConf};

mod error;
mod proxy;

fn main() {
    env_logger::init();
    // std::thread::spawn(move || {
    //     std::process::exit(0);
    // });

    let mut opt = Opt::default();
    println!("{opt:?}");
    // opt.daemon = true;
    let mut my_server = server::Server::new(Some(opt)).unwrap();
    my_server.bootstrap();

    let upstream = Upstream::new(&UpstreamConf {
        name: "mytestupstream".to_string(),
        addrs: vec!["10.128.14.186:20146".to_string()],
        ..Default::default()
    })
    .unwrap();
    let upstreams = vec![Arc::new(upstream)];
    let lo = Location::new(
        LocationConf {
            name: "mytestlocation".to_string(),
            upstream: "mytestupstream".to_string(),
            ..Default::default()
        },
        upstreams,
    )
    .unwrap();

    let ps = ProxyServer::new(
        ServerConf {
            addr: "0.0.0.0:6188".to_string(),
        },
        vec![lo],
    );

    let services = ps.run(&my_server.configuration);
    for item in services.round_robin_services {
        my_server.add_service(item);
    }
    for item in services.consistent_services {
        my_server.add_service(item);
    }
    my_server.add_service(services.lb);

    // http_proxy_service(&my_server.configuration, lo);

    // let mut upstreams = LoadBalancer::try_from_iter(["10.128.14.186:20146"]).unwrap();

    // let hc = TcpHealthCheck::new();
    // upstreams.set_health_check(hc);
    // upstreams.health_check_frequency = Some(Duration::from_secs(1));
    // let background = background_service("health check", upstreams);

    // let upstreams = background.task();

    // let mut lb = http_proxy_service(&my_server.configuration, LB(upstreams));
    // lb.add_tcp("0.0.0.0:6188");
    // my_server.add_service(lb);
    // my_server.add_service(background);

    println!("{}", std::process::id());
    my_server.run_forever();
}
