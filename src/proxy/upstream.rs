use crate::config::UpstreamConf;
use futures_util::FutureExt;
use humantime::parse_duration;
use pingora::http::RequestHeader;
use pingora::lb::health_check::{HealthCheck, HttpHealthCheck, TcpHealthCheck};
use pingora::lb::selection::{Consistent, RoundRobin};
use pingora::lb::{discovery, Backend, Backends, LoadBalancer};
use pingora::protocols::l4::socket::SocketAddr;
use pingora::upstreams::peer::HttpPeer;
use snafu::{ResultExt, Snafu};
use std::collections::BTreeSet;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Url parse error {source}, {url}"))]
    UrlParse {
        source: url::ParseError,
        url: String,
    },
    #[snafu(display("Io error {source}, {content}"))]
    Io {
        source: std::io::Error,
        content: String,
    },
}
type Result<T, E = Error> = std::result::Result<T, E>;

enum SelectionLb {
    RoundRobinLb(Arc<LoadBalancer<RoundRobin>>),
    ConsistentLb(Arc<LoadBalancer<Consistent>>),
}

pub struct Upstream {
    pub name: String,
    hash: String,
    tls: bool,
    sni: String,
    lb: SelectionLb,
    connection_timeout: Option<Duration>,
    total_connection_timeout: Option<Duration>,
    read_timeout: Option<Duration>,
    idle_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
}

pub struct HealthCheckConf {
    pub schema: String,
    pub host: String,
    pub path: String,
    pub connection_timeout: Duration,
    pub read_timeout: Duration,
    pub check_frequency: Duration,
    pub consecutive_success: usize,
    pub consecutive_failure: usize,
}

impl TryFrom<&str> for HealthCheckConf {
    type Error = Error;
    fn try_from(value: &str) -> Result<Self> {
        let value = Url::parse(value).context(UrlParseSnafu {
            url: value.to_string(),
        })?;
        let mut connection_timeout = Duration::from_secs(3);
        let mut read_timeout = Duration::from_secs(3);
        let mut check_frequency = Duration::from_secs(10);
        let mut consecutive_success = 1;
        let mut consecutive_failure = 2;
        let mut query_list = vec![];
        // HttpHealthCheck
        for (key, value) in value.query_pairs().into_iter() {
            match key.as_ref() {
                "connection_timeout" => {
                    if let Ok(d) = parse_duration(value.as_ref()) {
                        connection_timeout = d;
                    }
                }
                "read_timeout" => {
                    if let Ok(d) = parse_duration(value.as_ref()) {
                        read_timeout = d;
                    }
                }
                "check_frequency" => {
                    if let Ok(d) = parse_duration(value.as_ref()) {
                        check_frequency = d;
                    }
                }
                "success" => {
                    if let Ok(v) = value.parse::<usize>() {
                        consecutive_success = v;
                    }
                }
                "failure" => {
                    if let Ok(v) = value.parse::<usize>() {
                        consecutive_failure = v;
                    }
                }
                _ => {
                    if value.is_empty() {
                        query_list.push(key.to_string());
                    } else {
                        query_list.push(format!("{key}={value}"));
                    }
                }
            };
        }
        let host = if let Some(host) = value.host() {
            host.to_string()
        } else {
            "".to_string()
        };
        let mut path = value.path().to_string();
        if !query_list.is_empty() {
            path += &format!("?{}", query_list.join("&"));
        }
        Ok(HealthCheckConf {
            schema: value.scheme().to_string(),
            host,
            path,
            read_timeout,
            connection_timeout,
            check_frequency,
            consecutive_success,
            consecutive_failure,
        })
    }
}

fn new_tcp_health_check(conf: &HealthCheckConf) -> TcpHealthCheck {
    let mut check = TcpHealthCheck::default();
    check.peer_template.options.connection_timeout = Some(conf.connection_timeout);
    check.consecutive_success = conf.consecutive_success;
    check.consecutive_failure = conf.consecutive_failure;

    check
}

fn new_http_health_check(conf: &HealthCheckConf) -> HttpHealthCheck {
    let mut check = HttpHealthCheck::new(&conf.host, conf.schema == "https");
    check.peer_template.options.connection_timeout = Some(conf.connection_timeout);
    check.peer_template.options.read_timeout = Some(conf.read_timeout);
    check.consecutive_success = conf.consecutive_success;
    check.consecutive_failure = conf.consecutive_failure;
    // TODO 是否针对path做出错处理
    if let Ok(mut req) = RequestHeader::build("GET", conf.path.as_bytes(), None) {
        // 忽略append header fail
        let _ = req.append_header("Host", &conf.host);
        check.req = req;
    }

    check
}

impl Upstream {
    pub fn new(name: &str, conf: &UpstreamConf) -> Result<Self> {
        let mut upstreams = BTreeSet::new();
        let mut backends = vec![];
        for addr in conf.addrs.iter() {
            let arr: Vec<_> = addr.split(' ').collect();
            let weight = if arr.len() == 2 {
                arr[1].parse::<usize>().unwrap_or(1)
            } else {
                1
            };
            let mut addr = arr[0].to_string();
            if !addr.contains(':') {
                addr = format!("{addr}:80");
            }
            let ipv4_only = conf.ipv4_only.unwrap_or_default();
            for item in addr.to_socket_addrs().context(IoSnafu { content: addr })? {
                if ipv4_only && item.is_ipv6() {
                    continue;
                }
                let backend = Backend {
                    addr: SocketAddr::Inet(item),
                    weight,
                };
                backends.push(backend)
            }
        }
        upstreams.extend(backends);
        let discovery = discovery::Static::new(upstreams);
        let backends = Backends::new(discovery);

        let mut health_check_frequency = Duration::from_secs(5);
        let health_check = conf.health_check.clone().unwrap_or_default();
        let hc: Box<dyn HealthCheck + Send + Sync + 'static> = if health_check.is_empty() {
            let mut check = TcpHealthCheck::new();
            check.peer_template.options.connection_timeout = Some(Duration::from_secs(3));
            check
        } else {
            let mut health_check_conf: HealthCheckConf = health_check.as_str().try_into()?;
            if health_check_conf.host == name {
                health_check_conf.host = "".to_string();
            }
            health_check_frequency = health_check_conf.check_frequency;
            match health_check_conf.schema.as_str() {
                "http" | "https" => Box::new(new_http_health_check(&health_check_conf)),
                _ => Box::new(new_tcp_health_check(&health_check_conf)),
            }
        };
        let algo_method = conf.algo.clone().unwrap_or_default();
        let algo_params: Vec<&str> = algo_method.split(':').collect();
        let mut hash = "".to_string();
        let lb = match algo_params[0] {
            "hash" => {
                let mut lb = LoadBalancer::<Consistent>::from_backends(backends);
                if algo_params.len() > 1 {
                    hash = algo_params[1].to_string();
                }

                lb.update()
                    .now_or_never()
                    .expect("static should not block")
                    .expect("static should not error");
                lb.set_health_check(hc);
                lb.health_check_frequency = Some(health_check_frequency);
                SelectionLb::ConsistentLb(Arc::new(lb))
            }
            _ => {
                let mut lb = LoadBalancer::<RoundRobin>::from_backends(backends);

                lb.update()
                    .now_or_never()
                    .expect("static should not block")
                    .expect("static should not error");
                lb.set_health_check(hc);
                lb.health_check_frequency = Some(health_check_frequency);
                SelectionLb::RoundRobinLb(Arc::new(lb))
            }
        };
        let sni = conf.sni.clone().unwrap_or_default();
        Ok(Self {
            name: name.to_string(),
            tls: !sni.is_empty(),
            sni: sni.clone(),
            hash,
            lb,
            connection_timeout: conf.connection_timeout,
            total_connection_timeout: conf.total_connection_timeout,
            read_timeout: conf.read_timeout,
            idle_timeout: conf.idle_timeout,
            write_timeout: conf.write_timeout,
        })
    }
    pub fn new_http_peer(&self, header: &RequestHeader) -> Option<HttpPeer> {
        let upstream = match &self.lb {
            SelectionLb::RoundRobinLb(lb) => lb.select(b"", 256),
            SelectionLb::ConsistentLb(lb) => {
                let key = if let Some(value) = header.headers.get(&self.hash) {
                    value.as_bytes()
                } else {
                    header.uri.path().as_bytes()
                };
                lb.select(key, 256)
            }
        };
        upstream.map(|upstream| {
            let mut p = HttpPeer::new(upstream, self.tls, self.sni.clone());
            p.options.connection_timeout = self.connection_timeout;
            p.options.total_connection_timeout = self.total_connection_timeout;
            p.options.read_timeout = self.read_timeout;
            p.options.idle_timeout = self.idle_timeout;
            p.options.write_timeout = self.write_timeout;
            p
        })
    }
    pub fn get_round_robind(&self) -> Option<Arc<LoadBalancer<RoundRobin>>> {
        match &self.lb {
            SelectionLb::RoundRobinLb(lb) => Some(lb.clone()),
            SelectionLb::ConsistentLb(_) => None,
        }
    }
    pub fn get_consistent(&self) -> Option<Arc<LoadBalancer<Consistent>>> {
        match &self.lb {
            SelectionLb::RoundRobinLb(_) => None,
            SelectionLb::ConsistentLb(lb) => Some(lb.clone()),
        }
    }
}
