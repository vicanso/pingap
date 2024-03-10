use crate::error::{Error, Result};
use futures_util::FutureExt;
use humantime::parse_duration;
use pingora::http::RequestHeader;
use pingora::lb::health_check::{HealthCheck, HttpHealthCheck, TcpHealthCheck};
use pingora::lb::selection::{Consistent, RoundRobin};
use pingora::lb::{discovery, Backend, Backends, LoadBalancer};
use pingora::protocols::l4::socket::SocketAddr;
use std::collections::BTreeSet;
use std::time::Duration;
use url::Url;

#[derive(Debug, Default)]
pub struct UpstreamConf {
    pub addrs: Vec<String>,
    pub lb_method: String,
    pub health_check: String,
}

impl UpstreamConf {
    pub fn validate(&self) -> Result<()> {
        // validate upstream addr
        for addr in self.addrs.iter() {
            let arr: Vec<_> = addr.split(' ').collect();
            let _ = arr[0].parse::<std::net::SocketAddr>()?;
        }
        // validate health check
        if !self.health_check.is_empty() {
            let _ = Url::parse(&self.health_check)?;
        }

        Ok(())
    }
}

enum SelectionLb {
    RoundRobinLb(LoadBalancer<RoundRobin>),
    ConsistentLb(LoadBalancer<Consistent>),
}

pub struct LbUpstream {
    lb: SelectionLb,
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
        let value = Url::parse(value)?;

        let mut connection_timeout = Duration::from_secs(3);
        let mut read_timeout = Duration::from_secs(3);
        let mut check_frequency = Duration::from_secs(10);
        let mut consecutive_success = 1;
        let mut consecutive_failure = 1;
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
                _ => {}
            };
        }
        let host = if let Some(host) = value.host() {
            host.to_string()
        } else {
            "".to_string()
        };
        Ok(HealthCheckConf {
            schema: value.scheme().to_string(),
            host,
            path: value.path().to_string(),
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

impl LbUpstream {
    pub fn new(conf: &UpstreamConf) -> Result<Self> {
        let mut upstreams = BTreeSet::new();
        let mut backends = vec![];
        for addr in conf.addrs.iter() {
            let arr: Vec<_> = addr.split(' ').collect();
            let weight = if arr.len() == 2 {
                arr[1].parse::<usize>().unwrap_or(1)
            } else {
                1
            };
            let addr = arr[0].parse::<std::net::SocketAddr>()?;
            let backend = Backend {
                addr: SocketAddr::Inet(addr),
                weight,
            };
            backends.push(backend);
        }
        upstreams.extend(backends);
        let discovery = discovery::Static::new(upstreams);
        let backends = Backends::new(discovery);

        let mut health_check_frequency = Duration::from_secs(5);
        let hc: Box<dyn HealthCheck + Send + Sync + 'static> = if conf.health_check.is_empty() {
            TcpHealthCheck::new()
        } else {
            let health_check_conf: HealthCheckConf = conf.health_check.as_str().try_into()?;
            health_check_frequency = health_check_conf.check_frequency;
            match health_check_conf.schema.as_str() {
                "http" | "https" => Box::new(new_http_health_check(&health_check_conf)),
                _ => Box::new(new_tcp_health_check(&health_check_conf)),
            }
        };
        let lb = match conf.lb_method.as_str() {
            "consistent" => {
                let mut lb = LoadBalancer::<Consistent>::from_backends(backends);

                lb.update()
                    .now_or_never()
                    .expect("static should not block")
                    .expect("static should not error");
                lb.set_health_check(hc);
                lb.health_check_frequency = Some(health_check_frequency);
                SelectionLb::ConsistentLb(lb)
            }
            _ => {
                let mut lb = LoadBalancer::<RoundRobin>::from_backends(backends);

                lb.update()
                    .now_or_never()
                    .expect("static should not block")
                    .expect("static should not error");
                lb.set_health_check(hc);
                lb.health_check_frequency = Some(health_check_frequency);
                SelectionLb::RoundRobinLb(lb)
            }
        };
        Ok(Self { lb })
    }
    pub fn select(&self, key: &[u8]) -> Option<Backend> {
        match &self.lb {
            SelectionLb::RoundRobinLb(lb) => lb.select(key, 256),
            SelectionLb::ConsistentLb(lb) => lb.select(key, 256),
        }
    }
}
