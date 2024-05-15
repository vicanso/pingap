// Copyright 2024 Tree xie.
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

use crate::config::UpstreamConf;
use crate::state::State;
use crate::util;
use futures_util::FutureExt;
use humantime::parse_duration;
use log::debug;
use pingora::http::RequestHeader;
use pingora::lb::health_check::{HealthCheck, HttpHealthCheck, TcpHealthCheck};
use pingora::lb::selection::{Consistent, RoundRobin};
use pingora::lb::{discovery, Backend, Backends, LoadBalancer};
use pingora::protocols::l4::socket::SocketAddr;
use pingora::protocols::ALPN;
use pingora::proxy::Session;
use pingora::upstreams::peer::{HttpPeer, PeerOptions};
use snafu::{ResultExt, Snafu};
use std::collections::BTreeSet;
use std::fmt;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("{message}"))]
    Invalid { message: String },
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
    RoundRobin(Arc<LoadBalancer<RoundRobin>>),
    Consistent(Arc<LoadBalancer<Consistent>>),
    Empty,
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
    verify_cert: Option<bool>,
    alpn: ALPN,
}

impl fmt::Display for Upstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "name:{}", self.name)?;
        write!(f, "hash:{}", self.hash)?;
        write!(f, "tls:{}", self.tls)?;
        write!(f, "sni:{}", self.sni)?;
        write!(f, "connection_timeout:{:?}", self.connection_timeout)?;
        write!(
            f,
            "total_connection_timeout:{:?}",
            self.total_connection_timeout
        )?;
        write!(f, "read_timeout:{:?}", self.read_timeout)?;
        write!(f, "idle_timeout:{:?}", self.idle_timeout)?;
        write!(f, "write_timeout:{:?}", self.write_timeout)?;
        write!(f, "verify_cert:{:?}", self.verify_cert)?;
        write!(f, "alpn:{:?}", self.alpn)
    }
}

pub fn new_empty_upstream() -> Upstream {
    Upstream {
        name: "".to_string(),
        hash: "".to_string(),
        tls: false,
        sni: "".to_string(),
        lb: SelectionLb::Empty,
        connection_timeout: None,
        total_connection_timeout: None,
        read_timeout: None,
        idle_timeout: None,
        write_timeout: None,
        verify_cert: None,
        alpn: ALPN::H1,
    }
}

#[derive(Debug)]
pub struct HealthCheckConf {
    pub schema: String,
    pub host: String,
    pub path: String,
    pub connection_timeout: Duration,
    pub read_timeout: Duration,
    pub check_frequency: Duration,
    pub reuse_connection: bool,
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
        let mut reuse_connection = false;
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
                "reuse" => {
                    reuse_connection = true;
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
            reuse_connection,
            connection_timeout,
            check_frequency,
            consecutive_success,
            consecutive_failure,
        })
    }
}

fn update_peer_options(conf: &HealthCheckConf, opt: PeerOptions) -> PeerOptions {
    let mut options = opt;
    let timeout = Some(conf.connection_timeout);
    options.connection_timeout = timeout;
    options.total_connection_timeout = timeout;
    options.read_timeout = Some(conf.read_timeout);
    options.write_timeout = Some(conf.read_timeout);
    options.idle_timeout = Some(Duration::from_secs(0));
    options
}

fn new_tcp_health_check(conf: &HealthCheckConf) -> TcpHealthCheck {
    let mut check = TcpHealthCheck::default();
    check.peer_template.options = update_peer_options(conf, check.peer_template.options.clone());
    check.consecutive_success = conf.consecutive_success;
    check.consecutive_failure = conf.consecutive_failure;

    check
}

fn new_http_health_check(conf: &HealthCheckConf) -> HttpHealthCheck {
    let mut check = HttpHealthCheck::new(&conf.host, conf.schema == "https");
    check.peer_template.options = update_peer_options(conf, check.peer_template.options.clone());

    check.consecutive_success = conf.consecutive_success;
    check.consecutive_failure = conf.consecutive_failure;
    check.reuse_connection = conf.reuse_connection;
    // TODO 是否针对path做出错处理
    if let Ok(mut req) = RequestHeader::build("GET", conf.path.as_bytes(), None) {
        // 忽略append header fail
        let _ = req.append_header("Host", &conf.host);
        check.req = req;
    }

    check
}

fn new_healtch_check(
    name: &str,
    health_check: &str,
) -> Result<(Box<dyn HealthCheck + Send + Sync + 'static>, Duration)> {
    let mut health_check_frequency = Duration::from_secs(5);
    let hc: Box<dyn HealthCheck + Send + Sync + 'static> = if health_check.is_empty() {
        let mut check = TcpHealthCheck::new();
        check.peer_template.options.connection_timeout = Some(Duration::from_secs(3));
        check
    } else {
        let mut health_check_conf: HealthCheckConf = health_check.try_into()?;
        if health_check_conf.host == name {
            health_check_conf.host = "".to_string();
        }
        health_check_frequency = health_check_conf.check_frequency;
        match health_check_conf.schema.as_str() {
            "http" | "https" => Box::new(new_http_health_check(&health_check_conf)),
            _ => Box::new(new_tcp_health_check(&health_check_conf)),
        }
    };
    Ok((hc, health_check_frequency))
}

fn new_backends(addrs: &[String], tls: bool, ipv4_only: bool) -> Result<Backends> {
    let mut upstreams = BTreeSet::new();
    let mut backends = vec![];
    for addr in addrs.iter() {
        let arr: Vec<_> = addr.split(' ').collect();
        let weight = if arr.len() == 2 {
            arr[1].parse::<usize>().unwrap_or(1)
        } else {
            1
        };
        let mut addr = arr[0].to_string();
        if !addr.contains(':') {
            if tls {
                addr = format!("{addr}:443");
            } else {
                addr = format!("{addr}:80");
            }
        }
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
    Ok(backends)
}

impl Upstream {
    /// Creates a new upstream from config.
    pub fn new(name: &str, conf: &UpstreamConf) -> Result<Self> {
        if conf.addrs.is_empty() {
            return Err(Error::Invalid {
                message: "Upstream addrs is empty".to_string(),
            });
        }
        let mut hash = "".to_string();
        let sni = conf.sni.clone().unwrap_or_default();
        let tls = !sni.is_empty();
        let backends = new_backends(&conf.addrs, tls, conf.ipv4_only.unwrap_or_default())?;

        let (hc, health_check_frequency) =
            new_healtch_check(name, &conf.health_check.clone().unwrap_or_default())?;
        let algo_method = conf.algo.clone().unwrap_or_default();
        let algo_params: Vec<&str> = algo_method.split(':').collect();
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
                SelectionLb::Consistent(Arc::new(lb))
            }
            _ => {
                let mut lb = LoadBalancer::<RoundRobin>::from_backends(backends);
                lb.update()
                    .now_or_never()
                    .expect("static should not block")
                    .expect("static should not error");
                lb.set_health_check(hc);
                lb.health_check_frequency = Some(health_check_frequency);
                SelectionLb::RoundRobin(Arc::new(lb))
            }
        };

        let alpn = match conf
            .alpn
            .clone()
            .unwrap_or_default()
            .to_uppercase()
            .as_str()
        {
            "H2H1" => ALPN::H2H1,
            "H2" => ALPN::H2,
            _ => ALPN::H1,
        };
        // ALPN::H1
        let up = Self {
            name: name.to_string(),
            tls,
            sni: sni.clone(),
            hash,
            lb,
            alpn,
            connection_timeout: conf.connection_timeout,
            total_connection_timeout: conf.total_connection_timeout,
            read_timeout: conf.read_timeout,
            idle_timeout: conf.idle_timeout,
            write_timeout: conf.write_timeout,
            verify_cert: conf.verify_cert,
        };
        debug!("Upstream {up}");
        Ok(up)
    }
    /// Returns a new http peer, if there is no healthy backend, it will return `None`.
    pub fn new_http_peer(&self, ctx: &State, session: &Session) -> Option<HttpPeer> {
        let upstream = match &self.lb {
            SelectionLb::RoundRobin(lb) => lb.select(b"", 256),
            SelectionLb::Consistent(lb) => {
                let key = match self.hash.as_str() {
                    "url" => session.req_header().uri.to_string(),
                    "path" => session.req_header().uri.path().to_string(),
                    "ip" => {
                        if let Some(client_ip) = &ctx.client_ip {
                            client_ip.to_string()
                        } else {
                            util::get_client_ip(session)
                        }
                    }
                    _ => {
                        let header = session.req_header();
                        if let Some(value) = header.headers.get(&self.hash) {
                            value.to_str().unwrap_or_default().to_string()
                        } else {
                            header.uri.path().to_string()
                        }
                    }
                };
                lb.select(key.as_bytes(), 256)
            }
            _ => None,
        };
        upstream.map(|upstream| {
            let mut p = HttpPeer::new(upstream, self.tls, self.sni.clone());
            p.options.connection_timeout = self.connection_timeout;
            p.options.total_connection_timeout = self.total_connection_timeout;
            p.options.read_timeout = self.read_timeout;
            p.options.idle_timeout = self.idle_timeout;
            p.options.write_timeout = self.write_timeout;
            p.options.alpn = self.alpn.clone();
            if let Some(verify_cert) = self.verify_cert {
                p.options.verify_cert = verify_cert;
            }
            // TODO tcp_keepalive tcp_recv_buf
            p
        })
    }

    #[inline]
    pub fn as_round_robind(&self) -> Option<Arc<LoadBalancer<RoundRobin>>> {
        match &self.lb {
            SelectionLb::RoundRobin(lb) => Some(lb.clone()),
            _ => None,
        }
    }
    #[inline]
    pub fn as_consistent(&self) -> Option<Arc<LoadBalancer<Consistent>>> {
        match &self.lb {
            SelectionLb::Consistent(lb) => Some(lb.clone()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        new_backends, new_healtch_check, new_http_health_check, new_tcp_health_check,
        HealthCheckConf, State, Upstream, UpstreamConf,
    };
    use pingora::proxy::Session;
    use pingora::upstreams::peer::Peer;
    use std::time::Duration;
    use tokio_test::io::Builder;

    use pretty_assertions::assert_eq;
    #[test]
    fn test_health_check_conf() {
        let tcp_check: HealthCheckConf =
            "tcp://upstreamname?connection_timeout=3s&success=2&failure=1&check_frequency=10s"
                .try_into()
                .unwrap();
        assert_eq!(
            r###"HealthCheckConf { schema: "tcp", host: "upstreamname", path: "", connection_timeout: 3s, read_timeout: 3s, check_frequency: 10s, reuse_connection: false, consecutive_success: 2, consecutive_failure: 1 }"###,
            format!("{tcp_check:?}")
        );
        let tcp_check = new_tcp_health_check(&tcp_check);
        assert_eq!(1, tcp_check.consecutive_failure);
        assert_eq!(2, tcp_check.consecutive_success);
        assert_eq!(
            Duration::from_secs(3),
            tcp_check.peer_template.connection_timeout().unwrap()
        );

        let http_check: HealthCheckConf = "https://upstreamname/ping?connection_timeout=3s&read_timeout=1s&success=2&failure=1&check_frequency=10s&from=nginx&reuse".try_into().unwrap();
        assert_eq!(
            r###"HealthCheckConf { schema: "https", host: "upstreamname", path: "/ping?from=nginx", connection_timeout: 3s, read_timeout: 1s, check_frequency: 10s, reuse_connection: true, consecutive_success: 2, consecutive_failure: 1 }"###,
            format!("{http_check:?}")
        );
        let http_check = new_http_health_check(&http_check);
        assert_eq!(1, http_check.consecutive_failure);
        assert_eq!(2, http_check.consecutive_success);
        assert_eq!(true, http_check.reuse_connection);
        assert_eq!(
            Duration::from_secs(3),
            http_check.peer_template.options.connection_timeout.unwrap()
        );
        assert_eq!(
            Duration::from_secs(1),
            http_check.peer_template.options.read_timeout.unwrap()
        );
    }
    #[test]
    fn test_new_healtch_check() {
        let (_, frequency) = new_healtch_check("upstreamname", "https://upstreamname/ping?connection_timeout=3s&read_timeout=1s&success=2&failure=1&check_frequency=10s&from=nginx&reuse").unwrap();
        assert_eq!(Duration::from_secs(10), frequency);
    }
    #[test]
    fn test_new_backends() {
        let _ = new_backends(
            &[
                "192.168.1.1:8001".to_string(),
                "192.168.1.2:8001".to_string(),
            ],
            false,
            true,
        )
        .unwrap();
    }
    #[tokio::test]
    async fn test_upstream() {
        let headers = [
            "Host: github.com",
            "Referer: https://github.com/",
            "User-Agent: pingap/0.1.1",
            "Cookie: deviceId=abc",
            "Accept: application/json",
        ]
        .join("\r\n");
        let input_header = format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();

        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let up = Upstream::new(
            "upstreamname",
            &UpstreamConf {
                addrs: vec!["192.168.1.1:8001".to_string()],
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            true,
            up.new_http_peer(&State::default(), &session).is_some()
        );
        assert_eq!(true, up.as_round_robind().is_some());
    }
}
