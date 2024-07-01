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
use crate::discovery::{
    new_common_discover_backends, new_dns_discover_backends,
};
use crate::service::{CommonServiceTask, ServiceTask};
use crate::state::State;
use crate::util;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use futures_util::FutureExt;
use humantime::parse_duration;
use once_cell::sync::Lazy;
use pingora::http::RequestHeader;
use pingora::lb::health_check::{HealthCheck, HttpHealthCheck, TcpHealthCheck};
use pingora::lb::selection::{Consistent, RoundRobin};
use pingora::lb::{Backends, LoadBalancer};
use pingora::protocols::l4::ext::TcpKeepalive;
use pingora::protocols::ALPN;
use pingora::proxy::Session;
use pingora::upstreams::peer::{HttpPeer, PeerOptions, Tracer, Tracing};
use snafu::{ResultExt, Snafu};
use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info};
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
}
type Result<T, E = Error> = std::result::Result<T, E>;

enum SelectionLb {
    RoundRobin(Arc<LoadBalancer<RoundRobin>>),
    Consistent(Arc<LoadBalancer<Consistent>>),
}

#[derive(Clone, Debug)]
struct UpstreamPeerTracer {
    connected: Arc<AtomicU32>,
}

impl UpstreamPeerTracer {
    fn new() -> Self {
        Self {
            connected: Arc::new(AtomicU32::new(0)),
        }
    }
}

impl Tracing for UpstreamPeerTracer {
    fn on_connected(&self) {
        self.connected.fetch_add(1, Ordering::Relaxed);
    }
    fn on_disconnected(&self) {
        self.connected.fetch_sub(1, Ordering::Relaxed);
    }
    fn boxed_clone(&self) -> Box<dyn Tracing> {
        Box::new(self.clone())
    }
}

pub struct Upstream {
    pub name: String,
    hash: String,
    hash_key: String,
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
    tcp_keepalive: Option<TcpKeepalive>,
    tcp_recv_buf: Option<usize>,
    tcp_fast_open: Option<bool>,
    peer_tracer: Option<UpstreamPeerTracer>,
    tracer: Option<Tracer>,
}

impl fmt::Display for Upstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "name:{} ", self.name)?;
        write!(f, "hash:{} ", self.hash)?;
        write!(f, "hash_key:{} ", self.hash_key)?;
        write!(f, "tls:{} ", self.tls)?;
        write!(f, "sni:{} ", self.sni)?;
        write!(f, "connection_timeout:{:?} ", self.connection_timeout)?;
        write!(
            f,
            "total_connection_timeout:{:?} ",
            self.total_connection_timeout
        )?;
        write!(f, "read_timeout:{:?} ", self.read_timeout)?;
        write!(f, "idle_timeout:{:?} ", self.idle_timeout)?;
        write!(f, "write_timeout:{:?} ", self.write_timeout)?;
        write!(f, "verify_cert:{:?} ", self.verify_cert)?;
        write!(f, "alpn:{:?}", self.alpn)
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
                },
                "read_timeout" => {
                    if let Ok(d) = parse_duration(value.as_ref()) {
                        read_timeout = d;
                    }
                },
                "check_frequency" => {
                    if let Ok(d) = parse_duration(value.as_ref()) {
                        check_frequency = d;
                    }
                },
                "success" => {
                    if let Ok(v) = value.parse::<usize>() {
                        consecutive_success = v;
                    }
                },
                "failure" => {
                    if let Ok(v) = value.parse::<usize>() {
                        consecutive_failure = v;
                    }
                },
                "reuse" => {
                    reuse_connection = true;
                },
                _ => {
                    if value.is_empty() {
                        query_list.push(key.to_string());
                    } else {
                        query_list.push(format!("{key}={value}"));
                    }
                },
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

fn update_peer_options(
    conf: &HealthCheckConf,
    opt: PeerOptions,
) -> PeerOptions {
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
    check.peer_template.options =
        update_peer_options(conf, check.peer_template.options.clone());
    check.consecutive_success = conf.consecutive_success;
    check.consecutive_failure = conf.consecutive_failure;

    check
}

fn new_http_health_check(conf: &HealthCheckConf) -> HttpHealthCheck {
    let mut check = HttpHealthCheck::new(&conf.host, conf.schema == "https");
    check.peer_template.options =
        update_peer_options(conf, check.peer_template.options.clone());

    check.consecutive_success = conf.consecutive_success;
    check.consecutive_failure = conf.consecutive_failure;
    check.reuse_connection = conf.reuse_connection;
    match RequestHeader::build("GET", conf.path.as_bytes(), None) {
        Ok(mut req) => {
            // 忽略append header fail
            if let Err(e) = req.append_header("Host", &conf.host) {
                error!(
                    error = e.to_string(),
                    host = conf.host,
                    "http health check append host fail"
                );
            }
            check.req = req;
        },
        Err(e) => error!(error = e.to_string(), "http health check fail"),
    }

    check
}

fn new_health_check(
    name: &str,
    health_check: &str,
) -> Result<(Box<dyn HealthCheck + Send + Sync + 'static>, Duration)> {
    let mut health_check_frequency = Duration::from_secs(10);
    let hc: Box<dyn HealthCheck + Send + Sync + 'static> =
        if health_check.is_empty() {
            let mut check = TcpHealthCheck::new();
            check.peer_template.options.connection_timeout =
                Some(Duration::from_secs(3));
            info!(
                name,
                options = format!("{:?}", check.peer_template.options),
                "new health check"
            );
            check
        } else {
            let health_check_conf: HealthCheckConf = health_check.try_into()?;
            health_check_frequency = health_check_conf.check_frequency;
            info!(
                name,
                health_check_conf = format!("{health_check_conf:?}"),
                "new http health check"
            );
            match health_check_conf.schema.as_str() {
                "http" | "https" => {
                    Box::new(new_http_health_check(&health_check_conf))
                },
                _ => Box::new(new_tcp_health_check(&health_check_conf)),
            }
        };
    Ok((hc, health_check_frequency))
}

fn new_backends(
    addrs: &[String],
    tls: bool,
    ipv4_only: bool,
    discovery: String,
) -> Result<Backends> {
    if discovery == "dns" {
        new_dns_discover_backends(addrs, tls, ipv4_only).map_err(|e| {
            Error::Invalid {
                message: e.to_string(),
            }
        })
    } else {
        new_common_discover_backends(addrs, tls, ipv4_only).map_err(|e| {
            Error::Invalid {
                message: e.to_string(),
            }
        })
    }
}

fn get_hash_value(
    hash: &str,
    hash_key: &str,
    session: &Session,
    ctx: &State,
) -> String {
    match hash {
        "url" => session.req_header().uri.to_string(),
        "ip" => {
            if let Some(client_ip) = &ctx.client_ip {
                client_ip.to_string()
            } else {
                util::get_client_ip(session)
            }
        },
        "header" => {
            if let Some(value) = session.get_header(hash_key) {
                value.to_str().unwrap_or_default().to_string()
            } else {
                "".to_string()
            }
        },
        "cookie" => util::get_cookie_value(session.req_header(), hash_key)
            .unwrap_or_default()
            .to_string(),
        "query" => util::get_query_value(session.req_header(), hash_key)
            .unwrap_or_default()
            .to_string(),
        // default: path
        _ => session.req_header().uri.path().to_string(),
    }
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
        let backends = new_backends(
            &conf.addrs,
            tls,
            conf.ipv4_only.unwrap_or_default(),
            conf.discovery.clone().unwrap_or_default(),
        )?;

        let (hc, health_check_frequency) = new_health_check(
            name,
            &conf.health_check.clone().unwrap_or_default(),
        )?;
        let algo_method = conf.algo.clone().unwrap_or_default();
        let algo_params: Vec<&str> = algo_method.split(':').collect();
        let mut hash_key = "".to_string();
        let lb = match algo_params[0] {
            "hash" => {
                let mut lb =
                    LoadBalancer::<Consistent>::from_backends(backends);
                if algo_params.len() > 1 {
                    hash = algo_params[1].to_string();
                    if algo_params.len() > 2 {
                        hash_key = algo_params[2].to_string();
                    }
                }

                lb.update()
                    .now_or_never()
                    .expect("static should not block")
                    .expect("static should not error");
                lb.set_health_check(hc);
                lb.update_frequency = conf.update_frequency;
                lb.health_check_frequency = Some(health_check_frequency);
                SelectionLb::Consistent(Arc::new(lb))
            },
            _ => {
                let mut lb =
                    LoadBalancer::<RoundRobin>::from_backends(backends);
                lb.update()
                    .now_or_never()
                    .expect("static should not block")
                    .expect("static should not error");
                lb.set_health_check(hc);
                lb.update_frequency = conf.update_frequency;
                lb.health_check_frequency = Some(health_check_frequency);
                SelectionLb::RoundRobin(Arc::new(lb))
            },
        };

        let alpn = if let Some(alpn) = &conf.alpn {
            match alpn.to_uppercase().as_str() {
                "H2H1" => ALPN::H2H1,
                "H2" => ALPN::H2,
                _ => ALPN::H1,
            }
        } else {
            ALPN::H1
        };

        let tcp_keepalive = if conf.tcp_idle.is_some()
            && conf.tcp_probe_count.is_some()
            && conf.tcp_interval.is_some()
        {
            Some(TcpKeepalive {
                idle: conf.tcp_idle.unwrap_or_default(),
                count: conf.tcp_probe_count.unwrap_or_default(),
                interval: conf.tcp_interval.unwrap_or_default(),
            })
        } else {
            None
        };

        let peer_tracer = if conf.enable_tracer.unwrap_or_default() {
            Some(UpstreamPeerTracer::new())
        } else {
            None
        };
        let tracer = peer_tracer
            .as_ref()
            .map(|peer_tracer| Tracer(Box::new(peer_tracer.to_owned())));
        let up = Self {
            name: name.to_string(),
            tls,
            sni: sni.clone(),
            hash,
            hash_key,
            lb,
            alpn,
            connection_timeout: conf.connection_timeout,
            total_connection_timeout: conf.total_connection_timeout,
            read_timeout: conf.read_timeout,
            idle_timeout: conf.idle_timeout,
            write_timeout: conf.write_timeout,
            verify_cert: conf.verify_cert,
            tcp_recv_buf: conf.tcp_recv_buf.map(|item| item.as_u64() as usize),
            tcp_keepalive,
            tcp_fast_open: conf.tcp_fast_open,
            peer_tracer,
            tracer,
        };
        debug!(upstream = up.to_string(), "new upstream");
        Ok(up)
    }

    /// Returns a new http peer, if there is no healthy backend, it will return `None`.
    #[inline]
    pub fn new_http_peer(
        &self,
        session: &Session,
        ctx: &State,
    ) -> Option<HttpPeer> {
        let upstream = match &self.lb {
            SelectionLb::RoundRobin(lb) => lb.select(b"", 256),
            SelectionLb::Consistent(lb) => {
                let value =
                    get_hash_value(&self.hash, &self.hash_key, session, ctx);
                lb.select(value.as_bytes(), 256)
            },
        };
        upstream.map(|upstream| {
            let mut p = HttpPeer::new(upstream, self.tls, self.sni.clone());
            p.options.connection_timeout = self.connection_timeout;
            p.options.total_connection_timeout = self.total_connection_timeout;
            p.options.read_timeout = self.read_timeout;
            p.options.idle_timeout = self.idle_timeout;
            p.options.write_timeout = self.write_timeout;
            if let Some(verify_cert) = self.verify_cert {
                p.options.verify_cert = verify_cert;
            }
            p.options.alpn = self.alpn.clone();
            p.options.tcp_keepalive.clone_from(&self.tcp_keepalive);
            p.options.tcp_recv_buf = self.tcp_recv_buf;
            if let Some(tcp_fast_open) = self.tcp_fast_open {
                p.options.tcp_fast_open = tcp_fast_open;
            }
            p.options.tracer.clone_from(&self.tracer);
            p
        })
    }

    /// Get the connected count of upstream
    #[inline]
    pub fn connected(&self) -> Option<u32> {
        self.peer_tracer
            .as_ref()
            .map(|tracer| tracer.connected.load(Ordering::Relaxed))
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

type Upstreams = HashMap<String, Arc<Upstream>>;
static UPSTREAM_MAP: Lazy<ArcSwap<Upstreams>> =
    Lazy::new(|| ArcSwap::from_pointee(HashMap::new()));

pub fn get_upstream(name: &str) -> Option<Arc<Upstream>> {
    UPSTREAM_MAP.load().get(name).cloned()
}

pub fn try_init_upstreams(confs: &HashMap<String, UpstreamConf>) -> Result<()> {
    let mut upstreams = HashMap::new();
    for (name, conf) in confs.iter() {
        let up = Arc::new(Upstream::new(name, conf)?);
        upstreams.insert(name.to_string(), up);
    }
    UPSTREAM_MAP.store(Arc::new(upstreams));

    Ok(())
}

#[async_trait]
impl ServiceTask for HealthCheckTask {
    async fn run(&self) -> Option<bool> {
        let check_count = self.count.fetch_add(1, Ordering::Relaxed);
        let upstreams = {
            let mut upstreams = vec![];
            for (name, up) in UPSTREAM_MAP.load().iter() {
                upstreams.push((name.to_string(), up.clone()));
            }
            upstreams
        };
        let interval = self.interval.as_secs();
        let jobs = upstreams.into_iter().map(|(name, up)| {
            let runtime = pingora_runtime::current_handle();
            runtime.spawn(async move {
                let check_frequency_matched = |frequency: u64| -> bool {
                    let mut count = (frequency / interval) as u32;
                    if frequency % interval != 0 {
                        count += 1;
                    }
                    check_count % count == 0
                };

                let update_frequency = if let Some(lb) = up.as_round_robind() {
                    lb.update_frequency
                } else if let Some(lb) = up.as_consistent() {
                    lb.update_frequency
                } else {
                    None
                }
                .unwrap_or_default()
                .as_secs();

                if update_frequency > 0
                    && check_frequency_matched(update_frequency)
                {
                    debug!(name, "update backends is running",);
                    let result = if let Some(lb) = up.as_round_robind() {
                        lb.backends().update().await
                    } else if let Some(lb) = up.as_consistent() {
                        lb.backends().update().await
                    } else {
                        Ok(false)
                    };
                    match result {
                        Ok(different) => {
                            if different {
                                info!(
                                    name,
                                    "update backends with different value"
                                )
                            }
                        },
                        Err(e) => {
                            error!(
                                error = e.to_string(),
                                name, "update backends fail"
                            )
                        },
                    };
                    debug!(name, "update backend is done",);
                }

                let health_check_frequency =
                    if let Some(lb) = up.as_round_robind() {
                        lb.health_check_frequency
                    } else if let Some(lb) = up.as_consistent() {
                        lb.health_check_frequency
                    } else {
                        None
                    }
                    .unwrap_or_default()
                    .as_secs();

                if !check_frequency_matched(health_check_frequency) {
                    return;
                }

                debug!(name, "health check is running",);
                if let Some(lb) = up.as_round_robind() {
                    lb.backends()
                        .run_health_check(lb.parallel_health_check)
                        .await;
                } else if let Some(lb) = up.as_consistent() {
                    lb.backends()
                        .run_health_check(lb.parallel_health_check)
                        .await;
                }
                debug!(name, "health check is done",);
            })
        });
        futures::future::join_all(jobs).await;
        None
    }
    fn description(&self) -> String {
        "Upstream health check task".to_string()
    }
}

struct HealthCheckTask {
    interval: Duration,
    count: AtomicU32,
}

pub fn new_upstream_health_check_task(interval: Duration) -> CommonServiceTask {
    let interval = interval.max(Duration::from_secs(10));
    CommonServiceTask::new(
        "Upstream health check task",
        interval,
        HealthCheckTask {
            interval,
            count: AtomicU32::new(0),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::{
        get_hash_value, new_backends, new_health_check, new_http_health_check,
        new_tcp_health_check, HealthCheckConf, State, Upstream, UpstreamConf,
        UpstreamPeerTracer,
    };
    use pingora::protocols::ALPN;
    use pingora::proxy::Session;
    use pingora::upstreams::peer::{Peer, Tracing};
    use pretty_assertions::assert_eq;
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    use tokio_test::io::Builder;
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
    fn test_new_health_check() {
        let (_, frequency) = new_health_check("upstreamname", "https://upstreamname/ping?connection_timeout=3s&read_timeout=1s&success=2&failure=1&check_frequency=10s&from=nginx&reuse").unwrap();
        assert_eq!(Duration::from_secs(10), frequency);
    }
    #[test]
    fn test_new_backends() {
        let _ = new_backends(
            &[
                "192.168.1.1:8001 10".to_string(),
                "192.168.1.2:8001".to_string(),
            ],
            false,
            true,
            "".to_string(),
        )
        .unwrap();

        let _ = new_backends(
            &["192.168.1.1".to_string(), "192.168.1.2:8001".to_string()],
            true,
            true,
            "".to_string(),
        )
        .unwrap();
    }
    #[test]
    fn test_new_upstream() {
        let result = Upstream::new(
            "charts",
            &UpstreamConf {
                ..Default::default()
            },
        );
        assert_eq!(
            "Upstream addrs is empty",
            result.err().unwrap().to_string()
        );

        let up = Upstream::new(
            "charts",
            &UpstreamConf {
                addrs: vec!["192.168.1.1".to_string()],
                algo: Some("hash:cookie:user-id".to_string()),
                alpn: Some("h2".to_string()),
                connection_timeout: Some(Duration::from_secs(5)),
                total_connection_timeout: Some(Duration::from_secs(10)),
                read_timeout: Some(Duration::from_secs(3)),
                idle_timeout: Some(Duration::from_secs(30)),
                write_timeout: Some(Duration::from_secs(5)),
                tcp_idle: Some(Duration::from_secs(60)),
                tcp_probe_count: Some(100),
                tcp_interval: Some(Duration::from_secs(60)),
                tcp_recv_buf: Some(bytesize::ByteSize(1024)),
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!("cookie", up.hash);
        assert_eq!("user-id", up.hash_key);
        assert_eq!(ALPN::H2.to_string(), up.alpn.to_string());
        assert_eq!("Some(5s)", format!("{:?}", up.connection_timeout));
        assert_eq!("Some(10s)", format!("{:?}", up.total_connection_timeout));
        assert_eq!("Some(3s)", format!("{:?}", up.read_timeout));
        assert_eq!("Some(30s)", format!("{:?}", up.idle_timeout));
        assert_eq!("Some(5s)", format!("{:?}", up.write_timeout));
        assert_eq!(
            "Some(TcpKeepalive { idle: 60s, interval: 60s, count: 100 })",
            format!("{:?}", up.tcp_keepalive)
        );
        assert_eq!("Some(1024)", format!("{:?}", up.tcp_recv_buf));
        assert_eq!("name:charts hash:cookie hash_key:user-id tls:false sni: connection_timeout:Some(5s) total_connection_timeout:Some(10s) read_timeout:Some(3s) idle_timeout:Some(30s) write_timeout:Some(5s) verify_cert:None alpn:H2", up.to_string());
    }
    #[tokio::test]
    async fn test_get_hash_key_value() {
        let headers = [
            "Host: github.com",
            "Referer: https://github.com/",
            "User-Agent: pingap/0.1.1",
            "Cookie: deviceId=abc",
            "Accept: application/json",
            "X-Forwarded-For: 1.1.1.1",
        ]
        .join("\r\n");
        let input_header = format!(
            "GET /vicanso/pingap?id=1234 HTTP/1.1\r\n{headers}\r\n\r\n"
        );
        let mock_io = Builder::new().read(input_header.as_bytes()).build();

        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let mut ctx = State {
            ..Default::default()
        };

        assert_eq!(
            "/vicanso/pingap?id=1234",
            get_hash_value("url", "", &session, &ctx)
        );

        assert_eq!("1.1.1.1", get_hash_value("ip", "", &session, &ctx));
        ctx.client_ip = Some("2.2.2.2".to_string());
        assert_eq!("2.2.2.2", get_hash_value("ip", "", &session, &ctx));

        assert_eq!(
            "pingap/0.1.1",
            get_hash_value("header", "User-Agent", &session, &ctx)
        );

        assert_eq!("abc", get_hash_value("cookie", "deviceId", &session, &ctx));
        assert_eq!("1234", get_hash_value("query", "id", &session, &ctx));
        assert_eq!(
            "/vicanso/pingap",
            get_hash_value("path", "", &session, &ctx)
        );
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
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
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
            up.new_http_peer(&session, &State::default(),).is_some()
        );
        assert_eq!(true, up.as_round_robind().is_some());
    }
    #[test]
    fn test_upstream_peer_tracer() {
        let tracer = UpstreamPeerTracer::new();
        tracer.on_connected();
        assert_eq!(1, tracer.connected.load(Ordering::Relaxed));
        tracer.on_disconnected();
        assert_eq!(0, tracer.connected.load(Ordering::Relaxed));
    }
}
