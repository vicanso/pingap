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
    is_dns_discovery, is_docker_discovery, is_static_discovery,
    new_common_discover_backends, new_dns_discover_backends,
    new_docker_discover_backends,
};
use crate::health::new_health_check;
use crate::service::{CommonServiceTask, ServiceTask};
use crate::state::State;
use crate::util;
use ahash::AHashMap;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use futures_util::FutureExt;
use once_cell::sync::Lazy;
use pingora::lb::selection::{Consistent, RoundRobin};
use pingora::lb::{Backends, LoadBalancer};
use pingora::protocols::l4::ext::TcpKeepalive;
use pingora::protocols::ALPN;
use pingora::proxy::Session;
use pingora::upstreams::peer::{HttpPeer, Tracer, Tracing};
use snafu::Snafu;
use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Common error, category: {category}, {message}"))]
    Common { message: String, category: String },
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
    pub key: String,
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
    processing: AtomicI32,
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

fn new_backends(
    addrs: &[String],
    tls: bool,
    ipv4_only: bool,
    discovery: &str,
) -> Result<Backends> {
    if is_dns_discovery(discovery) {
        new_dns_discover_backends(addrs, tls, ipv4_only).map_err(|e| {
            Error::Common {
                category: "dns_discovery".to_string(),
                message: e.to_string(),
            }
        })
    } else if is_docker_discovery(discovery) {
        new_docker_discover_backends(addrs, tls, ipv4_only).map_err(|e| {
            Error::Common {
                category: "docker_discovery".to_string(),
                message: e.to_string(),
            }
        })
    } else {
        new_common_discover_backends(addrs, tls, ipv4_only).map_err(|e| {
            Error::Common {
                category: "static_discovery".to_string(),
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
            return Err(Error::Common {
                category: "new_upstream".to_string(),
                message: "Upstream addrs is empty".to_string(),
            });
        }
        let key = conf.hash_key();
        let discovery = conf.discovery.clone().unwrap_or_default();
        let mut hash = "".to_string();
        let sni = conf.sni.clone().unwrap_or_default();
        let tls = !sni.is_empty();
        let backends = new_backends(
            &conf.addrs,
            tls,
            conf.ipv4_only.unwrap_or_default(),
            discovery.as_str(),
        )?;

        let (hc, health_check_frequency) = new_health_check(
            name,
            &conf.health_check.clone().unwrap_or_default(),
        )
        .map_err(|e| Error::Common {
            message: e.to_string(),
            category: "health".to_string(),
        })?;

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
                if is_static_discovery(&discovery) {
                    lb.update()
                        .now_or_never()
                        .expect("static should not block")
                        .expect("static should not error");
                }
                lb.set_health_check(hc);
                lb.update_frequency = conf.update_frequency;
                lb.health_check_frequency = Some(health_check_frequency);
                SelectionLb::Consistent(Arc::new(lb))
            },
            _ => {
                let mut lb =
                    LoadBalancer::<RoundRobin>::from_backends(backends);
                if is_static_discovery(&discovery) {
                    lb.update()
                        .now_or_never()
                        .expect("static should not block")
                        .expect("static should not error");
                }
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
            key,
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
            processing: AtomicI32::new(0),
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
        self.processing.fetch_add(1, Ordering::Relaxed);
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
    pub fn as_round_robin(&self) -> Option<Arc<LoadBalancer<RoundRobin>>> {
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
    #[inline]
    pub fn completed(&self) -> i32 {
        self.processing.fetch_add(-1, Ordering::Relaxed)
    }
}

type Upstreams = AHashMap<String, Arc<Upstream>>;
static UPSTREAM_MAP: Lazy<ArcSwap<Upstreams>> =
    Lazy::new(|| ArcSwap::from_pointee(AHashMap::new()));

pub fn get_upstream(name: &str) -> Option<Arc<Upstream>> {
    UPSTREAM_MAP.load().get(name).cloned()
}

fn new_ahash_upstreams(
    confs: &HashMap<String, UpstreamConf>,
) -> Result<(Upstreams, Vec<String>)> {
    let mut upstreams = AHashMap::new();
    let mut updated_upstreams = vec![];
    for (name, conf) in confs.iter() {
        let key = conf.hash_key();
        if let Some(found) = get_upstream(name) {
            // not modified
            if found.key == key {
                upstreams.insert(name.to_string(), found);
                continue;
            }
        }
        let up = Arc::new(Upstream::new(name, conf)?);
        upstreams.insert(name.to_string(), up);
        updated_upstreams.push(name.to_string());
    }
    Ok((upstreams, updated_upstreams))
}

pub fn try_init_upstreams(confs: &HashMap<String, UpstreamConf>) -> Result<()> {
    let (upstreams, _) = new_ahash_upstreams(confs)?;
    UPSTREAM_MAP.store(Arc::new(upstreams));
    Ok(())
}

async fn run_health_check(up: &Arc<Upstream>) -> Result<()> {
    if let Some(lb) = up.as_round_robin() {
        lb.update().await.map_err(|e| Error::Common {
            category: "run_health_check".to_string(),
            message: e.to_string(),
        })?;
        lb.backends()
            .run_health_check(lb.parallel_health_check)
            .await;
    } else if let Some(lb) = up.as_consistent() {
        lb.update().await.map_err(|e| Error::Common {
            category: "run_health_check".to_string(),
            message: e.to_string(),
        })?;
        lb.backends()
            .run_health_check(lb.parallel_health_check)
            .await;
    }
    Ok(())
}

pub async fn try_update_upstreams(
    confs: &HashMap<String, UpstreamConf>,
) -> Result<Vec<String>> {
    let (upstreams, updated_upstreams) = new_ahash_upstreams(confs)?;
    for (name, up) in upstreams.iter() {
        // no need to run health check if not new upstream
        if !updated_upstreams.contains(name) {
            continue;
        }
        if let Err(e) = run_health_check(up).await {
            error!(
                error = e.to_string(),
                upstream = name,
                "update upstream health check fail"
            );
        }
    }
    UPSTREAM_MAP.store(Arc::new(upstreams));
    Ok(updated_upstreams)
}

#[async_trait]
impl ServiceTask for HealthCheckTask {
    async fn run(&self) -> Option<bool> {
        let check_count = self.count.fetch_add(1, Ordering::Relaxed);
        // get upstream names
        let upstreams = {
            let mut upstreams = vec![];
            for (name, up) in UPSTREAM_MAP.load().iter() {
                upstreams.push((name.to_string(), up.clone()));
            }
            upstreams
        };
        let interval = self.interval.as_secs();
        // run health check for each upstream
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

                // get update frequecy(update service)
                // and health check frequency
                let (update_frequency, health_check_frequency) =
                    if let Some(lb) = up.as_round_robin() {
                        let update_frequency =
                            lb.update_frequency.unwrap_or_default().as_secs();
                        let health_check_frequency = lb
                            .health_check_frequency
                            .unwrap_or_default()
                            .as_secs();
                        (update_frequency, health_check_frequency)
                    } else if let Some(lb) = up.as_consistent() {
                        let update_frequency =
                            lb.update_frequency.unwrap_or_default().as_secs();
                        let health_check_frequency = lb
                            .health_check_frequency
                            .unwrap_or_default()
                            .as_secs();
                        (update_frequency, health_check_frequency)
                    } else {
                        (0, 0)
                    };

                // the first time should match
                // update check
                if check_count == 0
                    || (update_frequency > 0
                        && check_frequency_matched(update_frequency))
                {
                    let result = if let Some(lb) = up.as_round_robin() {
                        lb.update().await
                    } else if let Some(lb) = up.as_consistent() {
                        lb.update().await
                    } else {
                        Ok(())
                    };
                    if let Err(e) = result {
                        error!(
                            error = e.to_string(),
                            name, "update backends fail"
                        )
                    } else {
                        debug!(name, "update backend success",);
                    }
                }

                // health check
                if !check_frequency_matched(health_check_frequency) {
                    return;
                }

                if let Some(lb) = up.as_round_robin() {
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
        "UpstreamHc".to_string()
    }
}

struct HealthCheckTask {
    interval: Duration,
    count: AtomicU32,
}

pub fn new_upstream_health_check_task(interval: Duration) -> CommonServiceTask {
    let interval = interval.max(Duration::from_secs(10));
    CommonServiceTask::new(
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
        get_hash_value, new_backends, State, Upstream, UpstreamConf,
        UpstreamPeerTracer,
    };
    use pingora::protocols::ALPN;
    use pingora::proxy::Session;
    use pingora::upstreams::peer::Tracing;
    use pretty_assertions::assert_eq;
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    use tokio_test::io::Builder;

    #[test]
    fn test_new_backends() {
        let _ = new_backends(
            &[
                "192.168.1.1:8001 10".to_string(),
                "192.168.1.2:8001".to_string(),
            ],
            false,
            true,
            "",
        )
        .unwrap();

        let _ = new_backends(
            &["192.168.1.1".to_string(), "192.168.1.2:8001".to_string()],
            true,
            true,
            "",
        )
        .unwrap();

        let _ = new_backends(&["github.com".to_string()], true, false, "dns")
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
            "Common error, category: new_upstream, Upstream addrs is empty",
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
        assert_eq!(true, up.as_round_robin().is_some());
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
