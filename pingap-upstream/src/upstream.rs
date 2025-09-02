// Copyright 2024-2025 Tree xie.
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

use crate::hash_strategy::HashStrategy;
use crate::peer_tracer::UpstreamPeerTracer;
use crate::{UpstreamProvider, LOG_CATEGORY};
use ahash::AHashMap;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use derive_more::Debug;
use futures_util::FutureExt;
use pingap_config::UpstreamConf;
use pingap_core::{
    BackgroundTask, BackgroundTaskService, Error as ServiceError,
};
use pingap_core::{NotificationData, NotificationLevel, NotificationSender};
use pingap_discovery::{
    is_dns_discovery, is_docker_discovery, is_static_discovery,
    new_dns_discover_backends, new_docker_discover_backends,
    new_static_discovery, Discovery, TRANSPARENT_DISCOVERY,
};
use pingap_health::new_health_check;
use pingora::lb::health_check::{HealthObserve, HealthObserveCallback};
use pingora::lb::selection::{
    BackendIter, BackendSelection, Consistent, RoundRobin,
};
use pingora::lb::Backend;
use pingora::lb::{Backends, LoadBalancer};
use pingora::protocols::l4::ext::TcpKeepalive;
use pingora::protocols::ALPN;
use pingora::proxy::Session;
use pingora::upstreams::peer::{HttpPeer, Tracer};
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use std::collections::HashMap;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tracing::{debug, error, info};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Common error, category: {category}, {message}"))]
    Common { message: String, category: String },
}
type Result<T, E = Error> = std::result::Result<T, E>;

pub struct BackendObserveNotification {
    name: String,
    sender: Arc<NotificationSender>,
}

#[async_trait]
impl HealthObserve for BackendObserveNotification {
    async fn observe(&self, backend: &Backend, healthy: bool) {
        let addr = backend.addr.to_string();
        let template = format!("upstream {}({addr}) becomes ", self.name);
        let info = if healthy {
            (NotificationLevel::Info, template + "healthy")
        } else {
            (NotificationLevel::Error, template + "unhealthy")
        };

        self.sender
            .notify(NotificationData {
                category: "backend_status".to_string(),
                level: info.0,
                title: "Upstream backend status changed".to_string(),
                message: info.1,
            })
            .await;
    }
}

fn new_observe(
    name: &str,
    sender: Option<Arc<NotificationSender>>,
) -> Option<HealthObserveCallback> {
    if let Some(sender) = sender {
        Some(Box::new(BackendObserveNotification {
            name: name.to_string(),
            sender: sender.clone(),
        }))
    } else {
        None
    }
}

// SelectionLb represents different load balancing strategies:
// - RoundRobin: Distributes requests evenly across backends
// - Consistent: Uses consistent hashing to map requests to backends
// - Transparent: Passes requests through without load balancing
enum SelectionLb {
    // Instead of storing Arc<LoadBalancer<S>>, we store Arc<dyn LoadBalancerTrait>.
    // This avoids the need for `as_round_robin`, `as_consistent`, etc.
    RoundRobin(LoadBalancer<RoundRobin>),
    Consistent {
        lb: LoadBalancer<Consistent>,
        hash: HashStrategy,
    },
    Transparent,
}

#[derive(Debug)]
/// Represents a group of backend servers and their configuration for load balancing and connection management
pub struct Upstream {
    /// Unique identifier for this upstream group
    pub name: String,

    /// Hash key used to detect configuration changes
    pub key: String,

    /// Whether to use TLS for connections to backend servers
    tls: bool,

    /// Server Name Indication value for TLS connections
    /// Special value "$host" means use the request's Host header
    sni: String,

    /// Load balancing strategy implementation:
    /// - RoundRobin: Distributes requests evenly
    /// - Consistent: Uses consistent hashing
    /// - Transparent: Direct passthrough
    #[debug("lb")]
    lb: SelectionLb,

    /// Maximum time to wait for establishing a connection
    connection_timeout: Option<Duration>,

    /// Maximum time for the entire connection lifecycle
    total_connection_timeout: Option<Duration>,

    /// Maximum time to wait for reading data
    read_timeout: Option<Duration>,

    /// Maximum time a connection can be idle before being closed
    idle_timeout: Option<Duration>,

    /// Maximum time to wait for writing data
    write_timeout: Option<Duration>,

    /// Whether to verify TLS certificates from backend servers
    verify_cert: Option<bool>,

    /// Application Layer Protocol Negotiation settings (H1, H2, H2H1)
    alpn: ALPN,

    /// TCP keepalive configuration for maintaining persistent connections
    tcp_keepalive: Option<TcpKeepalive>,

    /// Size of TCP receive buffer in bytes
    tcp_recv_buf: Option<usize>,

    /// Whether to enable TCP Fast Open for reduced connection latency
    tcp_fast_open: Option<bool>,

    /// Tracer for monitoring active connections to this upstream
    peer_tracer: Option<UpstreamPeerTracer>,

    /// Generic tracer interface for connection monitoring
    tracer: Option<Tracer>,

    /// Counter for number of requests currently being processed by this upstream
    pub processing: AtomicI32,
}

impl Upstream {
    pub async fn run_health_check(&self) -> Result<()> {
        if let Some(lb) = self.as_round_robin() {
            lb.update().await.map_err(|e| Error::Common {
                category: "run_health_check".to_string(),
                message: e.to_string(),
            })?;
            lb.backends()
                .run_health_check(lb.parallel_health_check)
                .await;
        } else if let Some(lb) = self.as_consistent() {
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
    pub fn is_transparent(&self) -> bool {
        matches!(self.lb, SelectionLb::Transparent)
    }
}

// Creates new backend servers based on discovery method (DNS/Docker/Static)
fn new_backends(
    discovery_category: &str,
    discovery: &Discovery,
) -> Result<Backends> {
    let (result, category) = match discovery_category {
        d if is_dns_discovery(d) => {
            (new_dns_discover_backends(discovery), "dns_discovery")
        },
        d if is_docker_discovery(d) => {
            (new_docker_discover_backends(discovery), "docker_discovery")
        },
        _ => (new_static_discovery(discovery), "static_discovery"),
    };
    result.map_err(|e| Error::Common {
        category: category.to_string(),
        message: e.to_string(),
    })
}

/// Get the processing and connected status of all upstreams
///
/// # Returns
/// * `HashMap<String, (i32, Option<i32>)>` - Processing and connected status of all upstreams
pub fn get_upstreams_processing_connected(
    upstreams: Arc<dyn UpstreamProvider>,
) -> HashMap<String, (i32, Option<i32>)> {
    let mut processing_connected = HashMap::new();
    upstreams.list().iter().for_each(|(k, v)| {
        let count = v.processing.load(Ordering::Relaxed);
        let connected = v.connected();
        processing_connected.insert(k.to_string(), (count, connected));
    });
    processing_connected
}

fn update_health_check_params<S>(
    mut lb: LoadBalancer<S>,
    name: &str,
    conf: &UpstreamConf,
    sender: Option<Arc<NotificationSender>>,
) -> Result<LoadBalancer<S>>
where
    S: BackendSelection + 'static,
    S::Iter: BackendIter,
{
    let mut update_frequency = if let Some(value) = conf.update_frequency {
        Some(value)
    } else {
        Some(Duration::from_secs(60))
    };
    // For static discovery, perform immediate backend update
    if is_static_discovery(&conf.guess_discovery()) {
        update_frequency = None;
        lb.update()
            .now_or_never()
            .expect("static should not block")
            .expect("static should not error");
    }

    // Set up health checking for the backends
    let (health_check_conf, hc) = new_health_check(
        name,
        &conf.health_check.clone().unwrap_or_default(),
        new_observe(name, sender),
    )
    .map_err(|e| Error::Common {
        message: e.to_string(),
        category: "health".to_string(),
    })?;
    // Configure health checking
    lb.parallel_health_check = health_check_conf.parallel_check;
    lb.set_health_check(hc);
    lb.update_frequency = update_frequency;
    lb.health_check_frequency = Some(health_check_conf.check_frequency);
    Ok(lb)
}

/// Creates a new load balancer instance based on the provided configuration
///
/// # Arguments
/// * `name` - Name identifier for the upstream service
/// * `conf` - Configuration for the upstream service
///
/// # Returns
/// * `Result<SelectionLb>` - Returns the load balancer
fn new_load_balancer(
    name: &str,
    conf: &UpstreamConf,
    sender: Option<Arc<NotificationSender>>,
) -> Result<SelectionLb> {
    // Validate that addresses are provided
    if conf.addrs.is_empty() {
        return Err(Error::Common {
            category: "new_upstream".to_string(),
            message: "upstream addrs is empty".to_string(),
        });
    }

    // Determine the service discovery method
    let discovery_category = conf.guess_discovery();
    // For transparent discovery, return early with no load balancing
    if discovery_category == TRANSPARENT_DISCOVERY {
        return Ok(SelectionLb::Transparent);
    }

    // Determine if TLS should be enabled based on SNI configuration
    let tls = conf
        .sni
        .as_ref()
        .map(|item| !item.is_empty())
        .unwrap_or_default();

    // Create backend servers using the configured addresses and discovery method
    let mut discovery = Discovery::new(conf.addrs.clone())
        .with_ipv4_only(conf.ipv4_only.unwrap_or_default())
        .with_tls(tls)
        .with_sender(sender.clone());
    if let Some(dns_server) = &conf.dns_server {
        discovery = discovery.with_dns_server(dns_server.clone());
    }
    if let Some(dns_domain) = &conf.dns_domain {
        discovery = discovery.with_domain(dns_domain.clone());
    }
    if let Some(dns_search) = &conf.dns_search {
        discovery = discovery.with_search(dns_search.clone());
    }
    let backends = new_backends(&discovery_category, &discovery)?;

    // Parse the load balancing algorithm configuration
    // Format: "algo:hash_type:hash_key" (e.g. "hash:cookie:session_id")
    // let algo_method = conf.algo.clone().unwrap_or_default();
    let algo_method = conf.algo.as_deref().unwrap_or("round_robin");

    match algo_method.split(':').collect::<Vec<_>>().as_slice() {
        ["hash", hash_type, hash_key] => {
            let lb = update_health_check_params(
                LoadBalancer::<Consistent>::from_backends(backends),
                name,
                conf,
                sender,
            )?;
            Ok(SelectionLb::Consistent {
                lb,
                hash: HashStrategy::from((*hash_type, *hash_key)),
            })
        },
        _ => {
            // Default to RoundRobin
            let lb = update_health_check_params(
                LoadBalancer::<RoundRobin>::from_backends(backends),
                name,
                conf,
                sender,
            )?;
            Ok(SelectionLb::RoundRobin(lb))
        },
    }
}

impl Upstream {
    /// Creates a new Upstream instance from the provided configuration
    ///
    /// # Arguments
    /// * `name` - Name identifier for the upstream service
    /// * `conf` - Configuration parameters for the upstream service
    ///
    /// # Returns
    /// * `Result<Self>` - New Upstream instance or error if creation fails
    pub fn new(
        name: &str,
        conf: &UpstreamConf,
        sender: Option<Arc<NotificationSender>>,
    ) -> Result<Self> {
        let lb = new_load_balancer(name, conf, sender)?;
        let key = conf.hash_key();
        let sni = conf.sni.clone().unwrap_or_default();
        let tls = !sni.is_empty();

        let alpn = if let Some(alpn) = &conf.alpn {
            match alpn.to_uppercase().as_str() {
                "H2H1" => ALPN::H2H1,
                "H2" => ALPN::H2,
                _ => ALPN::H1,
            }
        } else {
            ALPN::H1
        };

        let tcp_keepalive = if (conf.tcp_idle.is_some()
            && conf.tcp_probe_count.is_some()
            && conf.tcp_interval.is_some())
            || conf.tcp_user_timeout.is_some()
        {
            Some(TcpKeepalive {
                idle: conf.tcp_idle.unwrap_or_default(),
                count: conf.tcp_probe_count.unwrap_or_default(),
                interval: conf.tcp_interval.unwrap_or_default(),
                #[cfg(target_os = "linux")]
                user_timeout: conf.tcp_user_timeout.unwrap_or_default(),
            })
        } else {
            None
        };

        let peer_tracer = if conf.enable_tracer.unwrap_or_default() {
            Some(UpstreamPeerTracer::new(name))
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
            sni,
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
        debug!(
            category = LOG_CATEGORY,
            name = up.name,
            "new upstream: {up:?}"
        );
        Ok(up)
    }

    /// Creates and configures a new HTTP peer for handling requests
    ///
    /// # Arguments
    /// * `session` - Current HTTP session containing request details
    /// * `ctx` - Request context state
    ///
    /// # Returns
    /// * `Option<HttpPeer>` - Configured HTTP peer if a healthy backend is available, None otherwise
    ///
    /// This method:
    /// 1. Selects an appropriate backend using the configured load balancing strategy
    /// 2. Increments the processing counter
    /// 3. Creates and configures an HttpPeer with the connection settings
    #[inline]
    pub fn new_http_peer(
        &self,
        session: &Session,
        client_ip: &Option<String>,
    ) -> Option<HttpPeer> {
        // Select a backend based on the load balancing strategy
        let upstream = match &self.lb {
            // For round-robin, use empty key since selection is sequential
            SelectionLb::RoundRobin(lb) => lb.select(b"", 256),
            // For consistent hashing, generate hash value from request details
            SelectionLb::Consistent { lb, hash } => {
                let value = hash.get_value(session, client_ip);
                lb.select(value.as_bytes(), 256)
            },
            // For transparent mode, no backend selection needed
            SelectionLb::Transparent => None,
        };
        // Increment counter for requests being processed
        self.processing.fetch_add(1, Ordering::Relaxed);

        // Create HTTP peer based on load balancing mode
        let p = if matches!(self.lb, SelectionLb::Transparent) {
            // In transparent mode, use the request's host header
            let host = pingap_core::get_host(session.req_header())?;
            // Set SNI: either use host header ($host) or configured value
            let sni = if self.sni == "$host" {
                host.to_string()
            } else {
                self.sni.clone()
            };
            // use default port for transparent http/https
            let port = if self.tls { 443 } else { 80 };
            // Create peer with host:port, TLS settings, and SNI
            Some(HttpPeer::new(format!("{host}:{port}"), self.tls, sni))
        } else {
            // For load balanced modes, create peer from selected backend
            upstream.map(|upstream| {
                HttpPeer::new(upstream, self.tls, self.sni.clone())
            })
        };

        // Configure connection options for the peer
        p.map(|mut p| {
            // Set various timeout values
            p.options.connection_timeout = self.connection_timeout;
            p.options.total_connection_timeout = self.total_connection_timeout;
            p.options.read_timeout = self.read_timeout;
            p.options.idle_timeout = self.idle_timeout;
            p.options.write_timeout = self.write_timeout;
            // Configure TLS certificate verification if specified
            if let Some(verify_cert) = self.verify_cert {
                p.options.verify_cert = verify_cert;
            }
            // Set protocol negotiation settings
            p.options.alpn = self.alpn.clone();
            // Configure TCP-specific options
            p.options.tcp_keepalive.clone_from(&self.tcp_keepalive);
            p.options.tcp_recv_buf = self.tcp_recv_buf;
            if let Some(tcp_fast_open) = self.tcp_fast_open {
                p.options.tcp_fast_open = tcp_fast_open;
            }
            // Set connection tracing if enabled
            p.options.tracer.clone_from(&self.tracer);
            p
        })
    }

    /// Returns the current number of active connections to this upstream
    ///
    /// # Returns
    /// * `Option<i32>` - Number of active connections if tracking is enabled, None otherwise
    #[inline]
    pub fn connected(&self) -> Option<i32> {
        self.peer_tracer.as_ref().map(|tracer| tracer.connected())
    }

    /// Returns the round-robin load balancer if configured
    ///
    /// # Returns
    /// * `Option<Arc<LoadBalancer<RoundRobin>>>` - Round-robin load balancer if used, None otherwise
    #[inline]
    pub fn as_round_robin(&self) -> Option<&LoadBalancer<RoundRobin>> {
        match &self.lb {
            SelectionLb::RoundRobin(lb) => Some(lb),
            _ => None,
        }
    }

    /// Returns the consistent hash load balancer if configured
    ///
    /// # Returns
    /// * `Option<Arc<LoadBalancer<Consistent>>>` - Consistent hash load balancer if used, None otherwise
    #[inline]
    pub fn as_consistent(&self) -> Option<&LoadBalancer<Consistent>> {
        match &self.lb {
            SelectionLb::Consistent { lb, .. } => Some(lb),
            _ => None,
        }
    }

    /// Decrements and returns the number of requests being processed
    ///
    /// # Returns
    /// * `i32` - Previous count of requests being processed
    #[inline]
    pub fn completed(&self) -> i32 {
        self.processing.fetch_add(-1, Ordering::Relaxed)
    }
}

pub type Upstreams = AHashMap<String, Arc<Upstream>>;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamHealthyStatus {
    pub healthy: u32,
    pub total: u32,
    pub unhealthy_backends: Vec<String>,
}

/// Get the healthy status of all upstreams
///
/// # Returns
/// * `HashMap<String, UpstreamHealthyStatus>` - Healthy status of all upstreams
///
/// This function iterates through all upstreams and checks their health status.
pub fn get_upstream_healthy_status(
    upstreams: Arc<dyn UpstreamProvider>,
) -> HashMap<String, UpstreamHealthyStatus> {
    let mut healthy_status = HashMap::new();
    upstreams.list().iter().for_each(|(k, v)| {
        let mut total = 0;
        let mut healthy = 0;
        let mut unhealthy_backends = vec![];
        if let Some(lb) = v.as_round_robin() {
            let backends = lb.backends().get_backend();
            total = backends.len();
            backends.iter().for_each(|backend| {
                if lb.backends().ready(backend) {
                    healthy += 1;
                } else {
                    unhealthy_backends.push(backend.to_string());
                }
            });
        } else if let Some(lb) = v.as_consistent() {
            let backends = lb.backends().get_backend();
            total = backends.len();
            backends.iter().for_each(|backend| {
                if lb.backends().ready(backend) {
                    healthy += 1;
                } else {
                    unhealthy_backends.push(backend.to_string());
                }
            });
        }
        healthy_status.insert(
            k.to_string(),
            UpstreamHealthyStatus {
                healthy,
                total: total as u32,
                unhealthy_backends,
            },
        );
    });
    healthy_status
}

#[async_trait]
impl BackgroundTask for HealthCheckTask {
    async fn execute(&self, check_count: u32) -> Result<bool, ServiceError> {
        // get upstream names
        let upstreams = self.upstreams.list();
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

                // get update frequency(update service)
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
                            category = LOG_CATEGORY,
                            error = %e,
                            name,
                            "update backends fail"
                        )
                    } else {
                        debug!(
                            category = LOG_CATEGORY,
                            name, "update backend success"
                        );
                    }
                }

                // health check
                if !check_frequency_matched(health_check_frequency) {
                    return;
                }
                let health_check_start_time = SystemTime::now();
                if let Some(lb) = up.as_round_robin() {
                    lb.backends()
                        .run_health_check(lb.parallel_health_check)
                        .await;
                } else if let Some(lb) = up.as_consistent() {
                    lb.backends()
                        .run_health_check(lb.parallel_health_check)
                        .await;
                }
                info!(
                    category = LOG_CATEGORY,
                    name,
                    elapsed = format!(
                        "{}ms",
                        health_check_start_time
                            .elapsed()
                            .unwrap_or_default()
                            .as_millis()
                    ),
                    "health check is done"
                );
            })
        });
        futures::future::join_all(jobs).await;

        // each 10 times, check unhealthy upstreams
        if check_count % 10 == 1 {
            let current_unhealthy_upstreams =
                self.unhealthy_upstreams.load().clone();
            let mut notify_healthy_upstreams = vec![];
            let mut unhealthy_upstreams = vec![];
            for (name, status) in
                get_upstream_healthy_status(self.upstreams.clone()).iter()
            {
                if status.healthy == 0 {
                    unhealthy_upstreams.push(name.to_string());
                } else if current_unhealthy_upstreams.contains(name) {
                    notify_healthy_upstreams.push(name.to_string());
                }
            }
            let mut notify_unhealthy_upstreams = vec![];
            for name in unhealthy_upstreams.iter() {
                if !current_unhealthy_upstreams.contains(name) {
                    notify_unhealthy_upstreams.push(name.to_string());
                }
            }
            self.unhealthy_upstreams
                .store(Arc::new(unhealthy_upstreams));
            if let Some(sender) = &self.sender {
                if !notify_unhealthy_upstreams.is_empty() {
                    let data = NotificationData {
                        category: "upstream_status".to_string(),
                        title: "Upstream unhealthy".to_string(),
                        message: notify_unhealthy_upstreams.join(", "),
                        level: NotificationLevel::Error,
                    };
                    sender.notify(data).await;
                }
                if !notify_healthy_upstreams.is_empty() {
                    let data = NotificationData {
                        category: "upstream_status".to_string(),
                        title: "Upstream healthy".to_string(),
                        message: notify_healthy_upstreams.join(", "),
                        ..Default::default()
                    };
                    sender.notify(data).await;
                }
            }
        }
        Ok(true)
    }
}

struct HealthCheckTask {
    interval: Duration,
    sender: Option<Arc<NotificationSender>>,
    unhealthy_upstreams: ArcSwap<Vec<String>>,
    upstreams: Arc<dyn UpstreamProvider>,
}

pub fn new_upstream_health_check_task(
    interval: Duration,
    sender: Option<Arc<NotificationSender>>,
    upstreams: Arc<dyn UpstreamProvider>,
) -> BackgroundTaskService {
    let task = Box::new(HealthCheckTask {
        interval,
        sender,
        unhealthy_upstreams: ArcSwap::new(Arc::new(vec![])),
        upstreams,
    });
    let name = "upstream_health_check";
    let mut service =
        BackgroundTaskService::new_single(name, interval, name, task);
    service.set_immediately(true);
    service
}

#[cfg(test)]
mod tests {
    use super::{new_backends, Upstream, UpstreamConf};
    use pingap_discovery::Discovery;
    use pingora::protocols::ALPN;
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use std::time::Duration;
    use tokio_test::io::Builder;

    #[test]
    fn test_new_backends() {
        let _ = new_backends(
            "",
            &Discovery::new(vec![
                "192.168.1.1:8001 10".to_string(),
                "192.168.1.2:8001".to_string(),
            ]),
        )
        .unwrap();

        let _ = new_backends(
            "",
            &Discovery::new(vec![
                "192.168.1.1".to_string(),
                "192.168.1.2:8001".to_string(),
            ]),
        )
        .unwrap();

        let _ = new_backends(
            "dns",
            &Discovery::new(vec!["github.com".to_string()]),
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
            None,
        );
        assert_eq!(
            "Common error, category: new_upstream, upstream addrs is empty",
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
            None,
        )
        .unwrap();

        assert_eq!(ALPN::H2.to_string(), up.alpn.to_string());
        assert_eq!("Some(5s)", format!("{:?}", up.connection_timeout));
        assert_eq!("Some(10s)", format!("{:?}", up.total_connection_timeout));
        assert_eq!("Some(3s)", format!("{:?}", up.read_timeout));
        assert_eq!("Some(30s)", format!("{:?}", up.idle_timeout));
        assert_eq!("Some(5s)", format!("{:?}", up.write_timeout));
        #[cfg(target_os = "linux")]
        assert_eq!(
            "Some(TcpKeepalive { idle: 60s, interval: 60s, count: 100, user_timeout: 0ns })",
            format!("{:?}", up.tcp_keepalive)
        );
        #[cfg(not(target_os = "linux"))]
        assert_eq!(
            "Some(TcpKeepalive { idle: 60s, interval: 60s, count: 100 })",
            format!("{:?}", up.tcp_keepalive)
        );
        assert_eq!("Some(1024)", format!("{:?}", up.tcp_recv_buf));
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
            None,
        )
        .unwrap();
        assert_eq!(true, up.new_http_peer(&session, &None,).is_some());
        assert_eq!(true, up.as_round_robin().is_some());
    }
}
