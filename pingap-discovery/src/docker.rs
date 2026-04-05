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

use super::{DOCKER_DISCOVERY, Discovery, LOG_TARGET};
use super::{Error, Result};
use async_trait::async_trait;
use bollard::query_parameters::{EventsOptionsBuilder, ListContainersOptions};
use futures::StreamExt;
use http::Extensions;
use pingap_core::{NotificationData, NotificationLevel, NotificationSender};
use pingora::lb::discovery::ServiceDiscovery;
use pingora::lb::{Backend, Backends};
use pingora::protocols::l4::socket::SocketAddr;
use std::collections::{BTreeSet, HashMap};
use std::net::ToSocketAddrs;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tracing::{debug, error, info};

const CONTAINER_EVENTS: &[&str] = &[
    "start",
    "stop",
    "die",
    "kill",
    "pause",
    "unpause",
    "destroy",
    "health_status",
];

const EVENT_DEBOUNCE: Duration = Duration::from_millis(500);
const EVENT_RECONNECT_DELAY: Duration = Duration::from_secs(5);

type CachedAddrs = Vec<(std::net::SocketAddr, usize)>;

/// Container represents a Docker container with service discovery configuration
#[derive(Debug, Clone)]
struct Container {
    label: String,
    weight: usize,
    port: u16,
    addrs: Vec<String>,
}

impl Container {
    /// Creates a new Container instance from an address string
    /// Format: "label:port weight" or "label weight" or "label"
    fn new(addr: &str) -> Self {
        let (weight, label, port) = Self::parse_addr(addr);
        Self {
            label,
            weight,
            port,
            addrs: vec![],
        }
    }

    fn parse_addr(addr: &str) -> (usize, String, u16) {
        let parts: Vec<_> = addr.split(' ').collect();
        let weight = parts.get(1).and_then(|w| w.parse().ok()).unwrap_or(1);

        let (label, port) = parts[0]
            .split_once(':')
            .map(|(l, p)| (l.to_string(), p.parse().unwrap_or(0)))
            .unwrap_or((parts[0].to_string(), 0));

        (weight, label, port)
    }
}

/// Shared Docker discovery state accessible from both the event watcher
/// background task and the ServiceDiscovery impl.
struct DockerState {
    ipv4_only: bool,
    docker: bollard::Docker,
    containers: Vec<Container>,
    sender: Option<Arc<NotificationSender>>,
}

/// Checks if the discovery type is Docker
pub fn is_docker_discovery(value: &str) -> bool {
    value == DOCKER_DISCOVERY
}

impl DockerState {
    fn get_container_ports(
        container: &bollard::models::ContainerSummary,
        default_port: u16,
    ) -> Option<(u16, u16)> {
        let ports = container.ports.as_ref()?;

        if default_port > 0 {
            return Some((default_port, 0));
        }

        let port_info = ports.iter().find(|p| p.private_port > 0)?;
        Some((port_info.private_port, port_info.public_port.unwrap_or(0)))
    }

    async fn list_containers(&self) -> Result<Vec<Container>> {
        let mut containers = self.containers.clone();

        for container in containers.iter_mut() {
            let summaries: Vec<bollard::models::ContainerSummary> =
                self.list_containers_by_label(&container.label).await?;
            container.addrs = summaries
                .iter()
                .filter_map(|item| {
                    let (private_port, public_port) =
                        Self::get_container_ports(item, container.port)?;

                    let networks =
                        item.network_settings.as_ref()?.networks.as_ref()?;

                    let mut addrs = Vec::new();
                    for network in networks.values() {
                        if public_port > 0 {
                            if let Some(gateway) = &network.gateway {
                                addrs.push(format!("{gateway}:{public_port}"));
                            }
                        } else if let Some(ip) = &network.ip_address {
                            addrs.push(format!("{ip}:{private_port}"));
                        }
                    }
                    Some(addrs)
                })
                .flatten()
                .collect();
        }

        Ok(containers)
    }

    async fn list_containers_by_label(
        &self,
        label: &String,
    ) -> Result<Vec<bollard::models::ContainerSummary>> {
        let mut filters = HashMap::new();
        filters.insert("label".to_string(), vec![label.to_string()]);
        self.docker
            .list_containers(Some(ListContainersOptions {
                filters: Some(filters),
                ..Default::default()
            }))
            .await
            .map_err(|e| Error::Docker { source: e })
    }

    fn labels(&self) -> Vec<String> {
        self.containers
            .iter()
            .map(|item| item.label.clone())
            .collect()
    }

    /// Resolves all matching containers to a list of (SocketAddr, weight) pairs.
    async fn resolve_addrs(&self) -> Result<CachedAddrs> {
        let mut addrs = Vec::new();

        debug!(
            names = format!("{:?}", self.labels()),
            "docker discover is running"
        );
        let containers = self.list_containers().await?;
        for container in containers.iter() {
            for addr in container.addrs.iter() {
                for socket_addr in
                    addr.to_socket_addrs().map_err(|e| Error::Io {
                        source: e,
                        content: format!("{addr} to socket addr fail"),
                    })?
                {
                    if self.ipv4_only && !socket_addr.is_ipv4() {
                        continue;
                    }
                    addrs.push((socket_addr, container.weight));
                }
            }
        }

        Ok(addrs)
    }
}

fn addrs_to_backends(
    addrs: &CachedAddrs,
) -> (BTreeSet<Backend>, HashMap<u64, bool>) {
    let upstreams: BTreeSet<Backend> = addrs
        .iter()
        .map(|(addr, weight)| Backend {
            addr: SocketAddr::Inet(*addr),
            weight: *weight,
            ext: Extensions::new(),
        })
        .collect();
    (upstreams, HashMap::new())
}

/// Docker service discovery with event-based real-time updates.
///
/// A background task watches Docker container events (start, stop, die, etc.)
/// and refreshes the cached address list immediately, with debouncing to batch
/// rapid successive events. The `discover()` method reads from this cache,
/// falling back to direct discovery if the cache is not yet populated.
struct Docker {
    state: Arc<DockerState>,
    cached: Arc<Mutex<Option<CachedAddrs>>>,
    watcher_init: std::sync::Once,
}

impl Docker {
    fn new(
        addrs: &[String],
        ipv4_only: bool,
        sender: Option<Arc<NotificationSender>>,
    ) -> Result<Self> {
        let docker = bollard::Docker::connect_with_local_defaults()
            .map_err(|e| Error::Docker { source: e })?;

        let containers =
            addrs.iter().map(|addr| Container::new(addr)).collect();

        let state = Arc::new(DockerState {
            docker,
            containers,
            ipv4_only,
            sender,
        });

        let cached = Arc::new(Mutex::new(None));

        Ok(Self {
            state,
            cached,
            watcher_init: std::sync::Once::new(),
        })
    }

    fn read_cache(&self) -> Option<CachedAddrs> {
        self.cached.lock().ok()?.clone()
    }

    /// Ensures the background event watcher is spawned exactly once.
    /// Must be called from within a Tokio runtime context.
    fn ensure_watcher_started(&self) {
        let state = self.state.clone();
        let cached = self.cached.clone();
        self.watcher_init.call_once(move || {
            tokio::spawn(watch_docker_events(state, cached));
        });
    }
}

/// Refreshes the cached address list by querying Docker for matching containers.
async fn refresh_cache(
    state: &DockerState,
    cached: &Mutex<Option<CachedAddrs>>,
) {
    let now = SystemTime::now();
    let names = state.labels();
    match state.resolve_addrs().await {
        Ok(addrs) => {
            let addr_strs: Vec<String> =
                addrs.iter().map(|(a, _)| a.to_string()).collect();
            info!(
                target: LOG_TARGET,
                names = names.join(","),
                addrs = addr_strs.join(","),
                elapsed =
                    format!("{}ms", now.elapsed().unwrap_or_default().as_millis()),
                "docker discover refreshed via event"
            );
            if let Ok(mut guard) = cached.lock() {
                *guard = Some(addrs);
            }
        },
        Err(e) => {
            error!(
                target: LOG_TARGET,
                error = %e,
                names = names.join(","),
                "docker discover refresh failed"
            );
            if let Some(sender) = &state.sender {
                let msg = format!(
                    "docker discovery {:?}, error: {e}",
                    state.labels(),
                );
                sender
                    .notify(NotificationData {
                        category: "service_discover_fail".to_string(),
                        level: NotificationLevel::Warn,
                        message: msg,
                        ..Default::default()
                    })
                    .await;
            }
        },
    }
}

/// Background task: watches Docker container events and refreshes the
/// cached address list in real time. Reconnects automatically on stream
/// errors with a delay.
async fn watch_docker_events(
    state: Arc<DockerState>,
    cached: Arc<Mutex<Option<CachedAddrs>>>,
) {
    refresh_cache(&state, &cached).await;

    loop {
        let mut filters = HashMap::new();
        filters.insert("type".to_string(), vec!["container".to_string()]);
        filters.insert(
            "event".to_string(),
            CONTAINER_EVENTS.iter().map(|s| s.to_string()).collect(),
        );

        let options = EventsOptionsBuilder::default().filters(&filters).build();

        let mut stream = state.docker.events(Some(options));

        info!(
            target: LOG_TARGET,
            names = ?state.labels(),
            "docker event watcher started"
        );

        'events: while let Some(result) = stream.next().await {
            match result {
                Ok(event) => {
                    info!(
                        target: LOG_TARGET,
                        action = ?event.action,
                        names = ?state.labels(),
                        "docker container event received"
                    );
                    // Debounce: drain events arriving within a short window
                    // before refreshing, to batch rapid successive events
                    // (e.g. scaling up multiple containers at once).
                    let deadline = tokio::time::Instant::now() + EVENT_DEBOUNCE;
                    loop {
                        match tokio::time::timeout_at(deadline, stream.next())
                            .await
                        {
                            Err(_) => break,
                            Ok(Some(Ok(_))) => continue,
                            _ => {
                                refresh_cache(&state, &cached).await;
                                break 'events;
                            },
                        }
                    }
                    refresh_cache(&state, &cached).await;
                },
                Err(e) => {
                    error!(
                        target: LOG_TARGET,
                        error = %e,
                        "docker event stream error, will reconnect"
                    );
                    break;
                },
            }
        }

        tokio::time::sleep(EVENT_RECONNECT_DELAY).await;
    }
}

#[async_trait]
impl ServiceDiscovery for Docker {
    async fn discover(
        &self,
    ) -> pingora::Result<(BTreeSet<Backend>, HashMap<u64, bool>)> {
        self.ensure_watcher_started();

        let now = SystemTime::now();
        let names: Vec<String> = self.state.labels();

        // Fast path: return data from the event-driven cache.
        if let Some(addrs) = self.read_cache() {
            let result = addrs_to_backends(&addrs);
            let addr_strs: Vec<String> =
                result.0.iter().map(|b| b.addr.to_string()).collect();
            info!(
                target: LOG_TARGET,
                names = names.join(","),
                addrs = addr_strs.join(","),
                elapsed = format!(
                    "{}ms",
                    now.elapsed().unwrap_or_default().as_millis()
                ),
                "docker discover from cache"
            );
            return Ok(result);
        }

        // Slow path: cache not yet populated (first call before the
        // background watcher has completed its initial discovery).
        match self.state.resolve_addrs().await {
            Ok(addrs) => {
                if let Ok(mut guard) = self.cached.lock() {
                    *guard = Some(addrs.clone());
                }
                let result = addrs_to_backends(&addrs);
                let addr_strs: Vec<String> =
                    result.0.iter().map(|b| b.addr.to_string()).collect();
                info!(
                    target: LOG_TARGET,
                    names = names.join(","),
                    addrs = addr_strs.join(","),
                    elapsed = format!(
                        "{}ms",
                        now.elapsed().unwrap_or_default().as_millis()
                    ),
                    "docker discover success"
                );
                Ok(result)
            },
            Err(e) => {
                error!(
                    target: LOG_TARGET,
                    error = %e,
                    names = names.join(","),
                    elapsed = format!(
                        "{}ms",
                        now.elapsed().unwrap_or_default().as_millis()
                    ),
                    "docker discover fail"
                );
                if let Some(sender) = &self.state.sender {
                    sender
                        .notify(NotificationData {
                            category: "service_discover_fail".to_string(),
                            level: NotificationLevel::Warn,
                            message: format!(
                                "docker discovery {:?}, error: {e}",
                                self.state.labels(),
                            ),
                            ..Default::default()
                        })
                        .await;
                }
                Err(e.into())
            },
        }
    }
}

/// Creates a new Docker service discovery backend with event-based updates.
pub fn new_docker_discover_backends(discovery: &Discovery) -> Result<Backends> {
    let docker = Docker::new(
        &discovery.addr,
        discovery.ipv4_only,
        discovery.sender.clone(),
    )?;
    let backends = Backends::new(Box::new(docker));
    Ok(backends)
}
