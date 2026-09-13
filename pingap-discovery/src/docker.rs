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

use super::{DOCKER_DISCOVERY, Discovery, LOG_TARGET, split_addr};
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
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;
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

/// One `addrs` entry: the label containers are matched by, the port to
/// reach them on (0 for the container's own published port) and the weight
/// every matching container gets.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Container {
    label: String,
    weight: usize,
    port: u16,
}

impl Container {
    /// Parses `label[:port] [weight]`. A bad port or weight is a
    /// configuration error, the same as for the other discoveries.
    fn new(addr: &str) -> Result<Self> {
        let (label, port, weight) = split_addr(addr)?;
        Ok(Self {
            label,
            weight,
            port: port.unwrap_or(0),
        })
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

    async fn list_containers_by_label(
        &self,
        label: &str,
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

    /// Resolves all matching containers to a list of (SocketAddr, weight)
    /// pairs. Docker reports addresses as IP literals, so they are parsed
    /// directly; a network without a usable address (host networking
    /// leaves `ip_address` empty) is skipped rather than failing the whole
    /// round.
    async fn resolve_addrs(&self) -> Result<CachedAddrs> {
        let mut addrs = Vec::new();

        debug!(
            names = format!("{:?}", self.labels()),
            "docker discover is running"
        );
        for container in self.containers.iter() {
            let summaries =
                self.list_containers_by_label(&container.label).await?;
            for summary in summaries.iter() {
                let Some((private_port, public_port)) =
                    Self::get_container_ports(summary, container.port)
                else {
                    continue;
                };
                let Some(networks) = summary
                    .network_settings
                    .as_ref()
                    .and_then(|settings| settings.networks.as_ref())
                else {
                    continue;
                };
                for network in networks.values() {
                    // A published port is reached through the gateway, an
                    // unpublished one through the container's own address.
                    let (ip, port) = if public_port > 0 {
                        (network.gateway.as_deref(), public_port)
                    } else {
                        (network.ip_address.as_deref(), private_port)
                    };
                    let Some(ip) = ip.and_then(|ip| ip.parse::<IpAddr>().ok())
                    else {
                        debug!(
                            target: LOG_TARGET,
                            label = container.label,
                            "container network has no usable address"
                        );
                        continue;
                    };
                    if self.ipv4_only && !ip.is_ipv4() {
                        continue;
                    }
                    addrs.push((
                        std::net::SocketAddr::new(ip, port),
                        container.weight,
                    ));
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
    /// The event watcher, started by the first `discover` and stopped when
    /// this discovery is dropped: a reload replaces the upstream, and the
    /// old watcher must not keep its Docker connection, its refreshes and
    /// its failure notifications going for an upstream nobody uses.
    watcher: Mutex<Option<JoinHandle<()>>>,
}

impl Docker {
    fn new(
        addrs: &[String],
        ipv4_only: bool,
        sender: Option<Arc<NotificationSender>>,
    ) -> Result<Self> {
        let docker = bollard::Docker::connect_with_local_defaults()
            .map_err(|e| Error::Docker { source: e })?;

        let containers = addrs
            .iter()
            .map(|addr| Container::new(addr))
            .collect::<Result<Vec<_>>>()?;

        let state = Arc::new(DockerState {
            docker,
            containers,
            ipv4_only,
            sender,
        });

        Ok(Self {
            state,
            cached: Arc::new(Mutex::new(None)),
            watcher: Mutex::new(None),
        })
    }

    fn read_cache(&self) -> Option<CachedAddrs> {
        self.cached
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Spawns the background event watcher on the first call. Must run
    /// inside a Tokio runtime.
    fn ensure_watcher_started(&self) {
        let mut watcher = self
            .watcher
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if watcher.is_none() {
            *watcher = Some(tokio::spawn(watch_docker_events(
                self.state.clone(),
                self.cached.clone(),
            )));
        }
    }
}

impl Drop for Docker {
    fn drop(&mut self) {
        if let Some(watcher) = self
            .watcher
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            watcher.abort();
        }
    }
}

/// Refreshes the cached address list by querying Docker for matching
/// containers. A refresh that finds the same addresses is routine and logged
/// at debug; a changed set is logged at info.
async fn refresh_cache(
    state: &DockerState,
    cached: &Mutex<Option<CachedAddrs>>,
) {
    let start = Instant::now();
    let names = state.labels();
    match state.resolve_addrs().await {
        Ok(addrs) => {
            let changed = {
                let mut guard = cached
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let changed = guard.as_ref() != Some(&addrs);
                *guard = Some(addrs.clone());
                changed
            };
            let addr_strs: Vec<String> =
                addrs.iter().map(|(a, _)| a.to_string()).collect();
            if changed {
                info!(
                    target: LOG_TARGET,
                    names = names.join(","),
                    addrs = addr_strs.join(","),
                    elapsed = format!("{}ms", start.elapsed().as_millis()),
                    "docker discover refreshed"
                );
            } else {
                debug!(
                    target: LOG_TARGET,
                    names = names.join(","),
                    addrs = addr_strs.join(","),
                    "docker discover unchanged"
                );
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
/// errors with a delay, re-listing the containers first so nothing that
/// happened while the stream was down is missed.
async fn watch_docker_events(
    state: Arc<DockerState>,
    cached: Arc<Mutex<Option<CachedAddrs>>>,
) {
    loop {
        // Catch up: at start, and after every reconnect.
        refresh_cache(&state, &cached).await;

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

        while let Some(result) = stream.next().await {
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
                    let mut stream_ended = false;
                    loop {
                        match tokio::time::timeout_at(deadline, stream.next())
                            .await
                        {
                            Err(_) => break,
                            Ok(Some(Ok(_))) => continue,
                            _ => {
                                stream_ended = true;
                                break;
                            },
                        }
                    }
                    refresh_cache(&state, &cached).await;
                    if stream_ended {
                        // The reconnect below refreshes again.
                        break;
                    }
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

        let names: Vec<String> = self.state.labels();

        // Fast path: the event-driven cache. Serving it is routine; the
        // watcher logs when the set changes.
        if let Some(addrs) = self.read_cache() {
            debug!(
                target: LOG_TARGET,
                names = names.join(","),
                count = addrs.len(),
                "docker discover from cache"
            );
            return Ok(addrs_to_backends(&addrs));
        }

        // Slow path: cache not yet populated (first call before the
        // background watcher has completed its initial discovery).
        let start = Instant::now();
        match self.state.resolve_addrs().await {
            Ok(addrs) => {
                *self
                    .cached
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) =
                    Some(addrs.clone());
                let result = addrs_to_backends(&addrs);
                let addr_strs: Vec<String> =
                    result.0.iter().map(|b| b.addr.to_string()).collect();
                info!(
                    target: LOG_TARGET,
                    names = names.join(","),
                    addrs = addr_strs.join(","),
                    elapsed = format!("{}ms", start.elapsed().as_millis()),
                    "docker discover success"
                );
                Ok(result)
            },
            Err(e) => {
                error!(
                    target: LOG_TARGET,
                    error = %e,
                    names = names.join(","),
                    elapsed = format!("{}ms", start.elapsed().as_millis()),
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

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_container_new() {
        assert_eq!(
            Container {
                label: "app=api".to_string(),
                weight: 1,
                port: 0,
            },
            Container::new("app=api").unwrap()
        );
        assert_eq!(
            Container {
                label: "app=api".to_string(),
                weight: 5,
                port: 8080,
            },
            Container::new("app=api:8080 5").unwrap()
        );
        for bad in ["app=api:x", "app=api:8080 0", "app=api 1 2"] {
            assert_eq!(true, Container::new(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn test_get_container_ports() {
        let mut summary = bollard::models::ContainerSummary::default();
        // No port list at all: nothing to connect to.
        assert_eq!(None, DockerState::get_container_ports(&summary, 8080));

        summary.ports = Some(vec![bollard::models::PortSummary {
            private_port: 3000,
            public_port: Some(33000),
            ..Default::default()
        }]);
        // A configured port wins and is reached directly.
        assert_eq!(
            Some((8080, 0)),
            DockerState::get_container_ports(&summary, 8080)
        );
        // Otherwise the container's own mapping is used.
        assert_eq!(
            Some((3000, 33000)),
            DockerState::get_container_ports(&summary, 0)
        );
    }

    #[test]
    fn test_addrs_to_backends() {
        let addrs: CachedAddrs = vec![
            ("10.0.0.2:8080".parse().unwrap(), 2),
            ("10.0.0.1:8080".parse().unwrap(), 1),
            ("10.0.0.1:8080".parse().unwrap(), 1),
        ];
        let (backends, _) = addrs_to_backends(&addrs);
        let listed: Vec<(String, usize)> = backends
            .iter()
            .map(|backend| (backend.addr.to_string(), backend.weight))
            .collect();
        assert_eq!(
            vec![
                ("10.0.0.1:8080".to_string(), 1),
                ("10.0.0.2:8080".to_string(), 2)
            ],
            listed
        );
    }
}
