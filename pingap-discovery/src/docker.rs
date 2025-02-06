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

use super::{Error, Result};
use super::{DOCKER_DISCOVERY, LOG_CATEGORY};
use async_trait::async_trait;
use bollard::container::ListContainersOptions;
use bollard::secret::ContainerSummary;
use http::Extensions;
use pingora::lb::discovery::ServiceDiscovery;
use pingora::lb::{Backend, Backends};
use pingora::protocols::l4::socket::SocketAddr;
use std::collections::{BTreeSet, HashMap};
use std::net::ToSocketAddrs;
use std::time::SystemTime;
use tracing::{debug, error, info};

/// Container represents a Docker container with service discovery configuration
/// - label: The container label used for filtering
/// - weight: Load balancing weight for this container
/// - port: The port number to use for the service
/// - addrs: List of resolved addresses for this container
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

    /// Parses an address string into its components: weight, label, and port
    /// Returns a tuple of (weight, label, port)
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

/// Docker service discovery implementation
struct Docker {
    ipv4_only: bool,
    docker: bollard::Docker,
    containers: Vec<Container>,
}

/// Checks if the discovery type is Docker
pub fn is_docker_discovery(value: &str) -> bool {
    value == DOCKER_DISCOVERY
}

impl Docker {
    /// Creates a new Docker service discovery instance
    /// - addrs: List of container specifications in the format "label:port weight"
    /// - ipv4_only: Whether to only use IPv4 addresses
    fn new(addrs: &[String], ipv4_only: bool) -> Result<Self> {
        let docker = bollard::Docker::connect_with_local_defaults()
            .map_err(|e| Error::Docker { source: e })?;

        let containers =
            addrs.iter().map(|addr| Container::new(addr)).collect();

        Ok(Self {
            docker,
            containers,
            ipv4_only,
        })
    }

    /// Extracts port information from a container
    /// Returns a tuple of (private_port, public_port)
    fn get_container_ports(
        container: &ContainerSummary,
        default_port: u16,
    ) -> Option<(u16, u16)> {
        let ports = container.ports.as_ref()?;

        if default_port > 0 {
            return Some((default_port, 0));
        }

        let port_info = ports.iter().find(|p| p.private_port > 0)?;
        Some((port_info.private_port, port_info.public_port.unwrap_or(0)))
    }

    /// Lists all containers matching the configured labels
    async fn list_containers(&self) -> Result<Vec<Container>> {
        let mut containers = self.containers.clone();

        for container in containers.iter_mut() {
            let result =
                self.list_containers_by_label(&container.label).await?;

            container.addrs = result
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

    /// Lists containers that match a specific label
    async fn list_containers_by_label(
        &self,
        label: &String,
    ) -> Result<Vec<ContainerSummary>> {
        let mut filters = HashMap::new();
        filters.insert("label".to_string(), vec![label.to_string()]);
        self.docker
            .list_containers(Some(ListContainersOptions {
                filters,
                ..Default::default()
            }))
            .await
            .map_err(|e| Error::Docker { source: e })
    }

    /// Returns the list of container labels being monitored
    fn labels(&self) -> Vec<String> {
        self.containers
            .iter()
            .map(|item| item.label.clone())
            .collect()
    }

    /// Performs the service discovery by querying Docker for containers
    /// Returns a tuple of (upstreams, health_status)
    async fn run_discover(
        &self,
    ) -> Result<(BTreeSet<Backend>, HashMap<u64, bool>)> {
        let mut upstreams = BTreeSet::new();
        let mut backends = vec![];

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
                    backends.push(Backend {
                        addr: SocketAddr::Inet(socket_addr),
                        weight: container.weight,
                        ext: Extensions::new(),
                    });
                }
            }
        }

        upstreams.extend(backends);
        // no readiness
        let health = HashMap::new();
        Ok((upstreams, health))
    }
}

#[async_trait]
impl ServiceDiscovery for Docker {
    async fn discover(
        &self,
    ) -> pingora::Result<(BTreeSet<Backend>, HashMap<u64, bool>)> {
        let now = SystemTime::now();
        let names: Vec<String> = self.labels();
        match self.run_discover().await {
            Ok(data) => {
                let addrs: Vec<String> =
                    data.0.iter().map(|item| item.addr.to_string()).collect();

                info!(
                    category = LOG_CATEGORY,
                    names = names.join(","),
                    addrs = addrs.join(","),
                    elapsed = format!(
                        "{}ms",
                        now.elapsed().unwrap_or_default().as_millis()
                    ),
                    "docker discover success"
                );
                return Ok(data);
            },
            Err(e) => {
                error!(
                    category = LOG_CATEGORY,
                    error = %e,
                    names = names.join(","),
                    elapsed = format!(
                        "{}ms",
                        now.elapsed().unwrap_or_default().as_millis()
                    ),
                    "docker discover fail"
                );
                pingap_webhook::send_notification(pingap_webhook::SendNotificationParams {
                    category:
                        pingap_webhook::NotificationCategory::ServiceDiscoverFail,
                    level: pingap_webhook::NotificationLevel::Warn,
                    msg: format!(
                        "docker discovery {:?}, error: {e}",
                        self.labels(),
                    ),
                    remark: None,
                })
                .await;
                return Err(e.into());
            },
        }
    }
}

/// Creates a new Docker service discovery backend
/// - addrs: List of container specifications
/// - _tls: TLS configuration (currently unused)
/// - ipv4_only: Whether to only use IPv4 addresses
pub fn new_docker_discover_backends(
    addrs: &[String],
    _tls: bool,
    ipv4_only: bool,
) -> Result<Backends> {
    let docker = Docker::new(addrs, ipv4_only)?;
    let backends = Backends::new(Box::new(docker));
    Ok(backends)
}
