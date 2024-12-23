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

use super::{Error, Result};
use super::{DOCKER_DISCOVERY, LOG_CATEGORY};
use crate::webhook;
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

#[derive(Debug, Clone)]
struct Container {
    label: String,
    weight: usize,
    port: u16,
    addrs: Vec<String>,
}

struct Docker {
    ipv4_only: bool,
    docker: bollard::Docker,
    containers: Vec<Container>,
}

pub fn is_docker_discovery(value: &str) -> bool {
    value == DOCKER_DISCOVERY
}

impl Docker {
    fn new(addrs: &[String], ipv4_only: bool) -> Result<Self> {
        let docker = bollard::Docker::connect_with_local_defaults()
            .map_err(|e| Error::Docker { source: e })?;

        let mut containers = vec![];
        for addr in addrs.iter() {
            // get the weight of address
            let arr: Vec<_> = addr.split(' ').collect();
            let weight = if arr.len() == 2 {
                arr[1].parse::<usize>().unwrap_or(1)
            } else {
                1
            };
            let mut label = arr[0].to_string();
            let mut container_port = 0;
            if let Some((value, port)) = label.clone().split_once(":") {
                label = value.to_string();
                if let Ok(value) = port.parse::<u16>() {
                    container_port = value;
                }
            }
            containers.push(Container {
                label,
                weight,
                port: container_port,
                addrs: vec![],
            });
        }

        Ok(Self {
            docker,
            containers,
            ipv4_only,
        })
    }
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
    async fn list_containers(&self) -> Result<Vec<Container>> {
        let mut containers = self.containers.clone();
        for container in containers.iter_mut() {
            let result =
                self.list_containers_by_label(&container.label).await?;
            let mut addrs = vec![];
            for item in result.iter() {
                let Some(ports) = &item.ports else {
                    continue;
                };
                let mut private_port = container.port;
                let mut public_port = 0;
                if private_port == 0 {
                    for port in ports {
                        if let Some(value) = port.public_port {
                            public_port = value;
                        }
                        if port.private_port > 0 {
                            private_port = port.private_port;
                        }
                    }
                }

                let Some(network_settings) = &item.network_settings else {
                    continue;
                };
                let Some(networks) = &network_settings.networks else {
                    continue;
                };
                for network in networks.values() {
                    if public_port > 0 {
                        if let Some(gateway) = &network.gateway {
                            addrs.push(format!("{gateway}:{public_port}"));
                        }
                    } else if let Some(ip_address) = &network.ip_address {
                        addrs.push(format!("{ip_address}:{private_port}"));
                    }
                }
            }
            container.addrs = addrs;
        }

        Ok(containers)
    }
    pub fn labels(&self) -> Vec<String> {
        self.containers
            .iter()
            .map(|item| item.label.clone())
            .collect()
    }
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
                    error = e.to_string(),
                    names = names.join(","),
                    elapsed = format!(
                        "{}ms",
                        now.elapsed().unwrap_or_default().as_millis()
                    ),
                    "docker discover fail"
                );
                webhook::send_notification(webhook::SendNotificationParams {
                    category:
                        webhook::NotificationCategory::ServiceDiscoverFail,
                    level: webhook::NotificationLevel::Warn,
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

pub fn new_docker_discover_backends(
    addrs: &[String],
    _tls: bool,
    ipv4_only: bool,
) -> Result<Backends> {
    let docker = Docker::new(addrs, ipv4_only)?;
    let backends = Backends::new(Box::new(docker));
    Ok(backends)
}
