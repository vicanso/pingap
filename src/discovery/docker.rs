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
use substring::Substring;
use tokio::runtime::Handle;
use tracing::{debug, error, info};

struct Docker {
    ipv4_only: bool,
    docker: bollard::Docker,
    weights: HashMap<String, usize>,
    names: Vec<String>,
    category: FiilterCategory,
}

enum FiilterCategory {
    Image,
    Label,
    Name,
}

struct Container {
    weight: usize,
    addrs: Vec<String>,
}

const DOCKER_DISCOVERY: &str = "docker";

pub fn is_docker_discovery(value: &str) -> bool {
    value == DOCKER_DISCOVERY
}

impl Docker {
    fn new(addrs: &[String], ipv4_only: bool) -> Result<Self> {
        let docker = bollard::Docker::connect_with_socket_defaults()
            .map_err(|e| Error::Docker { source: e })?;

        let mut names = vec![];
        let mut weights = HashMap::new();
        let mut category = FiilterCategory::Name;
        let image_prefix = "image:";
        let label_prefix = "label:";
        for addr in addrs.iter() {
            // get the weight of address
            let arr: Vec<_> = addr.split(' ').collect();
            let weight = if arr.len() == 2 {
                arr[1].parse::<usize>().unwrap_or(1)
            } else {
                1
            };
            let mut name = arr[0].to_string();
            if name.starts_with(image_prefix) {
                category = FiilterCategory::Image;
                name =
                    name.substring(image_prefix.len(), name.len()).to_string();
            } else if name.starts_with(label_prefix) {
                category = FiilterCategory::Label;
                name =
                    name.substring(label_prefix.len(), name.len()).to_string();
            }
            names.push(name.clone());
            weights.insert(name, weight);
        }

        Ok(Self {
            docker,
            category,
            names,
            weights,
            ipv4_only,
        })
    }
    async fn list_containers_by_labels(
        &self,
        labels: &[String],
    ) -> Result<Vec<ContainerSummary>> {
        let mut filters = HashMap::new();
        filters.insert("label".to_string(), labels.to_owned());
        self.docker
            .list_containers(Some(ListContainersOptions {
                filters,
                ..Default::default()
            }))
            .await
            .map_err(|e| Error::Docker { source: e })
    }
    async fn list_containers_by_images(
        &self,
        images: &[String],
    ) -> Result<Vec<ContainerSummary>> {
        let mut filters = HashMap::new();
        filters.insert("ancestor".to_string(), images.to_owned());
        self.docker
            .list_containers(Some(ListContainersOptions {
                filters,
                ..Default::default()
            }))
            .await
            .map_err(|e| Error::Docker { source: e })
    }
    async fn list_containers_by_names(
        &self,
        filter_names: &[String],
    ) -> Result<Vec<ContainerSummary>> {
        let mut filters = HashMap::new();
        filters.insert("name".to_string(), filter_names.to_owned());
        let containers = self
            .docker
            .list_containers(Some(ListContainersOptions {
                filters,
                ..Default::default()
            }))
            .await
            .map_err(|e| Error::Docker { source: e })?;

        let containers = containers
            .iter()
            .filter(|item| {
                let Some(names) = &item.names else {
                    return false;
                };
                let Some(name) = names.first() else {
                    return false;
                };
                if !filter_names
                    .contains(&name.substring(1, name.len()).to_string())
                {
                    return false;
                }
                true
            })
            .cloned()
            .collect();

        Ok(containers)
    }
    async fn list_containers(&self) -> Result<Vec<Container>> {
        let result = match self.category {
            FiilterCategory::Image => {
                self.list_containers_by_images(&self.names).await?
            },
            FiilterCategory::Label => {
                self.list_containers_by_labels(&self.names).await?
            },
            _ => self.list_containers_by_names(&self.names).await?,
        };
        let mut containers = vec![];
        for container in result.iter() {
            let name = if let Some(names) = &container.names {
                names.first().cloned().unwrap_or_default()
            } else {
                "".to_string()
            };
            let Some(ports) = &container.ports else {
                continue;
            };
            let mut public_port = 0;
            let mut private_port = 0;
            for port in ports {
                if let Some(value) = port.public_port {
                    public_port = value;
                }
                if port.private_port > 0 {
                    private_port = port.private_port;
                }
            }
            let Some(network_settings) = &container.network_settings else {
                continue;
            };
            let Some(networks) = &network_settings.networks else {
                continue;
            };
            let mut addrs = vec![];
            for network in networks.values() {
                if public_port > 0 {
                    if let Some(gateway) = &network.gateway {
                        addrs.push(format!("{gateway}:{public_port}"));
                    }
                } else if let Some(ip_address) = &network.ip_address {
                    addrs.push(format!("{ip_address}:{private_port}"));
                }
            }
            let weight = if let Some(weight) = self.weights.get(&name) {
                weight.to_owned()
            } else {
                1
            };

            containers.push(Container { weight, addrs });
        }

        Ok(containers)
    }
    async fn run_discover(
        &self,
    ) -> Result<(BTreeSet<Backend>, HashMap<u64, bool>)> {
        let tokio_runtime = Handle::try_current().is_ok();
        let mut upstreams = BTreeSet::new();
        let mut backends = vec![];

        if tokio_runtime {
            debug!(
                names = format!("{:?}", self.names),
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
        let names: Vec<String> = self.names.clone();
        match self.run_discover().await {
            Ok(data) => {
                let addrs: Vec<String> =
                    data.0.iter().map(|item| item.addr.to_string()).collect();

                info!(
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
                    error = e.to_string(),
                    names = names.join(","),
                    elapsed = format!(
                        "{}ms",
                        now.elapsed().unwrap_or_default().as_millis()
                    ),
                    "docker discover fail"
                );
                webhook::send(webhook::SendNotificationParams {
                    category:
                        webhook::NotificationCategory::ServiceDiscoverFail,
                    level: webhook::NotificationLevel::Warn,
                    msg: format!(
                        "docker discovery {:?}, error: {e}",
                        self.names,
                    ),
                    remark: None,
                });
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
