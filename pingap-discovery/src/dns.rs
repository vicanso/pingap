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

use super::{format_addrs, Addr, Error, Result};
use super::{Discovery, DNS_DISCOVERY, LOG_CATEGORY};
use async_trait::async_trait;
use hickory_resolver::config::{
    LookupIpStrategy, NameServerConfigGroup, ResolverConfig, ResolverOpts,
};
use hickory_resolver::lookup_ip::LookupIp;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::system_conf::read_system_conf;
use hickory_resolver::Resolver;
use http::Extensions;
use pingap_core::NotificationSender;
use pingap_core::{NotificationData, NotificationLevel};
use pingora::lb::discovery::ServiceDiscovery;
use pingora::lb::{Backend, Backends};
use pingora::protocols::l4::socket::SocketAddr;
use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{debug, error, info};

/// DNS service discovery implementation
#[derive(Default)]
struct Dns {
    ipv4_only: bool,
    hosts: Vec<Addr>,
    sender: Option<Arc<NotificationSender>>,
    name_server: Option<String>,
}

/// Checks if the discovery type is DNS
pub fn is_dns_discovery(value: &str) -> bool {
    value == DNS_DISCOVERY
}

impl Dns {
    /// Creates a new DNS discovery instance
    ///
    /// # Arguments
    /// * `addrs` - List of addresses to resolve
    /// * `tls` - Whether to use TLS
    /// * `ipv4_only` - Whether to only use IPv4 addresses
    ///
    /// # Returns
    /// * `Result<Self>` - New DNS discovery instance
    fn new(addrs: &[String], tls: bool, ipv4_only: bool) -> Result<Self> {
        let hosts = format_addrs(addrs, tls);
        Ok(Self {
            hosts,
            ipv4_only,
            sender: None,
            ..Default::default()
        })
    }
    /// Sets the name server
    ///
    /// # Arguments
    /// * `name_server` - The name server
    ///
    /// # Returns
    /// * `Self` - The DNS discovery instance
    pub fn with_name_server(mut self, name_server: String) -> Self {
        if name_server.is_empty() {
            return self;
        }
        self.name_server = Some(name_server);
        self
    }
    /// Sets the notification sender
    ///
    /// # Arguments
    /// * `sender` - The notification sender
    ///
    /// # Returns
    /// * `Self` - The DNS discovery instance
    pub fn with_sender(
        mut self,
        sender: Option<Arc<NotificationSender>>,
    ) -> Self {
        self.sender = sender;
        self
    }

    /// Reads system DNS resolver configuration
    ///
    /// # Returns
    /// * `Result<(ResolverConfig, ResolverOpts)>` - Resolver configuration and options
    fn read_system_conf(&self) -> Result<(ResolverConfig, ResolverOpts)> {
        let (mut config, mut options) =
            read_system_conf().map_err(|e| Error::Resolve { source: e })?;

        if let Some(name_server) = &self.name_server {
            let mut ips = vec![];
            for item in name_server.split(",") {
                let ip = item.trim().parse::<IpAddr>().map_err(|e| {
                    Error::Invalid {
                        message: e.to_string(),
                    }
                })?;
                ips.push(ip);
            }
            let name_servers =
                NameServerConfigGroup::from_ips_clear(&ips, 53, true);
            config = ResolverConfig::from_parts(
                config.domain().cloned(),
                config.search().to_vec(),
                name_servers,
            );
        }

        options.ip_strategy = if self.ipv4_only {
            LookupIpStrategy::Ipv4Only
        } else {
            LookupIpStrategy::Ipv4AndIpv6
        };

        Ok((config, options))
    }

    /// Performs DNS lookups for configured hosts using tokio runtime
    ///
    /// # Returns
    /// * `Result<(Vec<LookupIp>, Vec<String>)>` - List of DNS lookup results and unhealthy backends
    async fn tokio_lookup_ip(&self) -> Result<(Vec<LookupIp>, Vec<String>)> {
        let provider = TokioConnectionProvider::default();
        let (config, options) = self.read_system_conf()?;
        let mut builder = Resolver::builder_with_config(config, provider);
        *builder.options_mut() = options;
        let resolver = builder.build();

        let mut lookup_ips = Vec::new();
        let mut failed_hosts = Vec::new();

        for (host, _, _) in self.hosts.iter() {
            match resolver.lookup_ip(host).await {
                Ok(lookup) => {
                    lookup_ips.push(lookup);
                },
                Err(e) => {
                    error!(
                        category = LOG_CATEGORY,
                        error = %e,
                        host,
                        "dns lookup failed"
                    );
                    failed_hosts.push(host.clone());
                },
            }
        }
        if lookup_ips.is_empty() {
            return Err(Error::Invalid {
                message: "resolve dns failed".to_string(),
            });
        }
        Ok((lookup_ips, failed_hosts))
    }

    /// Discovers backend services by resolving DNS
    ///
    /// # Returns
    /// * `Result<(BTreeSet<Backend>, HashMap<u64, bool>)>` - Set of discovered backends and their states
    async fn run_discover(
        &self,
    ) -> Result<(BTreeSet<Backend>, HashMap<u64, bool>, Vec<String>)> {
        let mut upstreams = BTreeSet::new();

        debug!(
            hosts = ?self.hosts,
            "dns discover is running"
        );

        let (lookup_ips, failed_hosts) = self.tokio_lookup_ip().await?;

        for ((_, port, weight), lookup_ip) in
            self.hosts.iter().zip(lookup_ips.iter())
        {
            for ip in lookup_ip
                .iter()
                .filter(|ip| !self.ipv4_only || ip.is_ipv4())
            {
                let addr = if port.is_empty() {
                    ip.to_string()
                } else {
                    format!("{ip}:{port}")
                };

                let socket_addrs =
                    addr.to_socket_addrs().map_err(|e| Error::Io {
                        source: e,
                        content: format!(
                            "Failed to convert {addr} to socket address"
                        ),
                    })?;

                upstreams.extend(socket_addrs.map(|socket_addr| Backend {
                    addr: SocketAddr::Inet(socket_addr),
                    weight: *weight,
                    ext: Extensions::new(),
                }));
            }
        }

        Ok((upstreams, HashMap::new(), failed_hosts))
    }
}

#[async_trait]
impl ServiceDiscovery for Dns {
    async fn discover(
        &self,
    ) -> pingora::Result<(BTreeSet<Backend>, HashMap<u64, bool>)> {
        let now = SystemTime::now();
        let hosts: Vec<String> =
            self.hosts.iter().map(|item| item.0.clone()).collect();
        match self.run_discover().await {
            Ok((upstreams, enablement, failed_hosts)) => {
                let addrs: Vec<String> = upstreams
                    .iter()
                    .map(|item| item.addr.to_string())
                    .collect();

                info!(
                    category = LOG_CATEGORY,
                    hosts = hosts.join(","),
                    addrs = addrs.join(","),
                    elapsed = format!(
                        "{}ms",
                        now.elapsed().unwrap_or_default().as_millis()
                    ),
                    "dns discover success"
                );
                if !failed_hosts.is_empty() {
                    if let Some(sender) = &self.sender {
                        sender
                            .notify(NotificationData {
                                category: "service_discover_fail".to_string(),
                                level: NotificationLevel::Warn,
                                message: format!(
                                    "dns discovery resolve failed: {failed_hosts:?}"
                                ),
                                ..Default::default()
                            })
                            .await;
                    }
                }
                return Ok((upstreams, enablement));
            },
            Err(e) => {
                error!(
                    category = LOG_CATEGORY,
                    error = %e,
                    hosts = hosts.join(","),
                    elapsed = format!(
                        "{}ms",
                        now.elapsed().unwrap_or_default().as_millis()
                    ),
                    "dns discover fail"
                );
                if let Some(sender) = &self.sender {
                    sender
                        .notify(NotificationData {
                            category: "service_discover_fail".to_string(),
                            level: NotificationLevel::Warn,
                            message: format!(
                                "dns discovery {:?}, error: {e}",
                                self.hosts
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

/// Creates a new DNS-based service discovery backend
///
/// # Arguments
/// * `discovery` - The discovery configuration
///
/// # Returns
/// * `Result<Backends>` - Configured service discovery backend
pub fn new_dns_discover_backends(discovery: &Discovery) -> Result<Backends> {
    let mut dns =
        Dns::new(&discovery.addr, discovery.tls, discovery.ipv4_only)?;
    if let Some(dns_server) = &discovery.dns_server {
        dns = dns.with_name_server(dns_server.clone());
    }
    let backends =
        Backends::new(Box::new(dns.with_sender(discovery.sender.clone())));
    Ok(backends)
}

#[cfg(test)]
mod tests {
    use super::Dns;
    use pretty_assertions::assert_eq;

    #[tokio::test]
    async fn test_async_dns_discover() {
        let dns = Dns::new(&["github.com".to_string()], true, true).unwrap();
        let (ip_list, _) = dns.tokio_lookup_ip().await.unwrap();
        assert_eq!(true, !ip_list.is_empty());

        let (backends, _, _) = dns.run_discover().await.unwrap();
        assert_eq!(true, !backends.is_empty());
    }
}
