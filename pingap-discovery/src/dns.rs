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

use super::{Addr, Error, Result, format_addrs};
use super::{DNS_DISCOVERY, Discovery, LOG_TARGET};
use async_trait::async_trait;
use futures::future::join_all;
use hickory_resolver::Name;
use hickory_resolver::Resolver;
use hickory_resolver::config::{
    LookupIpStrategy, NameServerConfigGroup, ResolverConfig, ResolverOpts,
};
use hickory_resolver::lookup_ip::LookupIp;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::system_conf::read_system_conf;
use http::Extensions;
use pingap_core::NotificationSender;
use pingap_core::{NotificationData, NotificationLevel};
use pingora::lb::discovery::ServiceDiscovery;
use pingora::lb::{Backend, Backends};
use pingora::protocols::l4::socket::SocketAddr;
use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, ToSocketAddrs};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, error, info};

/// DNS service discovery implementation
#[derive(Default)]
struct Dns {
    ipv4_only: bool,
    hosts: Vec<Addr>,
    sender: Option<Arc<NotificationSender>>,
    name_server: Option<String>,
    domain: Option<String>,
    search: Option<String>,
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

    /// Sets the domain
    ///
    /// # Arguments
    /// * `domain` - The domain
    ///
    /// # Returns
    /// * `Self` - The DNS discovery instance
    pub fn with_domain(mut self, domain: String) -> Self {
        self.domain = Some(domain);
        self
    }

    /// Sets the search
    ///
    /// # Arguments
    /// * `search` - The search
    ///
    /// # Returns
    /// * `Self` - The DNS discovery instance
    pub fn with_search(mut self, search: String) -> Self {
        self.search = Some(search);
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

        if let Some(domain) = &self.domain {
            if let Ok(name) = Name::from_str(domain) {
                config.set_domain(name);
            }
        }

        if let Some(search) = &self.search {
            search
                .split(',')
                .filter_map(|s| Name::from_str(s).ok())
                .for_each(|item| config.add_search(item));
        }

        if let Some(name_server) = &self.name_server {
            let ips = name_server
                .split(',')
                .filter_map(|s| s.trim().parse::<IpAddr>().ok())
                .collect::<Vec<_>>();
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

        let lookup_futures = self
            .hosts
            .iter()
            .map(|(host, _, _)| resolver.lookup_ip(host.as_str()));

        let results = join_all(lookup_futures).await;

        for (index, result) in results.iter().enumerate() {
            match result {
                Ok(lookup) => {
                    lookup_ips.push(lookup.clone());
                },
                Err(e) => {
                    let host = self
                        .hosts
                        .get(index)
                        .map(|item| item.0.clone())
                        .unwrap_or_default();
                    error!(
                        target: LOG_TARGET,
                        error = %e,
                        host,
                        "dns lookup failed"
                    );
                    failed_hosts.push(host);
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
        let start_time = Instant::now();
        let hosts: Vec<String> =
            self.hosts.iter().map(|item| item.0.clone()).collect();
        match self.run_discover().await {
            Ok((upstreams, enablement, failed_hosts)) => {
                let addrs: Vec<String> = upstreams
                    .iter()
                    .map(|item| item.addr.to_string())
                    .collect();

                info!(
                    target: LOG_TARGET,
                    hosts = hosts.join(","),
                    addrs = addrs.join(","),
                    elapsed = format!("{}ms", start_time.elapsed().as_millis()),
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
                    target: LOG_TARGET,
                    error = %e,
                    hosts = hosts.join(","),
                    elapsed = format!(
                        "{}ms",
                        start_time.elapsed().as_millis()
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
    if let Some(domain) = &discovery.dns_domain {
        dns = dns.with_domain(domain.clone());
    }
    if let Some(search) = &discovery.dns_search {
        dns = dns.with_search(search.clone());
    }
    let backends =
        Backends::new(Box::new(dns.with_sender(discovery.sender.clone())));
    Ok(backends)
}

#[cfg(test)]
mod tests {
    use super::{Dns, is_dns_discovery, new_dns_discover_backends};
    use crate::Discovery;
    use pretty_assertions::assert_eq;

    #[tokio::test]
    async fn test_async_dns_discover() {
        assert_eq!(true, is_dns_discovery("dns"));
        let dns = Dns::new(&["api".to_string()], true, true)
            .unwrap()
            .with_name_server("8.8.8.8".to_string())
            .with_domain("github.com".to_string());
        let (ip_list, _) = dns.tokio_lookup_ip().await.unwrap();
        assert_eq!(true, !ip_list.is_empty());

        let (backends, _, _) = dns.run_discover().await.unwrap();
        assert_eq!(true, !backends.is_empty());

        // new dns discover backends
        let result = new_dns_discover_backends(&Discovery {
            addr: vec!["api".to_string()],
            tls: true,
            ipv4_only: true,
            dns_server: Some("8.8.8.8".to_string()),
            dns_domain: Some("github.com".to_string()),
            dns_search: Some("local".to_string()),
            sender: None,
        });
        assert_eq!(true, result.is_ok());
    }
}
