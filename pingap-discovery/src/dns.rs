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
use super::{DNS_DISCOVERY, LOG_CATEGORY};
use async_trait::async_trait;
use hickory_resolver::config::{
    LookupIpStrategy, ResolverConfig, ResolverOpts,
};
use hickory_resolver::lookup_ip::LookupIp;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::system_conf::read_system_conf;
use hickory_resolver::AsyncResolver;
use http::Extensions;
use pingora::lb::discovery::ServiceDiscovery;
use pingora::lb::{Backend, Backends};
use pingora::protocols::l4::socket::SocketAddr;
use std::collections::{BTreeSet, HashMap};
use std::net::ToSocketAddrs;
use std::time::SystemTime;
use tracing::{debug, error, info};

/// DNS service discovery implementation
struct Dns {
    ipv4_only: bool,
    hosts: Vec<Addr>,
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
        Ok(Self { hosts, ipv4_only })
    }

    /// Reads system DNS resolver configuration
    ///
    /// # Returns
    /// * `Result<(ResolverConfig, ResolverOpts)>` - Resolver configuration and options
    fn read_system_conf(&self) -> Result<(ResolverConfig, ResolverOpts)> {
        let (config, mut options) =
            read_system_conf().map_err(|e| Error::Resolve { source: e })?;

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
    /// * `Result<Vec<LookupIp>>` - List of DNS lookup results
    async fn tokio_lookup_ip(&self) -> Result<Vec<LookupIp>> {
        let provider = TokioConnectionProvider::default();
        let (config, options) = self.read_system_conf()?;
        let resolver = AsyncResolver::new(config, options, provider);

        // Use futures::future::try_join_all for concurrent lookups
        let lookups = futures::future::try_join_all(
            self.hosts
                .iter()
                .map(|(host, _, _)| resolver.lookup_ip(host)),
        )
        .await
        .map_err(|e| Error::Resolve { source: e })?;

        Ok(lookups)
    }

    /// Discovers backend services by resolving DNS
    ///
    /// # Returns
    /// * `Result<(BTreeSet<Backend>, HashMap<u64, bool>)>` - Set of discovered backends and their states
    async fn run_discover(
        &self,
    ) -> Result<(BTreeSet<Backend>, HashMap<u64, bool>)> {
        let mut upstreams = BTreeSet::new();

        debug!(
            hosts = ?self.hosts,
            "dns discover is running"
        );

        let lookup_ip_list = self.tokio_lookup_ip().await?;

        for ((_, port, weight), lookup_ip) in
            self.hosts.iter().zip(lookup_ip_list.iter())
        {
            for ip in lookup_ip
                .iter()
                .filter(|ip| !self.ipv4_only || ip.is_ipv4())
            {
                let addr = if port.is_empty() {
                    ip.to_string()
                } else {
                    format!("{}:{port}", ip)
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

        Ok((upstreams, HashMap::new()))
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
            Ok(data) => {
                let addrs: Vec<String> =
                    data.0.iter().map(|item| item.addr.to_string()).collect();

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
                return Ok(data);
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
                pingap_webhook::send_notification(pingap_webhook::SendNotificationParams {
                    category:
                        pingap_webhook::NotificationCategory::ServiceDiscoverFail,
                    level: pingap_webhook::NotificationLevel::Warn,
                    msg: format!("dns discovery {:?}, error: {e}", self.hosts),
                    remark: None,
                })
                .await;
                Err(e.into())
            },
        }
    }
}

/// Creates a new DNS-based service discovery backend
///
/// # Arguments
/// * `addrs` - List of addresses to resolve
/// * `tls` - Whether to use TLS
/// * `ipv4_only` - Whether to only use IPv4 addresses
///
/// # Returns
/// * `Result<Backends>` - Configured service discovery backend
pub fn new_dns_discover_backends(
    addrs: &[String],
    tls: bool,
    ipv4_only: bool,
) -> Result<Backends> {
    let dns = Dns::new(addrs, tls, ipv4_only)?;
    let backends = Backends::new(Box::new(dns));
    Ok(backends)
}

#[cfg(test)]
mod tests {
    use super::Dns;
    use pretty_assertions::assert_eq;

    #[tokio::test]
    async fn test_async_dns_discover() {
        let dns = Dns::new(&["github.com".to_string()], true, true).unwrap();
        let ip_list = dns.tokio_lookup_ip().await.unwrap();
        assert_eq!(true, !ip_list.is_empty());

        let (backends, _) = dns.run_discover().await.unwrap();
        assert_eq!(true, !backends.is_empty());
    }
}
