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

use super::{format_addrs, Addr, Error, Result};
use crate::util;
use async_trait::async_trait;
use hickory_resolver::name_server::{GenericConnector, TokioRuntimeProvider};
use hickory_resolver::AsyncResolver;
use pingora::lb::discovery::ServiceDiscovery;
use pingora::lb::{Backend, Backends};
use pingora::protocols::l4::socket::SocketAddr;
use std::collections::{BTreeSet, HashMap};
use std::net::ToSocketAddrs;

struct Dns {
    resolver: AsyncResolver<GenericConnector<TokioRuntimeProvider>>,
    ipv4_only: bool,
    hosts: Vec<Addr>,
}

impl Dns {
    fn new(addrs: &[String], tls: bool, ipv4_only: bool) -> Result<Self> {
        let hosts = format_addrs(addrs, tls);
        let resolver = AsyncResolver::tokio_from_system_conf()
            .map_err(|e| Error::Resolve { source: e })?;
        Ok(Self {
            resolver,
            hosts,
            ipv4_only,
        })
    }
}

#[async_trait]
impl ServiceDiscovery for Dns {
    async fn discover(
        &self,
    ) -> pingora::Result<(BTreeSet<Backend>, HashMap<u64, bool>)> {
        let mut upstreams = BTreeSet::new();
        let mut backends = vec![];
        for (host, port, weight) in self.hosts.iter() {
            let ip =
                self.resolver.lookup_ip(host).await.map_err(|e| {
                    util::new_internal_error(500, e.to_string())
                })?;
            for item in ip.iter() {
                if self.ipv4_only && item.is_ipv6() {
                    continue;
                }
                let mut addr = item.to_string();
                if !port.is_empty() {
                    addr += &format!(":{port}");
                }
                for socket_addr in addr
                    .to_socket_addrs()
                    .map_err(|e| util::new_internal_error(500, e.to_string()))?
                {
                    backends.push(Backend {
                        addr: SocketAddr::Inet(socket_addr),
                        weight: weight.to_owned(),
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

pub fn new_dns_discover_backends(
    addrs: &[String],
    tls: bool,
    ipv4_only: bool,
) -> Result<Backends> {
    let dns = Dns::new(addrs, tls, ipv4_only)?;
    let backends = Backends::new(Box::new(dns));
    Ok(backends)
}
