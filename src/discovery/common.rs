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

use super::{format_addrs, Error, Result};
use super::{COMMON_DISCOVERY, LOG_CATEGORY};
use http::Extensions;
use pingora::lb::discovery;
use pingora::lb::{Backend, Backends};
use pingora::protocols::l4::socket::SocketAddr;
use std::collections::BTreeSet;
use std::net::ToSocketAddrs;
use std::time::SystemTime;
use tracing::info;

/// Checks if the discovery type is static
///
/// # Arguments
/// * `value` - The discovery type string to check
///
/// # Returns
/// * `bool` - True if the discovery type is static (empty or matches COMMON_DISCOVERY)
pub fn is_static_discovery(value: &str) -> bool {
    value.is_empty() || value == COMMON_DISCOVERY
}

/// Create a static discovery, execute it only once.
/// It will resolve the domain to socket address at the beginning stage.
///
/// # Arguments
/// * `addrs` - List of address strings to resolve
/// * `tls` - Whether to use TLS
/// * `ipv4_only` - Whether to only use IPv4 addresses
/// * `weight` - Weight for load balancing (higher values mean more traffic)
pub fn new_common_discover_backends(
    addrs: &[String],
    tls: bool,
    ipv4_only: bool,
) -> Result<Backends> {
    let hosts = addrs.join(",");
    let start_time = SystemTime::now();
    let formatted_addrs = format_addrs(addrs, tls);

    let backends: Vec<Backend> = formatted_addrs
        .iter()
        .flat_map(|(ip, port, weight)| {
            let addr = format!("{ip}:{port}");
            addr.to_socket_addrs()
                .map_err(|e| Error::Io {
                    source: e,
                    content: format!("{addr} to socket addr fail"),
                })
                .unwrap_or_default()
                .filter(|addr| !ipv4_only || addr.is_ipv4())
                .map(|socket_addr| Backend {
                    addr: SocketAddr::Inet(socket_addr),
                    weight: *weight,
                    ext: Extensions::new(),
                })
        })
        .collect();

    let resolved_addrs: Vec<String> = backends
        .iter()
        .map(|b| match &b.addr {
            SocketAddr::Inet(addr) => addr.to_string(),
            _ => String::new(),
        })
        .collect();

    info!(
        category = LOG_CATEGORY,
        hosts,
        addrs = resolved_addrs.join(","),
        elapsed = format!(
            "{}ms",
            start_time.elapsed().unwrap_or_default().as_millis()
        ),
        "common discover success"
    );

    let upstreams: BTreeSet<_> = backends.into_iter().collect();
    let discovery = discovery::Static::new(upstreams);
    Ok(Backends::new(discovery))
}
