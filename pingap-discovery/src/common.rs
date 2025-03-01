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

use super::{Error, Result, format_addrs};
use super::{LOG_CATEGORY, STATIC_DISCOVERY};
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
/// * `bool` - True if the discovery type is static (empty or matches STATIC_DISCOVERY)
pub fn is_static_discovery(value: &str) -> bool {
    // TODO the common may be removed in the future
    value.is_empty() || value == "common" || value == STATIC_DISCOVERY
}

/// Create a static discovery, execute it only once.
/// It will resolve the domain to socket address at the beginning stage.
///
/// # Arguments
/// * `addrs` - List of address strings to resolve
/// * `tls` - Whether to use TLS
/// * `ipv4_only` - Whether to only use IPv4 addresses
/// * `weight` - Weight for load balancing (higher values mean more traffic)
pub fn new_static_discovery(
    addrs: &[String],
    tls: bool,
    ipv4_only: bool,
) -> Result<Backends> {
    let hosts = addrs.join(",");
    let start_time = SystemTime::now();
    let formatted_addrs = format_addrs(addrs, tls);

    let mut backends: Vec<Backend> = vec![];

    // resolve ip and port to socket address
    for (ip, port, weight) in formatted_addrs {
        let addr = format!("{ip}:{port}");
        addr.to_socket_addrs()
            .map_err(|e| Error::Io {
                source: e,
                content: format!("{addr} to socket addr fail"),
            })?
            .filter(|socket_addr| !ipv4_only || socket_addr.is_ipv4())
            .for_each(|socket_addr| {
                backends.push(Backend {
                    addr: SocketAddr::Inet(socket_addr),
                    weight,
                    ext: Extensions::new(),
                });
            });
    }

    let resolved_addrs: Vec<String> = backends
        .iter()
        .map(|b| match &b.addr {
            SocketAddr::Inet(addr) => addr.to_string(),
            _ => String::new(),
        })
        .filter(|addr| !addr.is_empty())
        .collect();

    info!(
        category = LOG_CATEGORY,
        hosts,
        addrs = resolved_addrs.join(","),
        elapsed = format!(
            "{}ms",
            start_time.elapsed().unwrap_or_default().as_millis()
        ),
        "static discover success"
    );

    let upstreams: BTreeSet<_> = backends.into_iter().collect();
    let discovery = discovery::Static::new(upstreams);
    Ok(Backends::new(discovery))
}

#[cfg(test)]
mod tests {
    use super::new_static_discovery;
    use pretty_assertions::assert_eq;

    #[tokio::test]
    async fn test_new_static_discovery() {
        let backends =
            new_static_discovery(&["127.0.0.1:8080".to_string()], false, false)
                .unwrap();

        // no health check, so no healthy backend
        assert_eq!(backends.get_backend().len(), 0);

        backends.update(|_| {}).await.unwrap();
        assert_eq!(backends.get_backend().len(), 1);
    }
}
