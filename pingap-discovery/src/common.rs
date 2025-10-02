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

use super::{format_addrs, Result};
use super::{Discovery, LOG_TARGET, STATIC_DISCOVERY};
use http::Extensions;
use pingora::lb::discovery;
use pingora::lb::{Backend, Backends};
use pingora::protocols::l4::socket::SocketAddr;
use std::collections::BTreeSet;
use std::net::ToSocketAddrs;
use std::time::Instant;
use tracing::{info, warn};

/// Checks if the discovery type is static
///
/// # Arguments
/// * `value` - The discovery type string to check
///
/// # Returns
/// * `bool` - True if the discovery type is static (empty or matches STATIC_DISCOVERY)
pub fn is_static_discovery(value: &str) -> bool {
    // Using a match statement is slightly more idiomatic and extensible.
    matches!(value, "" | STATIC_DISCOVERY)
}

/// Create a static discovery, execute it only once.
/// It will resolve the domain to socket address at the beginning stage.
///
/// # Arguments
/// * `discovery` - The discovery configuration
///
/// # Returns
/// * `Result<Backends>` - Configured service discovery backend
pub fn new_static_discovery(discovery: &Discovery) -> Result<Backends> {
    let start_time = Instant::now();
    info!(
        target: LOG_TARGET,
        hosts = discovery.addr.join(","),
        "starting static discovery"
    );

    let formatted_addrs = format_addrs(&discovery.addr, discovery.tls);

    // Directly collect into a BTreeSet to handle deduplication and sorting automatically.
    let upstreams: BTreeSet<_> = formatted_addrs
        .into_iter()
        .flat_map(|(ip, port, weight)| {
            let addr_str = format!("{ip}:{port}");
            // The match now returns a Vec, a concrete type, which both arms can produce.
            let resolved_addrs: Vec<_> = match addr_str.to_socket_addrs() {
                Ok(addrs) => addrs.collect(), // Collect resolved addresses into a Vec
                Err(e) => {
                    // Log the error but don't stop the whole process.
                    warn!(
                        target: LOG_TARGET,
                        error = %e,
                        addr = addr_str,
                        "failed to resolve socket address"
                    );
                    // Return an empty Vec on error.
                    vec![]
                },
            };
            // Convert the Vec into an iterator and pair each address with the weight.
            resolved_addrs.into_iter().map(move |addr| (addr, weight))
        })
        // Filter out only valid addresses and apply the IPv4-only filter.
        .filter(|(socket_addr, _)| {
            !discovery.ipv4_only || socket_addr.is_ipv4()
        })
        // Map the resolved addresses to Backend structs.
        .map(|(socket_addr, weight)| Backend {
            addr: SocketAddr::Inet(socket_addr),
            weight,
            ext: Extensions::new(),
        })
        .collect();

    // Generate the log message from the final, deduplicated set of backends.
    let resolved_addrs: Vec<String> =
        upstreams.iter().map(|b| b.addr.to_string()).collect();
    info!(
        target: LOG_TARGET,
        hosts = discovery.addr.join(","),
        addrs = resolved_addrs.join(","),
        count = upstreams.len(),
        elapsed = ?start_time.elapsed(),
        "static discovery finished"
    );

    let discovery_service = discovery::Static::new(upstreams);
    Ok(Backends::new(discovery_service))
}
#[cfg(test)]
mod tests {
    use super::new_static_discovery;
    use super::Discovery;
    use pretty_assertions::assert_eq;

    #[tokio::test]
    async fn test_new_static_discovery() {
        let backends = new_static_discovery(&Discovery {
            addr: vec!["127.0.0.1:8080".to_string()],
            tls: false,
            ipv4_only: false,
            sender: None,
            dns_server: None,
            dns_domain: None,
            dns_search: None,
        })
        .unwrap();

        // no health check, so no healthy backend
        assert_eq!(backends.get_backend().len(), 0);

        backends.update(|_| {}).await.unwrap();
        assert_eq!(backends.get_backend().len(), 1);
    }
}
