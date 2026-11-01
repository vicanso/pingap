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

use super::{Discovery, Endpoint, LOG_TARGET, STATIC_DISCOVERY};
use super::{Result, split_addr};
use http::Extensions;
use pingora::lb::discovery;
use pingora::lb::{Backend, Backends};
use pingora::protocols::l4::socket::SocketAddr;
use std::collections::BTreeSet;
use std::net::{IpAddr, ToSocketAddrs};
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

/// An IP literal needs no lookup - and no trip through the blocking
/// resolver this runs on during a hot reload. A name that does not
/// resolve is left out; the other addresses of the upstream still serve.
fn resolve_host_port(host: &str, port: u16) -> Vec<std::net::SocketAddr> {
    match host.parse::<IpAddr>() {
        Ok(ip) => vec![std::net::SocketAddr::new(ip, port)],
        Err(_) => match format!("{host}:{port}").to_socket_addrs() {
            Ok(addrs) => addrs.collect(),
            Err(e) => {
                warn!(
                    target: LOG_TARGET,
                    error = %e,
                    host,
                    port,
                    "failed to resolve socket address"
                );
                vec![]
            },
        },
    }
}

/// A unix backend, built here. `Backend::new` only parses an IP address.
fn unix_backend(path: &str, weight: usize) -> Result<Backend> {
    #[cfg(unix)]
    {
        let addr = std::os::unix::net::SocketAddr::from_pathname(path)
            .map_err(|e| super::Error::Invalid {
                message: format!("unix socket {path}: {e}"),
            })?;
        Ok(Backend {
            addr: SocketAddr::Unix(addr),
            weight,
            ext: Extensions::new(),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (path, weight);
        Err(super::Error::Invalid {
            message: "unix sockets are not available on this build".to_string(),
        })
    }
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

    let default_port = if discovery.tls { 443 } else { 80 };
    let mut upstreams = BTreeSet::new();
    for addr in &discovery.addr {
        match split_addr(addr)? {
            Endpoint::Unix { path, weight } => {
                if discovery.ipv4_only {
                    return Err(super::Error::Invalid {
                        message: format!(
                            "ipv4_only does not apply to unix socket {addr}"
                        ),
                    });
                }
                upstreams.insert(unix_backend(&path, weight)?);
            },
            Endpoint::Tcp { host, port, weight } => {
                let port = port.unwrap_or(default_port);
                for socket_addr in resolve_host_port(&host, port) {
                    if discovery.ipv4_only && !socket_addr.is_ipv4() {
                        continue;
                    }
                    upstreams.insert(Backend {
                        addr: SocketAddr::Inet(socket_addr),
                        weight,
                        ext: Extensions::new(),
                    });
                }
            },
        }
    }

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
    use super::Discovery;
    use super::new_static_discovery;
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

    /// IPv6 literals and weights come through as configured, and a bad
    /// entry is rejected up front instead of being dropped with a warning.
    #[tokio::test]
    async fn test_static_discovery_ipv6_and_errors() {
        let backends = new_static_discovery(&Discovery {
            addr: vec![
                "[::1]:8080 3".to_string(),
                "127.0.0.1:8080".to_string(),
            ],
            ..Default::default()
        })
        .unwrap();
        backends.update(|_| {}).await.unwrap();
        let mut addrs: Vec<(String, usize)> = backends
            .get_backend()
            .iter()
            .map(|backend| (backend.addr.to_string(), backend.weight))
            .collect();
        addrs.sort();
        assert_eq!(
            vec![
                ("127.0.0.1:8080".to_string(), 1),
                ("[::1]:8080".to_string(), 3)
            ],
            addrs
        );

        // ipv4_only drops the IPv6 backend.
        let backends = new_static_discovery(&Discovery {
            addr: vec!["[::1]:8080".to_string(), "127.0.0.1:8080".to_string()],
            ipv4_only: true,
            ..Default::default()
        })
        .unwrap();
        backends.update(|_| {}).await.unwrap();
        assert_eq!(1, backends.get_backend().len());

        let err = new_static_discovery(&Discovery {
            addr: vec!["127.0.0.1:8080 0".to_string()],
            ..Default::default()
        })
        .err()
        .expect("a zero weight must be rejected");
        assert_eq!(
            "weight of 127.0.0.1:8080 0 must be a positive integer",
            err.to_string()
        );
    }

    /// A unix path is a backend of its own, with no port invented and no
    /// DNS lookup. `ipv4_only` does not drop it quietly.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_static_discovery_unix() {
        let backends = match new_static_discovery(&Discovery {
            addr: vec![
                "unix:/tmp/pingap-app.sock 2".to_string(),
                "127.0.0.1:8080".to_string(),
            ],
            ..Default::default()
        }) {
            Ok(backends) => backends,
            Err(err) => panic!("unix discovery failed: {err}"),
        };
        match backends.update(|_| {}).await {
            Ok(()) => {},
            Err(err) => panic!("update failed: {err}"),
        }
        let mut addrs: Vec<(String, usize)> = backends
            .get_backend()
            .iter()
            .map(|backend| (backend.addr.to_string(), backend.weight))
            .collect();
        addrs.sort();
        assert_eq!(
            vec![
                ("/tmp/pingap-app.sock".to_string(), 2),
                ("127.0.0.1:8080".to_string(), 1),
            ],
            addrs
        );

        match new_static_discovery(&Discovery {
            addr: vec!["unix:/tmp/pingap-app.sock".to_string()],
            ipv4_only: true,
            ..Default::default()
        }) {
            Err(err) => assert_eq!(
                "ipv4_only does not apply to unix socket unix:/tmp/pingap-app.sock",
                err.to_string()
            ),
            Ok(_) => panic!("ipv4_only with a unix socket accepted"),
        }
        match new_static_discovery(&Discovery {
            addr: vec!["unix:@app".to_string()],
            ..Default::default()
        }) {
            Err(err) => assert_eq!(
                "abstract unix sockets are not supported",
                err.to_string()
            ),
            Ok(_) => panic!("abstract socket accepted"),
        }
    }
}
