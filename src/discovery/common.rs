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

pub fn is_static_discovery(value: &str) -> bool {
    value.is_empty() || value == COMMON_DISCOVERY
}

/// Create a static discovery, execute it only once.
/// It will resolve the domain to socket address at the beginning stage.
pub fn new_common_discover_backends(
    addrs: &[String],
    tls: bool,
    ipv4_only: bool,
) -> Result<Backends> {
    let hosts = addrs.join(",");
    let now = SystemTime::now();
    let mut upstreams = BTreeSet::new();
    let mut backends = vec![];
    let addrs = format_addrs(addrs, tls);
    let mut new_addrs = vec![];
    for (ip, port, weight) in addrs.iter() {
        let addr = format!("{ip}:{port}");
        // resolve to socket addr
        for item in addr.to_socket_addrs().map_err(|e| Error::Io {
            source: e,
            content: format!("{addr} to socket addr fail"),
        })? {
            if ipv4_only && !item.is_ipv4() {
                continue;
            }
            new_addrs.push(item.to_string());
            let backend = Backend {
                addr: SocketAddr::Inet(item),
                weight: weight.to_owned(),
                ext: Extensions::new(),
            };
            backends.push(backend)
        }
    }
    info!(
        category = LOG_CATEGORY,
        hosts,
        addrs = new_addrs.join(","),
        elapsed =
            format!("{}ms", now.elapsed().unwrap_or_default().as_millis()),
        "common discover success"
    );
    upstreams.extend(backends);
    let discovery = discovery::Static::new(upstreams);
    let backends = Backends::new(discovery);
    Ok(backends)
}
