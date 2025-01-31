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

use crate::util;
use hickory_resolver::error::ResolveError;
use snafu::Snafu;

pub static LOG_CATEGORY: &str = "discovery";

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Io error {source}, {content}"))]
    Io {
        source: std::io::Error,
        content: String,
    },
    #[snafu(display("Resolve error {source}"))]
    Resolve { source: ResolveError },
    #[snafu(display("{message}"))]
    Invalid { message: String },
    #[snafu(display("Docker error {source}"))]
    Docker { source: bollard::errors::Error },
}
impl From<Error> for pingora::BError {
    fn from(value: Error) -> Self {
        util::new_internal_error(500, value.to_string())
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

pub(crate) type Addr = (String, String, usize);

/// Formats a list of address strings into a vector of structured address tuples.
///
/// # Arguments
///
/// * `addrs` - A slice of strings containing addresses in the format "host:port weight" or "host:port" or "host"
/// * `tls` - A boolean indicating whether to use TLS default port (443) or HTTP default port (80)
///
/// # Returns
///
/// Returns a vector of tuples containing (host, port, weight), where:
/// * host is the hostname or IP address
/// * port is either specified in the address or defaults to 443/80 based on TLS setting
/// * weight is either specified after the address or defaults to 1
pub(crate) fn format_addrs(addrs: &[String], tls: bool) -> Vec<Addr> {
    let mut new_addrs = vec![];
    for addr in addrs.iter() {
        // get the weight of address
        let arr: Vec<_> = addr.split(' ').collect();
        let weight = if arr.len() == 2 {
            arr[1].parse::<usize>().unwrap_or(1)
        } else {
            1
        };
        // split ip and port
        // the port will use default value if none
        if let Some((host, port)) = arr[0].split_once(':') {
            new_addrs.push((host.to_string(), port.to_string(), weight));
        } else {
            let port = if tls {
                "443".to_string()
            } else {
                "80".to_string()
            };
            new_addrs.push((arr[0].to_string(), port, weight));
        }
    }
    new_addrs
}

pub const DNS_DISCOVERY: &str = "dns";
pub const DOCKER_DISCOVERY: &str = "docker";
pub const STATIC_DISCOVERY: &str = "static";
pub const TRANSPARENT_DISCOVERY: &str = "transparent";

mod common;
mod dns;
mod docker;
pub use common::{is_static_discovery, new_static_discovery};
pub use dns::{is_dns_discovery, new_dns_discover_backends};
pub use docker::{is_docker_discovery, new_docker_discover_backends};

#[cfg(test)]
mod tests {
    use super::format_addrs;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_format_addrs() {
        let addrs = format_addrs(&["127.0.0.1:8080".to_string()], false);
        assert_eq!(format!("{:?}", addrs), r#"[("127.0.0.1", "8080", 1)]"#);

        let addrs = format_addrs(&["127.0.0.1".to_string()], false);
        assert_eq!(format!("{:?}", addrs), r#"[("127.0.0.1", "80", 1)]"#);

        let addrs = format_addrs(&["127.0.0.1".to_string()], true);
        assert_eq!(format!("{:?}", addrs), r#"[("127.0.0.1", "443", 1)]"#);

        let addrs = format_addrs(&["127.0.0.1 10".to_string()], false);
        assert_eq!(format!("{:?}", addrs), r#"[("127.0.0.1", "80", 10)]"#);
    }
}
