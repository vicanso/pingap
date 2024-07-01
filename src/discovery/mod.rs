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

use hickory_resolver::error::ResolveError;
use snafu::Snafu;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Io error {source}, {content}"))]
    Io {
        source: std::io::Error,
        content: String,
    },
    #[snafu(display("Resolve error {source}"))]
    Resolve { source: ResolveError },
}
pub type Result<T, E = Error> = std::result::Result<T, E>;

pub(crate) type Addr = (String, String, usize);

pub(crate) fn format_addrs(addrs: &[String], tls: bool) -> Vec<Addr> {
    let mut new_addrs = vec![];
    for addr in addrs.iter() {
        let arr: Vec<_> = addr.split(' ').collect();
        let weight = if arr.len() == 2 {
            arr[1].parse::<usize>().unwrap_or(1)
        } else {
            1
        };
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

mod common;
mod dns;
pub use common::new_common_discover_backends;
pub use dns::new_dns_discover_backends;
