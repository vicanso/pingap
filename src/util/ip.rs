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

use ipnet::IpNet;
use std::net::{AddrParseError, IpAddr};
use std::str::FromStr;

/// IpRules stores IP addresses and networks for access control
/// - ip_net_list: List of IP network ranges (CIDR notation)
/// - ip_list: List of individual IP addresses as strings
#[derive(Clone, Debug)]
pub struct IpRules {
    ip_net_list: Vec<IpNet>,
    ip_list: Vec<String>,
}

impl IpRules {
    /// Creates a new IpRules instance from a list of IP addresses/networks
    ///
    /// Separates the input values into two categories:
    /// - Valid CIDR networks go into ip_net_list
    /// - Individual IP addresses go into ip_list
    pub fn new(values: &Vec<String>) -> Self {
        let mut ip_net_list = vec![];
        let mut ip_list = vec![];
        for item in values {
            // Try parsing as CIDR network (e.g., "192.168.1.0/24")
            if let Ok(value) = IpNet::from_str(item) {
                ip_net_list.push(value);
            } else {
                // If not a valid CIDR, treat as individual IP
                ip_list.push(item.to_string());
            }
        }
        Self {
            ip_net_list,
            ip_list,
        }
    }

    /// Checks if a given IP address matches any of the stored rules
    ///
    /// Returns:
    /// - Ok(true) if IP matches either an individual IP or falls within a network range
    /// - Ok(false) if no match is found
    /// - Err if the IP address string cannot be parsed
    pub fn matched(&self, ip: &String) -> Result<bool, AddrParseError> {
        let found = if self.ip_list.contains(ip) {
            // First check for exact match in individual IP list
            true
        } else {
            // Then check if IP falls within any of the network ranges
            let addr = ip.parse::<IpAddr>()?;
            self.ip_net_list.iter().any(|item| item.contains(&addr))
        };
        Ok(found)
    }
}
