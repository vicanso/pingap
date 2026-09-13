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

use super::Error;
use ahash::AHashSet;
use ipnet::IpNet;
use std::net::{AddrParseError, IpAddr};
use std::str::FromStr;

/// IpRules stores pre-parsed IP addresses and networks for efficient access control.
#[derive(Clone, Debug)]
pub struct IpRules {
    ip_net_list: Vec<IpNet>,
    // Use a HashSet for O(1) average time complexity for individual IP lookups.
    ip_set: AHashSet<IpAddr>,
}

impl IpRules {
    /// Creates a new IpRules instance from a list of IP addresses and/or CIDR networks.
    ///
    /// The input values are parsed and stored in optimized data structures for fast lookups.
    /// An entry that is neither is dropped; [`IpRules::try_new`] rejects it
    /// instead, which is what configuration validation wants.
    pub fn new<T: AsRef<str>>(values: &[T]) -> Self {
        Self::parse(values).0
    }

    /// Like [`IpRules::new`], but an entry that is neither an IP address nor
    /// a CIDR network is an error. A typo in an allow or deny list must fail
    /// validation rather than silently let traffic through or block it.
    pub fn try_new<T: AsRef<str>>(values: &[T]) -> Result<Self, Error> {
        let (rules, invalid) = Self::parse(values);
        if invalid.is_empty() {
            return Ok(rules);
        }
        Err(Error::Invalid {
            message: format!("ip or cidr: {}", invalid.join(", ")),
        })
    }

    /// Parses every entry, returning the rules and the entries that were
    /// neither an address nor a network.
    fn parse<T: AsRef<str>>(values: &[T]) -> (Self, Vec<String>) {
        let mut ip_net_list = vec![];
        let mut ip_set = AHashSet::new();
        let mut invalid = vec![];

        for item in values {
            let item_str = item.as_ref().trim();
            // Try parsing as a CIDR network first.
            if let Ok(value) = IpNet::from_str(item_str) {
                ip_net_list.push(value);
            // If not a network, try parsing as a single IP address.
            } else if let Ok(value) = IpAddr::from_str(item_str) {
                ip_set.insert(value);
            } else {
                invalid.push(item_str.to_string());
            }
        }
        (
            Self {
                ip_net_list,
                ip_set,
            },
            invalid,
        )
    }

    /// Checks if a given IP address matches any of the stored rules.
    ///
    /// This is the primary method for checking access. It parses the string
    /// and then performs the efficient matching logic.
    pub fn is_match(&self, ip: &str) -> Result<bool, AddrParseError> {
        let addr = ip.parse::<IpAddr>()?;
        Ok(self.is_match_addr(&addr))
    }

    /// A more performant version of `is_match` that accepts a pre-parsed `IpAddr`.
    ///
    /// This allows callers to avoid re-parsing the IP address if they already
    /// have it in `IpAddr` form.
    pub fn is_match_addr(&self, ip_addr: &IpAddr) -> bool {
        // First, perform a fast O(1) lookup in the HashSet.
        if self.ip_set.contains(ip_addr) {
            return true;
        }
        // If not found, iterate through the network ranges.
        self.ip_net_list.iter().any(|net| net.contains(ip_addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_ip_rules() {
        let rules = IpRules::new(&[
            "192.168.1.0/24", // A network
            "10.0.0.1",       // A single IP
            "2001:db8::/32",  // An IPv6 network
            "2001:db8:a::1",  // A single IPv6
            "not-an-ip",      // An invalid entry that should be ignored
        ]);

        // Check that the constructor correctly parsed and stored the rules.
        assert_eq!(rules.ip_net_list.len(), 2);
        assert_eq!(rules.ip_set.len(), 2);

        // --- Test is_match_addr for performance-critical paths ---
        let ip_in_net_v4 = "192.168.1.100".parse().unwrap();
        let exact_ip_v4 = "10.0.0.1".parse().unwrap();
        let outside_ip_v4 = "192.168.2.1".parse().unwrap();

        let ip_in_net_v6 = "2001:db8:dead:beef::1".parse().unwrap();
        let exact_ip_v6 = "2001:db8:a::1".parse().unwrap();
        let outside_ip_v6 = "2001:db9::1".parse().unwrap();

        assert!(rules.is_match_addr(&ip_in_net_v4));
        assert!(rules.is_match_addr(&exact_ip_v4));
        assert!(!rules.is_match_addr(&outside_ip_v4));

        assert!(rules.is_match_addr(&ip_in_net_v6));
        assert!(rules.is_match_addr(&exact_ip_v6));
        assert!(!rules.is_match_addr(&outside_ip_v6));

        // --- Test is_match for user-facing convenience ---
        assert_eq!(rules.is_match("192.168.1.1"), Ok(true));
        assert_eq!(rules.is_match("10.0.0.1"), Ok(true));
        assert_eq!(rules.is_match("192.168.3.1"), Ok(false));
        // Test invalid IP string input for is_match
        assert!(rules.is_match("999.999.999.999").is_err());
    }

    #[test]
    fn test_try_new_rejects_invalid_entries() {
        let rules =
            IpRules::try_new(&[" 10.0.0.1 ", "192.168.1.0/24"]).unwrap();
        assert_eq!(rules.is_match("10.0.0.1"), Ok(true));

        let err = IpRules::try_new(&["10.0.0.1", "not-an-ip", "10.0.0/8"])
            .unwrap_err();
        assert_eq!("Invalid ip or cidr: not-an-ip, 10.0.0/8", err.to_string());
    }
}
