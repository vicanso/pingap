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

#[derive(Clone, Debug)]
pub struct IpRules {
    ip_net_list: Vec<IpNet>,
    ip_list: Vec<String>,
}

impl IpRules {
    pub fn new(values: &Vec<String>) -> Self {
        let mut ip_net_list = vec![];
        let mut ip_list = vec![];
        for item in values {
            if let Ok(value) = IpNet::from_str(item) {
                ip_net_list.push(value);
            } else {
                ip_list.push(item.to_string());
            }
        }
        Self {
            ip_net_list,
            ip_list,
        }
    }
    pub fn matched(&self, ip: &String) -> Result<bool, AddrParseError> {
        let found = if self.ip_list.contains(ip) {
            true
        } else {
            let addr = ip.parse::<IpAddr>()?;
            self.ip_net_list.iter().any(|item| item.contains(&addr))
        };
        Ok(found)
    }
}
