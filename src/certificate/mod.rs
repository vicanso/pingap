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

use crate::util;
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

mod chain;
mod self_signed;
mod tls_certificate;
mod validity_checker;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("X509 error, category: {category}, {message}"))]
    X509 { category: String, message: String },
    #[snafu(display("Invalid error, category: {category}, {message}"))]
    Invalid { message: String, category: String },
}

type Result<T, E = Error> = std::result::Result<T, E>;

fn parse_ip_addr(data: &[u8]) -> Result<IpAddr> {
    let addr = if data.len() == 4 {
        let arr: [u8; 4] = data.try_into().unwrap_or_default();
        IpAddr::V4(Ipv4Addr::from(arr))
    } else {
        let arr: [u8; 16] = data.try_into().unwrap_or_default();
        IpAddr::V6(Ipv6Addr::from(arr))
    };
    Ok(addr)
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct Certificate {
    pub domains: Vec<String>,
    pub pem: Vec<u8>,
    pub key: Vec<u8>,
    pub acme: Option<String>,
    pub not_after: i64,
    pub not_before: i64,
    pub issuer: String,
}
impl Certificate {
    pub fn new(pem: String, key: String) -> Result<Certificate> {
        let pem_data =
            util::convert_certificate_bytes(&Some(pem)).unwrap_or_default();
        let (_, p) =
            x509_parser::pem::parse_x509_pem(&pem_data).map_err(|e| {
                Error::X509 {
                    category: "parse_x509_pem".to_string(),
                    message: e.to_string(),
                }
            })?;
        let x509 = p.parse_x509().map_err(|e| Error::X509 {
            category: "parse_x509".to_string(),
            message: e.to_string(),
        })?;
        let mut dns_names = vec![];
        if let Ok(Some(subject_alternative_name)) =
            x509.subject_alternative_name()
        {
            for item in subject_alternative_name.value.general_names.iter() {
                match item {
                    x509_parser::prelude::GeneralName::DNSName(name) => {
                        dns_names.push(name.to_string());
                    },
                    x509_parser::prelude::GeneralName::IPAddress(data) => {
                        if let Ok(addr) = parse_ip_addr(data) {
                            dns_names.push(addr.to_string());
                        }
                    },
                    _ => {},
                };
            }
        };
        let validity = x509.validity();
        Ok(Self {
            domains: dns_names,
            pem: pem_data,
            key: util::convert_certificate_bytes(&Some(key))
                .unwrap_or_default(),
            not_after: validity.not_after.timestamp(),
            not_before: validity.not_before.timestamp(),
            issuer: x509.issuer.to_string(),
            ..Default::default()
        })
    }
    /// Get the common name of certificate issuer
    pub fn get_issuer_common_name(&self) -> String {
        let re = regex::Regex::new(r"CN=(?P<CN>[\S ]+?)($|,)").unwrap();
        if let Some(caps) = re.captures(&self.issuer) {
            return caps["CN"].to_string();
        }
        "".to_string()
    }
    /// Validate the cert is within the expiration date.
    pub fn valid(&self) -> bool {
        let ts = util::now().as_secs() as i64;
        self.not_after - ts > 2 * 24 * 3600
    }
    /// Get the cert pem data.
    pub fn get_cert(&self) -> Vec<u8> {
        self.pem.clone()
    }
    /// Get the cert key data.
    pub fn get_key(&self) -> Vec<u8> {
        self.key.clone()
    }
}

pub use self_signed::new_self_signed_certificate_validity_service;
pub use tls_certificate::TlsCertificate;
pub use validity_checker::new_certificate_validity_service;
