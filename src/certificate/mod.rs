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

/// Parses a byte slice into an IP address (IPv4 or IPv6)
///
/// # Arguments
/// * `data` - A byte slice containing the IP address data
///
/// # Returns
/// * `Result<IpAddr>` - The parsed IP address or an error if invalid
fn parse_ip_addr(data: &[u8]) -> Result<IpAddr> {
    match data.len() {
        4 => data
            .try_into()
            .map(|arr: [u8; 4]| IpAddr::V4(Ipv4Addr::from(arr)))
            .map_err(|_| Error::Invalid {
                category: "ip_parse".to_string(),
                message: "Invalid IPv4 address".to_string(),
            }),
        16 => data
            .try_into()
            .map(|arr: [u8; 16]| IpAddr::V6(Ipv6Addr::from(arr)))
            .map_err(|_| Error::Invalid {
                category: "ip_parse".to_string(),
                message: "Invalid IPv6 address".to_string(),
            }),
        len => Err(Error::Invalid {
            category: "ip_parse".to_string(),
            message: format!("invalid ip address length: {}", len),
        }),
    }
}

/// Represents a X.509 certificate with associated metadata
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
    /// Creates a new Certificate instance from PEM-encoded certificate and private key
    ///
    /// # Arguments
    /// * `pem` - PEM-encoded certificate string
    /// * `key` - PEM-encoded private key string
    ///
    /// # Returns
    /// * `Result<Certificate>` - The parsed certificate or an error if invalid
    pub fn new(pem: &str, key: &str) -> Result<Certificate> {
        let pem_data =
            util::convert_certificate_bytes(Some(pem)).ok_or_else(|| {
                Error::Invalid {
                    category: "certificate".to_string(),
                    message: "invalid pem data".to_string(),
                }
            })?;

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
        dns_names.sort();
        let validity = x509.validity();
        Ok(Self {
            domains: dns_names,
            pem: pem_data,
            key: util::convert_certificate_bytes(Some(key)).unwrap_or_default(),
            not_after: validity.not_after.timestamp(),
            not_before: validity.not_before.timestamp(),
            issuer: x509.issuer.to_string(),
            ..Default::default()
        })
    }
    /// Extracts the Common Name (CN) from the certificate issuer field
    ///
    /// # Returns
    /// * `String` - The issuer's Common Name or empty string if not found
    pub fn get_issuer_common_name(&self) -> String {
        static CN_REGEX: once_cell::sync::Lazy<regex::Regex> =
            once_cell::sync::Lazy::new(|| {
                regex::Regex::new(r"CN=(?P<CN>[\S ]+?)($|,)").unwrap()
            });

        CN_REGEX
            .captures(&self.issuer)
            .and_then(|caps| caps.name("CN"))
            .map(|m| m.as_str().to_string())
            .unwrap_or_default()
    }
    /// Checks if the certificate is valid and not expiring within 48 hours
    ///
    /// # Returns
    /// * `bool` - True if the certificate is valid, false otherwise
    pub fn valid(&self) -> bool {
        let ts = util::now().as_secs() as i64;
        self.not_after - ts > 2 * 24 * 3600
    }
    /// Returns the PEM-encoded certificate data
    ///
    /// # Returns
    /// * `Vec<u8>` - The certificate data as bytes
    pub fn get_cert(&self) -> Vec<u8> {
        self.pem.clone()
    }
    /// Returns the PEM-encoded private key data
    ///
    /// # Returns
    /// * `Vec<u8>` - The private key data as bytes
    pub fn get_key(&self) -> Vec<u8> {
        self.key.clone()
    }
}

pub use self_signed::new_self_signed_certificate_validity_service;
pub use tls_certificate::TlsCertificate;
pub use validity_checker::new_certificate_validity_service;
