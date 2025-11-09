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

use ahash::AHashMap;
use pingora::tls::x509::X509;
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::LazyLock;

mod chain;
mod dynamic_certificate;
mod self_signed;
mod tls_certificate;
mod validity_checker;

pub static LOG_TARGET: &str = "pingap::certificate";

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
    Ok(match data.len() {
        4 => IpAddr::V4(Ipv4Addr::from(
            // Should not fail due to len check
            TryInto::<[u8; 4]>::try_into(data).map_err(|e| Error::Invalid {
                category: "ip_parse".to_string(),
                // 这个错误在逻辑上不应该发生，但我们还是处理它
                message: format!(
                    "internal slice conversion error (4 bytes): {e}"
                ),
            })?,
        )),
        16 => IpAddr::V6(Ipv6Addr::from(
            // Should not fail due to len check
            TryInto::<[u8; 16]>::try_into(data).map_err(|e| {
                Error::Invalid {
                    category: "ip_parse".to_string(),
                    message: format!(
                        "internal slice conversion error (16 bytes): {e}"
                    ),
                }
            })?,
        )),
        len => {
            return Err(Error::Invalid {
                category: "ip_parse".to_string(),
                message: format!("invalid ip address length: {len}"),
            })
        },
    })
}

// parse leaf certificate and chain certificates from pem and key
pub fn parse_leaf_chain_certificates(
    pem: &str,
    key: &str,
) -> Result<(Certificate, Vec<X509>)> {
    let pem_data_list = pingap_util::convert_certificate_bytes(Some(pem))
        .ok_or_else(|| Error::Invalid {
            category: "certificate".to_string(),
            message: "invalid pem data".to_string(),
        })?;
    let key_data_list =
        pingap_util::convert_certificate_bytes(Some(key)).unwrap_or_default();
    let leaf_pem_data = &pem_data_list[0];
    let (_, p) =
        x509_parser::pem::parse_x509_pem(leaf_pem_data).map_err(|e| {
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
    if let Ok(Some(subject_alternative_name)) = x509.subject_alternative_name()
    {
        // get dns name and ip address of certificate
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

    let mut x509_certificates = vec![];
    for pem in pem_data_list.iter() {
        let cert = X509::from_pem(pem).map_err(|e| Error::Invalid {
            category: "x509_from_pem".to_string(),
            message: e.to_string(),
        })?;
        x509_certificates.push(cert);
    }
    let key = if key_data_list.is_empty() {
        vec![]
    } else {
        key_data_list[0].clone()
    };

    let leaf_certificate = Certificate {
        domains: dns_names,
        pem: leaf_pem_data.clone(),
        key,
        not_after: validity.not_after.timestamp(),
        not_before: validity.not_before.timestamp(),
        issuer: x509.issuer.to_string(),
        ..Default::default()
    };

    Ok((leaf_certificate, x509_certificates))
}

/// Represents a X.509 certificate with associated metadata
#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct Certificate {
    /// List of domain names and ip addresses that this certificate is valid for
    pub domains: Vec<String>,
    /// PEM-encoded certificate data as bytes
    pub pem: Vec<u8>,
    /// PEM-encoded private key data as bytes
    pub key: Vec<u8>,
    /// Optional ACME (Automated Certificate Management Environment) identifier
    pub acme: Option<String>,
    /// Unix timestamp when the certificate expires
    pub not_after: i64,
    /// Unix timestamp when the certificate becomes valid
    pub not_before: i64,
    /// Distinguished Name (DN) of the certificate issuer
    pub issuer: String,
}
impl Certificate {
    /// Extracts the Common Name (CN) from the certificate issuer field
    ///
    /// # Returns
    /// * `String` - The issuer's Common Name or empty string if not found
    pub fn get_issuer_common_name(&self) -> String {
        static CN_REGEX: LazyLock<Option<regex::Regex>> = LazyLock::new(|| {
            regex::Regex::new(r"CN=(?P<CN>[\S ]+?)($|,)").ok()
        });
        let Some(regex) = CN_REGEX.as_ref() else {
            return "".to_string();
        };

        regex
            .captures(&self.issuer)
            .and_then(|caps| caps.name("CN"))
            .map(|m| m.as_str().to_string())
            .unwrap_or_default()
    }
    /// Checks if the certificate is valid and not expiring within 48 hours
    ///
    /// # Returns
    /// * `bool` - True if the certificate is valid, false otherwise
    pub fn valid(&self, buffer_days: u16) -> bool {
        if self.not_after == 0 {
            return false;
        }
        let ts = pingap_core::now_sec() as i64;
        let mut days = buffer_days as i64;
        if days == 0 {
            days = 2;
        }
        self.not_after - ts > days * 24 * 3600
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

pub use dynamic_certificate::*;
pub use rcgen;
pub use self_signed::new_self_signed_certificate_validity_service;
pub use tls_certificate::TlsCertificate;
pub use validity_checker::new_certificate_validity_service;

// Type alias for storing certificates in a high-performance hash map
pub type DynamicCertificates = AHashMap<String, Arc<TlsCertificate>>;

pub trait CertificateProvider: Send + Sync {
    fn get(&self, sni: &str) -> Option<Arc<TlsCertificate>>;
    fn list(&self) -> Arc<DynamicCertificates>;
    fn store(&self, data: DynamicCertificates);
}

#[cfg(test)]
mod tests {
    use super::{parse_ip_addr, parse_leaf_chain_certificates};
    use pretty_assertions::assert_eq;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_parse_ip_addr() {
        assert_eq!(
            parse_ip_addr(&[192, 168, 1, 1]).unwrap(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
        );

        assert_eq!(
            parse_ip_addr(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
                .unwrap(),
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))
        );
        assert!(parse_ip_addr(&[192, 168, 1, 1, 1]).is_err());
    }

    #[test]
    fn test_cert() {
        // spellchecker:off
        let pem = r###"-----BEGIN CERTIFICATE-----
MIID/TCCAmWgAwIBAgIQJUGCkB1VAYha6fGExkx0KTANBgkqhkiG9w0BAQsFADBV
MR4wHAYDVQQKExVta2NlcnQgZGV2ZWxvcG1lbnQgQ0ExFTATBgNVBAsMDHZpY2Fu
c29AdHJlZTEcMBoGA1UEAwwTbWtjZXJ0IHZpY2Fuc29AdHJlZTAeFw0yNDA3MDYw
MjIzMzZaFw0yNjEwMDYwMjIzMzZaMEAxJzAlBgNVBAoTHm1rY2VydCBkZXZlbG9w
bWVudCBjZXJ0aWZpY2F0ZTEVMBMGA1UECwwMdmljYW5zb0B0cmVlMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv5dbylSPQNARrpT/Rn7qZf6JmH3cueMp
YdOpctuPYeefT0Jdgp67bg17fU5pfyR2BWYdwyvHCNmKqLdYPx/J69hwTiVFMOcw
lVQJjbzSy8r5r2cSBMMsRaAZopRDnPy7Ls7Ji+AIT4vshUgL55eR7ACuIJpdtUYm
TzMx9PTA0BUDkit6z7bTMaEbjDmciIBDfepV4goHmvyBJoYMIjnAwnTFRGRs/QJN
d2ikFq999fRINzTDbRDP1K0Kk6+zYoFAiCMs9lEDymu3RmiWXBXpINR/Sv8CXtz2
9RTVwTkjyiMOPY99qBfaZTiy+VCjcwTGKPyus1axRMff4xjgOBewOwIDAQABo14w
XDAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwHwYDVR0jBBgw
FoAUhU5Igu3uLUabIqUhUpVXjk1JVtkwFAYDVR0RBA0wC4IJcGluZ2FwLmlvMA0G
CSqGSIb3DQEBCwUAA4IBgQDBimRKrqnEG65imKriM2QRCEfdB6F/eP9HYvPswuAP
tvQ6m19/74qbtkd6vjnf6RhMbj9XbCcAJIhRdnXmS0vsBrLDsm2q98zpg6D04F2E
L++xTiKU6F5KtejXcTHHe23ZpmD2XilwcVDeGFu5BEiFoRH9dmqefGZn3NIwnIeD
Yi31/cL7BoBjdWku5Qm2nCSWqy12ywbZtQCbgbzb8Me5XZajeGWKb8r6D0Nb+9I9
OG7dha1L3kxerI5VzVKSiAdGU0C+WcuxfsKAP8ajb1TLOlBaVyilfqmiF457yo/2
PmTYzMc80+cQWf7loJPskyWvQyfmAnSUX0DI56avXH8LlQ57QebllOtKgMiCo7cr
CCB2C+8hgRNG9ZmW1KU8rxkzoddHmSB8d6+vFqOajxGdyOV+aX00k3w6FgtHOoKD
Ztdj1N0eTfn02pibVcXXfwESPUzcjERaMAGg1hoH1F4Gxg0mqmbySAuVRqNLnXp5
CRVQZGgOQL6WDg3tUUDXYOs=
-----END CERTIFICATE-----"###;
        // spellchecker:on
        let (cert, _) = parse_leaf_chain_certificates(pem, "").unwrap();

        assert_eq!(
            "O=mkcert development CA, OU=vicanso@tree, CN=mkcert vicanso@tree",
            cert.issuer
        );
        assert_eq!(1720232616, cert.not_before);
        assert_eq!(1791253416, cert.not_after);
        assert_eq!("mkcert vicanso@tree", cert.get_issuer_common_name());
        assert_eq!(true, cert.valid(2));
    }
}
