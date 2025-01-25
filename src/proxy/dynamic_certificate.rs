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

use crate::certificate::{Certificate, TlsCertificate};
use crate::config::CertificateConf;
use crate::util;
use ahash::AHashMap;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use once_cell::sync::Lazy;
use pingora::listeners::tls::TlsSettings;
use pingora::tls::ext;
use pingora::tls::pkey::{PKey, Private};
use pingora::tls::ssl::{NameType, SslRef};
use pingora::tls::x509::X509;
use snafu::Snafu;
use std::collections::HashMap;
use std::convert::TryInto;
use std::sync::Arc;
use tracing::{debug, error, info};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Invalid error, category: {category}, {message}"))]
    Invalid { message: String, category: String },
}
type Result<T, E = Error> = std::result::Result<T, E>;

// Type alias for storing certificates in a high-performance hash map
// AHashMap provides better performance than std::collections::HashMap by:
// - Using aHash algorithm optimized for short keys
// - Reducing collision probability
// - Having better cache utilization
type DynamicCertificates = AHashMap<String, Arc<TlsCertificate>>;

// Global certificate storage using thread-safe atomic references
// - ArcSwap enables atomic pointer swapping for zero-downtime updates
// - Lazy initialization ensures the map is only created when first accessed
// - Arc provides thread-safe reference counting for shared access
static DYNAMIC_CERTIFICATE_MAP: Lazy<ArcSwap<DynamicCertificates>> =
    Lazy::new(|| ArcSwap::from_pointee(AHashMap::new()));

// Fallback server name used when:
// - No SNI (Server Name Indication) is provided in TLS handshake
// - No matching certificate is found for the requested domain
// - Certificate is marked as default with is_default = true
static DEFAULT_SERVER_NAME: &str = "*";

// Parses certificate configurations and builds the certificate store
// Parameters:
// - certificate_configs: Map of certificate names to their configurations
// Returns:
// - DynamicCertificates: Map of domain names to parsed certificates
// - Vec<(String, String)>: List of (certificate_name, error_message) for failed parsing
fn parse_certificates(
    certificate_configs: &HashMap<String, CertificateConf>,
) -> (DynamicCertificates, Vec<(String, String)>) {
    let mut dynamic_certs = AHashMap::new();
    let mut errors = vec![];
    for (name, certificate) in certificate_configs.iter() {
        let result: Result<TlsCertificate, crate::certificate::Error> =
            certificate.try_into();
        match result {
            Ok(mut dynamic_cert) => {
                dynamic_cert.name = Some(name.clone());
                let mut domains = dynamic_cert.domains.clone();
                let cert = Arc::new(dynamic_cert);
                if let Some(value) = &certificate.domains {
                    domains =
                        value.split(',').map(|item| item.to_string()).collect();
                }
                for domain in domains.iter() {
                    dynamic_certs.insert(domain.to_string(), cert.clone());
                }
                let is_default = certificate.is_default.unwrap_or_default();
                if is_default {
                    dynamic_certs
                        .insert(DEFAULT_SERVER_NAME.to_string(), cert.clone());
                }
            },
            Err(e) => {
                errors.push((name.to_string(), e.to_string()));
            },
        };
    }
    (dynamic_certs, errors)
}

/// Updates the global certificate store with new configurations
///
/// # Arguments
/// * `certificate_configs` - HashMap of certificate names to their configurations
///
/// # Returns
/// * `Vec<String>` - List of domain names whose certificates were updated
/// * `String` - Semicolon-separated list of parsing errors
///
/// Updates certificates atomically using ArcSwap, detecting changes by comparing hash_keys.
/// Supports multiple domains per certificate and wildcard certificates.
pub fn try_update_certificates(
    certificate_configs: &HashMap<String, CertificateConf>,
) -> (Vec<String>, String) {
    let (dynamic_certs, errors) = parse_certificates(certificate_configs);
    let certs = DYNAMIC_CERTIFICATE_MAP.load();
    let mut updated_certificates = vec![];
    for (name, cert) in dynamic_certs.iter() {
        if let Some(value) = certs.get(name) {
            if value.hash_key == cert.hash_key {
                break;
            }
        }
        updated_certificates.push(name.clone());
    }
    let msg_list: Vec<String> = errors
        .iter()
        .map(|item| format!("{}({})", item.1, item.0))
        .collect();
    DYNAMIC_CERTIFICATE_MAP.store(Arc::new(dynamic_certs));
    (updated_certificates, msg_list.join(";"))
}

/// Retrieves a list of all certificates and their associated information
///
/// # Returns
/// * `Vec<(String, Certificate)>` - List of tuples containing certificate names and their info
///
/// The name will be either the configured certificate name or the domain name if no
/// specific name was set.
pub fn get_certificate_info_list() -> Vec<(String, Certificate)> {
    let mut infos = vec![];
    for (name, cert) in DYNAMIC_CERTIFICATE_MAP.load().iter() {
        if let Some(info) = &cert.info {
            let key = if let Some(name) = &cert.name {
                name.clone()
            } else {
                name.clone()
            };
            infos.push((key, info.clone()));
        }
    }
    infos
}

/// Parameters for configuring TLS settings
///
/// Contains all the necessary configuration options for setting up TLS,
/// including protocol versions, cipher suites, and HTTP/2 support.
#[derive(Debug)]
pub struct TlsSettingParams {
    pub server_name: String,
    pub enabled_h2: bool,            // Enable HTTP/2 support
    pub cipher_list: Option<String>, // Legacy cipher list
    pub ciphersuites: Option<String>, // Modern cipher suites
    pub tls_min_version: Option<String>, // Minimum TLS version
    pub tls_max_version: Option<String>, // Maximum TLS version
}

/// Applies certificate, private key and chain certificate to an SSL context
///
/// # Arguments
/// * `ssl` - Reference to the SSL context to modify
/// * `cert` - X509 certificate to apply
/// * `key` - Private key for the certificate
/// * `chain_certificate` - Optional chain certificate
///
/// # Side Effects
/// Logs errors if any operation fails but continues execution
#[inline]
fn ssl_certificate(
    ssl: &mut SslRef,
    cert: &X509,
    key: &PKey<Private>,
    chain_certificate: &Option<X509>,
) {
    // set tls certificate
    if let Err(e) = ext::ssl_use_certificate(ssl, cert) {
        error!(error = e.to_string(), "ssl use certificate fail");
    }
    // set private key
    if let Err(e) = ext::ssl_use_private_key(ssl, key) {
        error!(error = e.to_string(), "ssl use private key fail");
    }
    // set chain certificate
    if let Some(chain) = chain_certificate {
        if let Err(e) = ext::ssl_add_chain_cert(ssl, chain) {
            error!(error = e.to_string(), "ssl add chain cert fail");
        }
    }
}

/// GlobalCertificate implements SNI-based dynamic certificate selection
///
/// Provides runtime certificate selection during TLS handshake based on the
/// Server Name Indication (SNI). Supports:
/// - Dynamic certificate updates
/// - Wildcard certificates
/// - Default fallback certificates
/// - Self-signed CA certificates
#[derive(Debug, Clone, Default)]
pub struct GlobalCertificate {}

impl GlobalCertificate {
    /// New a dynamic certificate from tls setting parameters
    pub fn new_tls_settings(
        &self,
        params: &TlsSettingParams,
    ) -> Result<TlsSettings> {
        let name = params.server_name.clone();
        let mut tls_settings = TlsSettings::with_callbacks(Box::new(
            self.clone(),
        ))
        .map_err(|e| Error::Invalid {
            category: "new_tls_settings".to_string(),
            message: e.to_string(),
        })?;
        if params.enabled_h2 {
            tls_settings.enable_h2();
        }
        if let Some(cipher_list) = &params.cipher_list {
            if let Err(e) = tls_settings.set_cipher_list(cipher_list) {
                error!(error = e.to_string(), name, "set cipher list fail");
            }
        }
        if let Some(ciphersuites) = &params.ciphersuites {
            if let Err(e) = tls_settings.set_ciphersuites(ciphersuites) {
                error!(error = e.to_string(), name, "set ciphersuites fail");
            }
        }
        if let Some(version) =
            util::convert_tls_version(&params.tls_min_version)
        {
            if let Err(e) = tls_settings.set_min_proto_version(Some(version)) {
                error!(
                    error = e.to_string(),
                    name, "set tls min proto version fail"
                );
            }
            if version == pingora::tls::ssl::SslVersion::TLS1_1 {
                tls_settings.set_security_level(0);
                tls_settings
                    .clear_options(pingora::tls::ssl::SslOptions::NO_TLSV1_1);
            }
        }
        if let Err(e) = tls_settings.set_max_proto_version(
            util::convert_tls_version(&params.tls_max_version),
        ) {
            error!(
                error = e.to_string(),
                name, "set tls max proto version fail"
            );
        }

        // tls_settings.set_min_proto_version(version)
        if let Some(min_version) = tls_settings.min_proto_version() {
            info!(name, min_version = format!("{min_version:?}"), "tls proto");
        }
        if let Some(max_version) = tls_settings.max_proto_version() {
            info!(name, max_version = format!("{max_version:?}"), "tls proto");
        }

        Ok(tls_settings)
    }
}

#[async_trait]
impl pingora::listeners::TlsAccept for GlobalCertificate {
    async fn certificate_callback(&self, ssl: &mut SslRef) {
        // Certificate selection process:
        // 1. Extract SNI from TLS handshake
        // 2. Try exact domain match (example.com)
        // 3. Try wildcard domain match (*.example.com)
        // 4. Fall back to default certificate (DEFAULT_SERVER_NAME)
        // 5. Handle special case for CA certificates (self-signed)
        // 6. Apply certificate, private key, and chain to SSL context

        // TODO add more debug log
        debug!(ssl = format!("{ssl:?}"));
        let sni = ssl
            .servername(NameType::HOST_NAME)
            .unwrap_or(DEFAULT_SERVER_NAME);
        debug!(server_name = sni);

        let mut dynamic_certificate = None;
        let certs = DYNAMIC_CERTIFICATE_MAP.load();
        let wildcard_sni =
            &format!("*.{}", sni.split_once('.').unwrap_or_default().1);
        for item in [sni, wildcard_sni, DEFAULT_SERVER_NAME] {
            dynamic_certificate = certs.get(item);
            if dynamic_certificate.is_some() {
                break;
            }
        }

        let Some(d) = dynamic_certificate else {
            error!(sni, ssl = format!("{ssl:?}"), "no match certificate");
            return;
        };

        // ca
        if d.is_ca {
            match d.get_self_signed_certificate(sni) {
                Ok(result) => {
                    ssl_certificate(
                        ssl,
                        &result.x509,
                        &result.key,
                        &d.chain_certificate,
                    );
                },
                Err(err) => {
                    error!(
                        error = err.to_string(),
                        "get self signed cert fail"
                    );
                },
            };
            return;
        }

        if let Some((cert, key)) = &d.certificate {
            ssl_certificate(ssl, cert, key, &d.chain_certificate);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{GlobalCertificate, TlsSettingParams, DYNAMIC_CERTIFICATE_MAP};
    use crate::certificate::TlsCertificate;
    use crate::{config::CertificateConf, proxy::try_update_certificates};
    use pretty_assertions::assert_eq;
    use std::collections::HashMap;

    fn get_tls_pem() -> (String, String) {
        // spellchecker:off
        (
            r###"-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----"###
                .to_string(),
            r###"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC/l1vKVI9A0BGu
lP9Gfupl/omYfdy54ylh06ly249h559PQl2CnrtuDXt9Tml/JHYFZh3DK8cI2Yqo
t1g/H8nr2HBOJUUw5zCVVAmNvNLLyvmvZxIEwyxFoBmilEOc/LsuzsmL4AhPi+yF
SAvnl5HsAK4gml21RiZPMzH09MDQFQOSK3rPttMxoRuMOZyIgEN96lXiCgea/IEm
hgwiOcDCdMVEZGz9Ak13aKQWr3319Eg3NMNtEM/UrQqTr7NigUCIIyz2UQPKa7dG
aJZcFekg1H9K/wJe3Pb1FNXBOSPKIw49j32oF9plOLL5UKNzBMYo/K6zVrFEx9/j
GOA4F7A7AgMBAAECggEAWNDkx2XtxsDuAX2m3VpGdSPLS3rFURMCgwwpGEq6LEvA
qXB9gujswHbVkWBBPaR8ZcJR98EaknquccoUyaaF56Q9Y6yZZ7M07XS4vREUs06T
8wEX9Ec6BcjTOW/77BGpAGjyO7qOf7nA2oRsqF62Ua57CjglSryLU9nKxeCUZaEa
HWbpn/AVieddIBdCSK1ANFgXb1ySA3Rh2IaMggql1n2+gk2s4qyAScarNSz0PDps
v65iK1ZAABmQEItsklBE8XddIK0BE5ciaLShK+BLX/bnPjCle2QGdDOtbNKfn3Ab
8gMmY9q4/isO0i8njeNWtgrmOKpL8ETxbzCDGwqdEQKBgQDxe3nuxeDJSXUaj4Vl
LMJ+jln8AZTEegt5T0lm3kke4vJTyQAjwCtWrxB8xario5uWwf0Np/NvLvqJI7e4
+KIJF/5Vy15QngUHJ0c5D8Fm0DufWI9btuZDG3EYeqs4NRbc1Vu+QBziwZXvemkU
2hHwnVYn3lc2WKgiEXcLf2SAQwKBgQDLHAkc9JzWOnj6YIb/WWLGQxu7kVW6T3Fr
f+c4IZN9IhbjxrRilMG0Z/kQDX8dD2b3suOD+QjBZ1rJR34xDVGPPhbHx+3j+2rK
piUZLPAqk+vODHlx9ST9V7RklZnsitQpxZLI5OhylIKXkTk6I92jDUJNRF9ooeoV
zi2FHQasqQKBgFJg0g7PeEiSg51k+peyNkNgInhivbJtA/8FOkAaco1T1GEav65y
fxZaMGCwOgSI1aoPUVlYQyZZu2QPSDyUrQo3Ii94ahtMXOC82IIxysNdJAnO91DN
Sy33bZRxPHm3Oq5pJpv3WSNN8O06MCDJ57bSpbKCGfRTOEAu/xJwCgPrAoGBALtv
GN3WwvFTrpboA0yb8XIjNfGHMkSn0XQx6W+8VH5SuirjEU40FvnkRUzSF676qrwF
Ir6ET9cjCP3ccxDTSKPW2XDuCJOuTaPLZUrxVIUGUsKocl5+qu78Q+XaxNwsVZRi
1o176SLr+APlKZmExaEVuEzTvvQxD3Ol/A3udl1ZAoGBAKztzGZc2YG5nw62kJ8J
1XBrQG1rWuAMgrVbo/aDnPs04E31tPEOrZ2m7pKr/uGmf74OQeQrUaQ0+A5YZxrD
vmkKQHwfyX6cFGxuXwyCZa7q1E83qFNLPSZ0ZF8DHiJqeunLchxYm4uA4Y8BO1jK
aqcrKJfS+xaKWxXPiNlpBMG5
-----END PRIVATE KEY-----"###
                .to_string(),
        )
        // spellchecker:on
    }

    #[test]
    fn test_new_tls_settings() {
        let dynamic = GlobalCertificate::default();
        let mut tls_settings = dynamic
            .new_tls_settings(&TlsSettingParams {
                server_name: "pingap".to_string(),
                enabled_h2: true,
                cipher_list: Some(
                    "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA".to_string(),
                ),
                ciphersuites: Some(
                    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256"
                        .to_string(),
                ),
                tls_min_version: Some("tlsv1.1".to_string()),
                tls_max_version: Some("tlsv1.3".to_string()),
            })
            .unwrap();
        assert_eq!(true, tls_settings.min_proto_version().is_some());
        assert_eq!(true, tls_settings.max_proto_version().is_some());
    }

    #[test]
    fn test_parse_certificate() {
        let (tls_cert, tls_key) = get_tls_pem();
        let cert_info = CertificateConf {
            tls_cert: Some(tls_cert),
            tls_key: Some(tls_key),
            ..Default::default()
        };
        let dynamic_certificate: TlsCertificate =
            (&cert_info).try_into().unwrap();
        let info = dynamic_certificate.info.unwrap_or_default();

        assert_eq!("pingap.io", dynamic_certificate.domains.join(","));
        assert_eq!(
            "O=mkcert development CA, OU=vicanso@tree, CN=mkcert vicanso@tree",
            info.issuer
        );
        assert_eq!(1720232616, info.not_before);
        assert_eq!(1791253416, info.not_after);
        assert_eq!(true, dynamic_certificate.certificate.is_some());

        let mut map = HashMap::new();
        map.insert("pingap".to_string(), cert_info);
        try_update_certificates(&map);

        let cert = DYNAMIC_CERTIFICATE_MAP
            .load()
            .get("pingap.io")
            .cloned()
            .unwrap();
        assert_eq!(true, cert.certificate.is_some());
        assert_eq!(
            "O=mkcert development CA, OU=vicanso@tree, CN=mkcert vicanso@tree"
                .to_string(),
            cert.info.clone().unwrap().issuer
        );
    }
}
