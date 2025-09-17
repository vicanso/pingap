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

use super::CertificateProvider;
use super::DynamicCertificates;
use super::{Error, TlsCertificate, LOG_CATEGORY};
use ahash::AHashMap;
use async_trait::async_trait;
use pingap_config::CertificateConf;
use pingora::listeners::tls::TlsSettings;
use pingora::tls::ext;
use pingora::tls::pkey::{PKey, Private};
use pingora::tls::ssl::SslVersion;
use pingora::tls::ssl::{NameType, SslRef};
use pingora::tls::x509::X509;
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error, info};

type Result<T, E = Error> = std::result::Result<T, E>;

// Fallback server name used when:
// - No SNI (Server Name Indication) is provided in TLS handshake
// - No matching certificate is found for the requested domain
pub static DEFAULT_SERVER_NAME: &str = "*";

// Parses certificate configurations and builds the certificate store
// Parameters:
// - certificate_configs: Map of certificate names to their configurations
// Returns:
// - DynamicCertificates: Map of domain names to parsed certificates
// - Vec<(String, String)>: List of (certificate_name, error_message) for failed parsing
pub fn parse_certificates(
    certificate_configs: &HashMap<String, CertificateConf>,
) -> (DynamicCertificates, Vec<(String, String)>) {
    let mut dynamic_certs = AHashMap::new();
    let mut errors = vec![];

    // Use a temporary map to avoid cloning the Arc<TlsCertificate> for each domain.
    let mut cert_cache: AHashMap<String, Arc<TlsCertificate>> = AHashMap::new();

    for (name, conf) in certificate_configs.iter() {
        if conf.tls_cert.is_none() || conf.tls_key.is_none() {
            continue;
        }

        let cert_arc = match cert_cache.get(name) {
            Some(cert) => cert.clone(),
            None => match TlsCertificate::try_from(conf) {
                Ok(mut cert) => {
                    cert.name = Some(name.clone());
                    let arc_cert = Arc::new(cert);
                    cert_cache.insert(name.clone(), arc_cert.clone());
                    arc_cert
                },
                Err(e) => {
                    errors.push((name.clone(), e.to_string()));
                    continue;
                },
            },
        };

        // Determine which domains this certificate should be served for.
        let domains_to_serve: Cow<[String]> = if let Some(value) = &conf.domains
        {
            Cow::Owned(value.split(',').map(|s| s.trim().to_string()).collect())
        } else {
            Cow::Borrowed(&cert_arc.domains)
        };

        for domain in domains_to_serve.iter() {
            dynamic_certs.insert(domain.to_string(), cert_arc.clone());
        }

        if conf.is_default.unwrap_or_default() {
            dynamic_certs
                .insert(DEFAULT_SERVER_NAME.to_string(), cert_arc.clone());
        }
    }
    (dynamic_certs, errors)
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
    pub cipher_suites: Option<String>, // Modern cipher suites
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
    chain_certificates: &Option<Vec<X509>>,
) {
    // set tls certificate
    if let Err(e) = ext::ssl_use_certificate(ssl, cert) {
        error!(category = LOG_CATEGORY, error = %e, "ssl use certificate fail");
    }
    // set private key
    if let Err(e) = ext::ssl_use_private_key(ssl, key) {
        error!(category = LOG_CATEGORY, error = %e, "ssl use private key fail");
    }
    // set chain certificate
    if let Some(chain_certificates) = chain_certificates {
        for chain in chain_certificates.iter() {
            if let Err(e) = ext::ssl_add_chain_cert(ssl, chain) {
                error!(category = LOG_CATEGORY, error = %e, "ssl add chain cert fail");
            }
        }
    }
}

fn convert_tls_version(version: &Option<String>) -> Option<SslVersion> {
    if let Some(version) = &version {
        let version = match version.to_lowercase().as_str() {
            "tlsv1.1" => SslVersion::TLS1_1,
            "tlsv1.3" => SslVersion::TLS1_3,
            _ => SslVersion::TLS1_2,
        };
        return Some(version);
    }
    None
}

/// GlobalCertificate implements SNI-based dynamic certificate selection
///
/// Provides runtime certificate selection during TLS handshake based on the
/// Server Name Indication (SNI). Supports:
/// - Dynamic certificate updates
/// - Wildcard certificates
/// - Default fallback certificates
/// - Self-signed CA certificates
#[derive(Clone)]
pub struct GlobalCertificate {
    provider: Arc<dyn CertificateProvider>,
}

impl GlobalCertificate {
    pub fn new(provider: Arc<dyn CertificateProvider>) -> Self {
        Self { provider }
    }
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
                error!(category = LOG_CATEGORY, error = %e, name, "set cipher list fail");
            }
        }
        if let Some(cipher_suites) = &params.cipher_suites {
            if let Err(e) = tls_settings.set_ciphersuites(cipher_suites) {
                error!(category = LOG_CATEGORY, error = %e, name, "set cipher suites fail");
            }
        }
        if let Some(version) = convert_tls_version(&params.tls_min_version) {
            if let Err(e) = tls_settings.set_min_proto_version(Some(version)) {
                error!(category = LOG_CATEGORY, error = %e, name, "set tls min proto version fail");
            }
            if version == pingora::tls::ssl::SslVersion::TLS1_1 {
                tls_settings.set_security_level(0);
                tls_settings
                    .clear_options(pingora::tls::ssl::SslOptions::NO_TLSV1_1);
            }
        }
        if let Err(e) = tls_settings
            .set_max_proto_version(convert_tls_version(&params.tls_max_version))
        {
            error!(category = LOG_CATEGORY, error = %e, name, "set tls max proto version fail");
        }

        if let Some(min_version) = tls_settings.min_proto_version() {
            info!(
                category = LOG_CATEGORY,
                name,
                min_version = format!("{min_version:?}"),
                "tls proto"
            );
        }
        if let Some(max_version) = tls_settings.max_proto_version() {
            info!(
                category = LOG_CATEGORY,
                name,
                max_version = format!("{max_version:?}"),
                "tls proto"
            );
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

        let sni = ssl
            .servername(NameType::HOST_NAME)
            .unwrap_or(DEFAULT_SERVER_NAME);
        // TODO add more debug log
        debug!(
            category = LOG_CATEGORY,
            ssl = format!("{ssl:?}"),
            server_name = sni
        );

        // Optimized lookup sequence.
        let dynamic_certificate = self.provider.get(sni);

        let Some(d) = dynamic_certificate else {
            error!(
                category = LOG_CATEGORY,
                sni,
                ssl = format!("{ssl:?}"),
                "no match certificate"
            );
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
                        &d.chain_certificates,
                    );
                },
                Err(err) => {
                    error!(category = LOG_CATEGORY, error = %err, "get self signed cert fail");
                },
            };
            return;
        }

        if let Some((cert, key)) = &d.certificate {
            ssl_certificate(ssl, cert, key, &d.chain_certificates);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingap_config::CertificateConf;
    use pretty_assertions::assert_eq;

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
    fn test_convert_tls_version() {
        assert_eq!(
            SslVersion::TLS1_1,
            convert_tls_version(&Some("tlsv1.1".to_string())).unwrap()
        );
        assert_eq!(
            SslVersion::TLS1_2,
            convert_tls_version(&Some("tlsv1.2".to_string())).unwrap()
        );
        assert_eq!(
            SslVersion::TLS1_3,
            convert_tls_version(&Some("tlsv1.3".to_string())).unwrap()
        );
    }

    #[test]
    fn test_parse_certificate() {
        let (tls_cert, tls_key) = get_tls_pem();
        let cert_info = CertificateConf {
            tls_cert: Some(tls_cert),
            tls_key: Some(tls_key),
            is_default: Some(true),
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
    }
}
