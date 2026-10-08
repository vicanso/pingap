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
use super::{Error, LOG_TARGET, LoadedCertificate, TlsCertificate};
use ahash::AHashMap;
use async_trait::async_trait;
use pingap_config::CertificateConf;
use pingap_config::Hashable;
use pingap_core::TlsClientCert;
use pingora::listeners::tls::TlsSettings;
#[cfg(feature = "openssl")]
use pingora::tls::ssl::{NameType, SslRef, SslVersion};
use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
#[cfg(feature = "openssl")]
use tracing::info;
#[cfg(feature = "tls-rustls")]
use tracing::warn;
use tracing::{debug, error};

type Result<T, E = Error> = std::result::Result<T, E>;

// Fallback server name used when:
// - No SNI (Server Name Indication) is provided in TLS handshake
// - No matching certificate is found for the requested domain
pub static DEFAULT_SERVER_NAME: &str = "*";

/// Builds the certificate store (domain -> certificate) from the
/// configurations, keeping every entry of `previous` whose configuration
/// did not change: its PEM, key and chain are not parsed and loaded again.
///
/// Returns the store, `(name, error)` for the entries that failed, and the
/// names that were built anew. An entry that failed keeps the certificate
/// `previous` has under its name, when there is one.
pub fn update_certificates(
    certificate_configs: &HashMap<String, CertificateConf>,
    previous: &DynamicCertificates,
) -> (DynamicCertificates, Vec<(String, String)>, Vec<String>) {
    let mut previous_by_name: AHashMap<&str, &Arc<TlsCertificate>> =
        AHashMap::with_capacity(previous.len());
    for cert in previous.values() {
        if let Some(name) = &cert.name {
            previous_by_name.entry(name.as_str()).or_insert(cert);
        }
    }

    let mut dynamic_certs = AHashMap::new();
    let mut errors = vec![];
    let mut updated = vec![];
    for (name, conf) in certificate_configs.iter() {
        if conf.tls_cert.is_none() || conf.tls_key.is_none() {
            continue;
        }
        // The hash covers the configuration and, for file paths, the
        // files' content, so a matching one means nothing to reload.
        let hash_key = conf.hash_key();
        let reused = previous_by_name
            .get(name.as_str())
            .filter(|cert| cert.hash_key == hash_key)
            .map(|cert| Arc::clone(cert));
        let cert_arc = match reused {
            Some(cert) => cert,
            None => match TlsCertificate::try_from(conf) {
                Ok(mut cert) => {
                    cert.name = Some(name.clone());
                    updated.push(name.clone());
                    Arc::new(cert)
                },
                // A certificate that cannot be built is reported, and the
                // one it was to replace goes on serving: dropping the entry
                // took its domains off the air over a bad upload. It
                // serves what it served, not what the entry that failed
                // says: the new `domains` and `is_default` belong to a
                // certificate that is not there.
                Err(e) => {
                    errors.push((name.clone(), e.to_string()));
                    for (domain, cert) in previous.iter() {
                        if cert.name.as_deref() == Some(name.as_str()) {
                            dynamic_certs
                                .insert(domain.clone(), Arc::clone(cert));
                        }
                    }
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
    (dynamic_certs, errors, updated)
}

/// Builds the certificate store from scratch: `update_certificates` with
/// nothing to reuse.
pub fn parse_certificates(
    certificate_configs: &HashMap<String, CertificateConf>,
) -> (DynamicCertificates, Vec<(String, String)>) {
    let (certs, errors, _) =
        update_certificates(certificate_configs, &AHashMap::new());
    (certs, errors)
}

/// Parameters for configuring TLS settings
///
/// Contains all the necessary configuration options for setting up TLS,
/// including protocol versions, cipher suites, and HTTP/2 support.
#[derive(Debug, Default)]
pub struct TlsSettingParams {
    pub server_name: String,
    pub enabled_h2: bool,            // Enable HTTP/2 support
    pub cipher_list: Option<String>, // Legacy cipher list
    pub cipher_suites: Option<String>, // Modern cipher suites
    pub tls_min_version: Option<String>, // Minimum TLS version
    pub tls_max_version: Option<String>, // Maximum TLS version
    /// The CA the certificate of a client has to come from: a PEM file
    /// path, base64-encoded PEM or raw PEM, with one or more
    /// certificates. `None` asks clients for no certificate.
    pub client_ca: Option<String>,
    /// With `client_ca`: a client that shows no certificate is let in
    /// all the same. One that shows a certificate which does not verify
    /// is not, in either case.
    pub client_auth_optional: bool,
}

fn client_ca_error(server: &str, message: impl fmt::Display) -> Error {
    Error::Invalid {
        category: "tls_client_ca".to_string(),
        message: format!("server {server}: {message}"),
    }
}

/// The certificates of `tls_client_ca` as PEM blocks; an error when
/// there is none in it.
fn client_ca_pems(server: &str, value: &str) -> Result<Vec<Vec<u8>>> {
    let pems = pingap_util::convert_pem(value)
        .map_err(|e| client_ca_error(server, e))?;
    if pems.is_empty() {
        return Err(client_ca_error(server, "no certificate found"));
    }
    Ok(pems)
}

/// What is kept of the certificate a client showed, for the requests of
/// its connection: who it is for, and what tells it from any other.
///
/// `der` is a certificate the handshake has verified.
fn tls_client_cert(
    der: &[u8],
    fingerprint: &[u8],
) -> Option<Arc<dyn std::any::Any + Send + Sync>> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    let hex = |bytes: &[u8]| {
        bytes.iter().fold(
            String::with_capacity(bytes.len() * 2),
            |mut text, byte| {
                use std::fmt::Write;
                let _ = write!(text, "{byte:02x}");
                text
            },
        )
    };
    // Without the zero that DER puts in front of a number whose first
    // bit is set: the number as `openssl x509 -serial` prints it, which
    // is what a list of serials to refuse is made of.
    let serial = cert.raw_serial();
    let serial = &serial[serial
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(serial.len().saturating_sub(1))..];
    // Stored as an `Arc` of its own, so that a request takes a reference
    // and no copy.
    let info = Arc::new(TlsClientCert {
        subject: subject_text(cert.subject()),
        fingerprint: hex(fingerprint),
        serial: hex(serial),
    });
    Some(Arc::new(info))
}

/// The value of one part of a name, with what could be taken for the end
/// of it escaped the way RFC 4514 escapes it.
///
/// The subject goes into a header and into the access log as one string,
/// and whoever reads it there splits it again. Written as it is, an
/// organization called `x, CN=admin` reads as an organization and a
/// common name, and a line break in a value starts a line of the log that
/// no request made. A CA signs such a name without a second look when it
/// only checks what it is asked to check.
fn escape_name_value(value: &str) -> String {
    let mut text = String::with_capacity(value.len());
    let last = value.len().saturating_sub(1);
    for (index, c) in value.char_indices() {
        match c {
            ',' | '+' | '"' | '\\' | '<' | '>' | ';' | '=' => {
                text.push('\\');
                text.push(c);
            },
            '#' | ' ' if index == 0 => {
                text.push('\\');
                text.push(c);
            },
            ' ' if index == last => text.push_str("\\ "),
            c if c.is_control() => {
                use std::fmt::Write;
                let mut bytes = [0u8; 4];
                for byte in c.encode_utf8(&mut bytes).bytes() {
                    let _ = write!(text, "\\{byte:02X}");
                }
            },
            c => text.push(c),
        }
    }
    text
}

/// A name as one string: its parts in the order the certificate has
/// them, `O=Example, CN=device-42`, each value escaped.
fn subject_text(name: &x509_parser::x509::X509Name<'_>) -> String {
    use x509_parser::objects::{oid_registry, oid2abbrev};
    name.iter_rdn()
        .map(|rdn| {
            rdn.iter()
                .map(|attr| {
                    let key = oid2abbrev(attr.attr_type(), oid_registry())
                        .map(str::to_string)
                        .unwrap_or_else(|_| attr.attr_type().to_id_string());
                    // What is no text is written as its bytes, which is
                    // how RFC 4514 writes it.
                    let value = match attr.as_str() {
                        Ok(value) => escape_name_value(value),
                        Err(_) => attr.attr_value().data.iter().fold(
                            String::from("#"),
                            |mut text, byte| {
                                use std::fmt::Write;
                                let _ = write!(text, "{byte:02x}");
                                text
                            },
                        ),
                    };
                    format!("{key}={value}")
                })
                .collect::<Vec<_>>()
                .join("+")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// The OpenSSL protocol version named by a `tls_min_version` /
/// `tls_max_version` value. An unknown name is an error; it used to be
/// TLS 1.2 without a word.
#[cfg(feature = "openssl")]
fn convert_tls_version(version: &Option<String>) -> Result<Option<SslVersion>> {
    let Some(version) =
        version.as_deref().map(str::trim).filter(|v| !v.is_empty())
    else {
        return Ok(None);
    };
    let ssl_version = match version.to_lowercase().as_str() {
        "tlsv1.1" => SslVersion::TLS1_1,
        "tlsv1.2" => SslVersion::TLS1_2,
        "tlsv1.3" => SslVersion::TLS1_3,
        _ => {
            return Err(Error::Invalid {
                category: "tls_version".to_string(),
                message: format!(
                    "tls version {version:?} is invalid, expected tlsv1.1, tlsv1.2 or tlsv1.3"
                ),
            });
        },
    };
    Ok(Some(ssl_version))
}

/// Serves certificates to pingora's listener: exact, wildcard and default
/// SNI matches come from the provider, CA entries issue certificates on the
/// fly. The selection is shared by both TLS backends; only the hand-over
/// differs (`TlsAccept` for OpenSSL, `ResolvesServerCert` for rustls).
#[derive(Clone)]
pub struct GlobalCertificate {
    provider: Arc<dyn CertificateProvider>,
}

impl fmt::Debug for GlobalCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GlobalCertificate").finish_non_exhaustive()
    }
}

impl GlobalCertificate {
    pub fn new(provider: Arc<dyn CertificateProvider>) -> Self {
        Self { provider }
    }

    /// Picks the certificate to present for `sni`.
    fn select(&self, sni: &str) -> Option<Arc<LoadedCertificate>> {
        // Certificate selection process:
        // 1. Try exact domain match (example.com)
        // 2. Try wildcard domain match (*.example.com)
        // 3. Fall back to default certificate (DEFAULT_SERVER_NAME)
        // 4. Handle special case for CA certificates (self-signed)
        let Some(d) = self.provider.get(sni) else {
            error!(target: LOG_TARGET, sni, "no match certificate");
            return None;
        };
        if d.is_ca {
            return match d.get_self_signed_certificate(sni) {
                Ok(cert) => Some(cert.certificate.clone()),
                Err(err) => {
                    error!(target: LOG_TARGET, error = %err, "get self signed cert fail");
                    None
                },
            };
        }
        d.certificate.clone()
    }
}

#[cfg(feature = "openssl")]
impl GlobalCertificate {
    /// The listener's TLS settings. A cipher list, cipher suite or protocol
    /// version OpenSSL rejects is an error here, so the server does not
    /// come up with settings other than the ones configured; it used to
    /// log the rejection and carry on with OpenSSL's defaults.
    pub fn new_tls_settings(
        &self,
        params: &TlsSettingParams,
    ) -> Result<TlsSettings> {
        let name = params.server_name.as_str();
        let invalid = |what: &str, e: &dyn std::fmt::Display| Error::Invalid {
            category: "new_tls_settings".to_string(),
            message: format!("server {name}: {what} fail: {e}"),
        };
        let mut tls_settings =
            TlsSettings::with_callbacks(Box::new(self.clone()))
                .map_err(|e| invalid("new tls settings", &e))?;
        if params.enabled_h2 {
            tls_settings.enable_h2();
        }
        if let Some(cipher_list) = &params.cipher_list {
            tls_settings
                .set_cipher_list(cipher_list)
                .map_err(|e| invalid("set cipher list", &e))?;
        }
        if let Some(cipher_suites) = &params.cipher_suites {
            tls_settings
                .set_ciphersuites(cipher_suites)
                .map_err(|e| invalid("set cipher suites", &e))?;
        }
        if let Some(version) = convert_tls_version(&params.tls_min_version)? {
            tls_settings
                .set_min_proto_version(Some(version))
                .map_err(|e| invalid("set tls min proto version", &e))?;
            if version == pingora::tls::ssl::SslVersion::TLS1_1 {
                tls_settings.set_security_level(0);
                tls_settings
                    .clear_options(pingora::tls::ssl::SslOptions::NO_TLSV1_1);
            }
        }
        tls_settings
            .set_max_proto_version(convert_tls_version(
                &params.tls_max_version,
            )?)
            .map_err(|e| invalid("set tls max proto version", &e))?;

        if let Some(client_ca) = &params.client_ca {
            use pingora::tls::ssl::SslVerifyMode;
            use pingora::tls::x509::X509;
            use pingora::tls::x509::store::X509StoreBuilder;
            let invalid = |e: &dyn fmt::Display| client_ca_error(name, e);
            let mut store = X509StoreBuilder::new().map_err(|e| invalid(&e))?;
            let mut count = 0;
            for pem in client_ca_pems(name, client_ca)? {
                for cert in
                    X509::stack_from_pem(&pem).map_err(|e| invalid(&e))?
                {
                    // The names of the CA are sent to the client, which
                    // picks the certificate to show by them.
                    tls_settings
                        .add_client_ca(&cert)
                        .map_err(|e| invalid(&e))?;
                    store.add_cert(cert).map_err(|e| invalid(&e))?;
                    count += 1;
                }
            }
            if count == 0 {
                return Err(client_ca_error(name, "no certificate found"));
            }
            tls_settings
                .set_verify_cert_store(store.build())
                .map_err(|e| invalid(&e))?;
            let mut mode = SslVerifyMode::PEER;
            if !params.client_auth_optional {
                mode |= SslVerifyMode::FAIL_IF_NO_PEER_CERT;
            }
            tls_settings.set_verify(mode);
            // A session that is resumed is one whose client was verified
            // under this context. Without a context OpenSSL refuses to
            // resume a session of a server that verifies its clients, and
            // the second connection of every client failed.
            tls_settings
                .set_session_id_context(b"pingap")
                .map_err(|e| invalid(&e))?;
        }

        if let Some(min_version) = tls_settings.min_proto_version() {
            info!(
                target: LOG_TARGET,
                name,
                min_version = format!("{min_version:?}"),
                "tls proto"
            );
        }
        if let Some(max_version) = tls_settings.max_proto_version() {
            info!(
                target: LOG_TARGET,
                name,
                max_version = format!("{max_version:?}"),
                "tls proto"
            );
        }

        Ok(tls_settings)
    }
}

#[cfg(feature = "tls-rustls")]
impl GlobalCertificate {
    pub fn new_tls_settings(
        &self,
        params: &TlsSettingParams,
    ) -> Result<TlsSettings> {
        let name = params.server_name.clone();
        // No certificate files: the resolver below supplies every certificate.
        // With clients to verify the settings carry this as their
        // callbacks too: what is kept of a client's certificate is made
        // when its handshake is done.
        let settings = if params.client_ca.is_some() {
            TlsSettings::with_callbacks(Box::new(self.clone()))
        } else {
            TlsSettings::intermediate("", "")
        };
        let mut tls_settings = settings.map_err(|e| Error::Invalid {
            category: "new_tls_settings".to_string(),
            message: e.to_string(),
        })?;
        tls_settings.set_cert_resolver(Arc::new(self.clone()));
        if let Some(client_ca) = &params.client_ca {
            use pingora::tls::{CertificateDer, WebPkiClientVerifier};
            use rustls_pki_types::pem::PemObject;
            let invalid = |e: &dyn fmt::Display| client_ca_error(&name, e);
            let mut roots = rustls::RootCertStore::empty();
            for pem in client_ca_pems(&name, client_ca)? {
                for cert in CertificateDer::pem_slice_iter(&pem) {
                    roots
                        .add(cert.map_err(|e| invalid(&e))?)
                        .map_err(|e| invalid(&e))?;
                }
            }
            if roots.is_empty() {
                return Err(client_ca_error(&name, "no certificate found"));
            }
            // The verifier takes the provider of the process, and there
            // has to be one by now: without it making the verifier does
            // not fail, it panics.
            crate::install_default_crypto_provider();
            let builder = WebPkiClientVerifier::builder(Arc::new(roots));
            let builder = if params.client_auth_optional {
                builder.allow_unauthenticated()
            } else {
                builder
            };
            tls_settings.set_client_cert_verifier(
                builder.build().map_err(|e| invalid(&e))?,
            );
        }
        if params.enabled_h2 {
            tls_settings.enable_h2();
        }
        // pingora's rustls listener fixes TLS 1.2 + 1.3 with rustls' default
        // cipher suites; say so rather than silently dropping the settings.
        for (setting, value) in [
            ("tls_cipher_list", &params.cipher_list),
            ("tls_ciphersuites", &params.cipher_suites),
            ("tls_min_version", &params.tls_min_version),
            ("tls_max_version", &params.tls_max_version),
        ] {
            if value.is_some() {
                warn!(
                    target: LOG_TARGET,
                    name,
                    setting,
                    "ignored with the rustls backend, which fixes TLS 1.2/1.3 and its default cipher suites"
                );
            }
        }
        Ok(tls_settings)
    }
}

#[cfg(feature = "openssl")]
#[async_trait]
impl pingora::listeners::TlsAccept for GlobalCertificate {
    async fn certificate_callback(&self, ssl: &mut SslRef) {
        let sni = ssl
            .servername(NameType::HOST_NAME)
            .unwrap_or(DEFAULT_SERVER_NAME);
        debug!(
            target: LOG_TARGET,
            ssl = format!("{ssl:?}"),
            server_name = sni
        );
        if let Some(certificate) = self.select(sni) {
            certificate.apply(ssl);
        }
    }

    /// Keeps what a request is told of the client's certificate. There is
    /// one only on a server that asks for it, and then it has verified.
    async fn handshake_complete_callback(
        &self,
        ssl: &SslRef,
    ) -> Option<Arc<dyn std::any::Any + Send + Sync>> {
        let cert = ssl.peer_certificate()?;
        let der = cert.to_der().ok()?;
        let fingerprint = cert
            .digest(pingora::tls::hash::MessageDigest::sha256())
            .ok()?;
        tls_client_cert(&der, &fingerprint)
    }
}

/// With rustls the certificates come from the resolver below; what is
/// left for the callbacks is the client's certificate, once the
/// handshake is done.
#[cfg(feature = "tls-rustls")]
#[async_trait]
impl pingora::listeners::TlsAccept for GlobalCertificate {
    async fn handshake_complete_callback(
        &self,
        tls: &pingora::protocols::tls::TlsRef,
    ) -> Option<Arc<dyn std::any::Any + Send + Sync>> {
        let der = tls.peer_certificate_der()?;
        let fingerprint = pingora::tls::hash_certificate(
            &pingora::tls::CertificateDer::from(der),
        );
        tls_client_cert(der, &fingerprint)
    }
}

#[cfg(feature = "tls-rustls")]
impl pingora::tls::ResolvesServerCert for GlobalCertificate {
    fn resolve(
        &self,
        client_hello: pingora::tls::ClientHello<'_>,
    ) -> Option<Arc<pingora::tls::sign::CertifiedKey>> {
        let sni = client_hello.server_name().unwrap_or(DEFAULT_SERVER_NAME);
        debug!(target: LOG_TARGET, server_name = sni);
        self.select(sni)
            .map(|certificate| certificate.certified_key())
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

    // A CA, and a certificate it issued to `O=Pingap Test, CN=test-client`.
    // spellchecker:off
    const CLIENT_CA: &str = "-----BEGIN CERTIFICATE-----\nMIIBiDCCAS2gAwIBAgIUPFcjdGbZUo9hlQgHujn4VpJ+Bn8wCgYIKoZIzj0EAwIw\nGTEXMBUGA1UEAwwOcGluZ2FwIHRlc3QgY2EwHhcNMjYxMDA3MDk0MzQyWhcNMzYx\nMDA0MDk0MzQyWjAZMRcwFQYDVQQDDA5waW5nYXAgdGVzdCBjYTBZMBMGByqGSM49\nAgEGCCqGSM49AwEHA0IABEZvQgSvXHdnKYjnIDH30XZhifq/sLXbRk8RAoL9AWMd\nVqqPTi9rXv3+oH+HesJxsE1QXYDE9IykyX3GcMeiMvKjUzBRMB0GA1UdDgQWBBTi\nKcHWkQmZqdsiHyjrgovGsqq12DAfBgNVHSMEGDAWgBTiKcHWkQmZqdsiHyjrgovG\nsqq12DAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0kAMEYCIQDop5xPPcHB\n8M0GimlIbBfuVc6SkesW3MZiAeXHXOLhwgIhAPfmPP5CFvYZQisvjUuQz+VdTkwc\nFRoVRUyQmQTSRid3\n-----END CERTIFICATE-----";
    const CLIENT_CERT: &str = "-----BEGIN CERTIFICATE-----\nMIIBiTCCAS+gAwIBAgIUNClp5P/VCqYvyxD/pG2zGGDTQlEwCgYIKoZIzj0EAwIw\nGTEXMBUGA1UEAwwOcGluZ2FwIHRlc3QgY2EwHhcNMjYxMDA3MDk0MzQyWhcNMzYx\nMDA0MDk0MzQyWjAsMRQwEgYDVQQKDAtQaW5nYXAgVGVzdDEUMBIGA1UEAwwLdGVz\ndC1jbGllbnQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQP4q5L3ngZ+aX9Ii7v\nI7ySNugQuzvMBIkx0DvmW9IYtpSKfrRvP10t0xSwQU3Xv4wslFixRT4mTfQNVgJD\n52Ato0IwQDAdBgNVHQ4EFgQU1Z/2+9o7WTm1B5SiK6o3qGsoPgswHwYDVR0jBBgw\nFoAU4inB1pEJmanbIh8o64KLxrKqtdgwCgYIKoZIzj0EAwIDSAAwRQIhAL5oqSvF\n56C0NkEz2nIdK6Ni8UET4SqhR6RzAshJRDNwAiByIrZeLMG/rOHoUs81cXF5u+k/\nxOuznx6ERPEBpBhckQ==\n-----END CERTIFICATE-----";
    // spellchecker:on

    struct NoCertificates;

    impl CertificateProvider for NoCertificates {
        fn get(&self, _sni: &str) -> Option<Arc<TlsCertificate>> {
            None
        }
        fn list(&self) -> Arc<DynamicCertificates> {
            Arc::new(DynamicCertificates::default())
        }
        fn store(&self, _data: DynamicCertificates) {}
    }

    /// `tls_client_ca`: the settings of a listener that verifies its
    /// clients are made from a CA that reads, in both modes, and refused
    /// from one that does not.
    #[test]
    fn test_tls_settings_with_client_ca() {
        let certificates = GlobalCertificate::new(Arc::new(NoCertificates));
        let settings = |client_ca: Option<&str>, optional: bool| {
            certificates.new_tls_settings(&TlsSettingParams {
                server_name: "web".to_string(),
                client_ca: client_ca.map(str::to_string),
                client_auth_optional: optional,
                ..Default::default()
            })
        };
        assert_eq!(true, settings(None, false).is_ok());
        assert_eq!(true, settings(Some(CLIENT_CA), false).is_ok());
        assert_eq!(true, settings(Some(CLIENT_CA), true).is_ok());
        // As base64, like the other certificates of a configuration.
        let encoded = pingap_util::base64_encode(CLIENT_CA);
        assert_eq!(true, settings(Some(&encoded), false).is_ok());

        for client_ca in ["not a certificate", "/pingap/not/there.pem"] {
            let message = settings(Some(client_ca), false)
                .err()
                .map(|e| e.to_string())
                .unwrap_or_default();
            assert_eq!(
                true,
                message.contains("category: tls_client_ca")
                    && message.contains("server web: "),
                "{client_ca}: {message}"
            );
        }
    }

    /// What a request is told of the certificate a client showed.
    #[test]
    fn test_tls_client_cert() {
        let (_, pem) =
            x509_parser::pem::parse_x509_pem(CLIENT_CERT.as_bytes()).unwrap();
        let extension =
            tls_client_cert(&pem.contents, &[0xb5, 0x45, 0x0d, 0x00]).unwrap();
        let cert = extension.downcast_ref::<Arc<TlsClientCert>>().unwrap();
        assert_eq!("O=Pingap Test, CN=test-client", cert.subject);
        // The digest the handshake made of the certificate, in hex.
        assert_eq!("b5450d00", cert.fingerprint);
        assert_eq!("342969e4ffd50aa62fcb10ffa46db31860d34251", cert.serial);
        // What is no certificate gives nothing.
        assert_eq!(true, tls_client_cert(b"junk", &[1]).is_none());

        // A value can not pass for more parts of the name than it is, nor
        // for the start of another line.
        for (value, expected) in [
            ("device-42", "device-42"),
            ("x, CN=admin", "x\\, CN\\=admin"),
            ("a+b \"c\" <d>; e\\", "a\\+b \\\"c\\\" \\<d\\>\\; e\\\\"),
            ("line\nbreak\r", "line\\0Abreak\\0D"),
            (" padded ", "\\ padded\\ "),
            ("#hash", "\\#hash"),
            ("张三", "张三"),
            ("", ""),
        ] {
            assert_eq!(expected, escape_name_value(value), "{value:?}");
        }
    }

    #[cfg(feature = "openssl")]
    #[test]
    fn test_convert_tls_version() {
        let convert =
            |value: &str| convert_tls_version(&Some(value.to_string()));
        assert_eq!(Some(SslVersion::TLS1_1), convert("tlsv1.1").unwrap());
        assert_eq!(Some(SslVersion::TLS1_2), convert("TLSv1.2").unwrap());
        assert_eq!(Some(SslVersion::TLS1_3), convert("tlsv1.3").unwrap());
        assert_eq!(None, convert("").unwrap());
        assert_eq!(None, convert_tls_version(&None).unwrap());
        assert_eq!(
            "Invalid error, category: tls_version, tls version \"tlsv1.0\" is invalid, expected tlsv1.1, tlsv1.2 or tlsv1.3",
            convert("tlsv1.0").expect_err("error").to_string()
        );
    }

    /// A reload keeps the certificates whose configuration did not change
    /// and reports only the rebuilt ones.
    #[test]
    fn test_update_certificates_reuses_unchanged() {
        let (tls_cert, tls_key) = get_tls_pem();
        let conf = CertificateConf {
            tls_cert: Some(tls_cert),
            tls_key: Some(tls_key),
            domains: Some("a.example.com, b.example.com".to_string()),
            ..Default::default()
        };
        let configs = HashMap::from([("first".to_string(), conf.clone())]);
        let (certs, errors, updated) =
            update_certificates(&configs, &AHashMap::new());
        assert_eq!(true, errors.is_empty());
        assert_eq!(vec!["first".to_string()], updated);
        assert_eq!(2, certs.len());
        assert_eq!(
            true,
            Arc::ptr_eq(&certs["a.example.com"], &certs["b.example.com"])
        );

        // Same configuration: the same certificate object, nothing updated.
        let (again, errors, updated) = update_certificates(&configs, &certs);
        assert_eq!(true, errors.is_empty());
        assert_eq!(true, updated.is_empty());
        assert_eq!(
            true,
            Arc::ptr_eq(&certs["a.example.com"], &again["a.example.com"])
        );

        // A changed configuration is rebuilt; a broken one is reported and
        // left out.
        let mut changed = conf.clone();
        changed.is_default = Some(true);
        let configs = HashMap::from([
            ("first".to_string(), changed),
            (
                "broken".to_string(),
                CertificateConf {
                    tls_cert: Some("nope".to_string()),
                    tls_key: Some("nope".to_string()),
                    ..Default::default()
                },
            ),
        ]);
        let (next, errors, updated) = update_certificates(&configs, &again);
        assert_eq!(vec!["first".to_string()], updated);
        assert_eq!(1, errors.len());
        assert_eq!("broken", errors[0].0);
        assert_eq!(3, next.len());
        assert_eq!(
            false,
            Arc::ptr_eq(&again["a.example.com"], &next["a.example.com"])
        );
        assert_eq!(true, next.contains_key(DEFAULT_SERVER_NAME));
    }

    /// Regression: a certificate with the key of another one loaded and
    /// validated under OpenSSL, which only objects when the pair is put on
    /// a handshake - every handshake of its domains, then.
    #[test]
    fn test_key_has_to_be_the_one_of_the_certificate() {
        let (tls_cert, tls_key) = get_tls_pem();
        let other_key = rcgen::KeyPair::generate().unwrap().serialize_pem();
        let conf = |key: &str| CertificateConf {
            tls_cert: Some(tls_cert.clone()),
            tls_key: Some(key.to_string()),
            ..Default::default()
        };
        assert_eq!(true, TlsCertificate::try_from(&conf(&tls_key)).is_ok());
        let err = TlsCertificate::try_from(&conf(&other_key))
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert_eq!(false, err.is_empty(), "a mismatched key was accepted");
    }

    /// Regression: an entry that failed to build was dropped from the
    /// store, so a bad upload took the domains of a working certificate
    /// off the air. The one that was serving stays.
    #[test]
    fn test_update_certificates_keeps_the_previous_one_on_failure() {
        let (tls_cert, tls_key) = get_tls_pem();
        let conf = CertificateConf {
            tls_cert: Some(tls_cert.clone()),
            tls_key: Some(tls_key),
            domains: Some("a.example.com".to_string()),
            ..Default::default()
        };
        let configs = HashMap::from([("site".to_string(), conf.clone())]);
        let (certs, errors, _) =
            update_certificates(&configs, &AHashMap::new());
        assert_eq!(true, errors.is_empty());

        let mut broken = conf;
        broken.tls_key =
            Some(rcgen::KeyPair::generate().unwrap().serialize_pem());
        // Changed along with the key; it is the old certificate that
        // stays, for the domains it had.
        broken.domains = Some("b.example.com".to_string());
        broken.is_default = Some(true);
        let configs = HashMap::from([("site".to_string(), broken)]);
        let (next, errors, updated) = update_certificates(&configs, &certs);
        assert_eq!(1, errors.len());
        assert_eq!("site", errors[0].0);
        assert_eq!(true, updated.is_empty());
        assert_eq!(
            true,
            Arc::ptr_eq(&certs["a.example.com"], &next["a.example.com"])
        );
        assert_eq!(1, next.len());
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
