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
use super::{
    Error, LOG_TARGET, LoadedCertificate, TlsCertificate, certificate_key,
    split_certificate_key, unused_certificate_key,
};
use ahash::AHashMap;
use async_trait::async_trait;
use pingap_config::CertificateConf;
use pingap_config::Hashable;
use pingap_core::TlsClientCert;
use pingora::listeners::tls::TlsSettings;
#[cfg(feature = "openssl")]
use pingora::tls::ssl::{NameType, Ssl, SslContextBuilder, SslRef, SslVersion};
use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
#[cfg(feature = "openssl")]
use tracing::info;
use tracing::{debug, error, warn};

type Result<T, E = Error> = std::result::Result<T, E>;

// Fallback server name used when:
// - No SNI (Server Name Indication) is provided in TLS handshake
// - No matching certificate is found for the requested domain
pub static DEFAULT_SERVER_NAME: &str = "*";

/// Puts `cert` into the store under `key`, unless another certificate has
/// the key already: one certificate serves a name for each kind of key,
/// and the one that came first keeps it. Whether `cert` has the key.
fn claim(
    certs: &mut DynamicCertificates,
    key: String,
    cert: &Arc<TlsCertificate>,
) -> bool {
    use std::collections::hash_map::Entry;
    match certs.entry(key) {
        Entry::Vacant(entry) => {
            entry.insert(Arc::clone(cert));
            true
        },
        Entry::Occupied(entry) => {
            let serving = entry.get();
            let held = serving.name == cert.name;
            if !held {
                let (domain, rsa) = split_certificate_key(entry.key());
                warn!(
                    target: LOG_TARGET,
                    domain,
                    rsa,
                    serving = serving.name,
                    ignored = cert.name,
                    "two certificates with the same kind of key for one domain, only one of them is served"
                );
            }
            held
        },
    }
}

/// Keeps in the store a certificate that has none of its keys: see
/// `unused_certificate_key`.
fn keep_unused(certs: &mut DynamicCertificates, cert: &Arc<TlsCertificate>) {
    if let Some(name) = &cert.name {
        certs
            .entry(unused_certificate_key(name))
            .or_insert_with(|| Arc::clone(cert));
    }
}

/// Builds the certificate store (domain -> certificate) from the
/// configurations, keeping every entry of `previous` whose configuration
/// did not change: its PEM, key and chain are not parsed and loaded again.
///
/// A domain is served by one certificate, or by two whose keys are of
/// different kinds: one RSA, one not (see [`DynamicCertificates`]). Of
/// two entries that name a domain with keys of the same kind only one is
/// used, and it is the same one every time: an entry of ACME gives way to
/// one that is not, and among the rest the first by name has it. It used
/// to be whichever the map gave last, another one in every process.
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
    // The order a reload puts two stores together in
    // (`try_update_certificates_except` in the binary), so that a domain
    // is served by the same certificate either way.
    let mut entries: Vec<_> = certificate_configs.iter().collect();
    entries.sort_by_key(|(name, conf)| {
        let acme = conf.acme.as_deref().is_some_and(|acme| !acme.is_empty());
        (acme, name.as_str())
    });
    for (name, conf) in entries {
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
                    let mut kept = None;
                    let mut held = false;
                    for (key, cert) in previous.iter() {
                        if cert.name.as_deref() == Some(name.as_str()) {
                            held |=
                                claim(&mut dynamic_certs, key.clone(), cert);
                            kept = Some(cert);
                        }
                    }
                    if let Some(cert) = kept.filter(|_| !held) {
                        keep_unused(&mut dynamic_certs, cert);
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

        // Under the name in lower case: a server name is matched without
        // regard to case, and `Example.com` written here was a name no
        // handshake ever asked for.
        let is_rsa = cert_arc.is_rsa();
        let mut held = false;
        // `a.example.com,` names one domain, not that and none.
        for domain in domains_to_serve.iter().filter(|d| !d.is_empty()) {
            let key = certificate_key(&domain.to_lowercase(), is_rsa);
            held |= claim(&mut dynamic_certs, key, &cert_arc);
        }

        if conf.is_default.unwrap_or_default() {
            let key = certificate_key(DEFAULT_SERVER_NAME, is_rsa);
            held |= claim(&mut dynamic_certs, key, &cert_arc);
        }
        // One that serves nothing - it names no domain, or others have
        // them all - is in the store all the same.
        if !held {
            keep_unused(&mut dynamic_certs, &cert_arc);
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

/// The certificates a handshake was given, kept with it: OpenSSL goes on
/// with one of them, and the OCSP answer to staple is that one's.
#[cfg(feature = "openssl")]
type Applied = [Option<Arc<LoadedCertificate>>; 2];

/// How the certificates of a handshake are put with it and found again.
///
/// They are extra data of the `Ssl`, under an index whose type pingora
/// does not hand on (`openssl::ex_data::Index`): the two closures are made
/// where the index is, and it is never named.
#[cfg(feature = "openssl")]
struct AppliedData {
    set: SetApplied,
    get: GetApplied,
}

#[cfg(feature = "openssl")]
type SetApplied = Box<dyn Fn(&mut SslRef, Applied) + Send + Sync>;

#[cfg(feature = "openssl")]
type GetApplied =
    Box<dyn for<'a> Fn(&'a SslRef) -> Option<&'a Applied> + Send + Sync>;

#[cfg(feature = "openssl")]
static APPLIED: std::sync::LazyLock<Option<AppliedData>> =
    std::sync::LazyLock::new(|| {
        let index = Ssl::new_ex_index::<Applied>().ok()?;
        Some(AppliedData {
            set: Box::new(move |ssl, applied| ssl.set_ex_data(index, applied)),
            get: Box::new(move |ssl| ssl.ex_data(index)),
        })
    });

/// OCSP stapling under OpenSSL: a handshake whose client asks for the
/// status of the certificate is given the answer of the certificate it
/// goes on with, when there is one that has not run out.
#[cfg(feature = "openssl")]
fn set_status_callback(
    builder: &mut SslContextBuilder,
) -> std::result::Result<(), pingora::tls::error::ErrorStack> {
    builder.set_status_callback(|ssl| {
        let Some(data) = APPLIED.as_ref() else {
            return Ok(false);
        };
        let now = pingap_core::now_sec() as i64;
        let staple = (data.get)(ssl).and_then(|applied| {
            let chosen = ssl.certificate()?;
            applied
                .iter()
                .flatten()
                .find(|certificate| certificate.is_certificate(chosen))
                .and_then(|certificate| certificate.staple(now))
        });
        match staple {
            Some(staple) => ssl.set_ocsp_status(&staple.0).map(|_| true),
            None => Ok(false),
        }
    })
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

    /// Picks the certificates to present for `sni`: one, or where the
    /// name has one for each kind of key, the two of them - first the one
    /// that is not RSA, then the RSA one.
    fn select(&self, sni: &str) -> [Option<Arc<LoadedCertificate>>; 2] {
        // Certificate selection process:
        // 1. Try exact domain match (example.com)
        // 2. Try wildcard domain match (*.example.com)
        // 3. Fall back to default certificate (DEFAULT_SERVER_NAME)
        // 4. Handle special case for CA certificates (self-signed)
        // In lower case, as the store has it: OpenSSL hands the name over
        // as the client wrote it, and a CA entry would issue - and keep -
        // a certificate for every way of writing one name.
        let lower;
        let sni = if sni.bytes().any(|byte| byte.is_ascii_uppercase()) {
            lower = sni.to_ascii_lowercase();
            lower.as_str()
        } else {
            sni
        };
        let pair = self.provider.get_pair(sni);
        if pair.is_empty() {
            error!(target: LOG_TARGET, sni, "no match certificate");
        }
        [pair.other, pair.rsa].map(|d| {
            let d = d?;
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
        })
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

        set_status_callback(&mut tls_settings)
            .map_err(|e| invalid("set status callback", &e))?;

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
        // Both of them where the name has two: OpenSSL keeps one
        // certificate for each kind of key, each with its own chain, and
        // signs with the one the client can verify.
        let certificates = self.select(sni);
        for certificate in certificates.iter().flatten() {
            certificate.apply(ssl);
        }
        // For the status callback, which comes when OpenSSL has settled
        // on one of them and the client asks for its OCSP answer.
        if let Some(data) = APPLIED.as_ref() {
            (data.set)(ssl, certificates);
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

/// Whether the handshake of this client can be signed with `key`: the
/// client takes one of the key's signature schemes and, for what is below
/// TLS 1.3, where the cipher suite says what kind of key signs, offers a
/// suite that goes with it.
#[cfg(feature = "tls-rustls")]
fn is_usable_for(
    key: &pingora::tls::sign::CertifiedKey,
    client_hello: &pingora::tls::ClientHello<'_>,
) -> bool {
    if key
        .key
        .choose_scheme(client_hello.signature_schemes())
        .is_none()
    {
        return false;
    }
    let Some(provider) = pingora::tls::CryptoProvider::get_default() else {
        return true;
    };
    let algorithm = key.key.algorithm();
    let offered = client_hello.cipher_suites();
    provider.cipher_suites.iter().any(|suite| {
        suite.usable_for_signature_algorithm(algorithm)
            && offered.contains(&suite.suite())
    })
}

#[cfg(feature = "tls-rustls")]
impl pingora::tls::ResolvesServerCert for GlobalCertificate {
    fn resolve(
        &self,
        client_hello: pingora::tls::ClientHello<'_>,
    ) -> Option<Arc<pingora::tls::sign::CertifiedKey>> {
        let sni = client_hello.server_name().unwrap_or(DEFAULT_SERVER_NAME);
        debug!(target: LOG_TARGET, server_name = sni);
        let [other, rsa] = self
            .select(sni)
            .map(|certificate| Some(certificate?.certified_key()));
        // Where the name has one of each kind of key: the one that is not
        // RSA for every client that can verify it, which is the cheaper
        // signature, and the RSA one for the rest. A client that can
        // verify neither is given the first, for the handshake to fail
        // the way it does with one certificate.
        match (other, rsa) {
            (Some(other), Some(rsa)) => {
                if !is_usable_for(&other, &client_hello)
                    && is_usable_for(&rsa, &client_hello)
                {
                    Some(rsa)
                } else {
                    Some(other)
                }
            },
            (other, rsa) => other.or(rsa),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lookup_certificates;
    use pingap_config::CertificateConf;
    use pretty_assertions::assert_eq;

    /// The certificate `name` is served with, where it has one.
    fn of(certs: &DynamicCertificates, name: &str) -> Arc<TlsCertificate> {
        lookup_certificates(certs, name).first().cloned().unwrap()
    }

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
            Arc::ptr_eq(
                &of(&certs, "a.example.com"),
                &of(&certs, "b.example.com")
            )
        );

        // Same configuration: the same certificate object, nothing updated.
        let (again, errors, updated) = update_certificates(&configs, &certs);
        assert_eq!(true, errors.is_empty());
        assert_eq!(true, updated.is_empty());
        assert_eq!(
            true,
            Arc::ptr_eq(
                &of(&certs, "a.example.com"),
                &of(&again, "a.example.com")
            )
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
            Arc::ptr_eq(
                &of(&again, "a.example.com"),
                &of(&next, "a.example.com")
            )
        );
        // The certificate of the tests has an RSA key.
        assert_eq!(
            true,
            next.contains_key(&certificate_key(DEFAULT_SERVER_NAME, true))
        );
        assert_eq!(false, next.contains_key(DEFAULT_SERVER_NAME));
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
            Arc::ptr_eq(
                &of(&certs, "a.example.com"),
                &of(&next, "a.example.com")
            )
        );
        assert_eq!(1, next.len());
    }

    /// A certificate of `domains` signed by itself, with an RSA key or
    /// with an ECDSA one, as an entry of the configuration.
    fn new_conf(domains: &str, rsa: bool) -> CertificateConf {
        let key = if rsa {
            rcgen::KeyPair::generate_rsa_for(
                &rcgen::PKCS_RSA_SHA256,
                rcgen::RsaKeySize::_2048,
            )
        } else {
            rcgen::KeyPair::generate()
        }
        .unwrap();
        let names: Vec<String> =
            domains.split(',').map(str::to_string).collect();
        let cert = rcgen::CertificateParams::new(names)
            .unwrap()
            .self_signed(&key)
            .unwrap();
        CertificateConf {
            domains: Some(domains.to_string()),
            tls_cert: Some(cert.pem()),
            tls_key: Some(key.serialize_pem()),
            ..Default::default()
        }
    }

    fn names(pair: &crate::CertificatePair) -> Vec<&str> {
        pair.iter()
            .map(|cert| cert.name.as_deref().unwrap_or_default())
            .collect()
    }

    /// A domain is served with two certificates when their keys are of
    /// different kinds, and each level of the lookup - the name, its
    /// wildcard, the default - answers with the ones it has.
    #[test]
    fn test_two_certificates_for_one_domain() {
        let default_rsa = CertificateConf {
            is_default: Some(true),
            ..new_conf("fallback.test", true)
        };
        let default_ecdsa = CertificateConf {
            is_default: Some(true),
            ..new_conf("fallback.test", false)
        };
        let configs = HashMap::from([
            ("site-ecdsa".to_string(), new_conf("site.test", false)),
            ("site-rsa".to_string(), new_conf("site.test", true)),
            ("wild-ecdsa".to_string(), new_conf("*.site.test", false)),
            ("wild-rsa".to_string(), new_conf("*.site.test", true)),
            ("only-rsa".to_string(), new_conf("old.site.test", true)),
            ("default-rsa".to_string(), default_rsa),
            ("default-ecdsa".to_string(), default_ecdsa),
        ]);
        let (certs, errors, updated) =
            update_certificates(&configs, &AHashMap::new());
        assert_eq!(true, errors.is_empty(), "{errors:?}");
        assert_eq!(7, updated.len());
        // site.test, *.site.test, fallback.test and the default twice
        // each, old.site.test once.
        assert_eq!(9, certs.len());

        // The one that is not RSA comes first.
        let pair = lookup_certificates(&certs, "site.test");
        assert_eq!(vec!["site-ecdsa", "site-rsa"], names(&pair));
        assert_eq!(false, pair.other.as_ref().unwrap().is_rsa());
        assert_eq!(true, pair.rsa.as_ref().unwrap().is_rsa());
        assert_eq!(
            "site-ecdsa",
            pair.first().unwrap().name.as_deref().unwrap()
        );

        // Without regard to the case the client wrote the name in.
        let pair = lookup_certificates(&certs, "SITE.Test");
        assert_eq!(vec!["site-ecdsa", "site-rsa"], names(&pair));

        let pair = lookup_certificates(&certs, "www.site.test");
        assert_eq!(vec!["wild-ecdsa", "wild-rsa"], names(&pair));

        // A name with a certificate of its own is served with that, and
        // not with the other kind from its wildcard as well.
        let pair = lookup_certificates(&certs, "old.site.test");
        assert_eq!(vec!["only-rsa"], names(&pair));
        assert_eq!(true, pair.other.is_none());

        for name in ["other.test", "*", "a.b.site.test"] {
            let pair = lookup_certificates(&certs, name);
            assert_eq!(
                vec!["default-ecdsa", "default-rsa"],
                names(&pair),
                "{name}"
            );
        }

        // Nothing for a name: nothing.
        let (certs, _, _) = update_certificates(
            &HashMap::from([(
                "site-rsa".to_string(),
                new_conf("site.test", true),
            )]),
            &AHashMap::new(),
        );
        assert_eq!(true, lookup_certificates(&certs, "other.test").is_empty());
        assert_eq!(
            vec!["site-rsa"],
            names(&lookup_certificates(&certs, "site.test"))
        );
    }

    /// Regression: of two certificates for one domain the one that served
    /// was whichever the map gave last, another one in every process. With
    /// keys of the same kind it is one of them, and the same every time.
    #[test]
    fn test_one_certificate_for_each_kind_of_key() {
        let acme = |conf: CertificateConf| CertificateConf {
            acme: Some("lets_encrypt".to_string()),
            ..conf
        };
        // Enough entries for the order of a map to differ.
        let mut configs = HashMap::new();
        for index in 0..8 {
            configs
                .insert(format!("ecdsa-{index}"), new_conf("dup.test", false));
        }
        configs.insert("rsa-b".to_string(), new_conf("dup.test", true));
        configs.insert("rsa-a".to_string(), acme(new_conf("dup.test", true)));
        configs.insert("rsa-c".to_string(), new_conf("dup.test", true));
        for _ in 0..4 {
            // A new map each time, with a new order.
            let configs: HashMap<_, _> = configs
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            let (certs, errors, _) =
                update_certificates(&configs, &AHashMap::new());
            assert_eq!(true, errors.is_empty(), "{errors:?}");
            // Two of them serve the domain. The others are in the store
            // as well, under keys no client asks for: they are
            // configured, and are looked after like the rest.
            let serving = certs
                .keys()
                .filter(|key| !crate::is_unused_certificate_key(key))
                .count();
            assert_eq!(2, serving);
            assert_eq!(11, certs.len());
            let mut entries: Vec<_> = certs
                .values()
                .filter_map(|cert| cert.name.clone())
                .collect();
            entries.sort();
            entries.dedup();
            assert_eq!(11, entries.len());
            // The first by name, and of the RSA ones the first that is
            // not of ACME.
            assert_eq!(
                vec!["ecdsa-0", "rsa-b"],
                names(&lookup_certificates(&certs, "dup.test"))
            );
        }
    }

    /// Regression: `domains = "Example.com"` was a name no handshake asked
    /// for - the name of a client is in lower case, or is put there.
    #[test]
    fn test_domains_are_matched_without_regard_to_case() {
        let configs = HashMap::from([(
            "site".to_string(),
            CertificateConf {
                domains: Some("Case.Test, *.Case.Test,".to_string()),
                ..new_conf("case.test", false)
            },
        )]);
        let (certs, errors, _) =
            update_certificates(&configs, &AHashMap::new());
        assert_eq!(true, errors.is_empty(), "{errors:?}");
        // The comma at the end names no third domain.
        assert_eq!(2, certs.len());

        // An entry that names none at all serves nothing, and is in the
        // store for whoever goes through the certificates there are.
        let configs = HashMap::from([(
            "nothing".to_string(),
            CertificateConf {
                domains: Some(" , ".to_string()),
                ..new_conf("none.test", false)
            },
        )]);
        let (none, errors, _) = update_certificates(&configs, &AHashMap::new());
        assert_eq!(true, errors.is_empty(), "{errors:?}");
        assert_eq!(
            vec![crate::unused_certificate_key("nothing")],
            none.keys().cloned().collect::<Vec<_>>()
        );
        assert_eq!(true, lookup_certificates(&none, "none.test").is_empty());
        // Carried over as it is by the next update.
        let (again, _, updated) = update_certificates(&configs, &none);
        assert_eq!(true, updated.is_empty());
        assert_eq!(1, again.len());
        for name in ["case.test", "CASE.test", "www.case.test", "WWW.Case.Test"]
        {
            assert_eq!(
                vec!["site"],
                names(&lookup_certificates(&certs, name)),
                "{name}"
            );
        }
    }

    /// A store as the binary keeps it: both certificates of a name.
    struct Store(DynamicCertificates);

    impl CertificateProvider for Store {
        fn get(&self, sni: &str) -> Option<Arc<TlsCertificate>> {
            self.get_pair(sni).first().cloned()
        }
        fn get_pair(&self, sni: &str) -> crate::CertificatePair {
            lookup_certificates(&self.0, sni)
        }
        fn list(&self) -> Arc<DynamicCertificates> {
            Arc::new(self.0.clone())
        }
        fn store(&self, _data: DynamicCertificates) {}
    }

    /// The default certificates given, by kind of key.
    fn default_store(kinds: &[bool]) -> DynamicCertificates {
        let configs = kinds
            .iter()
            .map(|rsa| {
                let conf = CertificateConf {
                    is_default: Some(true),
                    ..new_conf("fallback.test", *rsa)
                };
                (format!("default-{rsa}"), conf)
            })
            .collect();
        let (certs, errors, _) =
            update_certificates(&configs, &AHashMap::new());
        assert_eq!(true, errors.is_empty(), "{errors:?}");
        certs
    }

    /// A store with the default certificates given, by kind of key.
    fn default_certificates(kinds: &[bool]) -> GlobalCertificate {
        GlobalCertificate::new(Arc::new(Store(default_store(kinds))))
    }

    /// The answer of the responder about the certificate of
    /// `issued_store` with that kind of key.
    fn answer(rsa: bool) -> Vec<u8> {
        use crate::ocsp::tests::{GOOD, GOOD_RSA};
        pingap_util::base64_decode(if rsa { GOOD_RSA } else { GOOD }).unwrap()
    }

    /// Two default certificates a CA issued, one for each kind of key,
    /// with the certificate of the CA after them: the ones the responder
    /// of the OCSP tests answered about. OpenSSL staples an answer only
    /// to the certificate it is about, and to none that signed itself.
    fn issued_store() -> DynamicCertificates {
        use crate::ocsp::tests::{CA, LEAF, LEAF_KEY, RSA_LEAF, RSA_LEAF_KEY};
        let conf = |cert: &str, key: &str| CertificateConf {
            is_default: Some(true),
            tls_cert: Some(format!("{cert}\n{CA}")),
            tls_key: Some(key.to_string()),
            ocsp_stapling: Some(true),
            ..Default::default()
        };
        let configs = HashMap::from([
            ("ecdsa".to_string(), conf(LEAF, LEAF_KEY)),
            ("rsa".to_string(), conf(RSA_LEAF, RSA_LEAF_KEY)),
        ]);
        let (certs, errors, _) =
            update_certificates(&configs, &AHashMap::new());
        assert_eq!(true, errors.is_empty(), "{errors:?}");
        certs
    }

    /// Gives every certificate of `certs` the OCSP answer for its kind of
    /// key, good for `lasts` seconds from now.
    fn staple(certs: &DynamicCertificates, lasts: i64) {
        let until = pingap_core::now_sec() as i64 + lasts;
        for cert in certs.values() {
            cert.certificate
                .as_ref()
                .unwrap()
                .set_staple(Some((answer(cert.is_rsa()), until)));
        }
    }

    /// OCSP stapling under OpenSSL: a client that asks for the status of
    /// the certificate gets the answer of the one the handshake went on
    /// with, of the two a name may have, and none once it has run out.
    #[cfg(feature = "openssl")]
    #[test]
    fn test_openssl_staples_the_answer_of_the_certificate() {
        use pingora::listeners::TlsAccept;
        use pingora::tls::ssl::{
            SslAcceptor, SslConnector, SslMethod, SslVerifyMode, StatusType,
        };
        use std::net::{TcpListener, TcpStream};

        // What a client that verifies `sigalgs` is stapled.
        let stapled = |certs: &DynamicCertificates, sigalgs: &str| {
            let certificates =
                GlobalCertificate::new(Arc::new(Store(certs.clone())));
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let mut acceptor =
                SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
            set_status_callback(&mut acceptor).unwrap();
            let acceptor = acceptor.build();
            let mut ssl = Ssl::new(acceptor.context()).unwrap();
            tokio_test::block_on(certificates.certificate_callback(&mut ssl));
            let server = std::thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                let _ = ssl.accept(stream);
            });
            let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
            builder.set_verify(SslVerifyMode::NONE);
            builder.set_sigalgs_list(sigalgs).unwrap();
            // The answer is the client's to look at when it comes, in
            // the callback OpenSSL has for that.
            let answer = Arc::new(std::sync::Mutex::new(None));
            let seen = answer.clone();
            builder
                .set_status_callback(move |ssl| {
                    *seen.lock().unwrap() =
                        ssl.ocsp_status().map(<[u8]>::to_vec);
                    Ok(true)
                })
                .unwrap();
            let mut client = builder
                .build()
                .configure()
                .unwrap()
                .into_ssl("fallback.test")
                .unwrap();
            client.set_status_type(StatusType::OCSP).unwrap();
            client.connect(TcpStream::connect(addr).unwrap()).unwrap();
            server.join().unwrap();
            let mut seen = answer.lock().unwrap();
            seen.take()
        };
        const RSA_ONLY: &str = "RSA-PSS+SHA256:RSA+SHA256";
        const ECDSA_ONLY: &str = "ECDSA+SHA256";

        let certs = issued_store();
        // What to ask the responder is known for both.
        assert_eq!(true, certs.values().all(|cert| cert.ocsp.is_some()));
        // Nothing to staple yet.
        assert_eq!(None, stapled(&certs, ECDSA_ONLY));
        staple(&certs, 3600);
        assert_eq!(Some(answer(false)), stapled(&certs, ECDSA_ONLY));
        assert_eq!(Some(answer(true)), stapled(&certs, RSA_ONLY));
        // One that has run out is not sent.
        staple(&certs, -1);
        assert_eq!(None, stapled(&certs, ECDSA_ONLY));
        assert_eq!(None, stapled(&certs, RSA_ONLY));
        // And taken away.
        staple(&certs, 3600);
        for cert in certs.values() {
            cert.certificate.as_ref().unwrap().set_staple(None);
        }
        assert_eq!(None, stapled(&certs, RSA_ONLY));
    }

    /// With OpenSSL both certificates of a name are put on the handshake,
    /// which signs with the one its client can verify: the ECDSA one for
    /// a client that takes either, the RSA one for a client that takes
    /// nothing else.
    #[cfg(feature = "openssl")]
    #[test]
    fn test_openssl_signs_with_what_the_client_verifies() {
        use pingora::listeners::TlsAccept;
        use pingora::tls::pkey::Id;
        use pingora::tls::ssl::{
            Ssl, SslAcceptor, SslConnector, SslMethod, SslVerifyMode,
        };
        use std::net::{TcpListener, TcpStream};

        // The kind of key of the certificate a client is shown: one that
        // verifies `sigalgs` only, up to TLS 1.2 or 1.3. `None` when the
        // handshake fails.
        let handshake = |certificates: &GlobalCertificate,
                         sigalgs: Option<&str>,
                         tls12: bool| {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            // The settings pingora makes a listener with.
            let acceptor =
                SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
                    .unwrap()
                    .build();
            let mut ssl = Ssl::new(acceptor.context()).unwrap();
            // No name has been read yet: the default certificates.
            tokio_test::block_on(certificates.certificate_callback(&mut ssl));
            let server = std::thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                let _ = ssl.accept(stream);
            });
            let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
            builder.set_verify(SslVerifyMode::NONE);
            if let Some(sigalgs) = sigalgs {
                builder.set_sigalgs_list(sigalgs).unwrap();
            }
            if tls12 {
                builder
                    .set_max_proto_version(Some(SslVersion::TLS1_2))
                    .unwrap();
            }
            let id = builder
                .build()
                .connect("fallback.test", TcpStream::connect(addr).unwrap())
                .ok()
                .and_then(|stream| stream.ssl().peer_certificate())
                .and_then(|cert| cert.public_key().ok())
                .map(|key| key.id());
            server.join().unwrap();
            id
        };
        const RSA_ONLY: &str = "RSA-PSS+SHA256:RSA+SHA256";
        const ECDSA_ONLY: &str = "ECDSA+SHA256";

        let both = default_certificates(&[false, true]);
        for tls12 in [false, true] {
            assert_eq!(Some(Id::EC), handshake(&both, None, tls12), "{tls12}");
            assert_eq!(
                Some(Id::EC),
                handshake(&both, Some(ECDSA_ONLY), tls12),
                "{tls12}"
            );
            assert_eq!(
                Some(Id::RSA),
                handshake(&both, Some(RSA_ONLY), tls12),
                "{tls12}"
            );
        }

        // What it is with one certificate: a client that cannot verify it
        // has no handshake.
        let ecdsa = default_certificates(&[false]);
        assert_eq!(Some(Id::EC), handshake(&ecdsa, None, false));
        assert_eq!(None, handshake(&ecdsa, Some(RSA_ONLY), false));
        let rsa = default_certificates(&[true]);
        assert_eq!(Some(Id::RSA), handshake(&rsa, None, false));
        assert_eq!(None, handshake(&rsa, Some(ECDSA_ONLY), false));
    }

    /// With rustls the handshake is given one certificate, picked by what
    /// its client said it verifies: the ECDSA one for a client that takes
    /// either, the RSA one for a client that takes nothing else.
    #[cfg(feature = "tls-rustls")]
    #[test]
    fn test_rustls_resolves_what_the_client_verifies() {
        use pingora::tls::ResolvesServerCert;
        use rustls::client::danger::{
            HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
        };
        use rustls::crypto::CryptoProvider;
        use rustls::{
            SignatureAlgorithm, SignatureScheme, SupportedCipherSuite,
        };

        // A client that says it verifies these schemes.
        #[derive(Debug)]
        struct Verifies(Vec<SignatureScheme>);
        impl ServerCertVerifier for Verifies {
            fn verify_server_cert(
                &self,
                _end_entity: &rustls_pki_types::CertificateDer<'_>,
                _intermediates: &[rustls_pki_types::CertificateDer<'_>],
                _server_name: &rustls_pki_types::ServerName<'_>,
                _ocsp_response: &[u8],
                _now: rustls_pki_types::UnixTime,
            ) -> Result<ServerCertVerified, rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }
            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &rustls_pki_types::CertificateDer<'_>,
                _dss: &rustls::DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &rustls_pki_types::CertificateDer<'_>,
                _dss: &rustls::DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                self.0.clone()
            }
        }

        crate::install_default_crypto_provider();
        let provider = CryptoProvider::get_default().unwrap();
        const RSA: &[SignatureScheme] = &[
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
        ];
        const ECDSA: &[SignatureScheme] =
            &[SignatureScheme::ECDSA_NISTP256_SHA256];
        let either = [ECDSA, RSA].concat();

        // Whether the certificate for a client is the RSA one: a client
        // that verifies `schemes` and, with `suites_of`, speaks TLS 1.2
        // with the cipher suites of that kind of key only.
        let resolve =
            |certificates: &GlobalCertificate,
             schemes: &[SignatureScheme],
             suites_of: Option<SignatureAlgorithm>| {
                let verifier = Arc::new(Verifies(schemes.to_vec()));
                let config = match suites_of {
                    Some(algorithm) => {
                        let mut provider = provider.as_ref().clone();
                        provider.cipher_suites.retain(|suite| {
                            matches!(suite, SupportedCipherSuite::Tls12(_))
                                && suite
                                    .usable_for_signature_algorithm(algorithm)
                        });
                        rustls::ClientConfig::builder_with_provider(Arc::new(
                            provider,
                        ))
                        .with_protocol_versions(&[&rustls::version::TLS12])
                        .unwrap()
                    },
                    None => rustls::ClientConfig::builder(),
                }
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth();
                let mut client = rustls::ClientConnection::new(
                    Arc::new(config),
                    "fallback.test".try_into().unwrap(),
                )
                .unwrap();
                let mut hello = vec![];
                client.write_tls(&mut hello).unwrap();
                let mut acceptor = rustls::server::Acceptor::default();
                acceptor.read_tls(&mut hello.as_slice()).unwrap();
                let accepted = acceptor.accept().ok().flatten().unwrap();
                certificates
                    .resolve(accepted.client_hello())
                    .map(|key| key.key.algorithm() == SignatureAlgorithm::RSA)
            };

        let both = default_certificates(&[false, true]);
        assert_eq!(Some(false), resolve(&both, &either, None));
        assert_eq!(Some(false), resolve(&both, ECDSA, None));
        assert_eq!(Some(true), resolve(&both, RSA, None));
        // Below TLS 1.3 the cipher suite has to go with the key as well:
        // a client that verifies either but offers the suites of RSA
        // alone can not be served with the other.
        assert_eq!(
            Some(true),
            resolve(&both, &either, Some(SignatureAlgorithm::RSA))
        );
        assert_eq!(
            Some(false),
            resolve(&both, &either, Some(SignatureAlgorithm::ECDSA))
        );

        // One certificate is the answer for every client, as before.
        let ecdsa = default_certificates(&[false]);
        assert_eq!(Some(false), resolve(&ecdsa, &either, None));
        assert_eq!(Some(false), resolve(&ecdsa, RSA, None));
        let rsa = default_certificates(&[true]);
        assert_eq!(Some(true), resolve(&rsa, ECDSA, None));
        // And with both, a client that verifies neither gets the first.
        assert_eq!(
            Some(false),
            resolve(&both, &[SignatureScheme::ED25519], None)
        );
    }

    /// OCSP stapling under rustls: the certificate handed to a handshake
    /// has the answer with it while it holds, and rustls sends it to the
    /// clients that ask.
    #[cfg(feature = "tls-rustls")]
    #[test]
    fn test_rustls_staples_the_answer_of_the_certificate() {
        let certs = issued_store();
        // The answer that goes with each of the two certificates, the one
        // that is not RSA first.
        let answers = |certs: &DynamicCertificates| {
            lookup_certificates(certs, "ocsp.test")
                .iter()
                .map(|cert| {
                    let key =
                        cert.certificate.as_ref().unwrap().certified_key();
                    key.ocsp.clone()
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(vec![None, None], answers(&certs));
        staple(&certs, 3600);
        assert_eq!(
            vec![Some(answer(false)), Some(answer(true))],
            answers(&certs)
        );
        let now = pingap_core::now_sec() as i64;
        for cert in certs.values() {
            let certificate = cert.certificate.as_ref().unwrap();
            assert_eq!(true, certificate.has_staple(now));
            // The certificate and its key are the ones they were.
            assert_eq!(
                certificate.leaf_der().unwrap(),
                certificate.certified_key().cert[0].to_vec()
            );
        }
        // One that has run out is not sent.
        staple(&certs, -1);
        assert_eq!(vec![None, None], answers(&certs));
        staple(&certs, 3600);
        for cert in certs.values() {
            cert.certificate.as_ref().unwrap().set_staple(None);
        }
        assert_eq!(vec![None, None], answers(&certs));
    }

    /// What a CA entry serves is what it issues, an ECDSA certificate,
    /// whatever the key of the CA is.
    #[test]
    fn test_kind_of_key() {
        let rsa =
            TlsCertificate::try_from(&new_conf("kind.test", true)).unwrap();
        assert_eq!(true, rsa.is_rsa());
        let ecdsa =
            TlsCertificate::try_from(&new_conf("kind.test", false)).unwrap();
        assert_eq!(false, ecdsa.is_rsa());
        let ca = TlsCertificate {
            is_ca: true,
            ..rsa.clone()
        };
        assert_eq!(false, ca.is_rsa());
        assert_eq!(false, TlsCertificate::default().is_rsa());

        assert_eq!("a.test", certificate_key("a.test", false));
        assert_eq!(("a.test", false), split_certificate_key("a.test"));
        let key = certificate_key("a.test", true);
        assert_eq!(true, key != "a.test");
        assert_eq!(("a.test", true), split_certificate_key(&key));
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
