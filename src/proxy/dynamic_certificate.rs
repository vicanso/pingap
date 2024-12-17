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

use crate::acme::Certificate;
use crate::config::CertificateConf;
use crate::service::{CommonServiceTask, ServiceTask};
use crate::{util, webhook};
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
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use substring::Substring;
use tracing::{debug, error, info};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Invalid error, category: {category}, {message}"))]
    Invalid { message: String, category: String },
}
type Result<T, E = Error> = std::result::Result<T, E>;

type DynamicCertificates = AHashMap<String, Arc<DynamicCertificate>>;
// global dynamic certificates
// static DYNAMIC_CERTIFICATE_MAP: OnceCell<DynamicCertificates> = OnceCell::new();
static DYNAMIC_CERTIFICATE_MAP: Lazy<ArcSwap<DynamicCertificates>> =
    Lazy::new(|| ArcSwap::from_pointee(AHashMap::new()));

struct SelfSignedCert {
    x509: X509,
    key: PKey<Private>,
    stale: AtomicBool,
    count: AtomicU32,
}
type SelfSignedCertKey = AHashMap<String, Arc<SelfSignedCert>>;
static SELF_SIGNED_CERT_KEY_MAP: Lazy<ArcSwap<SelfSignedCertKey>> =
    Lazy::new(|| ArcSwap::from_pointee(AHashMap::new()));

struct SelfSiginedStaleCertChecker {}

#[async_trait]
impl ServiceTask for SelfSiginedStaleCertChecker {
    async fn run(&self) -> Option<bool> {
        let mut m = AHashMap::new();
        for (k, v) in SELF_SIGNED_CERT_KEY_MAP.load().iter() {
            let count = v.count.load(Ordering::Relaxed);
            let stale = v.stale.load(Ordering::Relaxed);
            if stale && count == 0 {
                continue;
            }
            if count == 0 {
                v.stale.store(true, Ordering::Relaxed);
            } else {
                v.stale.store(false, Ordering::Relaxed);
                v.count.store(0, Ordering::Relaxed);
            }
            m.insert(k.to_string(), v.clone());
        }
        SELF_SIGNED_CERT_KEY_MAP.store(Arc::new(m));
        Some(false)
    }
    fn description(&self) -> String {
        "Self signed certificate stale checker".to_string()
    }
}

pub fn new_self_signed_cert_validity_service() -> CommonServiceTask {
    CommonServiceTask::new(
        // check interval: one day
        Duration::from_secs(24 * 60 * 60),
        SelfSiginedStaleCertChecker {},
    )
}

// https://letsencrypt.org/certificates/
const E5: &[u8] = include_bytes!("../assets/e5.pem");
const E6: &[u8] = include_bytes!("../assets/e6.pem");
const R10: &[u8] = include_bytes!("../assets/r10.pem");
const R11: &[u8] = include_bytes!("../assets/r11.pem");

fn parse_chain_certificate(data: &[u8]) -> Option<X509> {
    if let Ok(info) = Certificate::new(
        std::string::String::from_utf8_lossy(data).to_string(),
        "".to_string(),
    ) {
        if info.not_after > util::now().as_secs() as i64 {
            return X509::from_pem(data).ok();
        }
    }
    None
}
static E5_CERTIFICATE: Lazy<Option<X509>> =
    Lazy::new(|| parse_chain_certificate(E5));
static E6_CERTIFICATE: Lazy<Option<X509>> =
    Lazy::new(|| parse_chain_certificate(E6));
static R10_CERTIFICATE: Lazy<Option<X509>> =
    Lazy::new(|| parse_chain_certificate(R10));
static R11_CERTIFICATE: Lazy<Option<X509>> =
    Lazy::new(|| parse_chain_certificate(R11));

static LETS_ENCRYPT: &str = "lets_encrypt";

fn parse_certificate(
    certificate_config: &CertificateConf,
) -> Result<DynamicCertificate> {
    // parse certificate
    let info = Certificate::new(
        certificate_config.tls_cert.clone().unwrap_or_default(),
        certificate_config.tls_key.clone().unwrap_or_default(),
    )
    .map_err(|e| Error::Invalid {
        message: e.to_string(),
        category: "certificate".to_string(),
    })?;
    let category = if certificate_config.acme.is_some() {
        LETS_ENCRYPT
    } else {
        ""
    };

    let hash_key = certificate_config.hash_key();

    let tls_chain =
        util::convert_certificate_bytes(&certificate_config.tls_chain);
    let chain_certificate = if let Some(value) = &tls_chain {
        // ignore chain error
        X509::from_pem(value).ok()
    } else if category == LETS_ENCRYPT {
        // get chain of let's encrypt
        match info.get_issuer_common_name().as_str() {
            "E5" => E5_CERTIFICATE.clone(),
            "E6" => E6_CERTIFICATE.clone(),
            "R10" => R10_CERTIFICATE.clone(),
            "R11" => R11_CERTIFICATE.clone(),
            _ => None,
        }
    } else {
        None
    };
    let cert =
        X509::from_pem(&info.get_cert()).map_err(|e| Error::Invalid {
            category: "x509_from_pem".to_string(),
            message: e.to_string(),
        })?;

    let key = PKey::private_key_from_pem(&info.get_key()).map_err(|e| {
        Error::Invalid {
            category: "private_key_from_pem".to_string(),
            message: e.to_string(),
        }
    })?;
    Ok(DynamicCertificate {
        hash_key,
        chain_certificate,
        domains: info.domains.clone(),
        certificate: Some((cert, key)),
        info: Some(info),
        is_ca: certificate_config.is_ca.unwrap_or_default(),
        ..Default::default()
    })
}

static DEFAULT_SERVER_NAME: &str = "*";

fn parse_certificates(
    certificate_configs: &HashMap<String, CertificateConf>,
) -> (DynamicCertificates, Vec<(String, String)>) {
    let mut dynamic_certs = AHashMap::new();
    let mut errors = vec![];
    for (name, certificate) in certificate_configs.iter() {
        match parse_certificate(certificate) {
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

/// Init certificates, which use for global tls callback
pub fn init_certificates(
    certificate_configs: &HashMap<String, CertificateConf>,
) -> Vec<String> {
    let (dynamic_certs, errors) = parse_certificates(certificate_configs);
    if !errors.is_empty() {
        let msg_list: Vec<String> = errors
            .iter()
            .map(|item| format!("name:{}, error:{}", item.0, item.1))
            .collect();
        webhook::send(webhook::SendNotificationParams {
            category: webhook::NotificationCategory::ParseCertificateFail,
            level: webhook::NotificationLevel::Error,
            msg: msg_list.join(";"),
            remark: None,
        });
    }
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
    DYNAMIC_CERTIFICATE_MAP.store(Arc::new(dynamic_certs));
    updated_certificates
}

/// Get certificate info list
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

#[derive(Debug, Clone, Default)]
pub struct DynamicCertificate {
    name: Option<String>,
    chain_certificate: Option<X509>,
    certificate: Option<(X509, PKey<Private>)>,
    domains: Vec<String>,
    info: Option<Certificate>,
    hash_key: String,
    is_ca: bool,
}

pub struct TlsSettingParams {
    pub server_name: String,
    pub enabled_h2: bool,
    pub cipher_list: Option<String>,
    pub ciphersuites: Option<String>,
    pub tls_min_version: Option<String>,
    pub tls_max_version: Option<String>,
}

fn new_certificate_with_ca(
    root_ca: &DynamicCertificate,
    cn: &str,
) -> Result<(X509, PKey<Private>)> {
    let Some(info) = &root_ca.info else {
        return Err(Error::Invalid {
            message: "root ca is invalid".to_string(),
            category: "ca".to_string(),
        });
    };
    let binding = info.get_cert();
    let ca_pem = std::string::String::from_utf8_lossy(&binding);

    let ca_params = rcgen::CertificateParams::from_ca_cert_pem(&ca_pem)
        .map_err(|e| Error::Invalid {
            message: e.to_string(),
            category: "parse_ca".to_string(),
        })?;

    let binding = info.get_key();
    let ca_key = std::string::String::from_utf8_lossy(&binding);

    let ca_kp =
        rcgen::KeyPair::from_pem(&ca_key).map_err(|e| Error::Invalid {
            message: e.to_string(),
            category: "parse_ca_key".to_string(),
        })?;
    let not_before = ca_params.not_before;
    let not_after = ca_params.not_after;
    let ca_cert =
        ca_params.self_signed(&ca_kp).map_err(|e| Error::Invalid {
            message: e.to_string(),
            category: "self_sigined_ca".to_string(),
        })?;

    let mut params = rcgen::CertificateParams::new(vec![cn.to_string()])
        .map_err(|e| Error::Invalid {
            message: e.to_string(),
            category: "new_cert_params".to_string(),
        })?;
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, cn.to_string());
    if let Some(organ) = ca_cert
        .params()
        .distinguished_name
        .get(&rcgen::DnType::OrganizationName)
    {
        dn.push(rcgen::DnType::OrganizationName, organ.clone());
    };
    if let Some(unit) = ca_cert
        .params()
        .distinguished_name
        .get(&rcgen::DnType::OrganizationalUnitName)
    {
        dn.push(rcgen::DnType::OrganizationalUnitName, unit.clone());
    };

    params.distinguished_name = dn;
    params.not_before = not_before;
    params.not_after = not_after;

    let cert_key = rcgen::KeyPair::generate().map_err(|e| Error::Invalid {
        message: e.to_string(),
        category: "key_pair_generate".to_string(),
    })?;

    let cert = params.signed_by(&cert_key, &ca_cert, &ca_kp).map_err(|e| {
        Error::Invalid {
            message: e.to_string(),
            category: "signed_by_ca".to_string(),
        }
    })?;

    let cert =
        X509::from_pem(cert.pem().as_bytes()).map_err(|e| Error::Invalid {
            category: "x509_from_pem".to_string(),
            message: e.to_string(),
        })?;

    let key = PKey::private_key_from_pem(cert_key.serialize_pem().as_bytes())
        .map_err(|e| Error::Invalid {
        category: "private_key_from_pem".to_string(),
        message: e.to_string(),
    })?;

    Ok((cert, key))
}

impl DynamicCertificate {
    /// New a global dynamic certificate for tls callback
    pub fn new_global() -> Self {
        Self {
            chain_certificate: None,
            certificate: None,
            ..Default::default()
        }
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
    /// Get self signed certificate
    fn get_self_signed_cert(
        &self,
        server_name: &str,
    ) -> Result<Arc<SelfSignedCert>> {
        let arr: Vec<&str> = server_name.split('.').collect();
        let cn = if arr.len() > 2 {
            format!("*.{}", arr[1..].join("."))
        } else {
            server_name.to_string()
        };
        let k = format!("{:?}:{}", self.name, cn);
        if let Some(v) = SELF_SIGNED_CERT_KEY_MAP.load().get(&k) {
            return Ok(v.clone());
        }
        let (cert, key) = new_certificate_with_ca(self, &cn)?;
        info!(common_name = cn, "new self sigined cert",);
        let mut m = AHashMap::new();
        for (k, v) in SELF_SIGNED_CERT_KEY_MAP.load().iter() {
            m.insert(k.to_string(), v.clone());
        }
        let v = Arc::new(SelfSignedCert {
            x509: cert,
            key,
            stale: AtomicBool::new(false),
            count: AtomicU32::new(0),
        });
        m.insert(k, v.clone());
        SELF_SIGNED_CERT_KEY_MAP.store(Arc::new(m));

        Ok(v)
    }
}

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

#[async_trait]
impl pingora::listeners::TlsAccept for DynamicCertificate {
    async fn certificate_callback(&self, ssl: &mut SslRef) {
        // TODO add more debug log
        debug!(ssl = format!("{ssl:?}"));
        if let Some((cert, key)) = &self.certificate {
            ssl_certificate(ssl, cert, key, &self.chain_certificate);
            return;
        }
        let server_name = ssl.servername(NameType::HOST_NAME);
        debug!(server_name = format!("{server_name:?}"));
        let Some(sni) = server_name else {
            if let Some(d) =
                DYNAMIC_CERTIFICATE_MAP.load().get(DEFAULT_SERVER_NAME)
            {
                if let Some((cert, key)) = &d.certificate {
                    ssl_certificate(ssl, cert, key, &d.chain_certificate);
                    return;
                }
            }
            error!(ssl = format!("{ssl:?}"), "get server name fail");
            return;
        };
        let mut dynamic_certificate = None;
        let certs = DYNAMIC_CERTIFICATE_MAP.load();
        if let Some(d) = certs.get(sni) {
            dynamic_certificate = Some(d);
        } else {
            for (name, d) in certs.iter() {
                // not wildcard
                if !name.starts_with("*.") {
                    continue;
                }
                if sni.ends_with(name.substring(2, name.len())) {
                    dynamic_certificate = Some(d);
                    break;
                }
            }
            // get default certificate
            if dynamic_certificate.is_none() {
                dynamic_certificate = certs.get(DEFAULT_SERVER_NAME);
            }
        }
        let Some(d) = dynamic_certificate else {
            error!(sni, ssl = format!("{ssl:?}"), "no match certificate");
            return;
        };

        // ca
        if d.is_ca {
            match d.get_self_signed_cert(server_name.unwrap_or_default()) {
                Ok(result) => {
                    ssl_certificate(
                        ssl,
                        &result.x509,
                        &result.key,
                        &d.chain_certificate,
                    );
                    result.count.fetch_add(1, Ordering::Relaxed);
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
    use super::{parse_certificate, DynamicCertificate, TlsSettingParams};
    use crate::{
        config::CertificateConf,
        proxy::{
            dynamic_certificate::{DYNAMIC_CERTIFICATE_MAP, E5},
            init_certificates,
        },
    };
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
        let dynamic = DynamicCertificate::new_global();
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
            tls_chain: Some(std::str::from_utf8(E5).unwrap().to_string()),
            ..Default::default()
        };
        let dynamic_certificate = parse_certificate(&cert_info).unwrap();
        let info = dynamic_certificate.info.unwrap_or_default();

        assert_eq!("pingap.io", dynamic_certificate.domains.join(","));
        assert_eq!(
            "O=mkcert development CA, OU=vicanso@tree, CN=mkcert vicanso@tree",
            info.issuer
        );
        assert_eq!(1720232616, info.not_before);
        assert_eq!(1791253416, info.not_after);
        assert_eq!(true, dynamic_certificate.certificate.is_some());
        assert_eq!(true, dynamic_certificate.chain_certificate.is_some());

        let mut map = HashMap::new();
        map.insert("pingap".to_string(), cert_info);
        init_certificates(&map);

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
