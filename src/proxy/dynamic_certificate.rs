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

use crate::acme::{
    get_certificate_info, get_lets_encrypt_certificate, CertificateInfo,
};
use crate::config::CertificateConf;
use crate::{util, webhook};
use ahash::AHashMap;
use async_trait::async_trait;
use once_cell::sync::{Lazy, OnceCell};
use pingora::listeners::TlsSettings;
use pingora::tls::ext;
use pingora::tls::pkey::{PKey, Private};
use pingora::tls::ssl::{NameType, SslRef};
use pingora::tls::x509::X509;
use snafu::Snafu;
use std::collections::HashMap;
use std::path::Path;
use substring::Substring;
use tracing::{debug, error, info};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Invalid error, category: {category}, {message}"))]
    Invalid { message: String, category: String },
}
type Result<T, E = Error> = std::result::Result<T, E>;

type DynamicCertificates = AHashMap<String, DynamicCertificate>;
// global dynamic certificates
static DYNAMIC_CERTIFICATE_MAP: OnceCell<DynamicCertificates> = OnceCell::new();
const E5: &[u8] = include_bytes!("../assets/e5.pem");
const E6: &[u8] = include_bytes!("../assets/e6.pem");
const R10: &[u8] = include_bytes!("../assets/r10.pem");
const R11: &[u8] = include_bytes!("../assets/r11.pem");

fn parse_chain_certificate(data: &[u8]) -> Option<X509> {
    if let Ok(info) = get_certificate_info(data) {
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
) -> Result<(Vec<String>, DynamicCertificate, CertificateInfo)> {
    // parse certificate
    let (cert, key, category) =
        if let Some(file) = &certificate_config.certificate_file {
            let cert = get_lets_encrypt_certificate(
                &Path::new(&util::resolve_path(file)).to_path_buf(),
            )
            .map_err(|e| Error::Invalid {
                category: "get_lets_encrypt_certificate".to_string(),
                message: e.to_string(),
            })?;
            (cert.get_cert(), cert.get_key(), LETS_ENCRYPT)
        } else {
            (
                util::convert_certificate_bytes(&certificate_config.tls_cert)
                    .ok_or(Error::Invalid {
                    category: "convert_certificate_bytes".to_string(),
                    message: "convert certificate fail".to_string(),
                })?,
                util::convert_certificate_bytes(&certificate_config.tls_key)
                    .ok_or(Error::Invalid {
                        category: "convert_certificate_bytes".to_string(),
                        message: "convert certificate key fail".to_string(),
                    })?,
                "",
            )
        };
    let info = get_certificate_info(&cert).map_err(|e| Error::Invalid {
        category: "get_certificate_info".to_string(),
        message: e.to_string(),
    })?;

    let tls_chain =
        util::convert_certificate_bytes(&certificate_config.tls_chain);
    let chain_certificate = if let Some(value) = &tls_chain {
        // ingore chain error
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
    let cert = X509::from_pem(&cert).map_err(|e| Error::Invalid {
        category: "x509_from_pem".to_string(),
        message: e.to_string(),
    })?;
    let names = cert.subject_alt_names().ok_or(Error::Invalid {
        category: "subject_alt_names".to_string(),
        message: "get subject alt names fail".to_string(),
    })?;
    let mut domains = vec![];
    for item in names.iter() {
        domains.push(format!("{:?}", item));
    }

    let key = PKey::private_key_from_pem(&key).map_err(|e| Error::Invalid {
        category: "private_key_from_pem".to_string(),
        message: e.to_string(),
    })?;
    let d = DynamicCertificate {
        chain_certificate,
        certificate: Some((cert, key)),
    };
    Ok((domains, d, info))
}

/// Try to init certificates, which use for global tls callback
pub fn try_init_certificates(
    certificate_configs: &HashMap<String, CertificateConf>,
) -> Result<Vec<(String, CertificateInfo)>> {
    let mut certificate_info_list = vec![];
    DYNAMIC_CERTIFICATE_MAP.get_or_try_init(|| {
        let mut dynamic_certs = AHashMap::new();
        for (name, certificate) in certificate_configs.iter() {
            match parse_certificate(certificate) {
                Ok((domains, dynamic_cert, certificate_info)) => {
                    let mut names = domains;
                    if let Some(value) = &certificate.domains {
                        names = value
                            .split(',')
                            .map(|item| item.to_string())
                            .collect();
                    }
                    for name in names.iter() {
                        dynamic_certs
                            .insert(name.to_string(), dynamic_cert.clone());
                    }
                    info!(
                        name,
                        subject_alt_names = names.join(","),
                        "init certificates success"
                    );
                    certificate_info_list
                        .push((name.to_string(), certificate_info));
                },
                Err(e) => {
                    error!(
                        error = e.to_string(),
                        name, "parse certificate fail"
                    );
                    // not return error
                    // so send a webhook notification
                    webhook::send(webhook::SendNotificationParams {
                        category:
                            webhook::NotificationCategory::ParseCertificateFail,
                        level: webhook::NotificationLevel::Error,
                        msg: e.to_string(),
                        remark: None,
                    });
                },
            };
        }
        Ok(dynamic_certs)
    })?;
    Ok(certificate_info_list)
}

#[derive(Debug, Clone, Default)]
pub struct DynamicCertificate {
    chain_certificate: Option<X509>,
    certificate: Option<(X509, PKey<Private>)>,
}

pub struct TlsSettingParams {
    pub server_name: String,
    pub enbaled_h2: bool,
    pub cipher_list: Option<String>,
    pub ciphersuites: Option<String>,
    pub tls_min_version: Option<String>,
    pub tls_max_version: Option<String>,
}

impl DynamicCertificate {
    /// New a global dynamic certificate for tls callback
    pub fn new_global() -> Self {
        Self {
            chain_certificate: None,
            certificate: None,
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
        if params.enbaled_h2 {
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
    /// New a dynamic certificate from pem data
    pub fn new(cert: &[u8], key: &[u8]) -> Result<Self> {
        let cert = X509::from_pem(cert).map_err(|e| Error::Invalid {
            category: "x509_from_pem".to_string(),
            message: e.to_string(),
        })?;
        let names: Vec<String> = cert
            .subject_alt_names()
            .iter()
            .map(|name| format!("{name:?}"))
            .collect();
        info!(
            subject_alt_names = names.join(","),
            "get subject alt name from cert"
        );
        let key =
            PKey::private_key_from_pem(key).map_err(|e| Error::Invalid {
                category: "private_key_from_pem".to_string(),
                message: e.to_string(),
            })?;
        Ok(Self {
            chain_certificate: None,
            certificate: Some((cert, key)),
        })
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
            error!(ssl = format!("{ssl:?}"), "get server name fail");
            return;
        };
        let Some(m) = DYNAMIC_CERTIFICATE_MAP.get() else {
            error!(ssl = format!("{ssl:?}"), "get dynamic cert map fail");
            return;
        };
        let mut dynamic_certificate = None;
        if let Some(d) = m.get(sni) {
            dynamic_certificate = Some(d);
        } else {
            for (name, d) in m.iter() {
                // not wildcard
                if !name.starts_with("*.") {
                    continue;
                }
                if sni.ends_with(name.substring(2, name.len())) {
                    dynamic_certificate = Some(d);
                    break;
                }
            }
        }
        let Some(d) = dynamic_certificate else {
            error!(sni, ssl = format!("{ssl:?}"), "no match certificate");
            return;
        };
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
            try_init_certificates,
        },
    };
    use pretty_assertions::assert_eq;
    use std::collections::HashMap;

    fn get_tls_pem() -> (String, String) {
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
    }

    #[test]
    fn test_new_tls_settings() {
        let dynamic = DynamicCertificate::new_global();
        let mut tls_setings = dynamic
            .new_tls_settings(&TlsSettingParams {
                server_name: "pingap".to_string(),
                enbaled_h2: true,
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
        assert_eq!(true, tls_setings.min_proto_version().is_some());
        assert_eq!(true, tls_setings.max_proto_version().is_some());
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
        let (domains, dynamic_certificate, info) =
            parse_certificate(&cert_info).unwrap();

        assert_eq!("pingap.io", domains.join(","));
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
        let result = try_init_certificates(&map).unwrap();
        assert_eq!(1, result.len());
        assert_eq!("pingap".to_string(), result[0].0);
        assert_eq!(
            "O=mkcert development CA, OU=vicanso@tree, CN=mkcert vicanso@tree"
                .to_string(),
            result[0].1.issuer
        );
        let cert = DYNAMIC_CERTIFICATE_MAP
            .get()
            .unwrap()
            .get("pingap.io")
            .unwrap();
        assert_eq!(true, cert.certificate.is_some());
    }

    #[test]
    fn test_dynamic_certificate() {
        let (tls_cert, tls_key) = get_tls_pem();
        let dynamic_certificate =
            DynamicCertificate::new(tls_cert.as_bytes(), tls_key.as_bytes())
                .unwrap();

        assert_eq!(true, dynamic_certificate.certificate.is_some());
        assert_eq!(true, dynamic_certificate.chain_certificate.is_none());
    }
}
