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

use crate::acme::{get_certificate_info, get_lets_encrypt_cert, CertificateInfo};
use crate::config::CertificateConf;
use crate::{util, webhook};
use async_trait::async_trait;
use once_cell::sync::OnceCell;
use pingora::tls::ext;
use pingora::tls::pkey::{PKey, Private};
use pingora::tls::ssl::NameType;
use pingora::tls::x509::X509;
use snafu::Snafu;
use std::collections::HashMap;
use std::path::Path;
use substring::Substring;
use tracing::{debug, error, info};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Invalid {message}"))]
    Invalid { message: String },
}
type Result<T, E = Error> = std::result::Result<T, E>;

type DynamicCertificates = HashMap<String, DynamicCertificate>;
static DYNAMIC_CERT_MAP: OnceCell<DynamicCertificates> = OnceCell::new();

fn parse_certificate(
    certificate_config: &CertificateConf,
) -> Result<(Vec<String>, DynamicCertificate, CertificateInfo)> {
    let (cert, key) = if let Some(file) = &certificate_config.certificate_file {
        let cert = get_lets_encrypt_cert(&Path::new(&util::resolve_path(file)).to_path_buf())
            .map_err(|e| Error::Invalid {
                message: e.to_string(),
            })?;
        (cert.get_cert(), cert.get_key())
    } else {
        (
            util::convert_certificate_bytes(&certificate_config.tls_cert).ok_or(
                Error::Invalid {
                    message: "Convert certificate fail".to_string(),
                },
            )?,
            util::convert_certificate_bytes(&certificate_config.tls_key).ok_or(Error::Invalid {
                message: "Convert certificate key fail".to_string(),
            })?,
        )
    };
    let info = get_certificate_info(&cert).map_err(|e| Error::Invalid {
        message: e.to_string(),
    })?;
    let cert = X509::from_pem(&cert).map_err(|e| Error::Invalid {
        message: e.to_string(),
    })?;
    let names = cert.subject_alt_names().ok_or(Error::Invalid {
        message: "get subject alt names fail".to_string(),
    })?;
    let mut domains = vec![];
    for item in names.iter() {
        domains.push(format!("{:?}", item));
    }

    let key = PKey::private_key_from_pem(&key).map_err(|e| Error::Invalid {
        message: e.to_string(),
    })?;
    let d = DynamicCertificate {
        certificate: Some((cert, key)),
    };
    Ok((domains, d, info))
}

pub fn try_init_certificates(
    certificate_configs: &HashMap<String, CertificateConf>,
) -> Result<Vec<(String, CertificateInfo)>> {
    let mut certificate_info_list = vec![];
    DYNAMIC_CERT_MAP.get_or_try_init(|| {
        let mut dynamic_certs = HashMap::new();
        for (name, certificate) in certificate_configs.iter() {
            match parse_certificate(certificate) {
                Ok((domains, dynamic_cert, certificate_info)) => {
                    let mut names = domains;
                    if let Some(value) = &certificate.domains {
                        names = value.split(',').map(|item| item.to_string()).collect();
                    }
                    for name in names.iter() {
                        dynamic_certs.insert(name.to_string(), dynamic_cert.clone());
                    }
                    info!(
                        name,
                        subject_alt_names = names.join(","),
                        "init certificates success"
                    );
                    certificate_info_list.push((name.to_string(), certificate_info));
                }
                Err(e) => {
                    error!(error = e.to_string(), name, "parse certificate fail");
                    webhook::send(webhook::SendNotificationParams {
                        category: webhook::NotificationCategory::ParseCertificateFail,
                        level: webhook::NotificationLevel::Error,
                        msg: e.to_string(),
                    });
                }
            };
        }
        Ok(dynamic_certs)
    })?;
    Ok(certificate_info_list)
}

#[derive(Debug, Clone, Default)]
pub struct DynamicCertificate {
    certificate: Option<(X509, PKey<Private>)>,
}

impl DynamicCertificate {
    pub fn new_global() -> Self {
        DynamicCertificate { certificate: None }
    }
    pub fn new(cert: &[u8], key: &[u8]) -> Result<Self> {
        let cert = X509::from_pem(cert).map_err(|e| Error::Invalid {
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
        let key = PKey::private_key_from_pem(key).map_err(|e| Error::Invalid {
            message: e.to_string(),
        })?;
        Ok(DynamicCertificate {
            certificate: Some((cert, key)),
        })
    }
}

#[inline]
fn ssl_certificate(ssl: &mut pingora::tls::ssl::SslRef, cert: &X509, key: &PKey<Private>) {
    if let Err(e) = ext::ssl_use_certificate(ssl, cert) {
        error!(error = e.to_string(), "ssl use certificate fail");
    }
    if let Err(e) = ext::ssl_use_private_key(ssl, key) {
        error!(error = e.to_string(), "ssl use private key fail");
    }
}

#[async_trait]
impl pingora::listeners::TlsAccept for DynamicCertificate {
    async fn certificate_callback(&self, ssl: &mut pingora::tls::ssl::SslRef) {
        // TODO add more debug log
        debug!(ssl = format!("{ssl:?}"));
        if let Some((cert, key)) = &self.certificate {
            ssl_certificate(ssl, cert, key);
            return;
        }
        let Some(sni) = ssl.servername(NameType::HOST_NAME) else {
            error!(ssl = format!("{ssl:?}"), "get server name fail");
            return;
        };
        let Some(m) = DYNAMIC_CERT_MAP.get() else {
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
            ssl_certificate(ssl, cert, key);
        }
    }
}
