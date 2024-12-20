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

use super::chain::get_lets_encrypt_chain_certificate;
use super::self_signed::{
    add_self_signed_certificate, get_self_signed_certificate,
    SelfSignedCertificate,
};
use super::{Certificate, Error, Result};
use crate::config::CertificateConf;
use crate::util;
use pingora::tls::pkey::{PKey, Private};
use pingora::tls::x509::X509;
use std::sync::Arc;
use tracing::info;

#[derive(Debug, Clone, Default)]
pub struct TlsCertificate {
    pub name: Option<String>,
    pub chain_certificate: Option<X509>,
    pub certificate: Option<(X509, PKey<Private>)>,
    pub domains: Vec<String>,
    pub info: Option<Certificate>,
    pub hash_key: String,
    pub is_ca: bool,
}

impl TryFrom<&CertificateConf> for TlsCertificate {
    type Error = Error;
    fn try_from(value: &CertificateConf) -> Result<Self, Self::Error> {
        // parse certificate
        let info = Certificate::new(
            value.tls_cert.clone().unwrap_or_default(),
            value.tls_key.clone().unwrap_or_default(),
        )
        .map_err(|e| Error::Invalid {
            message: e.to_string(),
            category: "certificate".to_string(),
        })?;
        let category = if value.acme.is_some() {
            LETS_ENCRYPT
        } else {
            ""
        };

        let hash_key = value.hash_key();

        let tls_chain = util::convert_certificate_bytes(&value.tls_chain);
        let chain_certificate = if let Some(value) = &tls_chain {
            // ignore chain error
            X509::from_pem(value).ok()
        } else if category == LETS_ENCRYPT {
            get_lets_encrypt_chain_certificate(
                info.get_issuer_common_name().as_str(),
            )
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
        Ok(TlsCertificate {
            hash_key,
            chain_certificate,
            domains: info.domains.clone(),
            certificate: Some((cert, key)),
            info: Some(info),
            is_ca: value.is_ca.unwrap_or_default(),
            ..Default::default()
        })
    }
}

static LETS_ENCRYPT: &str = "lets_encrypt";

fn new_certificate_with_ca(
    root_ca: &TlsCertificate,
    cn: &str,
) -> Result<(X509, PKey<Private>, i64)> {
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
    let not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    let two_years_from_now =
        time::OffsetDateTime::now_utc() + time::Duration::days(365 * 2);
    let not_after = ca_params.not_after.min(two_years_from_now);
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

    Ok((cert, key, not_after.unix_timestamp()))
}

impl TlsCertificate {
    /// Get self signed certificate
    pub fn get_self_signed_certtificate(
        &self,
        server_name: &str,
    ) -> Result<Arc<SelfSignedCertificate>> {
        let arr: Vec<&str> = server_name.split('.').collect();
        let cn = if arr.len() > 2 {
            format!("*.{}", arr[1..].join("."))
        } else {
            server_name.to_string()
        };
        let k = format!("{:?}:{}", self.name, cn);
        if let Some(v) = get_self_signed_certificate(&k) {
            return Ok(v);
        }
        let (cert, key, not_after) = new_certificate_with_ca(self, &cn)?;
        info!(common_name = cn, "new self sigined cert",);
        Ok(add_self_signed_certificate(&k, cert, key, not_after))
    }
}
