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

use async_trait::async_trait;
use once_cell::sync::OnceCell;
use pingora::tls::ext;
use pingora::tls::pkey::{PKey, Private};
use pingora::tls::ssl::NameType;
use pingora::tls::x509::X509;
use snafu::Snafu;
use std::collections::HashMap;
use tracing::{debug, error, info};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Invalid {message}"))]
    Invalid { message: String },
}
type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Clone)]
pub struct DynamicCert {
    cert: X509,
    key: PKey<Private>,
}

impl DynamicCert {
    pub fn new(cert: &[u8], key: &[u8]) -> Result<Box<Self>> {
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
        Ok(Box::new(DynamicCert { cert, key }))
    }
}
type DynamicCerts = HashMap<String, DynamicCert>;
static DYNAMIC_CERT_MAP: OnceCell<DynamicCerts> = OnceCell::new();

pub struct GlobalDynamicCert {}

pub fn try_init_certificates(certs: Vec<(Vec<u8>, Vec<u8>)>) -> Result<()> {
    // TODO 生成证书失败发送webhook
    DYNAMIC_CERT_MAP.get_or_try_init(|| {
        let mut dynamic_certs = HashMap::new();
        for (cert, key) in certs.iter() {
            let cert = X509::from_pem(cert).map_err(|e| Error::Invalid {
                message: e.to_string(),
            })?;
            let names: Vec<String> = cert
                .subject_alt_names()
                .iter()
                .map(|name| format!("{name:?}"))
                .collect();

            let key = PKey::private_key_from_pem(key).map_err(|e| Error::Invalid {
                message: e.to_string(),
            })?;
            let d = DynamicCert { cert, key };
            for name in names.iter() {
                dynamic_certs.insert(name.to_string(), d.clone());
            }
            info!(
                subject_alt_names = names.join(","),
                "init certificates success"
            );
        }
        Ok(dynamic_certs)
    })?;
    Ok(())
}

#[async_trait]
impl pingora::listeners::TlsAccept for DynamicCert {
    async fn certificate_callback(&self, ssl: &mut pingora::tls::ssl::SslRef) {
        if let Some(sni) = ssl.servername(NameType::HOST_NAME) {
            // TODO get certificate by sni
            info!(sni, "certificate callback");
        }
        // TODO add more debug log
        ext::ssl_use_certificate(ssl, &self.cert).unwrap();
        ext::ssl_use_private_key(ssl, &self.key).unwrap();
        debug!(ssl = format!("{ssl:?}"));
    }
}

#[async_trait]
impl pingora::listeners::TlsAccept for GlobalDynamicCert {
    async fn certificate_callback(&self, ssl: &mut pingora::tls::ssl::SslRef) {
        let Some(sni) = ssl.servername(NameType::HOST_NAME) else {
            error!(ssl = format!("{ssl:?}"), "get server name fail");
            return;
        };
        let Some(m) = DYNAMIC_CERT_MAP.get() else {
            error!(ssl = format!("{ssl:?}"), "get dynamic cert map fail");
            return;
        };
        let Some(d) = m.get(sni) else {
            error!(sni, "get dynamic cert fail");
            return;
        };
        // TODO 通配符处理
        ext::ssl_use_certificate(ssl, &d.cert).unwrap();
        ext::ssl_use_private_key(ssl, &d.key).unwrap();
        debug!(ssl = format!("{ssl:?}"));
    }
}
