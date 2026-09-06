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

//! A certificate in the form pingora's TLS backend consumes.
//!
//! [`TlsCertificate`](crate::TlsCertificate) and the self-signed cache keep
//! one of these per certificate so the handshake path does no parsing. What
//! is inside depends on the backend: OpenSSL installs `X509`/`PKey` objects
//! on the `SslRef` during the handshake, rustls hands a ready `CertifiedKey`
//! back from a `ResolvesServerCert`.

use super::{Error, Result};

const ERROR_X509: &str = "x509_from_pem";
const ERROR_PRIVATE_KEY: &str = "private_key_from_pem";

fn empty_certificate() -> Error {
    Error::Invalid {
        category: ERROR_X509.to_string(),
        message: "certificate is empty".to_string(),
    }
}

#[cfg(feature = "openssl")]
mod imp {
    use super::{
        ERROR_PRIVATE_KEY, ERROR_X509, Error, Result, empty_certificate,
    };
    use crate::LOG_TARGET;
    use pingora::tls::ext;
    use pingora::tls::pkey::{PKey, Private};
    use pingora::tls::ssl::SslRef;
    use pingora::tls::x509::X509;
    use tracing::error;

    /// Leaf certificate, private key and intermediate chain as OpenSSL objects.
    #[derive(Debug)]
    pub struct LoadedCertificate {
        cert: X509,
        key: PKey<Private>,
        chain: Vec<X509>,
    }

    impl LoadedCertificate {
        /// Builds from PEM blocks (the leaf first, then its chain) and a
        /// PEM-encoded private key.
        pub fn from_pem(cert_pems: &[Vec<u8>], key_pem: &[u8]) -> Result<Self> {
            let mut certs = Vec::with_capacity(cert_pems.len());
            for pem in cert_pems {
                certs.push(X509::from_pem(pem).map_err(|e| {
                    Error::Invalid {
                        category: ERROR_X509.to_string(),
                        message: e.to_string(),
                    }
                })?);
            }
            if certs.is_empty() {
                return Err(empty_certificate());
            }
            let key = PKey::private_key_from_pem(key_pem).map_err(|e| {
                Error::Invalid {
                    category: ERROR_PRIVATE_KEY.to_string(),
                    message: e.to_string(),
                }
            })?;
            let cert = certs.remove(0);
            Ok(Self {
                cert,
                key,
                chain: certs,
            })
        }

        /// Installs the certificate, key and chain on a handshake in progress.
        pub fn apply(&self, ssl: &mut SslRef) {
            if let Err(e) = ext::ssl_use_certificate(ssl, &self.cert) {
                error!(target: LOG_TARGET, error = %e, "ssl use certificate fail");
            }
            if let Err(e) = ext::ssl_use_private_key(ssl, &self.key) {
                error!(target: LOG_TARGET, error = %e, "ssl use private key fail");
            }
            for chain in self.chain.iter() {
                if let Err(e) = ext::ssl_add_chain_cert(ssl, chain) {
                    error!(target: LOG_TARGET, error = %e, "ssl add chain cert fail");
                }
            }
        }

        /// DER encoding of the leaf certificate.
        #[cfg(test)]
        pub fn leaf_der(&self) -> Result<Vec<u8>> {
            self.cert.to_der().map_err(|e| Error::X509 {
                category: "to_der".to_string(),
                message: e.to_string(),
            })
        }
    }
}

#[cfg(feature = "tls-rustls")]
mod imp {
    use super::{
        ERROR_PRIVATE_KEY, ERROR_X509, Error, Result, empty_certificate,
    };
    use pingora::tls::sign::CertifiedKey;
    use pingora::tls::{CertificateDer, CryptoProvider, PrivateKeyDer};
    use rustls_pki_types::pem::PemObject;
    use std::sync::Arc;

    /// Leaf, chain and signing key as one rustls `CertifiedKey`.
    #[derive(Debug)]
    pub struct LoadedCertificate {
        certified_key: Arc<CertifiedKey>,
    }

    /// The process-wide rustls crypto provider, installed on first use.
    ///
    /// pingap's ACME client and JWT plugin already link aws-lc-rs, so that is
    /// what gets installed; pingora's later attempt to install ring is then a
    /// no-op and the whole process shares one provider.
    fn crypto_provider() -> Arc<CryptoProvider> {
        if let Some(provider) = CryptoProvider::get_default() {
            return provider.clone();
        }
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        CryptoProvider::get_default().cloned().unwrap_or_else(|| {
            Arc::new(rustls::crypto::aws_lc_rs::default_provider())
        })
    }

    impl LoadedCertificate {
        /// Builds from PEM blocks (the leaf first, then its chain) and a
        /// PEM-encoded private key.
        pub fn from_pem(cert_pems: &[Vec<u8>], key_pem: &[u8]) -> Result<Self> {
            let mut certs = Vec::with_capacity(cert_pems.len());
            for pem in cert_pems {
                for cert in CertificateDer::pem_slice_iter(pem) {
                    certs.push(cert.map_err(|e| Error::Invalid {
                        category: ERROR_X509.to_string(),
                        message: e.to_string(),
                    })?);
                }
            }
            if certs.is_empty() {
                return Err(empty_certificate());
            }
            let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| {
                Error::Invalid {
                    category: ERROR_PRIVATE_KEY.to_string(),
                    message: e.to_string(),
                }
            })?;
            let certified_key =
                CertifiedKey::from_der(certs, key, &crypto_provider())
                    .map_err(|e| Error::Invalid {
                        category: ERROR_PRIVATE_KEY.to_string(),
                        message: e.to_string(),
                    })?;
            Ok(Self {
                certified_key: Arc::new(certified_key),
            })
        }

        /// The key pingora's certificate resolver hands to the handshake.
        pub fn certified_key(&self) -> Arc<CertifiedKey> {
            self.certified_key.clone()
        }

        /// DER encoding of the leaf certificate.
        #[cfg(test)]
        pub fn leaf_der(&self) -> Result<Vec<u8>> {
            self.certified_key
                .cert
                .first()
                .map(|cert| cert.to_vec())
                .ok_or_else(empty_certificate)
        }
    }
}

pub use imp::LoadedCertificate;
