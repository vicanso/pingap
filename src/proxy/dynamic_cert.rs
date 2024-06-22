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
use pingora::tls::ext;
use pingora::tls::pkey::{PKey, Private};
use pingora::tls::x509::X509;
use snafu::Snafu;
use tracing::debug;

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
        let key = PKey::private_key_from_pem(key).map_err(|e| Error::Invalid {
            message: e.to_string(),
        })?;
        Ok(Box::new(DynamicCert { cert, key }))
    }
}

#[async_trait]
impl pingora::listeners::TlsAccept for DynamicCert {
    async fn certificate_callback(&self, ssl: &mut pingora::tls::ssl::SslRef) {
        // TODO add more debug log
        ext::ssl_use_certificate(ssl, &self.cert).unwrap();
        ext::ssl_use_private_key(ssl, &self.key).unwrap();
        debug!(ssl = format!("{ssl:?}"));
    }
}
