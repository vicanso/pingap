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

use crate::util;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use snafu::Snafu;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Instant error, {source}"))]
    Instant { source: instant_acme::Error },
    #[snafu(display("Rcgen error, {source}"))]
    Rcgen { source: rcgen::Error },
    #[snafu(display("Challenge not found error, {message}"))]
    NotFound { message: String },
    #[snafu(display("Lets encrypt fail, {message}"))]
    Fail { message: String },
    #[snafu(display("Io error, {source}"))]
    Io { source: std::io::Error },
    #[snafu(display("Serde json error, {source}"))]
    SerdeJson { source: serde_json::Error },
    #[snafu(display("X509 error, {message}"))]
    X509 { message: String },
}

type Result<T, E = Error> = std::result::Result<T, E>;

pub fn parse_x509_validity(data: &[u8]) -> Result<x509_parser::certificate::Validity> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(data).map_err(|e| Error::X509 {
        message: e.to_string(),
    })?;
    let x509 = pem.parse_x509().map_err(|e| Error::X509 {
        message: e.to_string(),
    })?;

    Ok(x509.validity().to_owned())
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct Cert {
    pub domains: Vec<String>,
    pub not_after: i64,
    pub not_before: i64,
    pub pem: String,
    pub key: String,
}
impl Cert {
    /// Validate the cert is within the expiration date.
    pub fn valid(&self) -> bool {
        let ts = util::now().as_secs() as i64;
        if self.not_before > ts {
            return false;
        }
        self.not_after - ts > 2 * 24 * 3600
    }
    /// Get the cert pem data.
    pub fn get_cert(&self) -> Vec<u8> {
        STANDARD.decode(&self.pem).unwrap_or_default()
    }
    /// Get the cert key data.
    pub fn get_key(&self) -> Vec<u8> {
        STANDARD.decode(&self.key).unwrap_or_default()
    }
}

mod lets_encrypt;
mod validity_checker;

pub use lets_encrypt::{get_lets_encrypt_cert, handle_lets_encrypt, new_lets_encrypt_service};
pub use validity_checker::new_tls_validity_service;

#[cfg(test)]
mod tests {
    use super::Cert;
    use pretty_assertions::assert_eq;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_cert() {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let mut cert = Cert {
            not_before: ts - 10,
            not_after: ts + 3 * 24 * 3600,
            ..Default::default()
        };
        assert_eq!(true, cert.valid());

        cert.not_after = ts;
        assert_eq!(false, cert.valid());
    }
}
