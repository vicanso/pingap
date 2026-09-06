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

use super::parse_leaf_chain_certificates;
use std::sync::LazyLock;

// Let's Encrypt chain certificates
const E5: &[u8] = include_bytes!("../assets/e5.pem");
const E6: &[u8] = include_bytes!("../assets/e6.pem");
const R10: &[u8] = include_bytes!("../assets/r10.pem");
const R11: &[u8] = include_bytes!("../assets/r11.pem");

/// Expiration buffer day for chain certificate
const EXPIRATION_BUFFER_DAYS: u64 = 30;
/// Seconds in a day
const SECONDS_PER_DAY: u64 = 24 * 3600;

/// Parses a PEM-encoded certificate and validates its expiration date
///
/// Returns None if:
/// - The certificate cannot be parsed
/// - The certificate will expire within EXPIRATION_BUFFER_DAYS
/// - The PEM data is invalid UTF-8
fn parse_chain_certificate(data: &[u8]) -> Option<Vec<u8>> {
    let expiration_threshold =
        pingap_core::now_sec() + EXPIRATION_BUFFER_DAYS * SECONDS_PER_DAY;

    String::from_utf8(data.to_vec())
        .ok()
        .and_then(|pem_str| parse_leaf_chain_certificates(&pem_str, "").ok())
        .filter(|(cert, _)| cert.not_after > expiration_threshold as i64)
        .map(|_| data.to_vec())
}

// Initialize static certificates
static E5_CERTIFICATE: LazyLock<Option<Vec<u8>>> =
    LazyLock::new(|| parse_chain_certificate(E5));
static E6_CERTIFICATE: LazyLock<Option<Vec<u8>>> =
    LazyLock::new(|| parse_chain_certificate(E6));
static R10_CERTIFICATE: LazyLock<Option<Vec<u8>>> =
    LazyLock::new(|| parse_chain_certificate(R10));
static R11_CERTIFICATE: LazyLock<Option<Vec<u8>>> =
    LazyLock::new(|| parse_chain_certificate(R11));

/// Returns a Let's Encrypt chain certificate based on the provided certificate name
///
/// # Arguments
///
/// * `cn` - Certificate name ("E5", "E6", "R10", or "R11")
///
/// # Returns
///
/// * `Some(X509)` if a valid certificate is found for the given name
/// * `None` if the certificate name is invalid or the certificate is expired
pub fn get_lets_encrypt_chain_certificate(cn: &str) -> Option<Vec<u8>> {
    match cn.to_uppercase().as_str() {
        "E5" => E5_CERTIFICATE.clone(),
        "E6" => E6_CERTIFICATE.clone(),
        "R10" => R10_CERTIFICATE.clone(),
        "R11" => R11_CERTIFICATE.clone(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::get_lets_encrypt_chain_certificate;
    use pretty_assertions::assert_eq;

    /// Subject and not-after of a PEM certificate, read with x509-parser so
    /// the check is the same on every TLS backend.
    fn describe(pem: &[u8]) -> (String, i64) {
        let (_, block) = x509_parser::pem::parse_x509_pem(pem).unwrap();
        let cert = block.parse_x509().unwrap();
        (
            cert.subject().to_string(),
            cert.validity().not_after.timestamp(),
        )
    }

    #[test]
    fn test_get_lets_encrypt_chain_certificate() {
        // All four intermediates expire on Mar 12 23:59:59 2027 GMT.
        let not_after = 1804895999;
        for name in ["E5", "E6", "R10", "R11"] {
            let pem = get_lets_encrypt_chain_certificate(name).unwrap();
            assert_eq!(
                (format!("C=US, O=Let's Encrypt, CN={name}"), not_after),
                describe(&pem),
                "{name}"
            );
        }
        assert_eq!(true, get_lets_encrypt_chain_certificate("A").is_none());
    }
}
