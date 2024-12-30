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

use super::Certificate;
use crate::util;
use once_cell::sync::Lazy;
use pingora::tls::x509::X509;

// Certificate file paths
const E5: &[u8] = include_bytes!("../assets/e5.pem");
const E6: &[u8] = include_bytes!("../assets/e6.pem");
const R10: &[u8] = include_bytes!("../assets/r10.pem");
const R11: &[u8] = include_bytes!("../assets/r11.pem");

/// Number of days to check for certificate expiration
const EXPIRATION_BUFFER_DAYS: u64 = 30;
/// Seconds in a day
const SECONDS_PER_DAY: u64 = 24 * 3600;

/// Parses a PEM-encoded certificate and validates its expiration date
///
/// Returns None if:
/// - The certificate cannot be parsed
/// - The certificate will expire within EXPIRATION_BUFFER_DAYS
/// - The PEM data is invalid UTF-8
fn parse_chain_certificate(data: &[u8]) -> Option<X509> {
    let expiration_threshold =
        util::now().as_secs() + EXPIRATION_BUFFER_DAYS * SECONDS_PER_DAY;

    String::from_utf8(data.to_vec())
        .ok()
        .and_then(|pem_str| Certificate::new(pem_str, String::new()).ok())
        .filter(|cert| cert.not_after > expiration_threshold as i64)
        .and_then(|_| X509::from_pem(data).ok())
}

// Initialize static certificates
static E5_CERTIFICATE: Lazy<Option<X509>> =
    Lazy::new(|| parse_chain_certificate(E5));
static E6_CERTIFICATE: Lazy<Option<X509>> =
    Lazy::new(|| parse_chain_certificate(E6));
static R10_CERTIFICATE: Lazy<Option<X509>> =
    Lazy::new(|| parse_chain_certificate(R10));
static R11_CERTIFICATE: Lazy<Option<X509>> =
    Lazy::new(|| parse_chain_certificate(R11));

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
pub fn get_lets_encrypt_chain_certificate(cn: &str) -> Option<X509> {
    match cn {
        "E5" => E5_CERTIFICATE.clone(),
        "E6" => E6_CERTIFICATE.clone(),
        "R10" => R10_CERTIFICATE.clone(),
        "R11" => R11_CERTIFICATE.clone(),
        _ => None,
    }
}
