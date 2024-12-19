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

pub fn get_lets_encrypt_chain_certificate(cn: &str) -> Option<X509> {
    match cn {
        "E5" => E5_CERTIFICATE.clone(),
        "E6" => E6_CERTIFICATE.clone(),
        "R10" => R10_CERTIFICATE.clone(),
        "R11" => R11_CERTIFICATE.clone(),
        _ => None,
    }
}
