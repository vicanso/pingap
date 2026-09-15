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

use async_trait::async_trait;
use pingap_certificate::rcgen;
use snafu::Snafu;

/// Category name for ACME-related logging
pub static LOG_TARGET: &str = "pingap::acme";

/// Errors that can occur during ACME operations
#[derive(Debug, Snafu)]
pub enum Error {
    /// Error from the instant-acme library
    #[snafu(display("ACME instant error: {source}, category: {category}"))]
    Instant {
        category: String,
        source: instant_acme::Error,
    },

    /// Error from certificate generation
    #[snafu(display(
        "Certificate generation error: {source}, category: {category}"
    ))]
    Rcgen {
        category: String,
        source: rcgen::Error,
    },

    /// Challenge not found during verification
    #[snafu(display("ACME challenge not found: {message}"))]
    NotFound { message: String },

    /// General Let's Encrypt operation failure
    #[snafu(display(
        "Let's Encrypt operation failed: {message}, category: {category}"
    ))]
    Fail { category: String, message: String },
}

/// Convenience type alias for Results with our Error type
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// `$ENV:NAME` is read from the environment; anything else (including an
/// unset variable's name) is returned as it is.
fn get_value_from_env(value: &str) -> String {
    value
        .strip_prefix("$ENV:")
        .and_then(|name| std::env::var(name).ok())
        .unwrap_or_else(|| value.to_string())
}

/// Acme DNS task
#[async_trait]
pub trait AcmeDnsTask: Sync + Send {
    /// Add a DNS TXT record
    async fn add_txt_record(&self, domain: &str, value: &str) -> Result<()>;
    /// Task done, it will clean up the added dns txt record
    async fn done(&self) -> Result<()>;
}

mod dns_ali;
mod dns_cf;
mod dns_huawei;
mod dns_manual;
mod dns_tencent;
mod lets_encrypt;

pub use lets_encrypt::{handle_lets_encrypt, new_lets_encrypt_service};

#[cfg(test)]
mod tests {
    use super::get_value_from_env;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_get_value_from_env() {
        assert_eq!("", get_value_from_env(""));
        assert_eq!("plain", get_value_from_env("plain"));
        assert_eq!(
            std::env::var("PATH").unwrap_or_default(),
            get_value_from_env("$ENV:PATH")
        );
        assert_eq!(
            "$ENV:PINGAP_NOT_SET_FOR_SURE",
            get_value_from_env("$ENV:PINGAP_NOT_SET_FOR_SURE")
        );
    }
}
