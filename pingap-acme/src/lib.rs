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

use snafu::Snafu;

/// Category name for ACME-related logging
pub static LOG_CATEGORY: &str = "acme";

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

/// Generates the token path for ACME challenges
///
/// # Arguments
///
/// * `key` - The challenge token key
///
/// # Returns
///
/// The formatted path string for the token
#[must_use]
pub fn get_token_path(key: &str) -> String {
    format!("pingap-acme-tokens/{key}")
}

mod lets_encrypt;

pub use lets_encrypt::{handle_lets_encrypt, new_lets_encrypt_service};
