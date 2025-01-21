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

#[cfg(test)]
mod tests {
    use crate::certificate::Certificate;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_cert() {
        // spellchecker:off
        let pem = r###"-----BEGIN CERTIFICATE-----
MIID/TCCAmWgAwIBAgIQJUGCkB1VAYha6fGExkx0KTANBgkqhkiG9w0BAQsFADBV
MR4wHAYDVQQKExVta2NlcnQgZGV2ZWxvcG1lbnQgQ0ExFTATBgNVBAsMDHZpY2Fu
c29AdHJlZTEcMBoGA1UEAwwTbWtjZXJ0IHZpY2Fuc29AdHJlZTAeFw0yNDA3MDYw
MjIzMzZaFw0yNjEwMDYwMjIzMzZaMEAxJzAlBgNVBAoTHm1rY2VydCBkZXZlbG9w
bWVudCBjZXJ0aWZpY2F0ZTEVMBMGA1UECwwMdmljYW5zb0B0cmVlMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv5dbylSPQNARrpT/Rn7qZf6JmH3cueMp
YdOpctuPYeefT0Jdgp67bg17fU5pfyR2BWYdwyvHCNmKqLdYPx/J69hwTiVFMOcw
lVQJjbzSy8r5r2cSBMMsRaAZopRDnPy7Ls7Ji+AIT4vshUgL55eR7ACuIJpdtUYm
TzMx9PTA0BUDkit6z7bTMaEbjDmciIBDfepV4goHmvyBJoYMIjnAwnTFRGRs/QJN
d2ikFq999fRINzTDbRDP1K0Kk6+zYoFAiCMs9lEDymu3RmiWXBXpINR/Sv8CXtz2
9RTVwTkjyiMOPY99qBfaZTiy+VCjcwTGKPyus1axRMff4xjgOBewOwIDAQABo14w
XDAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwHwYDVR0jBBgw
FoAUhU5Igu3uLUabIqUhUpVXjk1JVtkwFAYDVR0RBA0wC4IJcGluZ2FwLmlvMA0G
CSqGSIb3DQEBCwUAA4IBgQDBimRKrqnEG65imKriM2QRCEfdB6F/eP9HYvPswuAP
tvQ6m19/74qbtkd6vjnf6RhMbj9XbCcAJIhRdnXmS0vsBrLDsm2q98zpg6D04F2E
L++xTiKU6F5KtejXcTHHe23ZpmD2XilwcVDeGFu5BEiFoRH9dmqefGZn3NIwnIeD
Yi31/cL7BoBjdWku5Qm2nCSWqy12ywbZtQCbgbzb8Me5XZajeGWKb8r6D0Nb+9I9
OG7dha1L3kxerI5VzVKSiAdGU0C+WcuxfsKAP8ajb1TLOlBaVyilfqmiF457yo/2
PmTYzMc80+cQWf7loJPskyWvQyfmAnSUX0DI56avXH8LlQ57QebllOtKgMiCo7cr
CCB2C+8hgRNG9ZmW1KU8rxkzoddHmSB8d6+vFqOajxGdyOV+aX00k3w6FgtHOoKD
Ztdj1N0eTfn02pibVcXXfwESPUzcjERaMAGg1hoH1F4Gxg0mqmbySAuVRqNLnXp5
CRVQZGgOQL6WDg3tUUDXYOs=
-----END CERTIFICATE-----"###;
        // spellchecker:on
        let cert = Certificate::new(pem, "").unwrap();

        assert_eq!(
            "O=mkcert development CA, OU=vicanso@tree, CN=mkcert vicanso@tree",
            cert.issuer
        );
        assert_eq!(1720232616, cert.not_before);
        assert_eq!(1791253416, cert.not_after);
        assert_eq!("mkcert vicanso@tree", cert.get_issuer_common_name());
    }
}
