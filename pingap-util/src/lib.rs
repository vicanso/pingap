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

use base64::{engine::general_purpose::STANDARD, Engine};
use path_absolutize::*;
use snafu::Snafu;
use std::path::Path;
use substring::Substring;

mod crypto;
mod format;
mod ip;

pub use crypto::{aes_decrypt, aes_encrypt};
pub use format::*;
pub use ip::IpRules;

/// Error enum for various error types in the utility module
#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Encrypt error {message}"))]
    Aes { message: String },
    #[snafu(display("Base64 decode {source}"))]
    Base64Decode { source: base64::DecodeError },
    #[snafu(display("Invalid {message}"))]
    Invalid { message: String },
    #[snafu(display("Io error {source}, {file}"))]
    Io {
        source: std::io::Error,
        file: String,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Gets the package version.
pub fn get_pkg_version() -> &'static str {
    VERSION
}

/// Get the rustc version.
pub fn get_rustc_version() -> String {
    rustc_version_runtime::version().to_string()
}

/// Resolves a path string to its absolute form.
/// If the path starts with '~', it will be expanded to the user's home directory.
/// Returns an empty string if the input path is empty.
///
/// # Arguments
/// * `path` - The path string to resolve
///
/// # Returns
/// The absolute path as a String
pub fn resolve_path(path: &str) -> String {
    if path.is_empty() {
        return "".to_string();
    }
    let mut p = path.to_string();
    if p.starts_with('~') {
        if let Some(home) = dirs::home_dir() {
            p = home.to_string_lossy().to_string() + p.substring(1, p.len());
        };
    }
    if let Ok(p) = Path::new(&p).absolutize() {
        p.to_string_lossy().to_string()
    } else {
        p
    }
}

/// Checks if a string represents a PEM-formatted certificate/key
/// by looking for the "-----" prefix.
///
/// # Arguments
/// * `value` - The string to check
///
/// # Returns
/// true if the string appears to be PEM-formatted, false otherwise
pub fn is_pem(value: &str) -> bool {
    value.starts_with("-----")
}

/// Converts various certificate/key formats into bytes.
/// Supports PEM format, file paths, and base64-encoded data.
///
/// # Arguments
/// * `value` - The certificate/key data as a string
///
/// # Returns
/// Result containing the certificate/key bytes or an error
pub fn convert_pem(value: &str) -> Result<Vec<Vec<u8>>> {
    let buf = if is_pem(value) {
        value.as_bytes().to_vec()
    } else if Path::new(&resolve_path(value)).is_file() {
        std::fs::read(resolve_path(value)).map_err(|e| Error::Io {
            source: e,
            file: value.to_string(),
        })?
    } else {
        base64_decode(value).map_err(|e| Error::Base64Decode { source: e })?
    };
    let pems = pem::parse_many(&buf).map_err(|e| Error::Invalid {
        message: e.to_string(),
    })?;
    if pems.is_empty() {
        return Err(Error::Invalid {
            message: "pem data is empty".to_string(),
        });
    }
    let mut data = vec![];
    for pem in pems {
        data.push(pem::encode(&pem).as_bytes().to_vec());
    }

    Ok(data)
}

/// Converts an optional certificate string into bytes.
/// Handles PEM format, file paths, and base64-encoded data.
///
/// # Arguments
/// * `value` - Optional string containing the certificate data
///
/// # Returns
/// Optional vector of bytes containing the certificate data
pub fn convert_certificate_bytes(value: Option<&str>) -> Option<Vec<Vec<u8>>> {
    if let Some(value) = value {
        if value.is_empty() {
            return None;
        }
        return convert_pem(value).ok();
    }
    None
}

pub fn base64_encode<T: AsRef<[u8]>>(data: T) -> String {
    STANDARD.encode(data)
}

pub fn base64_decode<T: AsRef<[u8]>>(
    data: T,
) -> Result<Vec<u8>, base64::DecodeError> {
    STANDARD.decode(data)
}

/// Removes empty tables/sections from a TOML string
///
/// # Arguments
/// * `value` - TOML string to process
///
/// # Returns
/// Result containing the processed TOML string with empty sections removed
pub fn toml_omit_empty_value(value: &str) -> Result<String, Error> {
    let mut data =
        toml::from_str::<toml::Table>(value).map_err(|e| Error::Invalid {
            message: e.to_string(),
        })?;
    let mut omit_keys = vec![];
    for (key, value) in data.iter() {
        let Some(table) = value.as_table() else {
            omit_keys.push(key.to_string());
            continue;
        };
        if table.keys().len() == 0 {
            omit_keys.push(key.to_string());
            continue;
        }
    }
    for key in omit_keys {
        data.remove(&key);
    }
    toml::to_string_pretty(&data).map_err(|e| Error::Invalid {
        message: e.to_string(),
    })
}

/// Joins two path segments with a forward slash
/// Handles cases where segments already include slashes
///
/// # Arguments
/// * `value1` - First path segment
/// * `value2` - Second path segment
///
/// # Returns
/// Joined path as a String
pub fn path_join(value1: &str, value2: &str) -> String {
    let end_slash = value1.ends_with("/");
    let start_slash = value2.starts_with("/");
    if end_slash && start_slash {
        format!("{value1}{}", value2.substring(1, value2.len()))
    } else if end_slash || start_slash {
        format!("{value1}{value2}")
    } else {
        format!("{value1}/{value2}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base64_encode;
    use pretty_assertions::assert_eq;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_get_pkg_info() {
        assert_eq!(false, get_pkg_version().is_empty());
    }

    #[test]
    fn test_resolve_path() {
        assert_eq!(
            dirs::home_dir().unwrap().to_string_lossy(),
            resolve_path("~/")
        );
    }
    #[test]
    fn test_get_rustc_version() {
        assert_eq!(false, get_rustc_version().is_empty());
    }

    #[test]
    fn test_path_join() {
        assert_eq!("a/b", path_join("a", "b"));
        assert_eq!("a/b", path_join("a/", "b"));
        assert_eq!("a/b", path_join("a", "/b"));
        assert_eq!("a/b", path_join("a/", "/b"));
    }

    #[test]
    fn test_toml_omit_empty_value() {
        let data = r###"
        [upstreams.charts]
        addrs = ["127.0.0.1:5000", "127.0.0.1:5001 10"]
        [locations]
        "###;
        let result = toml_omit_empty_value(data).unwrap();
        assert_eq!(
            result,
            r###"[upstreams.charts]
addrs = [
    "127.0.0.1:5000",
    "127.0.0.1:5001 10",
]
"###
        );
    }

    #[test]
    fn test_convert_certificate_bytes() {
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
        let result = convert_certificate_bytes(Some(pem));
        assert_eq!(true, result.is_some());

        let mut tmp = NamedTempFile::new().unwrap();

        tmp.write_all(pem.as_bytes()).unwrap();

        let result = convert_certificate_bytes(
            Some(tmp.path().to_string_lossy()).as_deref(),
        );
        assert_eq!(true, result.is_some());

        let data = base64_encode(pem.as_bytes());
        assert_eq!(1924, data.len());
        let result = convert_certificate_bytes(Some(data).as_deref());
        assert_eq!(true, result.is_some());
    }
}
