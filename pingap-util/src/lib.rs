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

use base64::{Engine, engine::general_purpose::STANDARD};
use path_absolutize::*;
use snafu::Snafu;
use std::borrow::Cow;
use std::path::Path;
use std::sync::{LazyLock, OnceLock};

mod crypto;
mod format;
mod ip;

pub use crypto::{aes_decrypt, aes_encrypt, seal, unseal};
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

static PKG_VERSION: OnceLock<&'static str> = OnceLock::new();

/// Sets the binary package version so all workspace crates report the same version.
pub fn set_pkg_version(version: &'static str) {
    let _ = PKG_VERSION.set(version);
}

/// Gets the package version.
pub fn get_pkg_version() -> &'static str {
    PKG_VERSION.get().copied().unwrap_or(VERSION)
}

static RUSTC_VERSION: LazyLock<String> =
    LazyLock::new(|| rustc_version_runtime::version().to_string());

/// Get the rustc version the binary was built with.
pub fn get_rustc_version() -> &'static str {
    RUSTC_VERSION.as_str()
}

/// The home directory of the user this process runs as: `HOME`, or what
/// the system has for the user where that is not set or set to nothing.
/// A home that is an empty path is none, and not the root of the file
/// system that a path put after it would start at.
///
/// The standard library's own, which is no longer deprecated. It used to
/// come from the `dirs` crate, whose other directories were not used and
/// which brought a dependency under another license with it.
pub fn home_dir() -> Option<std::path::PathBuf> {
    std::env::home_dir().filter(|home| !home.as_os_str().is_empty())
}

/// Resolves a path string to its absolute form.
/// A leading `~` or `~/` is expanded to the user's home directory; `~name`
/// is somebody else's home and is left alone.
/// Returns an empty string if the input path is empty.
///
/// # Arguments
/// * `path` - The path string to resolve
///
/// # Returns
/// The absolute path as a String
pub fn resolve_path(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }
    let mut p = Cow::Borrowed(path);
    if (path == "~" || path.starts_with("~/"))
        && let Some(home) = home_dir()
    {
        let mut expanded = home.to_string_lossy().into_owned();
        expanded.push_str(&path[1..]);
        p = Cow::Owned(expanded);
    }
    match Path::new(p.as_ref()).absolutize() {
        Ok(absolute) => absolute.to_string_lossy().into_owned(),
        Err(_) => p.into_owned(),
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
    let value = value.trim();
    if let (Some(begin_idx), Some(end_idx)) =
        (value.find("-----BEGIN "), value.find("-----END "))
    {
        begin_idx < end_idx && value.ends_with("-----")
    } else {
        false
    }
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
    // PEM text is parsed in place; a file or base64 value is read into
    // `loaded` first.
    let loaded: Vec<u8>;
    let buf: &[u8] = if is_pem(value) {
        value.as_bytes()
    } else {
        let path = resolve_path(value);
        loaded = if Path::new(&path).is_file() {
            std::fs::read(&path).map_err(|e| Error::Io {
                source: e,
                file: value.to_string(),
            })?
        } else {
            base64_decode(value)
                .map_err(|e| Error::Base64Decode { source: e })?
        };
        &loaded
    };
    let pems = pem::parse_many(buf).map_err(|e| Error::Invalid {
        message: e.to_string(),
    })?;
    if pems.is_empty() {
        return Err(Error::Invalid {
            message: "pem data is empty".to_string(),
        });
    }
    Ok(pems
        .iter()
        .map(|pem| pem::encode(pem).into_bytes())
        .collect())
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
    let value = value?;
    if value.is_empty() {
        return None;
    }
    convert_pem(value).ok()
}

pub fn base64_encode<T: AsRef<[u8]>>(data: T) -> String {
    STANDARD.encode(data)
}

pub fn base64_decode<T: AsRef<[u8]>>(
    data: T,
) -> Result<Vec<u8>, base64::DecodeError> {
    STANDARD.decode(data)
}

/// Removes empty tables/sections from a TOML string. Only non-empty
/// tables survive: a top-level scalar goes too, since a pingap config has
/// nothing but tables at the top.
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
    data.retain(|_, value| {
        value.as_table().is_some_and(|table| !table.is_empty())
    });
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
    let end_slash = value1.ends_with('/');
    // Both sides bring a slash: keep the first one only.
    let value2 = match value2.strip_prefix('/') {
        Some(rest) if end_slash => rest,
        _ => value2,
    };
    let mut joined = String::with_capacity(value1.len() + value2.len() + 1);
    joined.push_str(value1);
    if !end_slash && !value2.starts_with('/') {
        joined.push('/');
    }
    joined.push_str(value2);
    joined
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
        let home = home_dir().unwrap().to_string_lossy().to_string();
        assert_eq!(home, resolve_path("~/"));
        assert_eq!(home, resolve_path("~"));
        assert_eq!(format!("{home}/opt/pingap"), resolve_path("~/opt/pingap"));
        // Somebody else's home is not this user's home with a suffix.
        assert_eq!(true, resolve_path("~other/x").ends_with("/~other/x"));
        assert_eq!("", resolve_path(""));
        assert_eq!("/opt/pingap", resolve_path("/opt/pingap/../pingap"));
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
        assert_eq!("/foo/bar", path_join("/foo/", "/bar"));
        assert_eq!("a/", path_join("a", "/"));
        assert_eq!("/b", path_join("", "b"));
        assert_eq!("a/", path_join("a/", ""));
        assert_eq!("/", path_join("", ""));
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

        // Top-level scalars and empty tables go, nested empty tables stay
        // inside their non-empty parent.
        let result =
            toml_omit_empty_value("name = \"x\"\n[a]\n[b]\nc = 1\n[b.d]\n")
                .unwrap();
        assert_eq!("[b]\nc = 1\n\n[b.d]\n", result);

        assert_eq!(true, toml_omit_empty_value("not = [toml").is_err());
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

    fn tiny_pem(label: &str, body: &str) -> String {
        format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n")
    }

    #[test]
    fn test_is_pem() {
        let pem = tiny_pem("CERTIFICATE", "YQ==");
        assert_eq!(true, is_pem(&pem));
        assert_eq!(true, is_pem(&format!("\n{pem}\n")));
        assert_eq!(false, is_pem(""));
        assert_eq!(false, is_pem("-----BEGIN CERTIFICATE-----"));
        assert_eq!(
            false,
            is_pem("-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----")
        );
        assert_eq!(false, is_pem("/etc/ssl/cert.pem"));
    }

    #[test]
    fn test_convert_pem_text_file_base64_and_errors() {
        let first = tiny_pem("CERTIFICATE", "YQ==");
        let second = tiny_pem("PRIVATE KEY", "Yg==");
        let both = format!("{first}{second}");
        let blocks = match convert_pem(&both) {
            Ok(blocks) => blocks,
            Err(err) => panic!("two pem blocks: {err}"),
        };
        assert_eq!(2, blocks.len());
        for block in &blocks {
            let text = String::from_utf8_lossy(block);
            assert_eq!(true, text.contains("-----BEGIN "));
            assert_eq!(true, text.contains("-----END "));
        }

        let padded = format!("\n{first}\n");
        match convert_pem(&padded) {
            Ok(blocks) => assert_eq!(1, blocks.len()),
            Err(err) => panic!("pem with surrounding whitespace: {err}"),
        }

        let encoded = base64_encode(first.as_bytes());
        match convert_pem(&encoded) {
            Ok(blocks) => assert_eq!(1, blocks.len()),
            Err(err) => panic!("base64 pem: {err}"),
        }
        match base64_decode(base64_encode(b"\xff\xfe")) {
            Ok(bytes) => assert_eq!(vec![0xff, 0xfe], bytes),
            Err(err) => panic!("base64 roundtrip: {err}"),
        }
        assert_eq!(true, base64_decode("!!!!").is_err());
        assert_eq!("", base64_encode(b""));

        let mut tmp = match NamedTempFile::new() {
            Ok(file) => file,
            Err(err) => panic!("temp file: {err}"),
        };
        if let Err(err) = tmp.write_all(first.as_bytes()) {
            panic!("write temp pem: {err}");
        }
        let path = tmp.path().to_string_lossy().into_owned();
        match convert_pem(&path) {
            Ok(blocks) => assert_eq!(1, blocks.len()),
            Err(err) => panic!("pem file: {err}"),
        }

        let mut empty = match NamedTempFile::new() {
            Ok(file) => file,
            Err(err) => panic!("temp file: {err}"),
        };
        let empty_path = empty.path().to_string_lossy().into_owned();
        match convert_pem(&empty_path) {
            Err(Error::Invalid { message }) => {
                assert_eq!("pem data is empty", message);
            },
            Ok(blocks) => panic!("empty file parsed: {blocks:?}"),
            Err(err) => panic!("expected invalid pem, got {err}"),
        }
        if let Err(err) = empty.write_all(b"not a pem") {
            panic!("write temp: {err}");
        }
        match convert_pem(&empty_path) {
            Err(Error::Invalid { .. }) => {},
            Ok(blocks) => panic!("garbage file parsed: {blocks:?}"),
            Err(err) => panic!("expected invalid pem, got {err}"),
        }

        assert_eq!(true, convert_pem("/no/such/pingap-util-cert.pem").is_err());
        // An empty body is still a PEM block. A body that is not base64 is not.
        match convert_pem("-----BEGIN X-----\n!!!!\n-----END X-----\n") {
            Err(Error::Invalid { .. }) => {},
            Ok(blocks) => panic!("invalid body parsed: {blocks:?}"),
            Err(err) => panic!("expected invalid pem, got {err}"),
        }

        assert_eq!(None, convert_certificate_bytes(None));
        assert_eq!(None, convert_certificate_bytes(Some("")));
        assert_eq!(None, convert_certificate_bytes(Some("not-a-certificate")));
    }

    #[test]
    fn test_resolve_path_relative_and_tilde_inside() {
        let cwd = match std::env::current_dir() {
            Ok(path) => path,
            Err(err) => panic!("cwd: {err}"),
        };
        assert_eq!(
            cwd.join("pingap-relative").to_string_lossy(),
            resolve_path("pingap-relative")
        );
        // A tilde that is not the start of the path is part of the path.
        assert_eq!(
            cwd.join("foo/~/bar").to_string_lossy(),
            resolve_path("foo/~/bar")
        );
        let home = match home_dir() {
            Some(path) => path,
            None => panic!("this environment has a home directory"),
        };
        let mut parent = home.clone();
        parent.push("..");
        let expected = match parent.absolutize() {
            Ok(path) => path.to_string_lossy().into_owned(),
            Err(err) => panic!("absolutize home parent: {err}"),
        };
        assert_eq!(expected, resolve_path("~/.."));
        assert_eq!(true, home_dir().is_some_and(|path| path.is_absolute()));
    }

    #[test]
    fn test_path_join_root_and_nested() {
        assert_eq!("/b", path_join("/", "b"));
        assert_eq!("/b", path_join("/", "/b"));
        assert_eq!("a/b/c", path_join("a/", "/b/c"));
        assert_eq!("http://a/b", path_join("http://a", "b"));
        assert_eq!("http://a/b", path_join("http://a/", "/b"));
    }

    #[test]
    fn test_pkg_version_and_toml_values_that_stay() {
        assert_eq!(env!("CARGO_PKG_VERSION"), get_pkg_version());
        assert_eq!(true, get_rustc_version().contains('.'));

        let kept = match toml_omit_empty_value(
            "[a]\nflag = false\nn = 0\ns = \"\"\nlist = []\n",
        ) {
            Ok(value) => value,
            Err(err) => panic!("non-empty table: {err}"),
        };
        assert_eq!(true, kept.contains("flag = false"));
        assert_eq!(true, kept.contains("n = 0"));
        assert_eq!(true, kept.contains("s = \"\""));
        assert_eq!(true, kept.contains("list = []"));

        let only_empty = match toml_omit_empty_value("[a]\n[b]\n") {
            Ok(value) => value,
            Err(err) => panic!("empty tables: {err}"),
        };
        assert_eq!(false, only_empty.contains("[a]"));
        assert_eq!(false, only_empty.contains("[b]"));

        let blank = match toml_omit_empty_value("") {
            Ok(value) => value,
            Err(err) => panic!("empty document: {err}"),
        };
        assert_eq!(false, blank.contains('['));
    }
}
