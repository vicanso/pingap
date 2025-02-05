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
use bytes::BytesMut;
use http::HeaderName;
use once_cell::sync::Lazy;
use path_absolutize::*;
use pingora::tls::ssl::SslVersion;
use pingora::{http::RequestHeader, proxy::Session};
use regex::Regex;
use snafu::Snafu;
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{path::Path, str::FromStr};
use substring::Substring;

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

mod crypto;
mod ip;

pub use crypto::{aes_decrypt, aes_encrypt};
pub use ip::IpRules;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Gets the package version.
pub fn get_pkg_version() -> &'static str {
    VERSION
}

/// Get the rustc version.
pub fn get_rustc_version() -> String {
    rustc_version_runtime::version().to_string()
}

/// Resolves the path as absolute.
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

pub static HTTP_HEADER_X_FORWARDED_FOR: Lazy<http::HeaderName> =
    Lazy::new(|| HeaderName::from_str("X-Forwarded-For").unwrap());

pub static HTTP_HEADER_X_REAL_IP: Lazy<http::HeaderName> =
    Lazy::new(|| HeaderName::from_str("X-Real-Ip").unwrap());

/// Get remote addr from session
pub fn get_remote_addr(session: &Session) -> Option<(String, u16)> {
    session
        .client_addr()
        .and_then(|addr| addr.as_inet())
        .map(|addr| (addr.ip().to_string(), addr.port()))
}

/// Gets client ip from X-Forwarded-For,
/// If none, get from X-Real-Ip,
/// If none, get remote addr.
pub fn get_client_ip(session: &Session) -> String {
    if let Some(value) = session.get_header(HTTP_HEADER_X_FORWARDED_FOR.clone())
    {
        let arr: Vec<&str> =
            value.to_str().unwrap_or_default().split(',').collect();
        if !arr.is_empty() {
            return arr[0].trim().to_string();
        }
    }
    if let Some(value) = session.get_header(HTTP_HEADER_X_REAL_IP.clone()) {
        return value.to_str().unwrap_or_default().to_string();
    }
    if let Some((addr, _)) = get_remote_addr(session) {
        return addr;
    }
    "".to_string()
}

/// Gets string value from req header.
///
/// # Arguments
/// * `req_header` - The HTTP request header
/// * `key` - The header key to look up
///
/// # Returns
/// The header value as a string slice if found and valid UTF-8, None otherwise
pub fn get_req_header_value<'a>(
    req_header: &'a RequestHeader,
    key: &str,
) -> Option<&'a str> {
    if let Some(value) = req_header.headers.get(key) {
        if let Ok(value) = value.to_str() {
            return Some(value);
        }
    }
    None
}

/// Gets cookie value from req header.
///
/// # Arguments
/// * `req_header` - The HTTP request header
/// * `cookie_name` - Name of the cookie to find
///
/// # Returns
/// The cookie value as a string slice if found, None otherwise
pub fn get_cookie_value<'a>(
    req_header: &'a RequestHeader,
    cookie_name: &str,
) -> Option<&'a str> {
    if let Some(cookie_value) = get_req_header_value(req_header, "Cookie") {
        for item in cookie_value.split(';') {
            if let Some((k, v)) = item.split_once('=') {
                if k == cookie_name {
                    return Some(v.trim());
                }
            }
        }
    }
    None
}

/// Converts query string to key-value map.
///
/// # Arguments
/// * `query` - Query string to parse (without leading '?')
///
/// # Returns
/// HashMap containing the parsed query parameters
pub fn convert_query_map(query: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for item in query.split('&') {
        if let Some((key, value)) = item.split_once('=') {
            m.insert(key.to_string(), value.to_string());
        } else {
            m.insert(item.to_string(), "".to_string());
        }
    }
    m
}

/// Gets query parameter value from request header.
///
/// # Arguments
/// * `req_header` - The HTTP request header
/// * `name` - Name of the query parameter to find
///
/// # Returns
/// The parameter value as a string slice if found, None otherwise
pub fn get_query_value<'a>(
    req_header: &'a RequestHeader,
    name: &str,
) -> Option<&'a str> {
    if let Some(query) = req_header.uri.query() {
        for item in query.split('&') {
            if let Some((k, v)) = item.split_once('=') {
                if k == name {
                    return Some(v.trim());
                }
            }
        }
    }
    None
}

/// Remove query parameter from request header URI
///
/// # Arguments
/// * `req_header` - The HTTP request header to modify
/// * `name` - Name of the query parameter to remove
///
/// # Returns
/// Result indicating success or failure of the URI modification
pub fn remove_query_from_header(
    req_header: &mut RequestHeader,
    name: &str,
) -> Result<(), http::uri::InvalidUri> {
    if let Some(query) = req_header.uri.query() {
        let mut query_list = vec![];
        for item in query.split('&') {
            if let Some((k, v)) = item.split_once('=') {
                if k != name {
                    query_list.push(format!("{k}={v}"));
                }
            } else if item != name {
                query_list.push(item.to_string());
            }
        }
        let query = query_list.join("&");
        let mut new_path = req_header.uri.path().to_string();
        if !query.is_empty() {
            new_path = format!("{new_path}?{query}");
        }
        return new_path
            .parse::<http::Uri>()
            .map(|uri| req_header.set_uri(uri));
    }

    Ok(())
}

/// Creates a new internal error
pub fn new_internal_error(status: u16, message: String) -> pingora::BError {
    pingora::Error::because(
        pingora::ErrorType::HTTPStatus(status),
        message,
        pingora::Error::new(pingora::ErrorType::InternalError),
    )
}

/// Test whether or not the string is pem
pub fn is_pem(value: &str) -> bool {
    value.starts_with("-----")
}

// 2022-05-07: 1651852800
// const SUPER_TIMESTAMP: u64 = 1651852800;
static SUPER_TIMESTAMP: Lazy<SystemTime> = Lazy::new(|| {
    UNIX_EPOCH
        .checked_add(Duration::from_secs(1651852800))
        .unwrap_or(SystemTime::now())
});

pub fn get_super_ts() -> u32 {
    if let Ok(value) = SystemTime::now().duration_since(*SUPER_TIMESTAMP) {
        value.as_secs() as u32
    } else {
        0
    }
}

#[inline]
pub fn now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
}

#[inline]
pub fn now_ms() -> u64 {
    now().as_millis() as u64
}

#[inline]
pub fn now_sec() -> u64 {
    now().as_secs()
}

pub fn local_ip_list() -> Vec<String> {
    let mut ip_list = vec![];

    if let Ok(value) = local_ip_address::local_ip() {
        ip_list.push(value);
    }
    if let Ok(value) = local_ip_address::local_ipv6() {
        ip_list.push(value);
    }

    ip_list
        .iter()
        .filter(|item| !item.is_loopback())
        .map(|item| item.to_string())
        .collect()
}

/// Get request host in this order of precedence:
/// host name from the request line,
/// or host name from the "Host" request header field
pub fn get_host(header: &RequestHeader) -> Option<&str> {
    if let Some(host) = header.uri.host() {
        return Some(host);
    }
    if let Some(host) = header.headers.get("Host") {
        if let Ok(value) = host.to_str().map(|host| host.split(':').next()) {
            return value;
        }
    }
    None
}

/// Get the content length from http request header.
pub fn get_content_length(header: &RequestHeader) -> Option<usize> {
    if let Some(content_length) =
        header.headers.get(http::header::CONTENT_LENGTH)
    {
        if let Ok(size) =
            content_length.to_str().unwrap_or_default().parse::<usize>()
        {
            return Some(size);
        }
    }
    None
}

#[inline]
pub fn get_latency(value: &Option<u64>) -> Option<u64> {
    let current = now_ms();
    if let Some(value) = value {
        Some(current - value)
    } else {
        Some(current)
    }
}

pub fn convert_tls_version(version: &Option<String>) -> Option<SslVersion> {
    if let Some(version) = &version {
        let version = match version.to_lowercase().as_str() {
            "tlsv1.1" => SslVersion::TLS1_1,
            "tlsv1.3" => SslVersion::TLS1_3,
            _ => SslVersion::TLS1_2,
        };
        return Some(version);
    }
    None
}

/// Convert pem to [u8]
pub fn convert_pem(value: &str) -> Result<Vec<u8>> {
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
    Ok(buf)
}

pub fn convert_certificate_bytes(value: Option<&str>) -> Option<Vec<u8>> {
    if let Some(value) = value {
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

/// RegexCapture provides a way to extract named captures from regex matches
///
/// # Example
/// ```
/// use pingap::pingap_util::RegexCapture;
/// let re = RegexCapture::new(r"(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})").unwrap();
/// let (matched, captures) = re.captures("2024-03-14");
/// assert_eq!(true, matched);
/// assert_eq!(Some(vec![("year".to_string(), "2024".to_string()), ("month".to_string(), "03".to_string()), ("day".to_string(), "14".to_string())]), captures);
/// ```
#[derive(Debug, Clone)]
pub struct RegexCapture {
    re: Regex,
    keys: Vec<String>,
}

impl RegexCapture {
    pub fn new(value: &str) -> Result<Self, regex::Error> {
        let re = Regex::new(value)?;
        let mut keys = vec![];
        for name in re.capture_names() {
            keys.push(name.unwrap_or_default().to_string());
        }
        Ok(RegexCapture { re, keys })
    }
    pub fn captures(
        &self,
        value: &str,
    ) -> (bool, Option<Vec<(String, String)>>) {
        let re = &self.re;
        if !re.is_match(value) {
            return (false, None);
        }
        let mut arr = vec![];
        let Some(cap) = re.captures(value) else {
            return (true, Some(arr));
        };
        let keys = &self.keys;
        for (index, value) in cap.iter().enumerate() {
            if index >= keys.len() {
                continue;
            }
            let key = &keys[index];
            if key.is_empty() {
                continue;
            }
            let Some(value) = value else {
                continue;
            };
            arr.push((key.to_string(), value.as_str().to_string()));
        }
        (true, Some(arr))
    }
}

const B_100: usize = 100;
const KB: usize = 1_000;
const KB_100: usize = 100 * KB;
const MB: usize = 1_000_000;
const MB_100: usize = 100 * MB;
const GB: usize = 1_000_000_000;

/// Formats a byte size into a human readable string with appropriate units (B, KB, MB, GB)
/// The function will add decimal points for values between units (e.g., 1.5KB)
///
/// # Arguments
/// * `buf` - BytesMut buffer to write the formatted string into
/// * `size` - Size in bytes to format
///
/// # Returns
/// BytesMut buffer containing the formatted string
#[inline]
pub fn format_byte_size(mut buf: BytesMut, size: usize) -> BytesMut {
    if size < KB {
        buf.extend(itoa::Buffer::new().format(size).as_bytes());
        buf.extend(b"B");
    } else if size < MB {
        buf.extend(itoa::Buffer::new().format(size / KB).as_bytes());
        let value = (size % KB) / B_100;
        if value != 0 {
            buf.extend(b".");
            buf.extend(itoa::Buffer::new().format(value).as_bytes());
        }
        buf.extend(b"KB");
    } else if size < GB {
        buf.extend(itoa::Buffer::new().format(size / MB).as_bytes());
        let value = (size % MB) / KB_100;
        if value != 0 {
            buf.extend(b".");
            buf.extend(itoa::Buffer::new().format(value).as_bytes());
        }
        buf.extend(b"MB");
    } else {
        buf.extend(itoa::Buffer::new().format(size / GB).as_bytes());
        let value = (size % GB) / MB_100;
        if value != 0 {
            buf.extend(b".");
            buf.extend(itoa::Buffer::new().format(value).as_bytes());
        }
        buf.extend(b"GB");
    }
    buf
}

const SEC: u64 = 1_000;

/// Formats a duration in milliseconds into a human readable string
/// For durations < 1000ms, formats as milliseconds
/// For durations >= 1000ms, formats as seconds with up to one decimal place
///
/// # Arguments
/// * `buf` - BytesMut buffer to write the formatted string into
/// * `ms` - Duration in milliseconds to format
///
/// # Returns
/// BytesMut buffer containing the formatted string
#[inline]
pub fn format_duration(mut buf: BytesMut, ms: u64) -> BytesMut {
    if ms < 1000 {
        buf.extend(itoa::Buffer::new().format(ms).as_bytes());
        buf.extend(b"ms");
    } else {
        buf.extend(itoa::Buffer::new().format(ms / SEC).as_bytes());
        let value = (ms % SEC) / 100;
        if value != 0 {
            buf.extend(b".");
            buf.extend(itoa::Buffer::new().format(value).as_bytes());
        }
        buf.extend(b"s");
    }
    buf
}

#[inline]
pub fn elapsed_ms(time: SystemTime) -> u64 {
    time.elapsed().unwrap_or_default().as_millis() as u64
}

#[inline]
pub fn elapsed_second(time: SystemTime) -> f64 {
    time.elapsed().unwrap_or_default().as_millis() as f64 / 1000.0
}

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

pub fn path_join(value1: &str, value2: &str) -> String {
    if value2.starts_with("/") {
        format!("{value1}{value2}")
    } else {
        format!("{value1}/{value2}")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        convert_certificate_bytes, convert_tls_version, format_byte_size,
        format_duration, get_latency, get_pkg_version, local_ip_list,
        remove_query_from_header, resolve_path,
    };
    use crate::base64_encode;
    use bytes::BytesMut;
    use pingora::{http::RequestHeader, tls::ssl::SslVersion};
    use pretty_assertions::assert_eq;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_remove_query_from_header() {
        let mut req =
            RequestHeader::build("GET", b"/?apikey=123", None).unwrap();
        remove_query_from_header(&mut req, "apikey").unwrap();
        assert_eq!("/", req.uri.to_string());

        let mut req =
            RequestHeader::build("GET", b"/?apikey=123&name=pingap", None)
                .unwrap();
        remove_query_from_header(&mut req, "apikey").unwrap();
        assert_eq!("/?name=pingap", req.uri.to_string());
    }

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
    fn test_get_latency() {
        let d = get_latency(&None);
        assert_eq!(true, d.is_some());
        assert_eq!(true, get_latency(&d).is_some());
    }
    #[test]
    fn test_convert_tls_version() {
        assert_eq!(
            SslVersion::TLS1_1,
            convert_tls_version(&Some("tlsv1.1".to_string())).unwrap()
        );
        assert_eq!(
            SslVersion::TLS1_2,
            convert_tls_version(&Some("tlsv1.2".to_string())).unwrap()
        );
        assert_eq!(
            SslVersion::TLS1_3,
            convert_tls_version(&Some("tlsv1.3".to_string())).unwrap()
        );
    }
    #[test]
    fn test_local_ip_list() {
        assert_eq!(false, local_ip_list().is_empty());
    }

    #[test]
    fn test_format_byte_size() {
        let mut buf = BytesMut::with_capacity(1024);
        buf = format_byte_size(buf, 512);
        assert_eq!(
            "512B",
            std::string::String::from_utf8_lossy(&buf).to_string()
        );

        buf.clear();
        buf = format_byte_size(buf, 1024);
        assert_eq!(
            "1KB",
            std::string::String::from_utf8_lossy(&buf).to_string()
        );

        buf.clear();
        buf = format_byte_size(buf, 1124);
        assert_eq!(
            "1.1KB",
            std::string::String::from_utf8_lossy(&buf).to_string()
        );

        buf.clear();
        buf = format_byte_size(buf, 1020 * 1000);
        assert_eq!(
            "1MB",
            std::string::String::from_utf8_lossy(&buf).to_string()
        );

        buf.clear();
        buf = format_byte_size(buf, 1220 * 1000);
        assert_eq!(
            "1.2MB",
            std::string::String::from_utf8_lossy(&buf).to_string()
        );

        buf.clear();
        buf = format_byte_size(buf, 122220 * 1000);
        assert_eq!(
            "122.2MB",
            std::string::String::from_utf8_lossy(&buf).to_string()
        );

        buf.clear();
        buf = format_byte_size(buf, 1000 * 1000 * 1000 + 500 * 1000 * 1000);
        assert_eq!(
            "1.5GB",
            std::string::String::from_utf8_lossy(&buf).to_string()
        );
    }

    #[test]
    fn test_format_duration() {
        let mut buf = BytesMut::with_capacity(1024);
        buf = format_duration(buf, 100);
        assert_eq!(
            "100ms",
            std::string::String::from_utf8_lossy(&buf).to_string()
        );

        buf.clear();
        buf = format_duration(buf, 12400);
        assert_eq!(
            "12.4s",
            std::string::String::from_utf8_lossy(&buf).to_string()
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
