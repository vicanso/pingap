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

use base64::{engine::general_purpose::STANDARD, Engine};
use bytes::BytesMut;
use http::HeaderName;
use once_cell::sync::Lazy;
use path_absolutize::*;
use pingora::tls::ssl::SslVersion;
use pingora::{http::RequestHeader, proxy::Session};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{path::Path, str::FromStr};
use substring::Substring;

const NAME: &str = env!("CARGO_PKG_NAME");
const VERSION: &str = env!("CARGO_PKG_VERSION");

pub static ADMIN_SERVER_PLUGIN: Lazy<String> =
    Lazy::new(|| uuid::Uuid::new_v4().to_string());

/// Gets the package name.
pub fn get_pkg_name() -> &'static str {
    NAME
}

/// Gets the package version.
pub fn get_pkg_version() -> &'static str {
    VERSION
}

/// Get the rustc version.
pub fn get_rustc_version() -> String {
    if let Ok(version) = rustc_version::version() {
        version.to_string()
    } else {
        "--".to_string()
    }
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

pub fn get_remote_addr(session: &Session) -> Option<String> {
    if let Some(addr) = session.client_addr() {
        if let Some(addr) = addr.as_inet() {
            return Some(addr.ip().to_string());
        }
    }
    None
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
    if let Some(addr) = get_remote_addr(session) {
        return addr;
    }
    "".to_string()
}

/// Gets string value from req header.
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

/// Gets query value from req header.
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

/// Remove query from req header
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

pub fn now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
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
    let current = now().as_millis() as u64;
    if let Some(value) = value {
        Some(current - value)
    } else {
        Some(current)
    }
}

pub fn convert_tls_version(version: &Option<String>) -> Option<SslVersion> {
    if let Some(version) = &version {
        let version = match version.as_str() {
            "tlsv1.1" => SslVersion::TLS1_1,
            "tlsv1.3" => SslVersion::TLS1_3,
            _ => SslVersion::TLS1_2,
        };
        return Some(version);
    }
    None
}

pub fn convert_certificate_bytes(value: &Option<String>) -> Option<Vec<u8>> {
    if let Some(value) = value {
        if is_pem(value) {
            return Some(value.as_bytes().to_vec());
        } else {
            let buf = STANDARD.decode(value).unwrap_or_default();
            return Some(buf);
        }
    }
    None
}

const B_100: usize = 100;
const KB: usize = 1_000;
const KB_100: usize = 100 * KB;
const MB: usize = 1_000_000;
const MB_100: usize = 100 * MB;
const GB: usize = 1_000_000_000;

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

#[cfg(test)]
mod tests {
    use super::{
        convert_tls_version, format_byte_size, format_duration, get_latency,
        get_pkg_name, get_pkg_version, local_ip_list, remove_query_from_header,
        resolve_path,
    };
    use bytes::BytesMut;
    use pingora::{http::RequestHeader, tls::ssl::SslVersion};
    use pretty_assertions::assert_eq;
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
        assert_eq!("pingap", get_pkg_name());
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
}
