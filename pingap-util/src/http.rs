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

use http::HeaderName;
use once_cell::sync::Lazy;
use pingora::http::RequestHeader;
use pingora::proxy::Session;
use pingora::tls::ssl::SslVersion;
use std::collections::HashMap;
use std::str::FromStr;

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

/// Creates a new internal error
pub fn new_internal_error(status: u16, message: String) -> pingora::BError {
    pingora::Error::because(
        pingora::ErrorType::HTTPStatus(status),
        message,
        pingora::Error::new(pingora::ErrorType::InternalError),
    )
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

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

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

    #[tokio::test]
    async fn test_get_client_ip() {
        let headers = ["X-Forwarded-For:192.168.1.1"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        assert_eq!(get_client_ip(&session), "192.168.1.1");

        let headers = ["X-Real-Ip:192.168.1.2"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        assert_eq!(get_client_ip(&session), "192.168.1.2");
    }

    #[tokio::test]
    async fn test_get_header_value() {
        let headers = ["Host: pingap.io"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        assert_eq!(
            get_req_header_value(&session.req_header(), "Host"),
            Some("pingap.io")
        );
    }

    #[tokio::test]
    async fn test_get_cookie_value() {
        let headers = ["Cookie: name=pingap"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        assert_eq!(
            get_cookie_value(&session.req_header(), "name"),
            Some("pingap")
        );
    }

    #[test]
    fn test_convert_query_map() {
        let query = "apikey=123&name=pingap";
        let map = convert_query_map(query);
        assert_eq!(map.len(), 2);
        assert_eq!(map["apikey"], "123");
        assert_eq!(map["name"], "pingap");
    }

    #[tokio::test]
    async fn test_get_query_value() {
        let headers = ["X-Forwarded-For:192.168.1.1"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        assert_eq!(get_query_value(&session.req_header(), "size"), Some("1"));
    }

    #[tokio::test]
    async fn test_get_content_length() {
        let headers = ["Content-Length: 123"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        assert_eq!(get_content_length(&session.req_header()), Some(123));
    }

    #[test]
    fn test_new_internal_error() {
        let error =
            new_internal_error(500, "Internal Server Error".to_string());
        assert_eq!(
            error.to_string().trim(),
            "HTTPStatus context: Internal Server Error cause:  InternalError"
        );
    }

    #[tokio::test]
    async fn test_get_host() {
        let headers = ["Host: pingap.io"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        assert_eq!(get_host(&session.req_header()), Some("pingap.io"));
    }
}
