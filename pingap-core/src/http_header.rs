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

use super::{get_hostname, Ctx};
use bytes::BytesMut;
use http::header;
use http::{HeaderName, HeaderValue};
use once_cell::sync::Lazy;
use pingora::http::RequestHeader;
use pingora::proxy::Session;
use snafu::{ResultExt, Snafu};
use std::collections::HashMap;
use std::str::FromStr;
use url::Url;
use urlencoding::encode;

pub static HTTP_HEADER_X_FORWARDED_FOR: Lazy<http::HeaderName> =
    Lazy::new(|| HeaderName::from_str("X-Forwarded-For").unwrap());

pub static HTTP_HEADER_X_REAL_IP: Lazy<http::HeaderName> =
    Lazy::new(|| HeaderName::from_str("X-Real-Ip").unwrap());

pub const HOST_NAME_TAG: &[u8] = b"$hostname";
const HOST_TAG: &[u8] = b"$host";
const SCHEME_TAG: &[u8] = b"$scheme";
const REMOTE_ADDR_TAG: &[u8] = b"$remote_addr";
const REMOTE_PORT_TAG: &[u8] = b"$remote_port";
const SERVER_ADDR_TAG: &[u8] = b"$server_addr";
const SERVER_PORT_TAG: &[u8] = b"$server_port";
const PROXY_ADD_FORWARDED_TAG: &[u8] = b"$proxy_add_x_forwarded_for";
const UPSTREAM_ADDR_TAG: &[u8] = b"$upstream_addr";

static SCHEME_HTTPS: HeaderValue = HeaderValue::from_static("https");
static SCHEME_HTTP: HeaderValue = HeaderValue::from_static("http");

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Invalid header value: {value} - {source}"))]
    InvalidHeaderValue {
        value: String,
        source: header::InvalidHeaderValue,
    },
    #[snafu(display("Invalid header name: {value} - {source}"))]
    InvalidHeaderName {
        value: String,
        source: header::InvalidHeaderName,
    },
}
type Result<T, E = Error> = std::result::Result<T, E>;

pub type HttpHeader = (HeaderName, HeaderValue);

/// Get request host in this order of precedence:
/// host name from the request line,
/// or host name from the "Host" request header field
pub fn get_host(header: &RequestHeader) -> Option<&str> {
    if let Some(host) = header.uri.host() {
        return Some(host);
    }
    if let Some(host) = header.headers.get(http::header::HOST) {
        if let Ok(value) = host.to_str().map(|host| host.split(':').next()) {
            return value;
        }
    }
    None
}

/// Converts a string in "name: value" format into an HTTP header tuple.
/// Returns None if the input string doesn't contain a colon separator.
///
/// # Arguments
/// * `value` - A string in the format "header_name: header_value"
///
/// # Returns
/// * `Result<Option<HttpHeader>>` - The parsed header tuple or None if invalid format
pub fn convert_header(value: &str) -> Result<Option<HttpHeader>> {
    value
        .split_once(':')
        .map(|(k, v)| {
            let name = HeaderName::from_str(k.trim())
                .context(InvalidHeaderNameSnafu { value: k })?;
            let value = HeaderValue::from_str(v.trim())
                .context(InvalidHeaderValueSnafu { value: v })?;
            Ok(Some((name, value)))
        })
        .unwrap_or(Ok(None))
}

/// Converts a slice of strings into HTTP headers.
/// Each string should be in "name: value" format.
///
/// # Arguments
/// * `header_values` - Slice of strings representing headers
///
/// # Returns
/// * `Result<Vec<HttpHeader>>` - Vector of parsed HTTP headers
pub fn convert_headers(header_values: &[String]) -> Result<Vec<HttpHeader>> {
    let mut arr = vec![];
    for item in header_values {
        if let Some(item) = convert_header(item)? {
            arr.push(item);
        }
    }
    Ok(arr)
}

pub static HTTP_HEADER_NO_STORE: Lazy<HttpHeader> = Lazy::new(|| {
    (
        header::CACHE_CONTROL,
        HeaderValue::from_str("private, no-store").unwrap(),
    )
});

pub static HTTP_HEADER_NO_CACHE: Lazy<HttpHeader> = Lazy::new(|| {
    (
        header::CACHE_CONTROL,
        HeaderValue::from_str("private, no-cache").unwrap(),
    )
});

pub static HTTP_HEADER_CONTENT_JSON: Lazy<HttpHeader> = Lazy::new(|| {
    (
        header::CONTENT_TYPE,
        HeaderValue::from_str("application/json; charset=utf-8").unwrap(),
    )
});

pub static HTTP_HEADER_CONTENT_HTML: Lazy<HttpHeader> = Lazy::new(|| {
    (
        header::CONTENT_TYPE,
        HeaderValue::from_str("text/html; charset=utf-8").unwrap(),
    )
});

pub static HTTP_HEADER_CONTENT_TEXT: Lazy<HttpHeader> = Lazy::new(|| {
    (
        header::CONTENT_TYPE,
        HeaderValue::from_str("text/plain; charset=utf-8").unwrap(),
    )
});

pub static HTTP_HEADER_TRANSFER_CHUNKED: Lazy<HttpHeader> = Lazy::new(|| {
    (
        header::TRANSFER_ENCODING,
        HeaderValue::from_str("chunked").unwrap(),
    )
});

pub static HTTP_HEADER_NAME_X_REQUEST_ID: Lazy<HeaderName> =
    Lazy::new(|| HeaderName::from_str("X-Request-Id").unwrap());

/// Processes special header values that contain dynamic variables.
/// Supports variables like $host, $scheme, $remote_addr etc.
///
/// # Arguments
/// * `value` - The header value to process
/// * `session` - The HTTP session context
/// * `ctx` - The application state
///
/// # Returns
/// * `Option<HeaderValue>` - The processed header value or None if no special handling needed
#[inline]
pub fn convert_header_value(
    value: &HeaderValue,
    session: &Session,
    ctx: &Ctx,
) -> Option<HeaderValue> {
    let buf = value.as_bytes();

    // Early return if not a special header (moved this check earlier)
    if buf.is_empty() || !(buf[0] == b'$' || buf[0] == b':') {
        return None;
    }

    // Helper closure to convert string to HeaderValue
    let to_header_value = |s: &str| HeaderValue::from_str(s).ok();

    match buf {
        HOST_TAG => get_host(session.req_header()).and_then(to_header_value),
        SCHEME_TAG => Some(if ctx.tls_version.is_some() {
            SCHEME_HTTPS.clone()
        } else {
            SCHEME_HTTP.clone()
        }),
        HOST_NAME_TAG => to_header_value(get_hostname()),
        REMOTE_ADDR_TAG => ctx.remote_addr.as_deref().and_then(to_header_value),
        REMOTE_PORT_TAG => ctx
            .remote_port
            .map(|p| p.to_string())
            .and_then(|s| to_header_value(&s)),
        SERVER_ADDR_TAG => ctx.server_addr.as_deref().and_then(to_header_value),
        SERVER_PORT_TAG => ctx
            .server_port
            .map(|p| p.to_string())
            .and_then(|s| to_header_value(&s)),
        UPSTREAM_ADDR_TAG => {
            if !ctx.upstream_address.is_empty() {
                to_header_value(&ctx.upstream_address)
            } else {
                None
            }
        },
        PROXY_ADD_FORWARDED_TAG => {
            ctx.remote_addr.as_deref().and_then(|remote_addr| {
                let value = match session
                    .get_header(HTTP_HEADER_X_FORWARDED_FOR.clone())
                {
                    Some(existing) => format!(
                        "{}, {}",
                        existing.to_str().unwrap_or_default(),
                        remote_addr
                    ),
                    None => remote_addr.to_string(),
                };
                to_header_value(&value)
            })
        },
        _ => handle_special_headers(buf, session, ctx),
    }
}

const HTTP_HEADER_PREFIX: &[u8] = b"$http_";
const HTTP_HEADER_PREFIX_LEN: usize = HTTP_HEADER_PREFIX.len();

#[inline]
fn handle_special_headers(
    buf: &[u8],
    session: &Session,
    ctx: &Ctx,
) -> Option<HeaderValue> {
    // Handle headers that reference other HTTP headers (e.g., $http_origin)
    if buf.starts_with(HTTP_HEADER_PREFIX) {
        return handle_http_header(buf, session);
    }
    // Handle environment variable references (e.g., $HOME)
    if buf.starts_with(b"$") {
        return handle_env_var(buf);
    }
    // Handle context value references (e.g., :connection_id)
    if buf.starts_with(b":") {
        return handle_context_value(buf, ctx);
    }
    None
}

#[inline]
fn handle_http_header(buf: &[u8], session: &Session) -> Option<HeaderValue> {
    // Skip the "$http_" prefix (6 bytes) and convert remaining bytes to header key
    let key = std::str::from_utf8(&buf[HTTP_HEADER_PREFIX_LEN..]).ok()?;
    // Look up and clone the header value from the session
    session.get_header(key).cloned()
}

#[inline]
fn handle_env_var(buf: &[u8]) -> Option<HeaderValue> {
    // Skip the "$" prefix and convert to environment variable name
    let var_name = std::str::from_utf8(&buf[1..]).ok()?;
    // Look up environment variable and convert to HeaderValue if found
    std::env::var(var_name)
        .ok()
        .and_then(|v| HeaderValue::from_str(&v).ok())
}

#[inline]
fn handle_context_value(buf: &[u8], ctx: &Ctx) -> Option<HeaderValue> {
    // Skip the ":" prefix and convert to context key
    let key = std::str::from_utf8(&buf[1..]).ok()?;
    // Pre-allocate buffer for value
    let mut value = BytesMut::with_capacity(20);
    // Append context value to buffer
    value = ctx.append_value(value, key);
    // Convert to HeaderValue if buffer is not empty
    if !value.is_empty() {
        HeaderValue::from_bytes(&value).ok()
    } else {
        None
    }
}

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
/// * `value` - Query string or http url to parse (without leading '?')
///
/// # Returns
/// HashMap containing the parsed query parameters
pub fn convert_query_map(value: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    let value = if !value.contains('?') {
        format!("http://host?{value}")
    } else {
        value.to_string()
    };
    let Ok(value) = Url::parse(&value) else {
        return m;
    };
    for item in value.query().unwrap_or_default().split('&') {
        if let Some((key, value)) = item.split_once('=') {
            m.insert(key.to_string(), encode(value).to_string());
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

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    #[test]
    fn test_convert_headers() {
        let headers = convert_headers(&[
            "Content-Type: application/octet-stream".to_string(),
            "X-Server: $hostname".to_string(),
            "X-User: $USER".to_string(),
        ])
        .unwrap();
        assert_eq!(3, headers.len());
        assert_eq!("content-type", headers[0].0.to_string());
        assert_eq!("application/octet-stream", headers[0].1.to_str().unwrap());
        assert_eq!("x-server", headers[1].0.to_string());
        assert_eq!(false, headers[1].1.to_str().unwrap().is_empty());
        assert_eq!("x-user", headers[2].0.to_string());
        assert_eq!(false, headers[2].1.to_str().unwrap().is_empty());
    }

    #[test]
    fn test_static_value() {
        assert_eq!(
            "cache-control: private, no-store",
            format!(
                "{}: {}",
                HTTP_HEADER_NO_STORE.0.to_string(),
                HTTP_HEADER_NO_STORE.1.to_str().unwrap_or_default()
            )
        );

        assert_eq!(
            "cache-control: private, no-cache",
            format!(
                "{}: {}",
                HTTP_HEADER_NO_CACHE.0.to_string(),
                HTTP_HEADER_NO_CACHE.1.to_str().unwrap_or_default()
            )
        );

        assert_eq!(
            "content-type: application/json; charset=utf-8",
            format!(
                "{}: {}",
                HTTP_HEADER_CONTENT_JSON.0.to_string(),
                HTTP_HEADER_CONTENT_JSON.1.to_str().unwrap_or_default()
            )
        );

        assert_eq!(
            "content-type: text/html; charset=utf-8",
            format!(
                "{}: {}",
                HTTP_HEADER_CONTENT_HTML.0.to_string(),
                HTTP_HEADER_CONTENT_HTML.1.to_str().unwrap_or_default()
            )
        );

        assert_eq!(
            "transfer-encoding: chunked",
            format!(
                "{}: {}",
                HTTP_HEADER_TRANSFER_CHUNKED.0.to_string(),
                HTTP_HEADER_TRANSFER_CHUNKED.1.to_str().unwrap_or_default()
            )
        );

        assert_eq!(
            "x-request-id",
            format!("{}", HTTP_HEADER_NAME_X_REQUEST_ID.to_string(),)
        );

        assert_eq!(
            "content-type: text/plain; charset=utf-8",
            format!(
                "{}: {}",
                HTTP_HEADER_CONTENT_TEXT.0.to_string(),
                HTTP_HEADER_CONTENT_TEXT.1.to_str().unwrap_or_default()
            )
        );
    }

    #[tokio::test]
    async fn test_convert_header_value() {
        let headers = ["Host: pingap.io"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let default_state = Ctx {
            tls_version: Some("tls1.3".to_string()),
            remote_addr: Some("10.1.1.1".to_string()),
            remote_port: Some(6000),
            server_addr: Some("10.1.1.2".to_string()),
            server_port: Some(6001),
            upstream_address: "10.1.1.3:4123".to_string(),
            connection_id: 102,
            ..Default::default()
        };

        let value = convert_header_value(
            &HeaderValue::from_str("$host").unwrap(),
            &session,
            &Ctx {
                ..Default::default()
            },
        );
        assert_eq!(true, value.is_some());
        assert_eq!("pingap.io", value.unwrap().to_str().unwrap());

        let value = convert_header_value(
            &HeaderValue::from_str("$scheme").unwrap(),
            &session,
            &Ctx {
                ..Default::default()
            },
        );
        assert_eq!(true, value.is_some());
        assert_eq!("http", value.unwrap().to_str().unwrap());
        let value = convert_header_value(
            &HeaderValue::from_str("$scheme").unwrap(),
            &session,
            &default_state,
        );
        assert_eq!(true, value.is_some());
        assert_eq!("https", value.unwrap().to_str().unwrap());

        let value = convert_header_value(
            &HeaderValue::from_str("$remote_addr").unwrap(),
            &session,
            &default_state,
        );
        assert_eq!(true, value.is_some());
        assert_eq!("10.1.1.1", value.unwrap().to_str().unwrap());

        let value = convert_header_value(
            &HeaderValue::from_str("$remote_port").unwrap(),
            &session,
            &default_state,
        );
        assert_eq!(true, value.is_some());
        assert_eq!("6000", value.unwrap().to_str().unwrap());

        let value = convert_header_value(
            &HeaderValue::from_str("$server_addr").unwrap(),
            &session,
            &default_state,
        );
        assert_eq!(true, value.is_some());
        assert_eq!("10.1.1.2", value.unwrap().to_str().unwrap());

        let value = convert_header_value(
            &HeaderValue::from_str("$server_port").unwrap(),
            &session,
            &default_state,
        );
        assert_eq!(true, value.is_some());
        assert_eq!("6001", value.unwrap().to_str().unwrap());

        let value = convert_header_value(
            &HeaderValue::from_str("$upstream_addr").unwrap(),
            &session,
            &default_state,
        );
        assert_eq!(true, value.is_some());
        assert_eq!("10.1.1.3:4123", value.unwrap().to_str().unwrap());

        let value = convert_header_value(
            &HeaderValue::from_str(":connection_id").unwrap(),
            &session,
            &default_state,
        );
        assert_eq!(true, value.is_some());
        assert_eq!("102", value.unwrap().to_str().unwrap());

        let headers = ["X-Forwarded-For: 1.1.1.1, 2.2.2.2"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let value = convert_header_value(
            &HeaderValue::from_str("$proxy_add_x_forwarded_for").unwrap(),
            &session,
            &Ctx {
                remote_addr: Some("10.1.1.1".to_string()),
                ..Default::default()
            },
        );
        assert_eq!(true, value.is_some());
        assert_eq!(
            "1.1.1.1, 2.2.2.2, 10.1.1.1",
            value.unwrap().to_str().unwrap()
        );

        let headers = [""].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let value = convert_header_value(
            &HeaderValue::from_str("$proxy_add_x_forwarded_for").unwrap(),
            &session,
            &Ctx {
                remote_addr: Some("10.1.1.1".to_string()),
                ..Default::default()
            },
        );
        assert_eq!(true, value.is_some());
        assert_eq!("10.1.1.1", value.unwrap().to_str().unwrap());

        let headers = [""].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let value = convert_header_value(
            &HeaderValue::from_str("$upstream_addr").unwrap(),
            &session,
            &Ctx {
                upstream_address: "10.1.1.1:8001".to_string(),
                ..Default::default()
            },
        );
        assert_eq!(true, value.is_some());
        assert_eq!("10.1.1.1:8001", value.unwrap().to_str().unwrap());

        let headers = ["Origin: https://github.com"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let value = convert_header_value(
            &HeaderValue::from_str("$http_origin").unwrap(),
            &session,
            &Ctx::default(),
        );
        assert_eq!(true, value.is_some());
        assert_eq!("https://github.com", value.unwrap().to_str().unwrap());

        let headers = ["Origin: https://github.com"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let value = convert_header_value(
            &HeaderValue::from_str("$hostname").unwrap(),
            &session,
            &Ctx::default(),
        );
        assert_eq!(true, value.is_some());

        let headers = ["Origin: https://github.com"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let value = convert_header_value(
            &HeaderValue::from_str("$HOME").unwrap(),
            &session,
            &Ctx::default(),
        );
        assert_eq!(true, value.is_some());

        let headers = ["Origin: https://github.com"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let value = convert_header_value(
            &HeaderValue::from_str("UUID").unwrap(),
            &session,
            &Ctx::default(),
        );
        assert_eq!(false, value.is_some());
    }

    #[tokio::test]
    async fn test_get_host() {
        let headers = ["Host: pingap.io"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        assert_eq!(get_host(session.req_header()), Some("pingap.io"));
    }

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
            get_req_header_value(session.req_header(), "Host"),
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
            get_cookie_value(session.req_header(), "name"),
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

        let query = "https://pingap.io/vicanso/pingap?apikey=123&name=pingap";
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
        assert_eq!(get_query_value(session.req_header(), "size"), Some("1"));
    }
}
