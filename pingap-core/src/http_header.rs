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

// Import necessary modules and types from supervisors and external crates.
use super::{get_hostname, Ctx};
use bytes::BytesMut;
use http::header;
use http::{HeaderName, HeaderValue};
use pingora::http::RequestHeader;
use pingora::proxy::Session;
use snafu::{ResultExt, Snafu};
use std::borrow::Cow;
use std::fmt::Write;
use std::str::FromStr;

// Define string constants for commonly used HTTP header names.
const HTTP_HEADER_X_FORWARDED_FOR: &str = "x-forwarded-for";
const HTTP_HEADER_X_REAL_IP: &str = "x-real-ip";

// Define byte slice constants for special variable tags used in header value processing.
// These are matched against the raw bytes of a header value.
pub const HOST_NAME_TAG: &[u8] = b"$hostname";
const HOST_TAG: &[u8] = b"$host";
const SCHEME_TAG: &[u8] = b"$scheme";
const REMOTE_ADDR_TAG: &[u8] = b"$remote_addr";
const REMOTE_PORT_TAG: &[u8] = b"$remote_port";
const SERVER_ADDR_TAG: &[u8] = b"$server_addr";
const SERVER_PORT_TAG: &[u8] = b"$server_port";
const PROXY_ADD_FORWARDED_TAG: &[u8] = b"$proxy_add_x_forwarded_for";
const UPSTREAM_ADDR_TAG: &[u8] = b"$upstream_addr";

// Define static HeaderValues for HTTP and HTTPS schemes to avoid re-creation.
static SCHEME_HTTPS: HeaderValue = HeaderValue::from_static("https");
static SCHEME_HTTP: HeaderValue = HeaderValue::from_static("http");

/// Defines the custom error types for this module using the snafu crate.
#[derive(Debug, Snafu)]
pub enum Error {
    /// Error for when a string cannot be parsed into a valid HeaderValue.
    #[snafu(display("invalid header value: {value} - {source}"))]
    InvalidHeaderValue {
        value: String,
        source: header::InvalidHeaderValue,
    },
    /// Error for when a string cannot be parsed into a valid HeaderName.
    #[snafu(display("invalid header name: {value} - {source}"))]
    InvalidHeaderName {
        value: String,
        source: header::InvalidHeaderName,
    },
}
/// A convenient type alias for `Result` with the module's `Error` type.
type Result<T, E = Error> = std::result::Result<T, E>;

/// A type alias for a tuple representing an HTTP header.
pub type HttpHeader = (HeaderName, HeaderValue);

/// Gets the request host by checking the URI first, then falling back to the "Host" header.
///
/// This function follows the common practice of prioritizing the host from the absolute URI
/// (e.g., in `GET http://example.com/path HTTP/1.1`) over the `Host` header field.
pub fn get_host(header: &RequestHeader) -> Option<&str> {
    // First, try to get the host directly from the parsed URI.
    // http2 will always have a host in the uri
    if let Some(host) = header.uri.host() {
        return Some(host);
    }
    // If not in the URI, fall back to the "Host" header.
    header
        .headers
        .get(http::header::HOST)
        // Convert the header value to a string slice.
        .and_then(|value| value.to_str().ok())
        // The host header can include a port (e.g., "example.com:8080"), so we split and take the first part.
        .and_then(|host| host.split(':').next())
}

/// Converts a single string in "name: value" format into an `HttpHeader` tuple.
///
/// This is a utility function for parsing header configurations. It trims whitespace
/// from both the name and the value.
pub fn convert_header(value: &str) -> Result<Option<HttpHeader>> {
    // `split_once` is an efficient way to split the string into two parts at the first colon.
    value
        .split_once(':')
        // If a colon exists, map the key and value parts.
        .map(|(k, v)| {
            // Parse the trimmed key into a HeaderName, wrapping errors.
            let name = HeaderName::from_str(k.trim())
                .context(InvalidHeaderNameSnafu { value: k })?;
            // Parse the trimmed value into a HeaderValue, wrapping errors.
            let value = HeaderValue::from_str(v.trim())
                .context(InvalidHeaderValueSnafu { value: v })?;
            // If both parsing steps succeed, return the header tuple.
            Ok(Some((name, value)))
        })
        // If `split_once` returns None (no colon), default to `Ok(None)`.
        .unwrap_or(Ok(None))
}

/// Converts a slice of strings into a `Vec` of `HttpHeader`s.
///
/// This function iterates over a list of header strings and uses `convert_header`
/// on each, collecting the valid results into a vector.
pub fn convert_headers(header_values: &[String]) -> Result<Vec<HttpHeader>> {
    header_values
        .iter()
        // `filter_map` is used to iterate, convert, and filter out `None` results elegantly.
        // `transpose` flips `Option<Result<T>>` to `Result<Option<T>>`, which is what `filter_map` expects.
        .filter_map(|item| convert_header(item).transpose())
        // `collect` gathers the `Result<HttpHeader>` items. If any item is an `Err`, `collect` will return that `Err`.
        .collect()
}

// Define common, pre-built HTTP headers as static constants for reuse and performance.
pub static HTTP_HEADER_NO_STORE: HttpHeader = (
    header::CACHE_CONTROL,
    HeaderValue::from_static("private, no-store"),
);
pub static HTTP_HEADER_NO_CACHE: HttpHeader = (
    header::CACHE_CONTROL,
    HeaderValue::from_static("private, no-cache"),
);
pub static HTTP_HEADER_CONTENT_JSON: HttpHeader = (
    header::CONTENT_TYPE,
    HeaderValue::from_static("application/json; charset=utf-8"),
);
pub static HTTP_HEADER_CONTENT_HTML: HttpHeader = (
    header::CONTENT_TYPE,
    HeaderValue::from_static("text/html; charset=utf-8"),
);
pub static HTTP_HEADER_CONTENT_TEXT: HttpHeader = (
    header::CONTENT_TYPE,
    HeaderValue::from_static("text/plain; charset=utf-8"),
);
pub static HTTP_HEADER_TRANSFER_CHUNKED: HttpHeader = (
    header::TRANSFER_ENCODING,
    HeaderValue::from_static("chunked"),
);
pub static HTTP_HEADER_NAME_X_REQUEST_ID: HeaderName =
    HeaderName::from_static("x-request-id");

/// Processes a `HeaderValue` that may contain a special dynamic variable (e.g., `$host`).
/// It replaces the variable with its corresponding runtime value.
#[inline]
pub fn convert_header_value(
    value: &HeaderValue,
    session: &Session,
    ctx: &Ctx,
) -> Option<HeaderValue> {
    // Work with the raw byte representation of the header value for efficient matching.
    let buf = value.as_bytes();

    // Perform a quick check for the special variable prefix ('$' or ':') to exit early
    // for normal header values, which is the most common case.
    if buf.is_empty() || !(buf[0] == b'$' || buf[0] == b':') {
        return None;
    }

    // A helper closure to reduce boilerplate when converting a string slice to a HeaderValue.
    let to_header_value = |s: &str| HeaderValue::from_str(s).ok();

    // Match the entire byte slice against the predefined variable tags.
    match buf {
        HOST_TAG => get_host(session.req_header()).and_then(to_header_value),
        SCHEME_TAG => Some(if ctx.conn.tls_version.is_some() {
            SCHEME_HTTPS.clone()
        } else {
            SCHEME_HTTP.clone()
        }),
        HOST_NAME_TAG => to_header_value(get_hostname()),
        REMOTE_ADDR_TAG => {
            ctx.conn.remote_addr.as_deref().and_then(to_header_value)
        },
        REMOTE_PORT_TAG => ctx.conn.remote_port.and_then(|p| {
            // Use `itoa` to format the integer directly into a valid header value
            // without creating an intermediate `String`.
            HeaderValue::from_str(itoa::Buffer::new().format(p)).ok()
        }),
        SERVER_ADDR_TAG => {
            ctx.conn.server_addr.as_deref().and_then(to_header_value)
        },
        SERVER_PORT_TAG => ctx.conn.server_port.and_then(|p| {
            HeaderValue::from_str(itoa::Buffer::new().format(p)).ok()
        }),
        UPSTREAM_ADDR_TAG => {
            if !ctx.upstream.address.is_empty() {
                to_header_value(&ctx.upstream.address)
            } else {
                None
            }
        },
        PROXY_ADD_FORWARDED_TAG => {
            ctx.conn.remote_addr.as_deref().and_then(|remote_addr| {
                // Build the new `x-forwarded-for` value efficiently using `BytesMut` to avoid `format!`.
                let mut value_buf = BytesMut::new();
                if let Some(existing) =
                    session.get_header(HTTP_HEADER_X_FORWARDED_FOR)
                {
                    value_buf.extend_from_slice(existing.as_bytes());
                    value_buf.extend_from_slice(b", ");
                }
                value_buf.extend_from_slice(remote_addr.as_bytes());
                HeaderValue::from_bytes(&value_buf).ok()
            })
        },
        // If no predefined tag matches, it might be a different type of variable (e.g., `$http_...`).
        _ => handle_special_headers(buf, session, ctx),
    }
}

/// A helper function to handle more complex or less common special header variables.
/// This function is called as a fallback from `convert_header_value`.
#[inline]
fn handle_special_headers(
    buf: &[u8],
    session: &Session,
    ctx: &Ctx,
) -> Option<HeaderValue> {
    // Handle variables that reference other request headers, like `$http_user_agent`.
    if buf.starts_with(b"$http_") {
        // Attempt to parse the header name from the slice after the prefix.
        let key = std::str::from_utf8(&buf[6..]).ok()?;
        // Get the corresponding header from the request and clone its value.
        return session.get_header(key).cloned();
    }
    // Handle variables that reference environment variables, like `$PATH`.
    if buf.starts_with(b"$") {
        let var_name = std::str::from_utf8(&buf[1..]).ok()?;
        // Look up the environment variable and convert its value to a HeaderValue.
        return std::env::var(var_name)
            .ok()
            .and_then(|v| HeaderValue::from_str(&v).ok());
    }
    // Handle variables that reference fields in the `Ctx` struct, like `:connection_id`.
    if buf.starts_with(b":") {
        let key = std::str::from_utf8(&buf[1..]).ok()?;
        // Use `append_log_value` to get the string representation of the context field.
        let mut value = BytesMut::with_capacity(20);
        ctx.append_log_value(&mut value, key);
        if !value.is_empty() {
            // Convert the resulting bytes to a HeaderValue.
            return HeaderValue::from_bytes(&value).ok();
        }
    }
    // If no pattern matches, return None.
    None
}

/// Gets the remote address (IP and port) from the session.
pub fn get_remote_addr(session: &Session) -> Option<(String, u16)> {
    session
        .client_addr()
        // Ensure the address is an IP address (v4 or v6).
        .and_then(|addr| addr.as_inet())
        // Map it to a tuple of (String, u16).
        .map(|addr| (addr.ip().to_string(), addr.port()))
}

/// Gets the client's IP address by checking proxy headers first, then the direct connection address.
///
/// The lookup order is:
/// 1. `X-Forwarded-For` (taking the first IP in the list)
/// 2. `X-Real-IP`
/// 3. The remote address of the direct TCP connection
pub fn get_client_ip(session: &Session) -> String {
    // 1. Check `X-Forwarded-For`.
    if let Some(value) = session.get_header(HTTP_HEADER_X_FORWARDED_FOR) {
        // Efficiently take the first IP without creating an intermediate Vec.
        if let Ok(s) = value.to_str() {
            if let Some(ip) = s.split(',').next() {
                let trimmed_ip = ip.trim();
                if !trimmed_ip.is_empty() {
                    return trimmed_ip.to_string();
                }
            }
        }
    }
    // 2. Check `X-Real-IP`.
    if let Some(value) = session.get_header(HTTP_HEADER_X_REAL_IP) {
        return value.to_str().unwrap_or_default().to_string();
    }
    // 3. Fall back to the direct connection's remote address.
    if let Some((addr, _)) = get_remote_addr(session) {
        return addr;
    }
    // If all checks fail, return an empty string.
    "".to_string()
}

/// A convenient helper to get a header value as a `&str` from a `RequestHeader`.
pub fn get_req_header_value<'a>(
    req_header: &'a RequestHeader,
    key: &str,
) -> Option<&'a str> {
    // Get the header by its key.
    if let Some(value) = req_header.headers.get(key) {
        // Try to convert it to a string slice. Fails if the value is not valid UTF-8.
        if let Ok(value) = value.to_str() {
            return Some(value);
        }
    }
    None
}

/// Parses the "Cookie" header to find the value of a specific cookie.
pub fn get_cookie_value<'a>(
    req_header: &'a RequestHeader,
    cookie_name: &str,
) -> Option<&'a str> {
    // First, get the entire "Cookie" header string. The '?' operator will short-circuit if it's not present.
    get_req_header_value(req_header, "cookie")?
        // Split the string into individual cookies.
        .split(';')
        // `find_map` is an efficient way to find the first cookie that matches our criteria.
        .find_map(|item| {
            // This chained logic attempts to quickly find a match.
            // It's more complex to handle cases like "key=value" vs "key=" correctly.
            item.trim()
                .strip_prefix(cookie_name)?
                .strip_prefix('=')
                .or_else(|| {
                    // Fallback logic to ensure the cookie name is an exact match.
                    let (k, v) = item.split_once('=')?;
                    if k.trim() == cookie_name {
                        Some(v.trim())
                    } else {
                        None
                    }
                })
        })
}

/// Gets the value of a specific query parameter from the request URI.
pub fn get_query_value<'a>(
    req_header: &'a RequestHeader,
    name: &str,
) -> Option<&'a str> {
    // Get the query string from the URI, exiting if it doesn't exist.
    req_header
        .uri
        .query()?
        // Split the query string into key-value pairs.
        .split('&')
        // `find_map` efficiently searches for the first pair where the key matches.
        .find_map(|item| {
            // Split the pair into key and value.
            let (k, v) = item.split_once('=')?;
            // If the key matches, return the value.
            if k == name {
                Some(v)
            } else {
                None
            }
        })
}

/// Removes a specific query parameter from the request header's URI.
///
/// This function modifies the `req_header` in place.
pub fn remove_query_from_header(
    req_header: &mut RequestHeader,
    name: &str,
) -> Result<(), http::uri::InvalidUri> {
    // If there is no query string, there is nothing to do.
    let Some(query_str) = req_header.uri.query() else {
        return Ok(());
    };

    // Pre-allocate a String with enough capacity to hold the new query string,
    // which is a performance optimization to avoid reallocations.
    let mut new_query = String::with_capacity(query_str.len());

    // Iterate over each key-value pair in the original query string.
    for item in query_str.split('&') {
        // Get the key part of the pair.
        let key = item.split('=').next().unwrap_or(item);

        // If the key is not the one we want to remove, keep the item.
        if key != name {
            // If the new query string is not empty, add a separator first.
            if !new_query.is_empty() {
                new_query.push('&');
            }
            // Append the original "key=value" slice, which is allocation-free.
            new_query.push_str(item);
        }
    }

    // Reconstruct the URI from its path and the new query string.
    let path = req_header.uri.path();
    // Use `Cow` (Clone-on-Write) to avoid allocating a new String for the path if the query is empty.
    let new_uri_str = if new_query.is_empty() {
        // If the new query is empty, the new URI is just the path. Borrow it.
        Cow::Borrowed(path)
    } else {
        // If the new query is not empty, build a new String. Own it.
        let mut s = String::with_capacity(path.len() + 1 + new_query.len());
        // `write!` is an efficient way to format into an existing String buffer.
        let _ = write!(&mut s, "{}?{}", path, &new_query);
        Cow::Owned(s)
    };

    // Parse the newly constructed string into a `http::Uri`.
    let new_uri = http::Uri::from_str(&new_uri_str)?;
    // Update the request header with the new URI.
    req_header.set_uri(new_uri);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConnectionInfo, UpstreamInfo};
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
            upstream: UpstreamInfo {
                address: "10.1.1.3:4123".to_string(),
                ..Default::default()
            },
            conn: ConnectionInfo {
                id: 102,
                remote_addr: Some("10.1.1.1".to_string()),
                remote_port: Some(6000),
                server_addr: Some("10.1.1.2".to_string()),
                server_port: Some(6001),
                tls_version: Some("tls1.3".to_string()),
                ..Default::default()
            },
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
                conn: ConnectionInfo {
                    remote_addr: Some("10.1.1.1".to_string()),
                    ..Default::default()
                },
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
                conn: ConnectionInfo {
                    remote_addr: Some("10.1.1.1".to_string()),
                    ..Default::default()
                },
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
                upstream: UpstreamInfo {
                    address: "10.1.1.1:8001".to_string(),
                    ..Default::default()
                },
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

    /// Tests `convert_header` with edge cases like empty strings,
    /// strings without colons, and invalid header names/values.
    #[test]
    fn test_convert_header_edge_cases() {
        // Empty string should result in Ok(None).
        assert!(convert_header("").unwrap().is_none());
        // String without a colon should result in Ok(None).
        assert!(convert_header("no-colon").unwrap().is_none());
        // Invalid header name should result in an error.
        assert!(convert_header("Invalid Name: value").is_err());
        // Invalid header value (with newline) should result in an error.
        assert!(convert_header("Valid-Name: invalid\r\nvalue").is_err());
    }

    /// Tests `get_host` logic with different request formats.
    #[test]
    fn test_get_host_variants() {
        // Case 1: Host is in the URI authority.
        let uri_string = "http://user:pass@authority.com/path";

        // 使用 .parse() 或 from_str 来创建 Uri
        let uri = http::Uri::from_str(uri_string).unwrap();
        let mut req_with_authority =
            RequestHeader::build("GET", b"/path", None).unwrap();
        req_with_authority.set_uri(uri);
        assert_eq!(get_host(&req_with_authority), Some("authority.com"));

        // Case 2: Host is in the "Host" header.
        let mut req_with_host_header =
            RequestHeader::build("GET", b"/path", None).unwrap();
        req_with_host_header
            .insert_header("Host", "header-host.com:8080")
            .unwrap();
        assert_eq!(get_host(&req_with_host_header), Some("header-host.com"));

        // Case 3: No host information available.
        let req_no_host = RequestHeader::build("GET", b"/path", None).unwrap();
        assert_eq!(get_host(&req_no_host), None);
    }

    /// Tests `get_cookie_value` with multiple cookies and edge cases.
    #[test]
    fn test_get_cookie_value_advanced() {
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("Cookie", "id=123; session=abc; theme=dark")
            .unwrap();

        assert_eq!(get_cookie_value(&req, "session"), Some("abc"));
        assert_eq!(get_cookie_value(&req, "id"), Some("123"));
        assert_eq!(get_cookie_value(&req, "theme"), Some("dark"));
        // Test for a non-existent cookie.
        assert_eq!(get_cookie_value(&req, "lang"), None);
        // Test for a cookie name that is a prefix of another.
        assert_eq!(get_cookie_value(&req, "the"), None);
    }

    #[test]
    fn test_remove_query_from_header_variants() {
        // Case 1: Remove the only query param.
        let mut req =
            RequestHeader::build("GET", b"/path?key=val", None).unwrap();
        remove_query_from_header(&mut req, "key").unwrap();
        assert_eq!(req.uri.to_string(), "/path");

        // Case 2: Remove the first of multiple params.
        let mut req =
            RequestHeader::build("GET", b"/path?key1=val1&key2=val2", None)
                .unwrap();
        remove_query_from_header(&mut req, "key1").unwrap();
        assert_eq!(req.uri.to_string(), "/path?key2=val2");

        // Case 3: Remove the last of multiple params.
        let mut req =
            RequestHeader::build("GET", b"/path?key1=val1&key2=val2", None)
                .unwrap();
        remove_query_from_header(&mut req, "key2").unwrap();
        assert_eq!(req.uri.to_string(), "/path?key1=val1");

        // Case 4: Remove a middle param.
        let mut req =
            RequestHeader::build("GET", b"/path?key1=v1&key2=v2&key3=v3", None)
                .unwrap();
        remove_query_from_header(&mut req, "key2").unwrap();
        assert_eq!(req.uri.to_string(), "/path?key1=v1&key3=v3");

        // Case 5: Param to remove is not present.
        let mut req =
            RequestHeader::build("GET", b"/path?key=val", None).unwrap();
        remove_query_from_header(&mut req, "nonexistent").unwrap();
        assert_eq!(req.uri.to_string(), "/path?key=val");

        // Case 6: No query string to begin with.
        let mut req = RequestHeader::build("GET", b"/path", None).unwrap();
        remove_query_from_header(&mut req, "key").unwrap();
        assert_eq!(req.uri.to_string(), "/path");
    }
}
