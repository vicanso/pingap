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

use http::header;
use http::{HeaderName, HeaderValue};
use once_cell::sync::Lazy;
use snafu::{ResultExt, Snafu};
use std::str::FromStr;

pub const HOST_NAME_TAG: &[u8] = b"$hostname";
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

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
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
}
