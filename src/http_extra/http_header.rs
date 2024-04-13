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

use http::header;
use http::{HeaderName, HeaderValue};
use once_cell::sync::Lazy;
use snafu::{ResultExt, Snafu};
use std::str::FromStr;

#[derive(Debug, Snafu)]
pub enum Error {
    InvalidHeaderValue {
        value: String,
        source: header::InvalidHeaderValue,
    },
    #[snafu(display("Invalid header name {source}, {value}"))]
    InvalidHeaderName {
        value: String,
        source: header::InvalidHeaderName,
    },
}
type Result<T, E = Error> = std::result::Result<T, E>;

pub type HttpHeader = (HeaderName, HeaderValue);

/// Converts string slice to http headers.
pub fn convert_headers(header_values: &[String]) -> Result<Vec<HttpHeader>> {
    let mut arr = vec![];
    for item in header_values {
        if let Some((k, v)) = item.split_once(':').map(|(k, v)| (k.trim(), v.trim())) {
            let name = HeaderName::from_str(k).context(InvalidHeaderNameSnafu { value: k })?;
            let value = HeaderValue::from_str(v).context(InvalidHeaderValueSnafu { value: v })?;
            arr.push((name, value));
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

pub static HTTP_HEADER_WWW_AUTHENTICATE: Lazy<HttpHeader> = Lazy::new(|| {
    (
        header::WWW_AUTHENTICATE,
        HeaderValue::from_str(r###"Basic realm="Pingap""###).unwrap(),
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

pub static HTTP_HEADER_TRANSFER_CHUNKED: Lazy<HttpHeader> = Lazy::new(|| {
    (
        header::TRANSFER_ENCODING,
        HeaderValue::from_str("chunked").unwrap(),
    )
});

#[cfg(test)]
mod tests {
    use super::convert_headers;
    use pretty_assertions::assert_eq;
    #[test]
    fn test_convert_headers() {
        let headers =
            convert_headers(&["Content-Type: application/octet-stream".to_string()]).unwrap();
        assert_eq!(1, headers.len());
        assert_eq!("content-type", headers[0].0.to_string());
        assert_eq!("application/octet-stream", headers[0].1.to_str().unwrap());
    }
}
