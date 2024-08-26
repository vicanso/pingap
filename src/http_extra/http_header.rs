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

use crate::state::{get_hostname, State};
use crate::util;
use bytes::BytesMut;
use http::header;
use http::{HeaderName, HeaderValue};
use once_cell::sync::Lazy;
use pingora::proxy::Session;
use snafu::{ResultExt, Snafu};
use std::str::FromStr;

pub const HOST_NAME_TAG: &[u8] = b"$hostname";
const REMOTE_ADDR_TAG: &[u8] = b"$remote_addr";
const PROXY_ADD_FORWARDED_TAG: &[u8] = b"$proxy_add_x_forwarded_for";
const HTTP_ORIGIN_TAG: &[u8] = b"$http_origin";
const UPSTREAM_ADDR_TAG: &[u8] = b"$upstream_addr";

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Invalid header value {source}, {value}"))]
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

pub fn convert_header(value: &str) -> Result<Option<HttpHeader>> {
    if let Some((k, v)) =
        value.split_once(':').map(|(k, v)| (k.trim(), v.trim()))
    {
        let name = HeaderName::from_str(k)
            .context(InvalidHeaderNameSnafu { value: k })?;
        let value = HeaderValue::from_str(v)
            .context(InvalidHeaderValueSnafu { value: v })?;
        Ok(Some((name, value)))
    } else {
        Ok(None)
    }
}

#[inline]
pub fn convert_header_value(
    value: &HeaderValue,
    session: &Session,
    ctx: &State,
) -> Option<HeaderValue> {
    let buf = value.as_bytes();
    match buf {
        HOST_NAME_TAG => {
            return HeaderValue::from_str(get_hostname()).ok();
        },
        REMOTE_ADDR_TAG => {
            if let Some(remote_addr) = &ctx.remote_addr {
                return HeaderValue::from_str(remote_addr).ok();
            }
        },
        UPSTREAM_ADDR_TAG => {
            if !ctx.upstream_address.is_empty() {
                return HeaderValue::from_str(&ctx.upstream_address).ok();
            }
        },
        PROXY_ADD_FORWARDED_TAG => {
            if let Some(remote_addr) = &ctx.remote_addr {
                let value = if let Some(value) = session
                    .get_header(util::HTTP_HEADER_X_FORWARDED_FOR.clone())
                {
                    format!(
                        "{}, {}",
                        value.to_str().unwrap_or_default(),
                        remote_addr
                    )
                } else {
                    remote_addr.to_string()
                };
                return HeaderValue::from_str(&value).ok();
            }
        },
        HTTP_ORIGIN_TAG => {
            return session.get_header("origin").cloned();
        },
        _ => {
            if buf.starts_with(b"$") {
                if let Ok(value) = std::env::var(
                    std::str::from_utf8(&buf[1..buf.len()]).unwrap_or_default(),
                ) {
                    return HeaderValue::from_str(&value).ok();
                }
            } else if buf.starts_with(b":") {
                let mut value = BytesMut::with_capacity(20);
                value = ctx.append_value(
                    value,
                    std::str::from_utf8(&buf[1..buf.len()]).unwrap_or_default(),
                );
                if !value.is_empty() {
                    return HeaderValue::from_bytes(&value).ok();
                }
            }
        },
    };
    // not match return none
    None
}

/// Convert string slice to http headers.
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
    use crate::state::State;

    use super::{
        convert_header_value, convert_headers, HTTP_HEADER_CONTENT_HTML,
        HTTP_HEADER_CONTENT_JSON, HTTP_HEADER_NAME_X_REQUEST_ID,
        HTTP_HEADER_NO_CACHE, HTTP_HEADER_NO_STORE,
        HTTP_HEADER_TRANSFER_CHUNKED, HTTP_HEADER_WWW_AUTHENTICATE,
    };
    use http::HeaderValue;
    use pingora::proxy::Session;
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

    #[tokio::test]
    async fn test_convert_header_value() {
        let headers = [""].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let value = convert_header_value(
            &HeaderValue::from_str("$remote_addr").unwrap(),
            &session,
            &State {
                remote_addr: Some("10.1.1.1".to_string()),
                ..Default::default()
            },
        );
        assert_eq!(true, value.is_some());
        assert_eq!("10.1.1.1", value.unwrap().to_str().unwrap());

        let headers = ["X-Forwarded-For: 1.1.1.1, 2.2.2.2"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let value = convert_header_value(
            &HeaderValue::from_str("$proxy_add_x_forwarded_for").unwrap(),
            &session,
            &State {
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
            &State {
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
            &State {
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
            &State::default(),
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
            &State::default(),
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
            &State::default(),
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
            &State::default(),
        );
        assert_eq!(false, value.is_some());
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
            r#"www-authenticate: Basic realm="Pingap""#,
            format!(
                "{}: {}",
                HTTP_HEADER_WWW_AUTHENTICATE.0.to_string(),
                HTTP_HEADER_WWW_AUTHENTICATE.1.to_str().unwrap_or_default()
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
    }
}
