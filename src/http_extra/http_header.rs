use crate::utils::split_to_two_trim;
use http::header;
use http::{HeaderName, HeaderValue};
use once_cell::sync::Lazy;
use snafu::{ResultExt, Snafu};
use std::str::FromStr;

#[derive(Debug, Snafu)]
pub enum Error {
    InvalidHeaderValue {
        value: String,
        source: http::header::InvalidHeaderValue,
    },
    #[snafu(display("Invalid header name {source}, {value}"))]
    InvalidHeaderName {
        value: String,
        source: http::header::InvalidHeaderName,
    },
}
type Result<T, E = Error> = std::result::Result<T, E>;

pub type HttpHeader = (HeaderName, HeaderValue);

/// Converts string slice to http headers
pub fn convert_headers(header_values: &[String]) -> Result<Vec<HttpHeader>> {
    let mut arr = vec![];
    for item in header_values {
        if let Some([k, v]) = split_to_two_trim(item, ":") {
            let name = HeaderName::from_str(&k).context(InvalidHeaderNameSnafu { value: k })?;
            let value = HeaderValue::from_str(&v).context(InvalidHeaderValueSnafu { value: v })?;
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
