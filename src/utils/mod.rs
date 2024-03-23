use http::{HeaderName, HeaderValue};
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

pub fn split_to_two_trim(value: &str, pat: &str) -> Option<[String; 2]> {
    let arr: Vec<&str> = value.split(pat).collect();
    if arr.len() < 2 {
        return None;
    }
    let value = arr[1..].join(pat).trim().to_string();

    Some([arr[0].trim().to_string(), value])
}

pub fn convert_headers(header_values: &[String]) -> Result<Vec<(HeaderName, HeaderValue)>> {
    let mut arr = vec![];
    for item in header_values {
        if let Some([k, v]) = split_to_two_trim(item, ":") {
            let name =
                HeaderName::from_str(&k).context(InvalidHeaderNameSnafu { value: k.clone() })?;
            let value =
                HeaderValue::from_str(&v).context(InvalidHeaderValueSnafu { value: v.clone() })?;
            arr.push((name, value));
        }
    }
    Ok(arr)
}

const NAME: &str = env!("CARGO_PKG_NAME");
const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn get_pkg_name() -> &'static str {
    NAME
}

pub fn get_pkg_version() -> &'static str {
    VERSION
}
