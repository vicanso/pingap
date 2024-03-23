use crate::utils::split_to_two_trim;
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

pub type HttpHeader = (HeaderName, HeaderValue);

pub fn convert_headers(header_values: &[String]) -> Result<Vec<HttpHeader>> {
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
