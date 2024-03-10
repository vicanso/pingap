use snafu::Snafu;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Addr parse error {source}"))]
    AddrParse { source: std::net::AddrParseError },
    #[snafu(display("Url parse error {source}"))]
    UrlParse { source: url::ParseError },
}

impl From<std::net::AddrParseError> for Error {
    fn from(err: std::net::AddrParseError) -> Self {
        Error::AddrParse { source: err }
    }
}

impl From<url::ParseError> for Error {
    fn from(err: url::ParseError) -> Self {
        Error::UrlParse { source: err }
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
