use snafu::Snafu;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Addr parse error {source}"))]
    AddrParse { source: std::net::AddrParseError },
    #[snafu(display("Url parse error {source}"))]
    UrlParse { source: url::ParseError },
    #[snafu(display("Invalid error {category} {message}"))]
    Invalid { category: String, message: String },
    #[snafu(display("Toml de error {source}"))]
    TomlDe { source: toml::de::Error },
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

impl From<Error> for pingora::BError {
    fn from(_value: Error) -> Self {
        // TODO convert error
        pingora::Error::new_str("server upstream error")
    }
}
impl From<toml::de::Error> for Error {
    fn from(err: toml::de::Error) -> Self {
        Error::TomlDe { source: err }
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
