use glob::glob;
use path_absolutize::*;
use serde::{Deserialize, Serialize};
use snafu::{ensure, ResultExt, Snafu};
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;
use substring::Substring;
use toml::{map::Map, Value};
use url::Url;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Invalid error {message}"))]
    Invalid { message: String },
    #[snafu(display("Glob pattern error {source}, {path}"))]
    Pattern {
        source: glob::PatternError,
        path: String,
    },
    #[snafu(display("Glob error {source}"))]
    Glob { source: glob::GlobError },
    #[snafu(display("Io error {source}, {file}"))]
    Io {
        source: std::io::Error,
        file: String,
    },
    #[snafu(display("Toml de error {source}"))]
    De { source: toml::de::Error },
    #[snafu(display("Url parse error {source}, {url}"))]
    UrlParse {
        source: url::ParseError,
        url: String,
    },
    #[snafu(display("Addr parse error {source}, {addr}"))]
    AddrParse {
        source: std::net::AddrParseError,
        addr: String,
    },
}
type Result<T, E = Error> = std::result::Result<T, E>;

impl UpstreamConf {
    pub fn validate(&self) -> Result<()> {
        // validate upstream addr
        for addr in self.addrs.iter() {
            let arr: Vec<_> = addr.split(' ').collect();
            let _ = arr[0]
                .parse::<std::net::SocketAddr>()
                .context(AddrParseSnafu {
                    addr: arr[0].to_string(),
                });
        }
        // validate health check
        let health_check = self.health_check.clone().unwrap_or_default();
        if !health_check.is_empty() {
            let _ = Url::parse(&health_check).context(UrlParseSnafu { url: health_check })?;
        }

        Ok(())
    }
}

#[derive(Debug, Default, Deserialize, Clone, Serialize)]
pub struct UpstreamConf {
    pub addrs: Vec<String>,
    pub lb: Option<String>,
    pub sni: Option<String>,
    pub health_check: Option<String>,
    pub ipv4_only: Option<bool>,
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub connection_timeout: Option<Duration>,
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub total_connection_timeout: Option<Duration>,
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub read_timeout: Option<Duration>,
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub idle_timeout: Option<Duration>,
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub write_timeout: Option<Duration>,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct LocationConf {
    pub path: Option<String>,
    pub host: Option<String>,
    pub proxy_headers: Option<Vec<String>>,
    pub headers: Option<Vec<String>>,
    pub rewrite: Option<String>,
    pub upstream: String,
}

#[derive(Debug, Default, Deserialize, Clone)]

pub struct ServerConf {
    pub addr: String,
    pub access_log: Option<String>,
    pub locations: Option<Vec<String>>,
}

static ERROR_TEMPLATE: &str = include_str!("../../error.html");

#[derive(Debug, Default, Clone)]
pub struct PingapConf {
    pub upstreams: HashMap<String, UpstreamConf>,
    pub locations: HashMap<String, LocationConf>,
    pub servers: HashMap<String, ServerConf>,
    pub error_template: String,
}

impl PingapConf {
    pub fn validate(&self) -> Result<()> {
        // TODO validate
        Ok(())
    }
}

#[derive(Deserialize, Debug)]
struct TomlConfig {
    servers: Map<String, Value>,
    upstreams: Map<String, Value>,
    locations: Map<String, Value>,
    error_template: Option<String>,
}

fn resolve_path(path: &str) -> String {
    if path.is_empty() {
        return "".to_string();
    }
    let mut p = path.to_string();
    if p.starts_with('~') {
        if let Some(home) = dirs::home_dir() {
            p = home.to_string_lossy().to_string() + p.substring(1, p.len());
        };
    }
    if let Ok(p) = Path::new(&p).absolutize() {
        p.to_string_lossy().to_string()
    } else {
        p
    }
}

fn format_toml(value: &Value) -> String {
    if let Some(value) = value.as_table() {
        value.to_string()
    } else {
        "".to_string()
    }
}

pub fn load_config(path: &str) -> Result<PingapConf> {
    let filepath = resolve_path(path);
    ensure!(
        !filepath.is_empty(),
        InvalidSnafu {
            message: "Config path is empty".to_string()
        }
    );
    let mut data = vec![];
    if Path::new(&filepath).is_dir() {
        for entry in
            glob(&format!("{filepath}/**/*.toml")).context(PatternSnafu { path: filepath })?
        {
            let f = entry.context(GlobSnafu)?;
            let mut buf = std::fs::read(&f).context(IoSnafu {
                file: f.to_string_lossy().to_string(),
            })?;
            data.append(&mut buf);
            data.push(0x0a);
        }
    } else {
        let mut buf = std::fs::read(&filepath).context(IoSnafu { file: filepath })?;
        data.append(&mut buf);
    }
    let data: TomlConfig = toml::from_str(
        std::string::String::from_utf8_lossy(&data)
            .to_string()
            .as_str(),
    )
    .context(DeSnafu)?;
    let mut conf = PingapConf {
        error_template: data.error_template.unwrap_or_default(),
        ..Default::default()
    };
    for (name, value) in data.upstreams {
        let upstream: UpstreamConf =
            toml::from_str(format_toml(&value).as_str()).context(DeSnafu)?;
        conf.upstreams.insert(name, upstream);
    }
    for (name, value) in data.locations {
        let location: LocationConf =
            toml::from_str(format_toml(&value).as_str()).context(DeSnafu)?;
        conf.locations.insert(name, location);
    }
    for (name, value) in data.servers {
        let server: ServerConf = toml::from_str(format_toml(&value).as_str()).context(DeSnafu)?;
        conf.servers.insert(name, server);
    }
    if conf.error_template.is_empty() {
        conf.error_template = ERROR_TEMPLATE.to_string();
    }

    Ok(conf)
}
