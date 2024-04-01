use crate::utils;
use base64::{engine::general_purpose::STANDARD, Engine};
use glob::glob;
use http::HeaderValue;
use serde::{Deserialize, Serialize};
use snafu::{ensure, ResultExt, Snafu};
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;
use toml::{map::Map, Value};
use url::Url;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("{message}"))]
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
    #[snafu(display("Toml ser error {source}"))]
    Ser { source: toml::ser::Error },
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
    #[snafu(display("base64 decode error {source}"))]
    Base64Decode { source: base64::DecodeError },
}
type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Default, Deserialize, Clone, Serialize)]
pub struct UpstreamConf {
    pub addrs: Vec<String>,
    pub algo: Option<String>,
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
impl UpstreamConf {
    pub fn validate(&self, name: &str) -> Result<()> {
        // validate upstream addr
        for addr in self.addrs.iter() {
            let arr: Vec<_> = addr.split(' ').collect();
            let _ = arr[0]
                .parse::<std::net::SocketAddr>()
                .context(AddrParseSnafu {
                    addr: format!("{}(upstream:{name})", arr[0]),
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
pub struct LocationConf {
    pub upstream: String,
    pub path: Option<String>,
    pub host: Option<String>,
    pub proxy_headers: Option<Vec<String>>,
    pub headers: Option<Vec<String>>,
    pub rewrite: Option<String>,
}

impl LocationConf {
    /// Validate the options of location config.
    fn validate(&self, name: &str, upstream_names: &[String]) -> Result<()> {
        // validate header for http
        let validate = |headers: &Option<Vec<String>>| -> Result<()> {
            if let Some(headers) = headers {
                for header in headers.iter() {
                    let arr = utils::split_to_two_trim(header, ":");
                    if arr.is_none() {
                        return Err(Error::Invalid {
                            message: format!("{header} is invalid header(location:{name})"),
                        });
                    }
                    HeaderValue::from_str(&arr.unwrap()[1]).map_err(|err| Error::Invalid {
                        message: format!("{}(location:{name})", err),
                    })?;
                }
            }
            Ok(())
        };
        validate(&self.proxy_headers)?;
        validate(&self.headers)?;
        if !upstream_names.contains(&self.upstream) {
            return Err(Error::Invalid {
                message: format!("{} upstream is not found(location:{name})", self.upstream),
            });
        }
        Ok(())
    }

    pub fn get_weight(&self) -> u32 {
        // path starts with
        // = 65536
        // prefix(default) 32768
        // ~ 16384
        // host exist 8192
        let mut weighted: u32 = 0;
        if let Some(path) = &self.path {
            if path.starts_with('=') {
                weighted += 65536;
            } else if path.starts_with('~') {
                weighted += 16384;
            } else {
                weighted += 32768;
            }
            weighted += path.len() as u32;
        };
        if self.host.is_some() {
            weighted += 8192;
        }
        weighted
    }
}

#[derive(Debug, Default, Deserialize, Clone, Serialize)]

pub struct ServerConf {
    pub addr: String,
    pub access_log: Option<String>,
    pub locations: Option<Vec<String>>,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub stats_path: Option<String>,
    pub admin_path: Option<String>,
}

impl ServerConf {
    /// Validate the options of server config.
    fn validate(&self, name: &str, location_names: &[String]) -> Result<()> {
        if let Some(locations) = &self.locations {
            for item in locations {
                if !location_names.contains(item) {
                    return Err(Error::Invalid {
                        message: format!("{item} location is not found(server:{name})"),
                    });
                }
            }
        }
        if let Some(value) = &self.tls_key {
            let _ = STANDARD.decode(value).context(Base64DecodeSnafu)?;
        }
        if let Some(value) = &self.tls_cert {
            let _ = STANDARD.decode(value).context(Base64DecodeSnafu)?;
        }

        Ok(())
    }
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct PingapConf {
    pub upstreams: HashMap<String, UpstreamConf>,
    pub locations: HashMap<String, LocationConf>,
    pub servers: HashMap<String, ServerConf>,
    pub error_template: String,
    pub pid_file: Option<String>,
    pub upgrade_sock: Option<String>,
    pub user: Option<String>,
    pub group: Option<String>,
    pub threads: Option<usize>,
    pub work_stealing: Option<bool>,
}

impl PingapConf {
    /// Validate the options of pinggap config.
    pub fn validate(&self) -> Result<()> {
        let mut upstream_names = vec![];
        for (name, upstream) in self.upstreams.iter() {
            upstream.validate(name)?;
            upstream_names.push(name.to_string());
        }
        let mut location_names = vec![];
        for (name, location) in self.locations.iter() {
            location.validate(name, &upstream_names)?;
            location_names.push(name.to_string());
        }
        for (name, server) in self.servers.iter() {
            server.validate(name, &location_names)?;
        }
        Ok(())
    }
}

#[derive(Deserialize, Debug)]
struct TomlConfig {
    servers: Map<String, Value>,
    upstreams: Map<String, Value>,
    locations: Map<String, Value>,
    error_template: Option<String>,
    pid_file: Option<String>,
    upgrade_sock: Option<String>,
    user: Option<String>,
    group: Option<String>,
    threads: Option<usize>,
    work_stealing: Option<bool>,
}

fn format_toml(value: &Value) -> String {
    if let Some(value) = value.as_table() {
        value.to_string()
    } else {
        "".to_string()
    }
}

/// Save the confog to path.
///
/// Validate the config before save.
pub fn save_config(path: &str, conf: &PingapConf) -> Result<()> {
    conf.validate()?;
    let filepath = utils::resolve_path(path);
    let buf = toml::to_string_pretty(conf).context(SerSnafu)?;
    std::fs::write(&filepath, buf).context(IoSnafu { file: filepath })?;

    Ok(())
}

/// Load the config from path.
pub fn load_config(path: &str, admin: bool) -> Result<PingapConf> {
    let filepath = utils::resolve_path(path);
    ensure!(
        !filepath.is_empty(),
        InvalidSnafu {
            message: "Config path is empty".to_string()
        }
    );

    if admin && !Path::new(&filepath).exists() {
        return Ok(PingapConf::default());
    }

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
    let threads = if let Some(threads) = data.threads {
        if threads > 0 {
            Some(threads)
        } else {
            Some(num_cpus::get())
        }
    } else {
        None
    };
    let mut conf = PingapConf {
        error_template: data.error_template.unwrap_or_default(),
        pid_file: data.pid_file,
        upgrade_sock: data.upgrade_sock,
        user: data.user,
        group: data.group,
        threads,
        work_stealing: data.work_stealing,
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

    Ok(conf)
}
