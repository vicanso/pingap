use glob::glob;
use path_absolutize::*;
use serde::Deserialize;
use snafu::{ensure, ResultExt, Snafu};
use std::path::Path;
use substring::Substring;
use toml::{map::Map, Value};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Invalid error {message}"))]
    Invalid { message: String },
    #[snafu(display("Glob pattern error {source}"))]
    Pattern { source: glob::PatternError },
    #[snafu(display("Glob error {source}"))]
    Glob { source: glob::GlobError },
    #[snafu(display("Io error {source}"))]
    Io { source: std::io::Error },
    #[snafu(display("Toml de error {source}"))]
    De { source: toml::de::Error },
}
type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Deserialize, Debug)]
struct TomlConfig {
    servers: Map<String, Value>,
    upstreams: Map<String, Value>,
    locations: Map<String, Value>,
}

#[derive(Default, Debug)]
pub struct Config {
    pub servers: Vec<String>,
    pub upstreams: Vec<String>,
    pub locations: Vec<String>,
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

fn format_toml(name: &str, value: &Value) -> String {
    if let Some(value) = value.as_table() {
        let mut data = value.clone();
        data.insert("name".to_string(), Value::String(name.to_string()));
        data.to_string()
    } else {
        "".to_string()
    }
}

pub fn load_config(path: &str) -> Result<Config> {
    let filepath = resolve_path(path);
    ensure!(
        !filepath.is_empty(),
        InvalidSnafu {
            message: "Config path is empty".to_string()
        }
    );
    let mut data = vec![];
    if Path::new(&filepath).is_dir() {
        for entry in glob(&format!("{filepath}/**/*.toml")).context(PatternSnafu)? {
            let f = entry.context(GlobSnafu)?;
            let mut buf = std::fs::read(&f).context(IoSnafu)?;
            data.append(&mut buf);
            data.push(0x0a);
        }
    } else {
        let mut buf = std::fs::read(&filepath).context(IoSnafu)?;
        data.append(&mut buf);
    }
    let data: TomlConfig = toml::from_str(
        std::string::String::from_utf8_lossy(&data)
            .to_string()
            .as_str(),
    )
    .context(DeSnafu)?;
    let mut conf = Config::default();
    for (name, value) in data.upstreams.iter() {
        conf.upstreams.push(format_toml(name, value));
    }
    for (name, value) in data.locations.iter() {
        conf.locations.push(format_toml(name, value));
    }
    for (name, value) in data.servers.iter() {
        conf.servers.push(format_toml(name, value));
    }

    Ok(conf)
}
