use path_absolutize::*;
use pingora::proxy::Session;
use std::path::Path;
use substring::Substring;

pub fn split_to_two_trim(value: &str, pat: &str) -> Option<[String; 2]> {
    let arr: Vec<&str> = value.split(pat).collect();
    if arr.len() < 2 {
        return None;
    }
    let value = arr[1..].join(pat).trim().to_string();

    Some([arr[0].trim().to_string(), value])
}

const NAME: &str = env!("CARGO_PKG_NAME");
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Gets the package name.
pub fn get_pkg_name() -> &'static str {
    NAME
}

/// Gets the package version.
pub fn get_pkg_version() -> &'static str {
    VERSION
}

/// Resolves the path as absolute.
pub fn resolve_path(path: &str) -> String {
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

/// Gets client ip from X-Forwarded-For,
/// If none, get from X-Real-Ip,
/// If none, get remote addr
pub fn get_client_ip(session: &Session) -> String {
    if let Some(value) = session.get_header("X-Forwarded-For") {
        let arr: Vec<&str> = value.to_str().unwrap_or_default().split(',').collect();
        if !arr.is_empty() {
            return arr[0].trim().to_string();
        }
    }
    if let Some(value) = session.get_header("X-Real-Ip") {
        return value.to_str().unwrap_or_default().to_string();
    }
    // TODO get remote addr
    "".to_string()
}
