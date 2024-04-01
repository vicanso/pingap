use path_absolutize::*;
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

pub fn get_pkg_name() -> &'static str {
    NAME
}

pub fn get_pkg_version() -> &'static str {
    VERSION
}

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
