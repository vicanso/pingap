// Copyright 2024 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use http::HeaderName;
use once_cell::sync::Lazy;
use path_absolutize::*;
use pingora::proxy::Session;
use std::{path::Path, str::FromStr};
use substring::Substring;

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

pub static HTTP_HEADER_X_FORWARDED_FOR: Lazy<http::HeaderName> =
    Lazy::new(|| HeaderName::from_str("X-Forwarded-For").unwrap());

pub static HTTP_HEADER_X_REAL_IP: Lazy<http::HeaderName> =
    Lazy::new(|| HeaderName::from_str("X-Real-Ip").unwrap());

pub fn get_remote_addr(session: &Session) -> Option<String> {
    if let Some(addr) = session.client_addr() {
        if let Some(addr) = addr.as_inet() {
            return Some(addr.ip().to_string());
        }
    }
    None
}

/// Gets client ip from X-Forwarded-For,
/// If none, get from X-Real-Ip,
/// If none, get remote addr
pub fn get_client_ip(session: &Session) -> String {
    if let Some(value) = session.get_header(HTTP_HEADER_X_FORWARDED_FOR.clone()) {
        let arr: Vec<&str> = value.to_str().unwrap_or_default().split(',').collect();
        if !arr.is_empty() {
            return arr[0].trim().to_string();
        }
    }
    if let Some(value) = session.get_header(HTTP_HEADER_X_REAL_IP.clone()) {
        return value.to_str().unwrap_or_default().to_string();
    }
    if let Some(addr) = get_remote_addr(session) {
        return addr;
    }
    "".to_string()
}
