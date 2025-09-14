// Copyright 2024-2025 Tree xie.
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

use super::Error;
use pingap_core::parse_query_string;
use std::fs;
use std::path::Path;
use tracing_appender::rolling::RollingFileAppender;

pub(crate) fn new_file_appender(
    log_path: &str,
) -> Result<RollingFileAppender, Error> {
    let mut file = pingap_util::resolve_path(log_path);
    let mut rolling_type = "".to_string();
    if let Some((_, query)) = log_path.split_once('?') {
        file = file.replace(&format!("?{query}"), "");
        let m = parse_query_string(query);
        if let Some(value) = m.get("rolling") {
            rolling_type = value.to_string();
        }
    }

    let filepath = Path::new(&file);
    let dir = if filepath.is_dir() {
        filepath
    } else {
        filepath.parent().ok_or_else(|| Error::Invalid {
            message: "parent of file log is invalid".to_string(),
        })?
    };
    fs::create_dir_all(dir).map_err(|e| Error::Io { source: e })?;

    let filename = if filepath.is_dir() {
        "".to_string()
    } else {
        filepath
            .file_name()
            .ok_or_else(|| Error::Invalid {
                message: "file log is invalid".to_string(),
            })?
            .to_string_lossy()
            .to_string()
    };
    let file_appender = match rolling_type.as_str() {
        "minutely" => tracing_appender::rolling::minutely(dir, filename),
        "hourly" => tracing_appender::rolling::hourly(dir, filename),
        "never" => tracing_appender::rolling::never(dir, filename),
        _ => tracing_appender::rolling::daily(dir, filename),
    };
    Ok(file_appender)
}
