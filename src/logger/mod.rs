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

use crate::util;
use crate::util::convert_query_map;
use std::error::Error;
use std::fs;
use std::io;
use std::path::Path;
use std::sync::Mutex;
use tracing::{info, Level};
use tracing_subscriber::fmt::writer::BoxMakeWriter;

#[derive(Default, Debug)]
pub struct LoggerParams {
    pub log: String,
    pub level: String,
    pub capacity: u64,
    pub json: bool,
}

pub fn logger_try_init(params: LoggerParams) -> Result<(), Box<dyn Error>> {
    let level = if params.level.is_empty() {
        std::env::var("RUST_LOG").unwrap_or("INFO".to_string())
    } else {
        params.level.clone()
    };

    let level = match level.to_lowercase().as_str() {
        "error" => Level::ERROR,
        "warn" => Level::WARN,
        "debug" => Level::DEBUG,
        _ => Level::INFO,
    };

    let seconds = chrono::Local::now().offset().local_minus_utc();
    let hours = (seconds / 3600) as i8;
    let minutes = ((seconds % 3600) / 60) as i8;
    let is_dev = cfg!(debug_assertions);

    let builder = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_ansi(is_dev)
        .with_timer(tracing_subscriber::fmt::time::OffsetTime::new(
            time::UtcOffset::from_hms(hours, minutes, 0).unwrap(),
            time::format_description::well_known::Rfc3339,
        ))
        .with_target(is_dev);
    let writer = if params.log.is_empty() {
        BoxMakeWriter::new(std::io::stderr)
    } else {
        let mut file = util::resolve_path(&params.log);
        let mut rolling_type = "".to_string();
        if let Some((_, query)) = params.log.split_once('?') {
            file = file.replace(&format!("?{query}"), "");
            let m = convert_query_map(query);
            if let Some(value) = m.get("rolling") {
                rolling_type = value.to_string();
            }
        }

        let filepath = Path::new(&file);
        let dir = if filepath.is_dir() {
            filepath
        } else {
            filepath.parent().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Other,
                    "parent of file log is invalid",
                )
            })?
        };
        fs::create_dir_all(dir)?;
        let filename = if filepath.is_dir() {
            "".to_string()
        } else {
            filepath
                .file_name()
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::Other, "file log is invalid")
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

        if params.capacity < 4096 {
            BoxMakeWriter::new(file_appender)
        } else {
            // buffer writer for better performance
            let w = io::BufWriter::with_capacity(
                params.capacity as usize,
                file_appender,
            );
            BoxMakeWriter::new(Mutex::new(w))
        }
    };
    if params.json {
        builder
            .event_format(tracing_subscriber::fmt::format::json())
            .with_writer(writer)
            .init();
    } else {
        builder.with_writer(writer).init();
    }

    info!(
        capacity = params.capacity,
        utc_offset = chrono::Local::now().offset().to_string(),
        "init tracing subscriber success",
    );

    Ok(())
}
