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

use std::error::Error;
use std::fs;
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Mutex;
use tracing::{info, Level};
use tracing_subscriber::fmt::writer::BoxMakeWriter;
use crate::util;

#[derive(Default, Debug)]
pub struct LoggerParams {
    pub file: String,
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
    let writer = if params.file.is_empty() {
        BoxMakeWriter::new(std::io::stderr)
    } else {
        let file = util::resolve_path(&params.file);
        let filepath = Path::new(&file);
        if let Some(dir) = filepath.parent() {
            fs::create_dir_all(dir)?;
        }
        let file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            // open read() in case there are no readers
            // available otherwise we will panic with
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(filepath)?;
        if params.capacity < 4096 {
            BoxMakeWriter::new(file)
        } else {
            // buffer writer for better performance
            let w =
                io::BufWriter::with_capacity(params.capacity as usize, file);
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
