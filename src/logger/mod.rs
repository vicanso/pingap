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

use crate::service::{CommonServiceTask, ServiceTask};
use crate::util;
use crate::util::convert_query_map;
use async_trait::async_trait;
use bytesize::ByteSize;
use chrono::Timelike;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::error::Error;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};
use tracing::{error, info, Level};
use tracing_subscriber::fmt::writer::BoxMakeWriter;
use walkdir::WalkDir;

static GZIP_EXT: &str = "gz";
static ZSTD_EXT: &str = "zst";

fn zstd_compress(file: &Path, level: u8) -> Result<(u64, u64), Box<dyn Error>> {
    let level = if level == 0 { 9 } else { level as i32 };
    let zst_file = file.with_extension(ZSTD_EXT);
    let mut original_file = fs::File::open(file)?;
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&zst_file)?;

    let mut encoder = zstd::stream::Encoder::new(&file, level)?;
    let original_size = io::copy(&mut original_file, &mut encoder)?;
    encoder.finish()?;
    let size = file.metadata().map(|item| item.size()).unwrap_or_default();
    Ok((size, original_size))
}

fn gzip_compress(file: &Path, level: u8) -> Result<(u64, u64), Box<dyn Error>> {
    let gzip_file = file.with_extension(GZIP_EXT);
    let mut original_file = fs::File::open(file)?;
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&gzip_file)?;
    let level = if level == 0 {
        Compression::best()
    } else {
        Compression::new(level as u32)
    };
    let mut encoder = GzEncoder::new(&file, level);
    let original_size = io::copy(&mut original_file, &mut encoder)?;
    encoder.finish()?;
    let size = file.metadata().map(|item| item.size()).unwrap_or_default();
    Ok((size, original_size))
}

pub struct LogCompressionTask {
    compression: String,
    path: PathBuf,
    level: u8,
    days_ago: u16,
    time_point_hour: u8,
}

#[async_trait]
impl ServiceTask for LogCompressionTask {
    async fn run(&self) -> Option<bool> {
        if self.time_point_hour != chrono::Local::now().hour() as u8 {
            return Some(false);
        }
        let mut days_ago = self.days_ago;
        if days_ago == 0 {
            days_ago = 7;
        }
        let Some(access_before) = SystemTime::now()
            .checked_sub(Duration::from_secs(24 * 3600 * days_ago as u64))
        else {
            return Some(false);
        };
        let compresssion_exts = [GZIP_EXT.to_string(), ZSTD_EXT.to_string()];
        for entry in WalkDir::new(&self.path).into_iter().filter_map(|e| e.ok())
        {
            let ext = entry
                .path()
                .extension()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            if compresssion_exts.contains(&ext) {
                continue;
            }
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            let Ok(accessed) = metadata.accessed() else {
                continue;
            };
            if accessed > access_before {
                continue;
            }
            let start = SystemTime::now();
            let result = if self.compression == "gzip" {
                gzip_compress(entry.path(), self.level)
            } else {
                zstd_compress(entry.path(), self.level)
            };
            let file = entry.path().to_string_lossy().to_string();
            match result {
                Err(e) => {
                    error!(err = e.to_string(), file, "compress log fail");
                },
                Ok((size, original_size)) => {
                    let elapsed = format!("{}ms", util::elapsed_ms(start));
                    info!(
                        file,
                        elapsed,
                        original_size = ByteSize::b(original_size).to_string(),
                        size = ByteSize::b(size).to_string(),
                        "compress log success",
                    );
                    // ignore remove
                    let _ = fs::remove_file(entry.path());
                },
            }
        }

        Some(false)
    }
    fn description(&self) -> String {
        "LogCompression".to_string()
    }
}

#[derive(Default, Debug)]
pub struct LoggerParams {
    pub log: String,
    pub level: String,
    pub capacity: u64,
    pub json: bool,
}

pub fn logger_try_init(
    params: LoggerParams,
) -> Result<Option<CommonServiceTask>, Box<dyn Error>> {
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
    let mut task = None;
    let writer = if params.log.is_empty() {
        BoxMakeWriter::new(std::io::stderr)
    } else {
        let mut file = util::resolve_path(&params.log);
        let mut rolling_type = "".to_string();
        let mut compression = "".to_string();
        let mut level = 0;
        let mut days_ago = 0;
        let mut time_point_hour = 0;
        if let Some((_, query)) = params.log.split_once('?') {
            file = file.replace(&format!("?{query}"), "");
            let m = convert_query_map(query);
            if let Some(value) = m.get("rolling") {
                rolling_type = value.to_string();
            }
            if let Some(value) = m.get("compression") {
                compression = value.to_string();
            }
            if let Some(value) = m.get("level") {
                level = value.parse::<u8>().unwrap_or_default();
            }
            if let Some(value) = m.get("days_ago") {
                days_ago = value.parse::<u16>().unwrap_or_default();
            }
            if let Some(value) = m.get("time_point_hour") {
                time_point_hour = value.parse::<u8>().unwrap_or_default();
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
        if !compression.is_empty() {
            task = Some(CommonServiceTask::new(
                Duration::from_secs(3600),
                LogCompressionTask {
                    compression,
                    path: dir.to_path_buf(),
                    days_ago,
                    level,
                    time_point_hour,
                },
            ))
        }

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

    Ok(task)
}
