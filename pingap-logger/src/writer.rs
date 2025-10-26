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

use super::file_appender::new_rolling_file_writer;
use super::new_env_filter;
#[cfg(unix)]
use super::syslog::new_syslog_writer;
use super::{Error, LOG_TARGET};
use async_trait::async_trait;
use bytesize::ByteSize;
use chrono::Timelike;
use flate2::write::GzEncoder;
use flate2::Compression;
use pingap_core::BackgroundTask;
use pingap_core::Error as ServiceError;
use std::collections::HashSet;
use std::fs;
use std::io;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
use std::path::Path;
use std::sync::Mutex;
use std::time::Instant;
use std::time::{Duration, SystemTime};
use tracing::Subscriber;
use tracing::{error, info};
use tracing_subscriber::fmt::writer::BoxMakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::reload::Handle;
use tracing_subscriber::reload::Layer;
use tracing_subscriber::{EnvFilter, Registry};
use walkdir::WalkDir;

const DEFAULT_COMPRESSION_LEVEL: u8 = 9;
const DEFAULT_DAYS_AGO: u16 = 7;
/// Minimum capacity in bytes for buffered log writing. When capacity is specified
/// below this value, no buffering will be used.
const MIN_BUFFER_CAPACITY: u64 = 4096;

static GZIP_EXT: &str = "gz";
static ZSTD_EXT: &str = "zst";

type Result<T, E = Error> = std::result::Result<T, E>;

pub type LoggerReloadHandle = Handle<EnvFilter, Registry>;

/// Compresses a file using zstd compression
///
/// # Arguments
/// * `file` - Path to the file to compress
/// * `level` - Compression level (0 uses default level)
///
/// # Returns
/// A tuple of (compressed_size, original_size) in bytes
fn zstd_compress(file: &Path, level: u8) -> Result<(u64, u64)> {
    let level = if level == 0 {
        DEFAULT_COMPRESSION_LEVEL
    } else {
        level
    }
    .min(22);
    let zst_file = file.with_extension(ZSTD_EXT);
    let mut original_file =
        fs::File::open(file).map_err(|e| Error::Io { source: e })?;
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&zst_file)
        .map_err(|e| Error::Io { source: e })?;

    let mut encoder = zstd::stream::Encoder::new(&file, level as i32)
        .map_err(|e| Error::Io { source: e })?;
    let original_size = io::copy(&mut original_file, &mut encoder)
        .map_err(|e| Error::Io { source: e })?;
    encoder.finish().map_err(|e| Error::Io { source: e })?;
    #[cfg(unix)]
    let size = file.metadata().map(|item| item.size()).unwrap_or_default();
    #[cfg(windows)]
    let size = file
        .metadata()
        .map(|item| item.file_size())
        .unwrap_or_default();
    Ok((size, original_size))
}

/// Compresses a file using gzip compression
///
/// # Arguments
/// * `file` - Path to the file to compress
/// * `level` - Compression level (0 uses best compression)
///
/// # Returns
/// A tuple of (compressed_size, original_size) in bytes
fn gzip_compress(file: &Path, level: u8) -> Result<(u64, u64)> {
    let gzip_file = file.with_extension(GZIP_EXT);
    let mut original_file =
        fs::File::open(file).map_err(|e| Error::Io { source: e })?;
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&gzip_file)
        .map_err(|e| Error::Io { source: e })?;
    let level = if level == 0 {
        Compression::best()
    } else {
        Compression::new(level.min(9) as u32)
    };
    let mut encoder = GzEncoder::new(&file, level);
    let original_size = io::copy(&mut original_file, &mut encoder)
        .map_err(|e| Error::Io { source: e })?;
    encoder.finish().map_err(|e| Error::Io { source: e })?;
    #[cfg(unix)]
    let size = file.metadata().map(|item| item.size()).unwrap_or_default();
    #[cfg(windows)]
    let size = file
        .metadata()
        .map(|item| item.file_size())
        .unwrap_or_default();
    Ok((size, original_size))
}

/// Parameters for log compression configuration
#[derive(Debug, Clone, Default)]
pub struct LogCompressParams {
    dirs: Vec<String>,
    compression: String,
    level: u8,
    days_ago: u16,
    time_point_hour: u8,
}

impl LogCompressParams {
    pub fn new(dirs: Vec<String>) -> Self {
        Self {
            dirs,
            ..Default::default()
        }
    }
    pub fn set_compression(&mut self, compression: String) {
        self.compression = compression;
    }
    pub fn set_level(&mut self, level: u8) {
        self.level = level;
    }
    pub fn set_days_ago(&mut self, days_ago: u16) {
        self.days_ago = days_ago;
    }
    pub fn set_time_point_hour(&mut self, time_point_hour: u8) {
        self.time_point_hour = time_point_hour;
    }
}

/// Performs log file compression based on specified parameters
///
/// # Arguments
/// * `count` - Counter used for timing compression runs
/// * `params` - Configuration parameters for compression
///
/// # Returns
/// Boolean indicating if compression was performed
async fn do_compress(
    count: u32,
    params: &LogCompressParams,
) -> Result<bool, ServiceError> {
    const OFFSET: u32 = 60;
    if count % OFFSET != 0
        || params.time_point_hour != chrono::Local::now().hour() as u8
    {
        return Ok(false);
    }

    let days_ago = if params.days_ago == 0 {
        DEFAULT_DAYS_AGO
    } else {
        params.days_ago
    };
    let access_before = SystemTime::now()
        .checked_sub(Duration::from_secs(24 * 3600 * days_ago as u64))
        .ok_or_else(|| ServiceError::Invalid {
            message: "Failed to calculate access time".to_string(),
        })?;
    let compression_exts = [GZIP_EXT.to_string(), ZSTD_EXT.to_string()];
    let unique_paths: HashSet<String> = params.dirs.iter().cloned().collect();

    for path in unique_paths {
        for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
            let ext = entry
                .path()
                .extension()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            if compression_exts.contains(&ext) {
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
            let start = Instant::now();
            let result = if params.compression == "gzip" {
                gzip_compress(entry.path(), params.level)
            } else {
                zstd_compress(entry.path(), params.level)
            };
            let file = entry.path().to_string_lossy().to_string();
            match result {
                Err(e) => {
                    error!(
                        target: LOG_TARGET,
                        error = %e,
                        file,
                        "compress log fail"
                    );
                },
                Ok((size, original_size)) => {
                    let elapsed = format!("{}ms", start.elapsed().as_millis());
                    info!(
                        target: LOG_TARGET,
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
    }
    Ok(true)
}

struct LogCompressTask {
    params: LogCompressParams,
}

#[async_trait]
impl BackgroundTask for LogCompressTask {
    async fn execute(&self, count: u32) -> Result<bool, ServiceError> {
        do_compress(count, &self.params).await?;
        Ok(true)
    }
}

/// Creates a new log compression service task
///
/// # Arguments
/// * `params` - Configuration parameters for the compression service
///
/// # Returns
/// Optional tuple containing service name and task future
pub fn new_log_compress_service(
    params: LogCompressParams,
) -> Box<dyn BackgroundTask> {
    Box::new(LogCompressTask { params })
}

/// Parameters for logger configuration
#[derive(Default, Debug)]
pub struct LoggerParams {
    pub log: String,
    pub level: String,
    pub capacity: u64,
    pub json: bool,
}

fn new_file_writer(params: &LoggerParams) -> Result<(BoxMakeWriter, String)> {
    let rolling_file_writer = new_rolling_file_writer(&params.log)?;
    let file = params
        .log
        .split_once('?')
        .unwrap_or((params.log.as_str(), ""))
        .0;

    let filepath = Path::new(&file);
    let dir = if filepath.is_dir() {
        filepath
    } else {
        filepath.parent().ok_or_else(|| Error::Invalid {
            message: "parent of file log is invalid".to_string(),
        })?
    };

    let writer = if params.capacity < MIN_BUFFER_CAPACITY {
        BoxMakeWriter::new(rolling_file_writer.writer)
    } else {
        // buffer writer for better performance
        let w = io::BufWriter::with_capacity(
            params.capacity as usize,
            rolling_file_writer.writer,
        );
        BoxMakeWriter::new(Mutex::new(w))
    };
    Ok((writer, dir.to_string_lossy().to_string()))
}

/// Initializes the logging system with the specified configuration
///
/// # Arguments
/// * `params` - Logger configuration parameters
///
/// # Returns
/// Optional log path if file log is enabled
pub fn logger_try_init(
    params: LoggerParams,
) -> Result<(LoggerReloadHandle, Option<String>)> {
    let level = if params.level.is_empty() {
        std::env::var("RUST_LOG").unwrap_or("INFO".to_string())
    } else {
        params.level.clone()
    };

    let seconds = chrono::Local::now().offset().local_minus_utc();
    let hours = (seconds / 3600) as i8;
    let minutes = ((seconds % 3600) / 60) as i8;
    let is_dev = cfg!(debug_assertions);

    let initial_filter = new_env_filter(&level);
    let (filter_layer, reload_handle) = Layer::new(initial_filter);
    let registry = tracing_subscriber::registry().with(filter_layer);

    let mut log_path = None;
    let mut log_type = "stdio";
    let writer = if params.log.is_empty() {
        BoxMakeWriter::new(std::io::stderr)
    } else if params.log.starts_with("syslog://") {
        #[cfg(unix)]
        {
            new_syslog_writer(&params.log)?
        }
        #[cfg(not(unix))]
        {
            return Err(Error::Invalid {
                message: "syslog is only supported on Unix systems".to_string(),
            });
        }
    } else {
        log_type = "file";
        let (w, dir) = new_file_writer(&params)?;
        log_path = Some(dir);
        w
    };
    if params.json {
        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_timer(tracing_subscriber::fmt::time::OffsetTime::new(
                time::UtcOffset::from_hms(hours, minutes, 0).unwrap(),
                time::format_description::well_known::Rfc3339,
            ))
            .with_target(is_dev)
            .with_writer(writer)
            .json();
        let subscriber = registry.with(fmt_layer);
        let boxed_subscriber: Box<dyn Subscriber + Send + Sync> =
            Box::new(subscriber);

        // set as global default
        tracing::subscriber::set_global_default(boxed_subscriber).map_err(
            |e| Error::Invalid {
                message: e.to_string(),
            },
        )?
    } else {
        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_ansi(is_dev) // text format with color if dev
            .with_timer(tracing_subscriber::fmt::time::OffsetTime::new(
                time::UtcOffset::from_hms(hours, minutes, 0).unwrap(),
                time::format_description::well_known::Rfc3339,
            ))
            .with_target(is_dev)
            .with_writer(writer);

        let subscriber = registry.with(fmt_layer);
        let boxed_subscriber: Box<dyn Subscriber + Send + Sync> =
            Box::new(subscriber);

        tracing::subscriber::set_global_default(boxed_subscriber).map_err(
            |e| Error::Invalid {
                message: e.to_string(),
            },
        )?
    }

    info!(
        target: LOG_TARGET,
        capacity = params.capacity,
        log_type,
        level = level.to_string(),
        json_format = params.json,
        utc_offset = chrono::Local::now().offset().to_string(),
        "init tracing subscriber success",
    );

    Ok((reload_handle, log_path))
}
