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

use bytesize::ByteSize;
use chrono::Timelike;
use flate2::write::GzEncoder;
use flate2::Compression;
use pingap_core::convert_query_map;
use pingap_core::Error as ServiceError;
use pingap_core::SimpleServiceTaskFuture;
use snafu::{ResultExt, Snafu};
use std::fs;
use std::io;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};
use tracing::{error, info, Level};
use tracing_subscriber::fmt::writer::BoxMakeWriter;
use walkdir::WalkDir;

const DEFAULT_COMPRESSION_LEVEL: u8 = 9;
const DEFAULT_DAYS_AGO: u16 = 7;
/// Minimum capacity in bytes for buffered log writing. When capacity is specified
/// below this value, no buffering will be used.
const MIN_BUFFER_CAPACITY: u64 = 4096;

const LOG_CATEGORY: &str = "logger";

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("IO error {source}"))]
    Io { source: std::io::Error },
    #[snafu(display("Invalid {message}"))]
    Invalid { message: String },
}
type Result<T, E = Error> = std::result::Result<T, E>;

static GZIP_EXT: &str = "gz";
static ZSTD_EXT: &str = "zst";

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
    };
    let zst_file = file.with_extension(ZSTD_EXT);
    let mut original_file = fs::File::open(file).context(IoSnafu)?;
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&zst_file)
        .context(IoSnafu)?;

    let mut encoder =
        zstd::stream::Encoder::new(&file, level as i32).context(IoSnafu)?;
    let original_size =
        io::copy(&mut original_file, &mut encoder).context(IoSnafu)?;
    encoder.finish().context(IoSnafu)?;
    #[cfg(unix)]
    let size = file.metadata().map(|item| item.size()).unwrap_or_default();
    #[cfg(windows)]
    let size = file.metadata().map(|item| item.file_size()).unwrap_or_default();
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
    let mut original_file = fs::File::open(file).context(IoSnafu)?;
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&gzip_file)
        .context(IoSnafu)?;
    let level = if level == 0 {
        Compression::best()
    } else {
        Compression::new(level as u32)
    };
    let mut encoder = GzEncoder::new(&file, level);
    let original_size =
        io::copy(&mut original_file, &mut encoder).context(IoSnafu)?;
    encoder.finish().context(IoSnafu)?;
    #[cfg(unix)]
    let size = file.metadata().map(|item| item.size()).unwrap_or_default();
    #[cfg(windows)]
    let size = file.metadata().map(|item| item.file_size()).unwrap_or_default();
    Ok((size, original_size))
}

/// Parameters for log compression configuration
#[derive(Debug, Clone)]
struct LogCompressParams {
    compression: String,
    path: PathBuf,
    level: u8,
    days_ago: u16,
    time_point_hour: u8,
}

impl Default for LogCompressParams {
    fn default() -> Self {
        Self {
            compression: String::new(),
            path: PathBuf::new(),
            level: DEFAULT_COMPRESSION_LEVEL,
            days_ago: DEFAULT_DAYS_AGO,
            time_point_hour: 0,
        }
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
    params: LogCompressParams,
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
    for entry in WalkDir::new(&params.path)
        .into_iter()
        .filter_map(|e| e.ok())
    {
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
        let start = SystemTime::now();
        let result = if params.compression == "gzip" {
            gzip_compress(entry.path(), params.level)
        } else {
            zstd_compress(entry.path(), params.level)
        };
        let file = entry.path().to_string_lossy().to_string();
        match result {
            Err(e) => {
                error!(
                    category = LOG_CATEGORY,
                    error = %e,
                    file,
                    "compress log fail"
                );
            },
            Ok((size, original_size)) => {
                let elapsed = format!("{}ms", pingap_util::elapsed_ms(start));
                info!(
                    category = LOG_CATEGORY,
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
    Ok(true)
}

/// Creates a new log compression service task
///
/// # Arguments
/// * `params` - Configuration parameters for the compression service
///
/// # Returns
/// Optional tuple containing service name and task future
fn new_log_compress_service(
    params: LogCompressParams,
) -> Option<(String, SimpleServiceTaskFuture)> {
    let task: SimpleServiceTaskFuture = Box::new(move |count: u32| {
        Box::pin({
            let value = params.clone();
            async move {
                let value = value.clone();
                do_compress(count, value).await
            }
        })
    });
    Some(("logCompress".to_string(), task))
}

/// Parameters for logger configuration
#[derive(Default, Debug)]
pub struct LoggerParams {
    pub log: String,
    pub level: String,
    pub capacity: u64,
    pub json: bool,
}

/// Initializes the logging system with the specified configuration
///
/// # Arguments
/// * `params` - Logger configuration parameters
///
/// # Returns
/// Optional tuple containing compression service name and task future if compression is enabled
pub fn logger_try_init(
    params: LoggerParams,
) -> Result<Option<(String, SimpleServiceTaskFuture)>> {
    let level = if params.level.is_empty() {
        std::env::var("RUST_LOG").unwrap_or("INFO".to_string())
    } else {
        params.level.clone()
    };

    let level = match level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
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
    let mut log_type = "stdio";
    let writer = if params.log.is_empty() {
        BoxMakeWriter::new(std::io::stderr)
    } else {
        let mut file = pingap_util::resolve_path(&params.log);
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
            filepath.parent().ok_or_else(|| Error::Invalid {
                message: "parent of file log is invalid".to_string(),
            })?
        };
        log_type = "file";
        fs::create_dir_all(dir).context(IoSnafu)?;
        if !compression.is_empty() {
            task = new_log_compress_service(LogCompressParams {
                compression,
                path: dir.to_path_buf(),
                days_ago,
                level,
                time_point_hour,
            });
        }

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

        if params.capacity < MIN_BUFFER_CAPACITY {
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
        category = LOG_CATEGORY,
        capacity = params.capacity,
        log_type,
        level = level.to_string(),
        json_format = params.json,
        utc_offset = chrono::Local::now().offset().to_string(),
        "init tracing subscriber success",
    );

    Ok(task)
}
