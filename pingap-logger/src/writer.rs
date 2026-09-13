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
use pingap_core::BackgroundTask;
use pingap_core::Error as ServiceError;
use std::collections::HashSet;
use std::fs;
use std::io;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Instant;
use std::time::{Duration, SystemTime};
use tracing::{Subscriber, error, info, warn};
use tracing_appender::rolling::RollingFileAppender;
use tracing_log::LogTracer;
use tracing_subscriber::Layer as _;
use tracing_subscriber::fmt::writer::{BoxMakeWriter, MakeWriter};
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

#[derive(Debug, Clone, Copy, PartialEq)]
enum Compression {
    Gzip,
    Zstd,
}

impl Compression {
    fn ext(self) -> &'static str {
        match self {
            Self::Gzip => GZIP_EXT,
            Self::Zstd => ZSTD_EXT,
        }
    }
}

/// Compresses `file` next to itself as `<file>.gz` / `<file>.zst`, and
/// returns `(compressed_size, original_size)`. Level 0 means the default
/// (gzip: best, zstd: 9); higher levels are clamped to what the codec
/// accepts.
fn compress_file(
    file: &Path,
    compression: Compression,
    level: u8,
) -> Result<(u64, u64)> {
    let target = file.with_extension(compression.ext());
    let mut original =
        fs::File::open(file).map_err(|e| Error::Io { source: e })?;
    let output = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&target)
        .map_err(|e| Error::Io { source: e })?;
    let original_size = match compression {
        Compression::Gzip => {
            let level = if level == 0 {
                flate2::Compression::best()
            } else {
                flate2::Compression::new(level.min(9) as u32)
            };
            let mut encoder = GzEncoder::new(&output, level);
            let size = io::copy(&mut original, &mut encoder)
                .map_err(|e| Error::Io { source: e })?;
            encoder.finish().map_err(|e| Error::Io { source: e })?;
            size
        },
        Compression::Zstd => {
            let level = if level == 0 {
                DEFAULT_COMPRESSION_LEVEL
            } else {
                level.min(22)
            };
            let mut encoder = zstd::stream::Encoder::new(&output, level as i32)
                .map_err(|e| Error::Io { source: e })?;
            let size = io::copy(&mut original, &mut encoder)
                .map_err(|e| Error::Io { source: e })?;
            encoder.finish().map_err(|e| Error::Io { source: e })?;
            size
        },
    };
    let size = output.metadata().map(|m| m.len()).unwrap_or_default();
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

/// Compresses every log file under `dirs` that has not been modified for
/// `days_ago` days, then removes the original. Runs on the blocking pool:
/// compressing a day of logs at level 9 takes seconds to minutes, and the
/// background runtime this task shares with the certificate, webhook and
/// cache tasks must not sit still for that long.
fn compress_dirs(params: &LogCompressParams) {
    let days_ago = if params.days_ago == 0 {
        DEFAULT_DAYS_AGO
    } else {
        params.days_ago
    };
    let Some(modified_before) = SystemTime::now()
        .checked_sub(Duration::from_secs(24 * 3600 * days_ago as u64))
    else {
        return;
    };
    let compression = if params.compression == "gzip" {
        Compression::Gzip
    } else {
        Compression::Zstd
    };
    let unique_dirs: HashSet<&String> = params.dirs.iter().collect();
    for dir in unique_dirs {
        for entry in WalkDir::new(dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let path = entry.path();
            let ext = path.extension().and_then(|ext| ext.to_str());
            if ext == Some(GZIP_EXT) || ext == Some(ZSTD_EXT) {
                continue;
            }
            let Some(modified) =
                entry.metadata().ok().and_then(|m| m.modified().ok())
            else {
                continue;
            };
            if modified > modified_before {
                continue;
            }
            let start = Instant::now();
            let file = path.display().to_string();
            match compress_file(path, compression, params.level) {
                Err(e) => {
                    error!(
                        target: LOG_TARGET,
                        error = %e,
                        file,
                        "compress log fail"
                    );
                },
                Ok((size, original_size)) => {
                    info!(
                        target: LOG_TARGET,
                        file,
                        elapsed = format!("{}ms", start.elapsed().as_millis()),
                        original_size = ByteSize::b(original_size).to_string(),
                        size = ByteSize::b(size).to_string(),
                        "compress log success",
                    );
                    // ignore remove
                    let _ = fs::remove_file(path);
                },
            }
        }
    }
}

/// Runs the compression once an hour (every 60 ticks of the minute
/// service) during the configured hour.
async fn do_compress(
    count: u32,
    params: &LogCompressParams,
) -> Result<bool, ServiceError> {
    const OFFSET: u32 = 60;
    if !count.is_multiple_of(OFFSET)
        || params.time_point_hour != chrono::Local::now().hour() as u8
    {
        return Ok(false);
    }
    let params = params.clone();
    tokio::task::spawn_blocking(move || compress_dirs(&params))
        .await
        .map_err(|e| ServiceError::Invalid {
            message: format!("compress log task fail: {e}"),
        })?;
    Ok(true)
}

struct LogCompressTask {
    params: LogCompressParams,
}

#[async_trait]
impl BackgroundTask for LogCompressTask {
    async fn execute(&self, count: u32) -> Result<bool, ServiceError> {
        do_compress(count, &self.params).await
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

type BufferedWriter = Arc<Mutex<BufWriter<RollingFileAppender>>>;

/// `MakeWriter` over the shared buffered writer: the subscriber and the
/// flush task write through the same lock.
struct SharedWriter(BufferedWriter);

struct SharedWriterGuard<'a>(MutexGuard<'a, BufWriter<RollingFileAppender>>);

impl<'a> MakeWriter<'a> for SharedWriter {
    type Writer = SharedWriterGuard<'a>;
    fn make_writer(&'a self) -> Self::Writer {
        // A panic while holding the lock poisons it; the writer inside is
        // still usable, and losing the application log over it is worse.
        SharedWriterGuard(self.0.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

impl Write for SharedWriterGuard<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.0.write_all(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

/// The buffered application log writer, when `capacity` asked for one. The
/// subscriber that owns it lives for the whole process, so nothing ever
/// drops it - and a `BufWriter` that is never dropped is never flushed on
/// its own: without `flush_application_log` the last lines before an exit,
/// and on a quiet server the last lines for a long while, would stay in
/// the buffer.
static BUFFERED_WRITER: OnceLock<BufferedWriter> = OnceLock::new();

/// Flushes the buffered application log, if there is one. A no-op for an
/// unbuffered log.
pub fn flush_application_log() {
    let Some(writer) = BUFFERED_WRITER.get() else {
        return;
    };
    let mut writer = writer.lock().unwrap_or_else(|e| e.into_inner());
    if let Err(e) = writer.flush() {
        // The subscriber owns this writer, so a failure here has nowhere
        // else to go.
        eprintln!("flush application log fail: {e}");
    }
}

struct LogFlushTask {}

#[async_trait]
impl BackgroundTask for LogFlushTask {
    async fn execute(&self, _count: u32) -> Result<bool, ServiceError> {
        flush_application_log();
        Ok(true)
    }
}

/// A task that flushes the buffered application log on every tick, so a
/// buffered log lags the events by at most one tick. `None` when the log
/// is not buffered.
pub fn new_log_flush_service() -> Option<Box<dyn BackgroundTask>> {
    BUFFERED_WRITER.get()?;
    Some(Box::new(LogFlushTask {}))
}

fn new_file_writer(params: &LoggerParams) -> Result<(BoxMakeWriter, String)> {
    let rolling_file_writer = new_rolling_file_writer(&params.log)?;
    let dir = rolling_file_writer.dir;
    let writer = if params.capacity < MIN_BUFFER_CAPACITY {
        BoxMakeWriter::new(rolling_file_writer.writer)
    } else {
        // buffer writer for better performance
        let writer = Arc::new(Mutex::new(BufWriter::with_capacity(
            params.capacity as usize,
            rolling_file_writer.writer,
        )));
        // A second init (tests) keeps the first writer; the subscriber
        // cannot be replaced either.
        let _ = BUFFERED_WRITER.set(writer.clone());
        BoxMakeWriter::new(SharedWriter(writer))
    };
    Ok((writer, dir))
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
    let timer = tracing_subscriber::fmt::time::OffsetTime::new(
        time::UtcOffset::from_hms(hours, minutes, 0)
            .unwrap_or(time::UtcOffset::UTC),
        time::format_description::well_known::Rfc3339,
    );

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_timer(timer)
        .with_target(is_dev)
        .with_writer(writer);
    let fmt_layer = if params.json {
        fmt_layer.with_ansi(false).json().boxed()
    } else {
        // text format with color if dev
        fmt_layer.with_ansi(is_dev).boxed()
    };
    let subscriber: Box<dyn Subscriber + Send + Sync> =
        Box::new(registry.with(fmt_layer));
    tracing::subscriber::set_global_default(subscriber).map_err(|e| {
        Error::Invalid {
            message: e.to_string(),
        }
    })?;

    // Pingora and a few other dependencies emit through the `log` crate, not
    // `tracing`. Without this bridge nothing installs a `log::Log`
    // implementation, so those records - including the bootstrap failure that
    // explains why a hot upgrade did not take over the listening sockets - are
    // silently discarded.
    //
    // `LogTracer` keeps `log::max_level` at `Trace` (its default), which leaves
    // `EnvFilter` as the single filtering point. That matters because the level
    // can be changed at runtime through the reload handle: `Handle::modify`
    // rebuilds the interest cache, and `LogTracer::enabled` re-reads
    // `LevelFilter::current()` on every record, so a level change applies to
    // `log` records immediately. Pinning `log::max_level` to the level observed
    // here instead would freeze the bridge at whatever the config said on boot.
    //
    // Note the target of a bridged record is `log` as far as `EnvFilter`
    // directives are concerned - only the rendered output carries the original
    // target, via the `tracing-log` feature of `tracing-subscriber`.
    if let Err(e) = LogTracer::init() {
        // Only fails when another logger won the race. The tracing side is
        // already up by this point, so downgrade it to a warning rather than
        // failing startup over a diagnostics-only feature.
        warn!(
            target: LOG_TARGET,
            error = %e,
            "log tracer init fail, logs from the log crate are dropped"
        );
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

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    /// Both codecs round-trip and report sizes; the original is left to the
    /// caller.
    #[test]
    fn test_compress_file() {
        let dir = tempfile::tempdir().unwrap();
        let content = "log line\n".repeat(1000);
        for (compression, ext) in
            [(Compression::Gzip, "gz"), (Compression::Zstd, "zst")]
        {
            let file = dir.path().join(format!("app-{ext}.log"));
            fs::write(&file, &content).unwrap();
            let (size, original_size) =
                compress_file(&file, compression, 0).unwrap();
            assert_eq!(content.len() as u64, original_size);
            assert_eq!(true, size > 0 && size < original_size, "{ext}");
            assert_eq!(true, file.with_extension(ext).exists());
            // the target exists now, so a second run must not clobber it
            assert_eq!(true, compress_file(&file, compression, 0).is_err());
        }
    }

    /// A buffered application log reaches the file through
    /// `flush_application_log`, which the flush task and the exit path
    /// call; nothing else ever flushes it.
    #[test]
    fn test_buffered_application_log_flush() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("app.log");
        let (writer, log_dir) = new_file_writer(&LoggerParams {
            log: format!("{}?rolling=never", file.display()),
            capacity: 64 * 1024,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(dir.path().display().to_string(), log_dir);
        assert_eq!(true, new_log_flush_service().is_some());

        writer.make_writer().write_all(b"buffered line\n").unwrap();
        // Still in the buffer: the file is empty.
        assert_eq!("", fs::read_to_string(&file).unwrap());
        flush_application_log();
        assert_eq!("buffered line\n", fs::read_to_string(&file).unwrap());
    }

    /// Only files older than `days_ago` (by modification time) are
    /// compressed, and already compressed files are left alone.
    #[test]
    fn test_compress_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let old = dir.path().join("old.log");
        let fresh = dir.path().join("fresh.log");
        let done = dir.path().join("done.log.zst");
        for file in [&old, &fresh, &done] {
            fs::write(file, "log line\n".repeat(100)).unwrap();
        }
        let eight_days_ago = SystemTime::now() - Duration::from_secs(8 * 86400);
        fs::File::open(&old)
            .unwrap()
            .set_modified(eight_days_ago)
            .unwrap();
        fs::File::open(&done)
            .unwrap()
            .set_modified(eight_days_ago)
            .unwrap();

        let params =
            LogCompressParams::new(vec![dir.path().display().to_string()]);
        compress_dirs(&params);

        assert_eq!(false, old.exists());
        assert_eq!(true, dir.path().join("old.zst").exists());
        assert_eq!(true, fresh.exists());
        assert_eq!(true, done.exists());
        assert_eq!(false, dir.path().join("done.log.zst.zst").exists());
    }
}
