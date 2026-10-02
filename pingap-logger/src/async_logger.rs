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

use super::LOG_TARGET;
use super::file_appender::new_rolling_file_writer;
#[cfg(unix)]
use super::syslog::{SyslogSender, new_syslog_sender};
use super::target::{LogTarget, parse_log_target};
use async_trait::async_trait;
use bytes::BytesMut;
use pingap_core::Error;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use serde::{Deserialize, Serialize};
use std::io::{self, BufWriter, Write};
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tracing::{error, info};
use tracing_appender::rolling::RollingFileAppender;

type Result<T> = std::result::Result<T, Error>;

/// Where the access log task writes its lines.
enum AccessLogSink {
    File(BufWriter<RollingFileAppender>),
    Stdout(BufWriter<io::Stdout>),
    Stderr(BufWriter<io::Stderr>),
    /// Unbuffered: each line is its own message.
    #[cfg(unix)]
    Syslog(SyslogSender),
}

/// Line then newline, straight into the `BufWriter`: no growing the line
/// to append the newline. `write_all`, not `write`: a short write would
/// silently truncate the line.
fn write_buffered<W: Write>(
    writer: &mut BufWriter<W>,
    line: &[u8],
) -> io::Result<()> {
    writer.write_all(line)?;
    writer.write_all(b"\n")
}

impl AccessLogSink {
    fn write_line(&mut self, line: &[u8]) -> io::Result<()> {
        match self {
            Self::File(writer) => write_buffered(writer, line),
            Self::Stdout(writer) => write_buffered(writer, line),
            Self::Stderr(writer) => write_buffered(writer, line),
            #[cfg(unix)]
            Self::Syslog(sender) => sender.send(line),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::File(writer) => writer.flush(),
            Self::Stdout(writer) => writer.flush(),
            Self::Stderr(writer) => writer.flush(),
            #[cfg(unix)]
            Self::Syslog(_) => Ok(()),
        }
    }
    /// Standard streams are read as they are written (`docker logs`, a
    /// terminal), so they are flushed after every batch rather than on
    /// the timer; under load a batch is still one write.
    fn flushes_every_batch(&self) -> bool {
        matches!(self, Self::Stdout(_) | Self::Stderr(_))
    }
}

pub struct AsyncLoggerTask {
    dir: Option<String>,
    path: String,
    channel_buffer: usize,
    receiver: Mutex<Option<Receiver<BytesMut>>>,
    sink: Mutex<Option<AccessLogSink>>,
    flush_timeout: Duration,
}
impl AsyncLoggerTask {
    /// The directory of a file log, for the compression task; `None` for
    /// the other destinations.
    pub fn get_dir(&self) -> Option<String> {
        self.dir.clone()
    }
}

#[derive(Debug, PartialEq, Deserialize, Serialize, Default)]
struct AsyncLoggerWriterParams {
    channel_buffer: Option<usize>,
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    flush_timeout: Option<Duration>,
}

fn new_sink(target: &str) -> Result<(AccessLogSink, Option<String>)> {
    let invalid = |message: String| Error::Invalid {
        message: format!("{target}: {message}"),
    };
    match parse_log_target(target) {
        LogTarget::Stdout => {
            Ok((AccessLogSink::Stdout(BufWriter::new(io::stdout())), None))
        },
        LogTarget::Stderr => {
            Ok((AccessLogSink::Stderr(BufWriter::new(io::stderr())), None))
        },
        #[cfg(unix)]
        LogTarget::Syslog(value) => {
            let sender =
                new_syslog_sender(value).map_err(|e| invalid(e.to_string()))?;
            Ok((AccessLogSink::Syslog(sender), None))
        },
        #[cfg(not(unix))]
        LogTarget::Syslog(_) => Err(invalid(
            "syslog is only supported on Unix systems".to_string(),
        )),
        LogTarget::File(_) => {
            let rolling_file_writer = new_rolling_file_writer(target)
                .map_err(|e| invalid(e.to_string()))?;
            Ok((
                AccessLogSink::File(BufWriter::new(rolling_file_writer.writer)),
                Some(rolling_file_writer.dir),
            ))
        },
    }
}

/// The access log task for `target`: a file path, `stdout`, `stderr` or a
/// `syslog://` URL, each with its parameters after `?`, plus
/// `channel_buffer` and `flush_timeout` for all of them.
pub async fn new_async_logger(
    target: &str,
) -> Result<(Sender<BytesMut>, AsyncLoggerTask)> {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let params: AsyncLoggerWriterParams =
        serde_qs::from_str(query).map_err(|e| Error::Invalid {
            message: format!("access log params {target} is invalid: {e}"),
        })?;

    let (sink, dir) = new_sink(target)?;
    let channel_buffer = params.channel_buffer.unwrap_or(1000);
    let flush_timeout = params.flush_timeout.unwrap_or(Duration::from_secs(10));

    let (tx, rx) = channel::<BytesMut>(channel_buffer);

    let task = AsyncLoggerTask {
        dir,
        channel_buffer,
        path: path.to_string(),
        receiver: Mutex::new(Some(rx)),
        sink: Mutex::new(Some(sink)),
        flush_timeout,
    };

    Ok((tx, task))
}

#[async_trait]
impl BackgroundService for AsyncLoggerTask {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let Some(mut receiver) = self.receiver.lock().await.take() else {
            return;
        };
        let Some(mut sink) = self.sink.lock().await.take() else {
            return;
        };
        info!(
            target: LOG_TARGET,
            path = self.path,
            channel_buffer = self.channel_buffer,
            flush_timeout = format!("{:?}", self.flush_timeout),
            "async logger is running",
        );
        const MAX_BATCH_SIZE: usize = 128;
        let mut interval = tokio::time::interval(self.flush_timeout);

        // The shutdown signal must NOT end this task: requests keep completing
        // (and logging) through the whole grace period, and the senders live
        // inside the proxy services, which are only dropped when the runtimes
        // are torn down. Waiting for `recv()` to return `None` after the
        // signal therefore never ends either - the runtime teardown kills the
        // task mid-await, and everything still sitting in the `BufWriter`
        // (up to `flush_timeout` worth of lines) used to die with it. So:
        // keep running, and once the signal has arrived flush after every
        // batch, so a kill at any moment loses at most the batch in flight.
        let mut shutting_down = false;
        let flush = |sink: &mut AccessLogSink| {
            if let Err(e) = sink.flush() {
                error!(
                    target: LOG_TARGET,
                    error = %e,
                    "flush fail",
                );
            }
        };
        // No batch `Vec` in between: each line goes straight to the sink.
        let write_line = |sink: &mut AccessLogSink, msg: BytesMut| {
            if let Err(e) = sink.write_line(&msg) {
                error!(
                    target: LOG_TARGET,
                    error = %e,
                    "write fail",
                );
            }
        };
        loop {
            tokio::select! {
                _ = shutdown.changed(), if !shutting_down => {
                    shutting_down = true;
                    flush(&mut sink);
                }
                msg = receiver.recv() => {
                    let Some(msg) = msg else {
                        // all senders are gone
                        break;
                    };
                    write_line(&mut sink, msg);
                    // Drain what has queued up meanwhile, bounded so a
                    // flood cannot starve the flush timer.
                    let mut batched = 1;
                    while batched < MAX_BATCH_SIZE
                        && let Ok(msg) = receiver.try_recv()
                    {
                        write_line(&mut sink, msg);
                        batched += 1;
                    }
                    if shutting_down || sink.flushes_every_batch() {
                        flush(&mut sink);
                    }
                }
                _ = interval.tick() => {
                    flush(&mut sink);
                }
            }
        }
        // All senders are gone; drain what is left and flush.
        while let Ok(msg) = receiver.try_recv() {
            write_line(&mut sink, msg);
        }
        flush(&mut sink);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::time::Duration;

    /// Reads back everything the logger wrote (the rolling appender may add a
    /// date suffix to the file name, so match by prefix).
    fn read_logged(dir: &std::path::Path, prefix: &str) -> String {
        let mut content = String::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            if entry.file_name().to_string_lossy().starts_with(prefix) {
                content += &std::fs::read_to_string(entry.path()).unwrap();
            }
        }
        content
    }

    #[tokio::test]
    async fn test_lines_after_shutdown_signal_reach_disk() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("access.log");
        // A flush interval far beyond the test duration, so anything on disk
        // got there through the shutdown-triggered flushes - the ones that
        // used to not exist - and not through the timer.
        let (sender, task) = new_async_logger(&format!(
            "{}?flush_timeout=60s",
            path.to_string_lossy()
        ))
        .await
        .unwrap();

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let handle = tokio::spawn(async move {
            task.start(shutdown_rx).await;
        });

        sender
            .send(BytesMut::from("before shutdown"))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // The grace period begins: the signal fires, but the senders stay
        // alive and requests keep logging.
        shutdown_tx.send(true).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        sender
            .send(BytesMut::from("during grace period"))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Both lines are on disk while the task still runs and the sender is
        // still alive - a kill at this point loses nothing.
        let content = read_logged(dir.path(), "access.log");
        assert_eq!(true, content.contains("before shutdown"), "{content}");
        assert_eq!(true, content.contains("during grace period"), "{content}");

        // And once the senders drop, the task ends on its own.
        drop(sender);
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("task must end when all senders are gone")
            .unwrap();
    }

    /// Only a file has a directory for the compression task.
    #[tokio::test]
    async fn test_targets() {
        for target in
            ["stdout", "stderr", "/dev/stdout", "stdout?flush_timeout=1s"]
        {
            let (_, task) = new_async_logger(target).await.unwrap();
            assert_eq!(None, task.get_dir(), "{target}");
        }
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("access.log");
        let (_, task) =
            new_async_logger(&path.to_string_lossy()).await.unwrap();
        assert_eq!(
            Some(dir.path().to_string_lossy().to_string()),
            task.get_dir()
        );
    }

    /// Each access log line is one syslog message.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_syslog_target() {
        let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let port = server.local_addr().unwrap().port();
        let (sender, task) = new_async_logger(&format!(
            "syslog://127.0.0.1:{port}?process=access&channel_buffer=10"
        ))
        .await
        .unwrap();
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            task.start(shutdown_rx).await;
        });
        sender.send(BytesMut::from("GET / 200")).await.unwrap();
        sender.send(BytesMut::from("GET /b 404")).await.unwrap();
        let messages = tokio::task::spawn_blocking(move || {
            let mut buf = [0; 1024];
            (0..2)
                .map(|_| {
                    let size = server.recv(&mut buf).unwrap();
                    String::from_utf8_lossy(&buf[..size]).to_string()
                })
                .collect::<Vec<_>>()
        })
        .await
        .unwrap();
        // RFC 3164 by default, under the `process` name
        assert_eq!(true, messages[0].contains(" access["), "{messages:?}");
        assert_eq!(true, messages[0].ends_with("]: GET / 200"), "{messages:?}");
        assert_eq!(
            true,
            messages[1].ends_with("]: GET /b 404"),
            "{messages:?}"
        );
    }

    #[tokio::test]
    async fn test_invalid_params_are_rejected() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("access.log");
        let err = new_async_logger(&format!(
            "{}?flush_timeout=soon",
            path.to_string_lossy()
        ))
        .await
        .err()
        .expect("error")
        .to_string();
        assert_eq!(true, err.contains("access log params"), "{err}");
    }
}
