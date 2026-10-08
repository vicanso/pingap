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
use super::file_appender::{
    ACCESS_LOG_PARAMS, LogFiles, new_rolling_file_writer,
    unknown_file_log_params,
};
use super::filter::FILTER_PARAMS;
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
use tracing::{error, info, warn};
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
    /// The application log: each line is an event of it.
    Application,
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
            Self::Application => {
                // Under the target the proxy itself logged these with, so
                // a filter written for it goes on applying.
                info!(
                    target: "pingap::proxy",
                    "{}",
                    String::from_utf8_lossy(line)
                );
                Ok(())
            },
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::File(writer) => writer.flush(),
            Self::Stdout(writer) => writer.flush(),
            Self::Stderr(writer) => writer.flush(),
            #[cfg(unix)]
            Self::Syslog(_) => Ok(()),
            Self::Application => Ok(()),
        }
    }
    /// Standard streams are read as they are written (`docker logs`, a
    /// terminal), so they are flushed after every batch rather than on
    /// the timer; under load a batch is still one write.
    fn flushes_every_batch(&self) -> bool {
        matches!(self, Self::Stdout(_) | Self::Stderr(_))
    }
    /// Whether whoever sends the lines can write them without this task.
    /// A line of the application log is an event anyone can emit; the
    /// other destinations are held by the task alone.
    fn senders_can_write(&self) -> bool {
        matches!(self, Self::Application)
    }
}

pub struct AsyncLoggerTask {
    files: Option<LogFiles>,
    path: String,
    /// The destination as it is configured, parameters included: what a
    /// file log is opened again from.
    target: String,
    channel_buffer: usize,
    receiver: Mutex<Option<Receiver<BytesMut>>>,
    sink: Mutex<Option<AccessLogSink>>,
    flush_timeout: Duration,
    /// How long the files a file log rolled are kept, `None` for good.
    keep: Option<Duration>,
}

/// How often the rolled files of a log with `keep` are looked through.
const KEEP_CHECK_INTERVAL: Duration = Duration::from_secs(3600);

/// Removes what a log with `keep` has rolled and kept long enough. On a
/// thread of its own: a directory is read and files are unlinked, and the
/// task that writes the log does not wait for either.
fn remove_old_files(files: &LogFiles, keep: Duration) {
    let files = files.clone();
    tokio::task::spawn_blocking(move || {
        let dir = files.dir.as_str();
        match files.remove_older_than(keep) {
            Ok((removed, failed)) => {
                if removed > 0 {
                    info!(target: LOG_TARGET, dir, removed, "old log files removed");
                }
                if let Some(e) = failed {
                    error!(target: LOG_TARGET, dir, error = %e, "remove old log files fail");
                }
            },
            Err(e) => {
                error!(target: LOG_TARGET, dir, error = %e, "remove old log files fail");
            },
        }
    });
}

/// Resolves when the process is told to open its log files again
/// (`SIGUSR1`), which is what `logrotate` does after it has moved one
/// away; never where there is no such signal, or nothing to open again.
#[cfg(unix)]
async fn reopen_requested(
    signal: &mut Option<tokio::signal::unix::Signal>,
) -> Option<()> {
    match signal {
        Some(signal) => signal.recv().await,
        None => std::future::pending().await,
    }
}
impl AsyncLoggerTask {
    /// The files of a file log, for the compression task; `None` for the
    /// other destinations.
    pub fn get_log_files(&self) -> Option<LogFiles> {
        self.files.clone()
    }
}

#[derive(Debug, PartialEq, Deserialize, Serialize, Default)]
struct AsyncLoggerWriterParams {
    channel_buffer: Option<usize>,
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    flush_timeout: Option<Duration>,
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    keep: Option<Duration>,
}

fn new_sink(target: &str) -> Result<(AccessLogSink, Option<LogFiles>)> {
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
            let known = [ACCESS_LOG_PARAMS, FILTER_PARAMS].concat();
            for param in unknown_file_log_params(target, &known) {
                warn!(
                    target: LOG_TARGET,
                    param,
                    log = target,
                    "this parameter of the log is not known and has no effect"
                );
            }
            Ok((
                AccessLogSink::File(BufWriter::new(rolling_file_writer.writer)),
                Some(rolling_file_writer.files),
            ))
        },
    }
}

/// The parameters of an access log's destination that its task reads,
/// or what is wrong with them.
fn parse_writer_params(target: &str) -> Result<AsyncLoggerWriterParams> {
    let (_, query) = target.split_once('?').unwrap_or((target, ""));
    let params: AsyncLoggerWriterParams =
        serde_qs::from_str(query).map_err(|e| Error::Invalid {
            message: format!("access log params {target} is invalid: {e}"),
        })?;
    // Kept for no time at all is a slip, not a wish. And the other two
    // are what tokio makes a timer and a channel of, which panics for
    // either at zero: the process went down with the first log task.
    let zero = [
        ("keep", params.keep.is_some_and(|keep| keep.is_zero())),
        (
            "flush_timeout",
            params.flush_timeout.is_some_and(|value| value.is_zero()),
        ),
        ("channel_buffer", params.channel_buffer == Some(0)),
    ];
    if let Some((name, _)) = zero.iter().find(|(_, is_zero)| *is_zero) {
        return Err(Error::Invalid {
            message: format!(
                "access log params {target} is invalid: {name} should be more than 0"
            ),
        });
    }
    Ok(params)
}

/// Whether the destination of an access log is one its task can be made
/// for, as far as that can be said without opening it: a `flush_timeout`
/// or `keep` that is no duration, a `rolling` there is no such thing as.
/// For a check of the configuration, which opens no log: these used to
/// pass `pingap -t` and fail the start.
pub fn check_access_log_target(target: &str) -> Result<()> {
    parse_writer_params(target)?;
    if let LogTarget::File(_) = parse_log_target(target) {
        super::file_appender::check_rolling_file_params(target).map_err(
            |e| Error::Invalid {
                message: format!("{target}: {e}"),
            },
        )?;
    }
    Ok(())
}

/// The access log task for `target`: a file path, `stdout`, `stderr` or a
/// `syslog://` URL, each with its parameters after `?`, plus
/// `channel_buffer` and `flush_timeout` for all of them.
pub async fn new_async_logger(
    target: &str,
) -> Result<(Sender<BytesMut>, AsyncLoggerTask)> {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let params = parse_writer_params(target)?;

    // The path of a file as it is now, for good: the log is opened again
    // later from what is kept here, and by then a daemon has moved to
    // `/`, where a relative path names another file.
    let resolved;
    let target = match parse_log_target(target) {
        LogTarget::File(_) => {
            resolved = if query.is_empty() {
                pingap_util::resolve_path(path)
            } else {
                format!("{}?{query}", pingap_util::resolve_path(path))
            };
            resolved.as_str()
        },
        _ => target,
    };
    let (sink, files) = new_sink(target)?;
    let channel_buffer = params.channel_buffer.unwrap_or(1000);
    let flush_timeout = params.flush_timeout.unwrap_or(Duration::from_secs(10));
    // Only a file log has files to remove.
    if params.keep.is_some() && files.is_none() {
        warn!(
            target: LOG_TARGET,
            log = target,
            "keep is for a log that is written to files and has no effect here"
        );
    }

    let (tx, rx) = channel::<BytesMut>(channel_buffer);

    let task = AsyncLoggerTask {
        keep: params.keep.filter(|_| files.is_some()),
        files,
        channel_buffer,
        path: path.to_string(),
        target: target.to_string(),
        receiver: Mutex::new(Some(rx)),
        sink: Mutex::new(Some(sink)),
        flush_timeout,
    };

    Ok((tx, task))
}

/// How many lines wait for the application log before the request path
/// writes its own again: more than the others keep, since each of these is
/// a write of its own to whatever the application log goes to.
const APPLICATION_CHANNEL_BUFFER: usize = 8192;

/// The access log task for an access log that names no destination: its
/// lines are events of the application log.
///
/// They used to be written where the request ended, on a worker thread:
/// a lock shared by every thread that logs, and with the log on stderr a
/// write to it, for each request. Four threads logging that way spent 17
/// microseconds a line waiting on each other; handing the line to this
/// task takes half of one.
///
/// A sender whose `try_send` fails is expected to write the line itself:
/// that is the case when the task is behind by the whole buffer, and from
/// the shutdown signal on, when the task takes no more lines.
pub fn new_application_logger() -> (Sender<BytesMut>, AsyncLoggerTask) {
    let (tx, rx) = channel::<BytesMut>(APPLICATION_CHANNEL_BUFFER);
    let task = AsyncLoggerTask {
        files: None,
        keep: None,
        channel_buffer: APPLICATION_CHANNEL_BUFFER,
        path: "application log".to_string(),
        target: String::new(),
        receiver: Mutex::new(Some(rx)),
        sink: Mutex::new(Some(AccessLogSink::Application)),
        // Nothing of its own to flush.
        flush_timeout: Duration::from_secs(3600),
    };
    (tx, task)
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
        // What the log rolled and has kept long enough is removed when
        // the task starts and then every hour.
        let retention = self.files.as_ref().zip(self.keep);
        let mut keep_check = tokio::time::interval(KEEP_CHECK_INTERVAL);
        // A file log is opened again when asked to. Only a file log: the
        // signal has no handler until someone listens for it, and what a
        // process does with it then is exit.
        #[cfg(unix)]
        let mut reopen = matches!(sink, AccessLogSink::File(_))
            .then(|| {
                tokio::signal::unix::signal(
                    tokio::signal::unix::SignalKind::user_defined1(),
                )
                // Said, because of what it leaves behind: without a
                // listener the signal ends the process.
                .inspect_err(|e| {
                    warn!(
                        target: LOG_TARGET,
                        path = self.path,
                        error = %e,
                        "the access log will not be opened again on SIGUSR1"
                    );
                })
                .ok()
            })
            .flatten();

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
                    // What is still waiting when the runtimes are torn down
                    // is lost. Where the senders can write the lines
                    // themselves, take no more of them: a send fails from
                    // here on, and the loop ends once it has written out
                    // what it holds.
                    if sink.senders_can_write() {
                        receiver.close();
                    }
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
                _ = keep_check.tick(), if retention.is_some() => {
                    if let Some((files, keep)) = retention {
                        remove_old_files(files, keep);
                    }
                }
                Some(()) = async {
                    #[cfg(unix)]
                    { reopen_requested(&mut reopen).await }
                    #[cfg(not(unix))]
                    { std::future::pending::<Option<()>>().await }
                } => {
                    // What is buffered belongs to the file that was
                    // moved away; the next line goes to a new one under
                    // the old name.
                    flush(&mut sink);
                    match new_sink(&self.target) {
                        Ok((opened, _)) => {
                            sink = opened;
                            info!(
                                target: LOG_TARGET,
                                path = self.path,
                                "access log is opened again"
                            );
                        },
                        Err(e) => error!(
                            target: LOG_TARGET,
                            path = self.path,
                            error = %e,
                            "open the access log again fail"
                        ),
                    }
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
            assert_eq!(None, task.get_log_files(), "{target}");
        }
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("access.log");
        let (_, task) =
            new_async_logger(&path.to_string_lossy()).await.unwrap();
        assert_eq!(
            Some(LogFiles {
                dir: dir.path().to_string_lossy().to_string(),
                prefix: "access.log".to_string(),
            }),
            task.get_log_files()
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

        // Regression: these passed the check of the configuration, and
        // tokio panics for a timer of no time and a channel of no size -
        // with the first log task the process was gone.
        for (params, name) in [
            ("flush_timeout=0s", "flush_timeout"),
            ("channel_buffer=0", "channel_buffer"),
            ("keep=0s", "keep"),
        ] {
            for target in [
                format!("/tmp/access.log?{params}"),
                format!("stdout?{params}"),
            ] {
                let err = super::check_access_log_target(&target)
                    .expect_err("error")
                    .to_string();
                assert_eq!(
                    true,
                    err.contains(&format!("{name} should be more than 0")),
                    "{err}"
                );
            }
        }
        for target in [
            "/tmp/access.log?flush_timeout=1s&channel_buffer=1&keep=1d",
            "stdout",
        ] {
            assert_eq!(true, super::check_access_log_target(target).is_ok());
        }
    }

    /// An access log without a destination is written by the task, as
    /// events of the application log under the proxy's target, until the
    /// process is told to stop.
    #[tokio::test]
    async fn test_application_logger_writes_events() {
        use std::sync::{Arc, Mutex as StdMutex};
        use tracing_subscriber::fmt::MakeWriter;

        #[derive(Clone, Default)]
        struct Captured(Arc<StdMutex<Vec<u8>>>);
        impl io::Write for Captured {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        impl<'a> MakeWriter<'a> for Captured {
            type Writer = Captured;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }
        let captured = Captured::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(captured.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let (tx, task) = new_application_logger();
        assert_eq!(true, task.get_log_files().is_none());
        tx.send(BytesMut::from("GET /a 200")).await.unwrap();
        tx.send(BytesMut::from("GET /b 404")).await.unwrap();
        // With every sender gone the task writes what is left and ends.
        drop(tx);
        let (_stop, shutdown) = tokio::sync::watch::channel(false);
        task.start(shutdown).await;

        let output =
            String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        let lines: Vec<_> = output
            .lines()
            .filter(|line| line.contains("pingap::proxy"))
            .collect();
        assert_eq!(2, lines.len(), "{output}");
        assert_eq!(true, lines[0].ends_with("GET /a 200"), "{output}");
        assert_eq!(true, lines[1].ends_with("GET /b 404"), "{output}");
        assert_eq!(true, lines[0].contains("INFO"), "{output}");

        // Lines waiting for the task when the runtimes are torn down are
        // lost. From the shutdown signal on it takes no more: it writes
        // what it holds and ends, though the sender is still there (as the
        // proxy's is), and the sender is told to write the line itself.
        // In this test and not one of its own: two threads meeting the
        // event for the first time can leave it disabled for both.
        let (tx, task) = new_application_logger();
        tx.send(BytesMut::from("GET /c 200")).await.unwrap();
        let (stop, shutdown) = tokio::sync::watch::channel(false);
        stop.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(5), task.start(shutdown))
            .await
            .expect("the task should end after the shutdown signal");
        let refused = tx.try_send(BytesMut::from("GET /d 200"));
        assert_eq!(
            "GET /d 200",
            String::from_utf8_lossy(&refused.unwrap_err().into_inner())
        );
        let output =
            String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        assert_eq!(true, output.contains("GET /c 200"), "{output}");
        assert_eq!(false, output.contains("GET /d 200"), "{output}");
    }
}
