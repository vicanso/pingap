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
use async_trait::async_trait;
use bytes::BytesMut;
use pingap_core::Error;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use serde::{Deserialize, Serialize};
use std::io::{BufWriter, Write};
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tracing::{error, info};
use tracing_appender::rolling::RollingFileAppender;

type Result<T> = std::result::Result<T, Error>;

pub struct AsyncLoggerTask {
    dir: String,
    path: String,
    channel_buffer: usize,
    receiver: Mutex<Option<Receiver<BytesMut>>>,
    writer: Mutex<Option<BufWriter<RollingFileAppender>>>,
    flush_timeout: Duration,
}
impl AsyncLoggerTask {
    pub fn get_dir(&self) -> String {
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

pub async fn new_async_logger(
    path: &str,
) -> Result<(Sender<BytesMut>, AsyncLoggerTask)> {
    let original_path = path.to_string();
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    let params: AsyncLoggerWriterParams =
        serde_qs::from_str(query).unwrap_or_default();

    let rolling_file_writer =
        new_rolling_file_writer(&original_path).map_err(|e| {
            Error::Invalid {
                message: format!("{}: {}", original_path, e),
            }
        })?;

    let buffered_writer = BufWriter::new(rolling_file_writer.writer);
    let channel_buffer = params.channel_buffer.unwrap_or(1000);
    let flush_timeout = params.flush_timeout.unwrap_or(Duration::from_secs(10));

    let (tx, rx) = channel::<BytesMut>(channel_buffer);

    let task = AsyncLoggerTask {
        dir: rolling_file_writer.dir,
        channel_buffer,
        path: path.to_string(),
        receiver: Mutex::new(Some(rx)),
        writer: Mutex::new(Some(buffered_writer)),
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
        let Some(mut writer) = self.writer.lock().await.take() else {
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
        let flush = |writer: &mut BufWriter<RollingFileAppender>| {
            if let Err(e) = writer.flush() {
                error!(
                    target: LOG_TARGET,
                    error = %e,
                    "flush fail",
                );
            }
        };
        loop {
            tokio::select! {
                _ = shutdown.changed(), if !shutting_down => {
                    shutting_down = true;
                    flush(&mut writer);
                }
                msg = receiver.recv() => {
                    let Some(msg) = msg else {
                        // all senders are gone
                        break;
                    };
                    let mut messages = Vec::with_capacity(MAX_BATCH_SIZE);
                    messages.push(msg);
                    while messages.len() < MAX_BATCH_SIZE {
                        match receiver.try_recv() {
                            Ok(msg) => {
                                messages.push(msg);
                            }
                            Err(_) => break,
                        }
                    }
                    for mut msg in messages {
                        msg.extend_from_slice(b"\n");
                        // `write_all`, not `write`: a short write would
                        // silently truncate the line
                        if let Err(e) = writer.write_all(&msg) {
                            error!(
                                target: LOG_TARGET,
                                error = %e,
                                "write fail",
                            );
                        }
                    }
                    if shutting_down {
                        flush(&mut writer);
                    }
                }
                _ = interval.tick() => {
                    flush(&mut writer);
                }
            }
        }
        // All senders are gone; drain what is left and flush.
        while let Ok(mut msg) = receiver.try_recv() {
            msg.extend_from_slice(b"\n");
            if let Err(e) = writer.write_all(&msg) {
                error!(
                    target: LOG_TARGET,
                    error = %e,
                    "write fail",
                );
            }
        }
        flush(&mut writer);
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
}
