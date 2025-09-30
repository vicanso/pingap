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
use super::LOG_CATEGORY;
use async_trait::async_trait;
use bytes::BytesMut;
use pingap_core::Error;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use serde::{Deserialize, Serialize};
use std::io::{BufWriter, Write};
use std::time::Duration;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::Mutex;
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
                message: e.to_string(),
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
            category = LOG_CATEGORY,
            path = self.path,
            channel_buffer = self.channel_buffer,
            flush_timeout = format!("{:?}", self.flush_timeout),
            "async logger is running",
        );
        const MAX_BATCH_SIZE: usize = 128;
        let mut interval = tokio::time::interval(self.flush_timeout);

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    break;
                }
                Some(msg) = receiver.recv() => {
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
                        if let Err(e) = writer.write(&msg) {
                            error!(
                                category = LOG_CATEGORY,
                                error = %e,
                                "write fail",
                            );
                        }
                    }
                }
                _ = interval.tick() => {
                    if let Err(e) = writer.flush() {
                        error!(
                            category = LOG_CATEGORY,
                            error = %e,
                            "flush fail",
                        );
                    }
                }
                else => {
                    // `recv()` return None, all senders are gone
                    break;
                }
            }
        }
        // clear channel
        while let Some(mut msg) = receiver.recv().await {
            msg.extend_from_slice(b"\n");
            if let Err(e) = writer.write_all(&msg) {
                error!(
                    category = LOG_CATEGORY,
                    error = %e,
                    "write fail",
                );
            }
        }

        // flush writer
        if let Err(e) = writer.flush() {
            error!(
                category = LOG_CATEGORY,
                error = %e,
                "flush fail",
            );
        }
    }
}
