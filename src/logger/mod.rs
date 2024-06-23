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
use std::os::unix::fs::OpenOptionsExt;
use tracing::{info, Level};

pub struct LoggerParams {
    pub file: String,
    pub level: String,
    pub capacity: usize,
    pub json: bool,
}

pub fn logger_try_init(params: LoggerParams) -> Result<(), Box<dyn Error>> {
    let level = if !params.level.is_empty() {
        match params.level.to_lowercase().as_str() {
            "error" => Level::ERROR,
            "warn" => Level::WARN,
            "debug" => Level::DEBUG,
            _ => Level::INFO,
        }
    } else {
        Level::INFO
    };

    // let mut builder = tracing_appender::non_blocking::NonBlockingBuilder::default();
    // let mut buffered_lines = params.capacity / 2 * 2;
    // if buffered_lines < 16 {
    //     buffered_lines = 16;
    // }
    // builder = builder.buffered_lines_limit(buffered_lines);
    // builder = builder.thread_name("pingap");
    // let (non_blocking, guard) = if params.file.is_empty() {
    //     builder.finish(std::io::stdout())
    // } else {
    //     let file = util::resolve_path(&params.file);
    //     let file = Path::new(&file);
    //     let filename = if let Some(filename) = file.file_name() {
    //         filename.to_string_lossy().to_string()
    //     } else {
    //         "pingap.log".to_string()
    //     };
    //     let dir = file.parent().ok_or(util::new_internal_error(
    //         400,
    //         "log path is invalid".to_string(),
    //     ))?;

    //     let file_appender =
    //         tracing_appender::rolling::daily(dir.to_string_lossy().to_string(), filename);
    //     builder.finish(file_appender)
    // };

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
    if !params.file.is_empty() {
        let file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            // open read() in case there are no readers
            // available otherwise we will panic with
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&params.file)?;
        if params.json {
            builder
                .event_format(tracing_subscriber::fmt::format::json())
                .with_writer(file)
                .init();
        } else {
            builder.with_writer(file).init();
        }
    } else {
        if params.json {
            builder
                .event_format(tracing_subscriber::fmt::format::json())
                .with_writer(std::io::stderr)
                .init();
        } else {
            builder.with_writer(std::io::stderr).init();
        }
    }

    info!(
        capacity = params.capacity,
        utc_offset = chrono::Local::now().offset().to_string(),
        "init tracing subscriber success",
    );

    // // TODO get the status change from event callback
    // builder.format(move |buf, record| {
    //     let msg = format!("{}", record.args());
    //     if record.level() == Level::Warn && msg.contains("becomes unhealthy") {
    //         webhook::send(webhook::SendNotificationParams {
    //             level: webhook::NotificationLevel::Warn,
    //             category: webhook::NotificationCategory::BackendStatus,
    //             msg: format!("{}", record.args()),
    //         });
    //     }

    //     writeln!(
    //         buf,
    //         "{} {} {msg}",
    //         record.level(),
    //         chrono::Local::now().to_rfc3339(),
    //     )
    // });

    // builder.try_init()?;
    Ok(())
}
