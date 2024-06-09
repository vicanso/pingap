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

use crate::webhook;
use log::Level;
use std::error::Error;
use std::io::{BufWriter, Write};
use std::os::unix::fs::OpenOptionsExt;

pub struct LoggerParams {
    pub file: String,
    pub level: String,
    pub capacity: usize,
}

pub fn logger_try_init(params: LoggerParams) -> Result<(), Box<dyn Error>> {
    let mut builder = env_logger::Builder::from_env(env_logger::Env::default());
    if !params.level.is_empty() {
        match params.level.to_lowercase().as_str() {
            "error" => builder.filter_level(log::LevelFilter::Error),
            "warn" => builder.filter_level(log::LevelFilter::Warn),
            "debug" => builder.filter_level(log::LevelFilter::Debug),
            _ => builder.filter_level(log::LevelFilter::Info),
        };
    } else if std::env::var(env_logger::DEFAULT_FILTER_ENV).is_err() {
        builder.filter_level(log::LevelFilter::Error);
    }
    if !params.file.is_empty() {
        let capacity = params.capacity;
        let file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            // open read() in case there are no readers
            // available otherwise we will panic with
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&params.file)?;
        if capacity > 512 {
            let w = BufWriter::with_capacity(capacity, file);
            builder.target(env_logger::Target::Pipe(Box::new(w)));
        } else {
            builder.target(env_logger::Target::Pipe(Box::new(file)));
        }
    }

    // TODO get the status change from event callback
    builder.format(move |buf, record| {
        let msg = format!("{}", record.args());
        if record.level() == Level::Warn && msg.contains("becomes unhealthy") {
            webhook::send(webhook::SendNotificationParams {
                level: webhook::NotificationLevel::Warn,
                category: webhook::NotificationCategory::BackendStatus,
                msg: format!("{}", record.args()),
            });
        }

        writeln!(
            buf,
            "{} {} {msg}",
            record.level(),
            chrono::Local::now().to_rfc3339(),
        )
    });

    builder.try_init()?;
    Ok(())
}
