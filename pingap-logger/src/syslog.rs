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

use super::Error;
use pingap_core::get_hostname;
use serde::{Deserialize, Serialize};
use std::io;
use std::str::FromStr;
use std::sync::Mutex;
use syslog::{Facility, Formatter3164, Formatter5424};
use tracing_subscriber::fmt::writer::BoxMakeWriter;

type Result<T, E = Error> = std::result::Result<T, E>;

struct SyslogWriter<F> {
    logger: Mutex<syslog::Logger<syslog::LoggerBackend, F>>,
}

impl<'a, F: 'a> tracing_subscriber::fmt::writer::MakeWriter<'a>
    for SyslogWriter<F>
where
    SyslogWriterGuard<'a, F>: io::Write,
{
    type Writer = SyslogWriterGuard<'a, F>;

    fn make_writer(&'a self) -> Self::Writer {
        SyslogWriterGuard {
            guard: self.logger.lock().unwrap(),
        }
    }
}

struct SyslogWriterGuard<'a, F> {
    guard: std::sync::MutexGuard<'a, syslog::Logger<syslog::LoggerBackend, F>>,
}

// Implement Write trait for Formatter3164
impl io::Write for SyslogWriterGuard<'_, Formatter3164> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let s = std::str::from_utf8(buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // trim end of line, syslog will auto add '\n'
        let s = s.trim_end_matches('\n');
        if !s.is_empty() {
            self.guard.info(s).map_err(io::Error::other)?;
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// Implement Write trait for Formatter5424
impl io::Write for SyslogWriterGuard<'_, Formatter5424> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let s = std::str::from_utf8(buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // trim end of line, syslog will auto add '\n'
        let s = s.trim_end_matches('\n');
        if !s.is_empty() {
            let msg_id = 0u32; // message id
            let empty_data = std::collections::BTreeMap::new(); // empty structured data
            self.guard
                .info((msg_id, empty_data, s))
                .map_err(io::Error::other)?;
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug, PartialEq, Deserialize, Serialize, Default)]
struct SyslogWriterParams {
    format: Option<String>,
    process: Option<String>,
    facility: Option<String>,
}

pub fn new_syslog_writer(value: &str) -> Result<BoxMakeWriter> {
    let (_, query) = value.split_once('?').unwrap_or((value, ""));
    let params: SyslogWriterParams =
        serde_qs::from_str(query).unwrap_or_default();

    let format_type = params.format.unwrap_or_default();
    let process = params.process.unwrap_or("pingap".to_string());

    let facility =
        Facility::from_str(params.facility.unwrap_or_default().as_str())
            .unwrap_or_default();

    if format_type == "5424" {
        let formatter = syslog::Formatter5424 {
            process,
            facility,
            hostname: Some(get_hostname().to_string()),
            ..Default::default()
        };
        let logger = syslog::unix(formatter).map_err(|e| Error::Invalid {
            message: e.to_string(),
        })?;

        let syslog_writer = SyslogWriter {
            logger: Mutex::new(logger),
        };

        Ok(BoxMakeWriter::new(syslog_writer))
    } else {
        let formatter = syslog::Formatter3164 {
            process,
            facility,
            hostname: Some(get_hostname().to_string()),
            ..Default::default()
        };
        let logger = syslog::unix(formatter).map_err(|e| Error::Invalid {
            message: e.to_string(),
        })?;

        let syslog_writer = SyslogWriter {
            logger: Mutex::new(logger),
        };

        Ok(BoxMakeWriter::new(syslog_writer))
    }
}
