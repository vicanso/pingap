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
use pingap_util::resolve_path;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use tracing_appender::rolling::RollingFileAppender;

type Result<T> = std::result::Result<T, Error>;

/// The files of one file log: the directory they are written to and the
/// name they start with. A rolled file is `<prefix>.<date>`, or `<date>`
/// alone for a log that was given as a directory.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LogFiles {
    pub dir: String,
    pub prefix: String,
}

impl LogFiles {
    /// Whether `name` is a file this log rolled, going by the name the
    /// appender gives one: `access.log.2026-10-05`, with `-13` for hourly
    /// and `-13-45` for minutely on the end.
    ///
    /// The file being written matches as well, the compression leaves it
    /// alone by its modification time. A log that never rolls has the bare
    /// prefix for a name and does not match.
    pub(crate) fn is_rolled(&self, name: &str) -> bool {
        let date = if self.prefix.is_empty() {
            name
        } else {
            let Some(date) = name
                .strip_prefix(self.prefix.as_str())
                .and_then(|rest| rest.strip_prefix('.'))
            else {
                return false;
            };
            date
        };
        is_rolling_date(date)
    }
}

/// `2026-10-05`, `2026-10-05-13` or `2026-10-05-13-45`.
fn is_rolling_date(value: &str) -> bool {
    let mut count = 0;
    for (index, part) in value.split('-').enumerate() {
        let len = if index == 0 { 4 } else { 2 };
        if part.len() != len || !part.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        count += 1;
    }
    (3..=5).contains(&count)
}

pub struct RollingFileWriter {
    pub files: LogFiles,
    pub writer: RollingFileAppender,
}

#[derive(Debug, PartialEq, Deserialize, Serialize, Default)]
struct RollingFileWriterParams {
    #[serde(default)]
    file: String,
    #[serde(default)]
    rolling: String,
}

impl TryFrom<&str> for RollingFileWriterParams {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        let (file, query) = value.split_once('?').unwrap_or((value, ""));

        let mut params: Self = if !query.is_empty() {
            serde_qs::from_str(query).map_err(|e| Error::Invalid {
                message: format!("log params {value} is invalid: {e}"),
            })?
        } else {
            Self::default()
        };

        params.file = file.to_string();
        Ok(params)
    }
}

pub(crate) fn new_rolling_file_writer(
    log_path: &str,
) -> Result<RollingFileWriter> {
    let params = RollingFileWriterParams::try_from(log_path)?;
    let file = resolve_path(params.file.as_str());

    let filepath = Path::new(&file);
    let dir = if filepath.is_dir() {
        filepath
    } else {
        filepath.parent().ok_or_else(|| Error::Invalid {
            message: "parent of file log is invalid".to_string(),
        })?
    };
    fs::create_dir_all(dir).map_err(|e| Error::Io { source: e })?;

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
    let prefix = filename.clone();
    // An unknown rolling used to mean daily without a word.
    let writer = match params.rolling.as_str() {
        "minutely" => tracing_appender::rolling::minutely(dir, filename),
        "hourly" => tracing_appender::rolling::hourly(dir, filename),
        "never" => tracing_appender::rolling::never(dir, filename),
        "" | "daily" => tracing_appender::rolling::daily(dir, filename),
        rolling => {
            return Err(Error::Invalid {
                message: format!(
                    "rolling {rolling} is invalid, expected daily, hourly, minutely or never"
                ),
            });
        },
    };
    Ok(RollingFileWriter {
        files: LogFiles {
            dir: dir.to_string_lossy().to_string(),
            prefix,
        },
        writer,
    })
}

#[cfg(test)]
mod tests {
    use super::{LogFiles, RollingFileWriterParams, new_rolling_file_writer};

    #[test]
    fn test_log_files_is_rolled() {
        let files = |prefix: &str| LogFiles {
            dir: "/var/log".to_string(),
            prefix: prefix.to_string(),
        };
        let log = files("access.log");
        for name in [
            "access.log.2026-10-05",
            "access.log.2026-10-05-13",
            "access.log.2026-10-05-13-45",
        ] {
            assert!(log.is_rolled(name), "{name}");
        }
        for name in [
            // a log that never rolls
            "access.log",
            // already compressed
            "access.log.2026-10-05.zst",
            "access.log.2026-10-05.gz",
            // other files of the same directory
            "error.log.2026-10-05",
            "access.log.bak",
            "access.log.2026-10",
            "access.log.2026-10-05-13-45-00",
            "access.log.20261005",
            "access.log.2026-1o-05",
            "access.logx.2026-10-05",
            "syslog",
            "2026-10-05",
            "",
        ] {
            assert!(!log.is_rolled(name), "{name}");
        }
        // Given a directory, the appender names the files by the date alone.
        let log = files("");
        assert!(log.is_rolled("2026-10-05"));
        assert!(log.is_rolled("2026-10-05-13"));
        assert!(!log.is_rolled("access.log.2026-10-05"));
        assert!(!log.is_rolled("messages"));
    }

    #[test]
    fn test_rolling_file_writer_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().display().to_string();
        let writer =
            new_rolling_file_writer(&format!("{root}/app.log?rolling=hourly"))
                .unwrap();
        assert_eq!(
            LogFiles {
                dir: root.clone(),
                prefix: "app.log".to_string(),
            },
            writer.files
        );
        let writer = new_rolling_file_writer(&root).unwrap();
        assert_eq!(
            LogFiles {
                dir: root,
                prefix: "".to_string(),
            },
            writer.files
        );
    }

    #[test]
    fn test_rolling_is_validated() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("app.log").display().to_string();
        for rolling in ["", "daily", "hourly", "minutely", "never"] {
            assert!(
                new_rolling_file_writer(&format!("{file}?rolling={rolling}"))
                    .is_ok(),
                "{rolling}"
            );
        }
        let err = new_rolling_file_writer(&format!("{file}?rolling=monthly"))
            .err()
            .expect("error")
            .to_string();
        assert_eq!(
            "Invalid rolling monthly is invalid, expected daily, hourly, minutely or never",
            err
        );
    }

    #[test]
    fn test_try_from_path_only() {
        let input = "access.log";
        let params = RollingFileWriterParams::try_from(input).unwrap();
        assert_eq!(
            params,
            RollingFileWriterParams {
                file: "access.log".to_string(),
                rolling: "".to_string(), // rolling should be default
            }
        );
    }

    #[test]
    fn test_try_from_with_empty_query() {
        let input = "error.log?";
        let params = RollingFileWriterParams::try_from(input).unwrap();
        assert_eq!(
            params,
            RollingFileWriterParams {
                file: "error.log".to_string(),
                rolling: "".to_string(),
            }
        );
    }

    #[test]
    fn test_try_from_with_valid_query() {
        let input = "app.log?rolling=daily";
        let params = RollingFileWriterParams::try_from(input).unwrap();
        assert_eq!(
            params,
            RollingFileWriterParams {
                file: "app.log".to_string(),
                rolling: "daily".to_string(),
            }
        );
    }

    #[test]
    fn test_try_from_with_extra_params() {
        // serde_qs should ignore extra parameters
        let input = "metrics.log?rolling=hourly&format=json";
        let params = RollingFileWriterParams::try_from(input).unwrap();
        assert_eq!(
            params,
            RollingFileWriterParams {
                file: "metrics.log".to_string(),
                rolling: "hourly".to_string(),
            }
        );
    }

    #[test]
    fn test_try_from_empty_input() {
        let input = "";
        let params = RollingFileWriterParams::try_from(input).unwrap();
        assert_eq!(
            params,
            RollingFileWriterParams {
                file: "".to_string(),
                rolling: "".to_string(),
            }
        );
    }

    #[test]
    fn test_try_from_query_only() {
        let input = "?rolling=monthly";
        let params = RollingFileWriterParams::try_from(input).unwrap();
        assert_eq!(
            params,
            RollingFileWriterParams {
                file: "".to_string(),
                rolling: "monthly".to_string(),
            }
        );
    }
}
