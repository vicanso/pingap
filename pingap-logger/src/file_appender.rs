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

pub struct RollingFileWriter {
    pub dir: String,
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
                message: e.to_string(),
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
    let writer = match params.rolling.as_str() {
        "minutely" => tracing_appender::rolling::minutely(dir, filename),
        "hourly" => tracing_appender::rolling::hourly(dir, filename),
        "never" => tracing_appender::rolling::never(dir, filename),
        _ => tracing_appender::rolling::daily(dir, filename),
    };
    Ok(RollingFileWriter {
        dir: dir.to_string_lossy().to_string(),
        writer,
    })
}

#[cfg(test)]
mod tests {
    use super::RollingFileWriterParams;

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
