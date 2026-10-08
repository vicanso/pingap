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
use tracing_appender::rolling::{RollingFileAppender, Rotation};

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

impl LogFiles {
    /// Removes the files this log rolled that were last written more than
    /// `keep` ago, compressed or not. Says how many went, and what stood
    /// in the way of the first that did not: one file that can not be
    /// removed is not a reason to keep the others.
    ///
    /// Never the file being written. On a site nobody visited for longer
    /// than `keep` it is as old as the others, and removed it would go on
    /// taking lines nobody can read until the next roll. Which one that
    /// is can only be told by signs, so both are taken, of the files
    /// that are not compressed: the one written last (a log whose
    /// `rolling` was changed has files of both ways of naming them, and
    /// an hourly one sorts after today's), and the one that is last by
    /// its name (an older file somebody has touched or put back is the
    /// one written last). At most one file too many is kept for it,
    /// until the next roll.
    pub(crate) fn remove_older_than(
        &self,
        keep: std::time::Duration,
    ) -> std::io::Result<(usize, Option<std::io::Error>)> {
        let now = std::time::SystemTime::now();
        let mut rolled = vec![];
        for entry in fs::read_dir(&self.dir)?.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let (plain, compressed) = match name
                .strip_suffix(".gz")
                .or_else(|| name.strip_suffix(".zst"))
            {
                Some(plain) => (plain, true),
                None => (name.as_str(), false),
            };
            if !self.is_rolled(plain) {
                continue;
            }
            // Gone since it was listed, or not a file: nothing to do.
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if !metadata.is_file() {
                continue;
            }
            let age = metadata
                .modified()
                .ok()
                .and_then(|modified| now.duration_since(modified).ok())
                .unwrap_or_default();
            rolled.push((compressed, age, entry.path()));
        }
        let plain = || rolled.iter().filter(|(compressed, _, _)| !compressed);
        let written_last = plain()
            .min_by_key(|(_, age, _)| *age)
            .map(|(_, _, path)| path.clone());
        let last_by_name = plain().map(|(_, _, path)| path).max().cloned();
        let mut removed = 0;
        let mut failed = None;
        for (_, age, path) in rolled {
            if age <= keep
                || Some(&path) == written_last.as_ref()
                || Some(&path) == last_by_name.as_ref()
            {
                continue;
            }
            match fs::remove_file(&path) {
                Ok(()) => removed += 1,
                // Removed by someone else in the meantime: the
                // compression of this log, or a second server that
                // writes to the same one.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
                Err(e) => {
                    failed.get_or_insert(e);
                },
            }
        }
        Ok((removed, failed))
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

/// The parameters the path of the application log takes.
pub(crate) const APPLICATION_LOG_PARAMS: &[&str] = &["rolling"];
/// The parameters the path of an access log takes: `rolling`, and the two
/// its task reads.
pub(crate) const ACCESS_LOG_PARAMS: &[&str] =
    &["rolling", "channel_buffer", "flush_timeout", "keep"];

/// The parameters of `log_path` that are not among `known`, the ones
/// whoever opens the log reads.
///
/// They used to be listed in the README as if they were: `compression`,
/// `level`, `days_ago` and `time_point_hour` on the path of a log have
/// never had an effect, the compression of rotated files is set with
/// `basic.log_compress_*`. A parameter that is not known is not an error,
/// since configurations written by that README carry them; whoever opens
/// the log says so in it.
pub(crate) fn unknown_file_log_params(
    log_path: &str,
    known: &[&str],
) -> Vec<String> {
    let Some((_, query)) = log_path.split_once('?') else {
        return vec![];
    };
    query
        .split('&')
        .filter_map(|pair| pair.split('=').next())
        .map(str::trim)
        .filter(|name| !name.is_empty() && !known.contains(name))
        .map(str::to_string)
        .collect()
}

/// How often a file log starts a new file. An unknown `rolling` used to
/// mean daily without a word.
fn parse_rotation(rolling: &str) -> Result<Rotation> {
    Ok(match rolling {
        "minutely" => Rotation::MINUTELY,
        "hourly" => Rotation::HOURLY,
        "never" => Rotation::NEVER,
        "" | "daily" => Rotation::DAILY,
        rolling => {
            return Err(Error::Invalid {
                message: format!(
                    "rolling {rolling} is invalid, expected daily, hourly, minutely or never"
                ),
            });
        },
    })
}

/// Whether the parameters of a file log read, without touching the file.
pub(crate) fn check_rolling_file_params(log_path: &str) -> Result<()> {
    let params = RollingFileWriterParams::try_from(log_path)?;
    parse_rotation(&params.rolling).map(|_| ())
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
    let rotation = parse_rotation(&params.rolling)?;
    // Through the builder, which says when the file can not be opened.
    // `rolling::daily` and the others of its kind panic then, and a
    // release build ends the process on a panic: a log that is opened
    // again while the server runs - after `logrotate` put a file in its
    // place that this user may not write to - took the server with it.
    let writer = RollingFileAppender::builder()
        .rotation(rotation)
        .filename_prefix(filename)
        .build(dir)
        .map_err(|e| Error::Invalid {
            message: format!("log file {file} can not be opened: {e}"),
        })?;
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
    use pretty_assertions::assert_eq;

    /// `keep`: what the log rolled long enough ago goes, compressed or
    /// not; the file being written and what is not the log's stay.
    #[test]
    fn test_remove_older_than() {
        use std::time::{Duration, SystemTime};
        let dir = tempfile::tempdir().unwrap();
        let day = Duration::from_secs(24 * 3600);
        let touch = |name: &str, age: Duration| {
            let path = dir.path().join(name);
            std::fs::write(&path, name).unwrap();
            std::fs::File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_modified(SystemTime::now() - age)
                .unwrap();
        };
        let left = || {
            let mut names: Vec<String> = std::fs::read_dir(dir.path())
                .unwrap()
                .map(|entry| {
                    entry.unwrap().file_name().to_string_lossy().to_string()
                })
                .collect();
            names.sort();
            names
        };
        touch("access.log.2026-09-01", day * 30);
        touch("access.log.2026-09-02.gz", day * 29);
        touch("access.log.2026-09-03.zst", day * 28);
        touch("access.log.2026-09-28", day * 10);
        // The one being written, on a site nobody has asked anything of
        // for more than a week: past `keep` like the others, and the one
        // that was written last.
        touch("access.log.2026-09-30", day * 8);
        // Not this log's.
        touch("error.log.2026-09-01", day * 30);
        touch("access.log", day * 30);
        touch("access.log.bak", day * 30);
        touch("notes.gz", day * 30);

        let files = LogFiles {
            dir: dir.path().to_string_lossy().to_string(),
            prefix: "access.log".to_string(),
        };
        let (removed, failed) = files.remove_older_than(day * 7).unwrap();
        assert_eq!((4, true), (removed, failed.is_none()));
        assert_eq!(
            vec![
                "access.log",
                "access.log.2026-09-30",
                "access.log.bak",
                "error.log.2026-09-01",
                "notes.gz",
            ],
            left()
        );
        // Nothing more to do.
        assert_eq!(0, files.remove_older_than(day * 7).unwrap().0);

        // The file being written is the one written last, whatever the
        // files are called: an hourly one from before `rolling` was
        // changed sorts after today's by its name. That one stays as
        // well, as the last by its name, until there is a later file.
        touch("access.log.2026-10-01-23", day * 9);
        touch("access.log.2026-10-01", day * 8 - Duration::from_secs(60));
        assert_eq!(1, files.remove_older_than(day * 7).unwrap().0);
        assert_eq!(
            vec![
                "access.log",
                "access.log.2026-10-01",
                "access.log.2026-10-01-23",
                "access.log.bak",
                "error.log.2026-09-01",
                "notes.gz",
            ],
            left()
        );
        touch("access.log.2026-10-02", day * 8 - Duration::from_secs(120));
        assert_eq!(2, files.remove_older_than(day * 7).unwrap().0);
        assert_eq!(false, left().iter().any(|name| name.contains("10-01")));

        // Regression: and it is the last by its name when an older file
        // was written to since - touched, or put back from a backup. By
        // the time of writing alone that one took the place of the file
        // being written, which was removed.
        touch("access.log.2026-09-15", Duration::from_secs(60));
        assert_eq!(0, files.remove_older_than(day * 7).unwrap().0);
        assert_eq!(
            vec![
                "access.log",
                "access.log.2026-09-15",
                "access.log.2026-10-02",
                "access.log.bak",
                "error.log.2026-09-01",
                "notes.gz",
            ],
            left()
        );
    }

    /// Regression: a log file that can not be opened was a panic, and a
    /// release build ends the process on one. That is how a log is opened
    /// again while the server runs, after `logrotate` has put a file in
    /// its place.
    #[cfg(unix)]
    #[test]
    fn test_file_that_can_not_be_opened_is_an_error() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            dir.path(),
            std::fs::Permissions::from_mode(0o555),
        )
        .unwrap();
        let target =
            format!("{}/access.log?rolling=never", dir.path().display());
        let result = new_rolling_file_writer(&target);
        std::fs::set_permissions(
            dir.path(),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        // Whoever may write anywhere has nothing to be refused.
        if let Err(e) = result {
            assert_eq!(
                true,
                e.to_string().contains("can not be opened"),
                "{e}"
            );
        }

        assert_eq!(
            true,
            super::check_rolling_file_params("a.log?rolling=hourly").is_ok()
        );
        assert_eq!(
            true,
            super::check_rolling_file_params("a.log?rolling=weekly").is_err()
        );
    }

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

    #[test]
    fn test_unknown_file_log_params() {
        use super::{
            ACCESS_LOG_PARAMS, APPLICATION_LOG_PARAMS, unknown_file_log_params,
        };
        let access =
            |path: &str| unknown_file_log_params(path, ACCESS_LOG_PARAMS);
        let application =
            |path: &str| unknown_file_log_params(path, APPLICATION_LOG_PARAMS);
        assert_eq!(true, access("/var/log/a.log").is_empty());
        let with_task_params =
            "/var/log/a.log?rolling=hourly&flush_timeout=5s&channel_buffer=10";
        assert_eq!(true, access(with_task_params).is_empty());
        // The application log has no task that reads those two.
        assert_eq!(
            vec!["flush_timeout".to_string(), "channel_buffer".to_string()],
            application(with_task_params)
        );
        assert_eq!(
            vec!["compression".to_string(), "days_ago".to_string()],
            access("/var/log/a.log?rolling=daily&compression=gzip&days_ago=7")
        );
    }
}
