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

/// Where a log is written: the application log's `--log`, or the
/// destination in front of an access log format.
#[derive(Debug, PartialEq)]
pub(crate) enum LogTarget<'a> {
    Stdout,
    Stderr,
    /// The whole `syslog://...` value.
    Syslog(&'a str),
    /// The whole value: the path and its `?` parameters.
    File(&'a str),
}

/// `stdout` and `stderr` (or `/dev/stdout`, `/dev/stderr`, which as files
/// would get a rotation suffix appended and fail) are the standard
/// streams, `syslog://...` is syslog, anything else is a file. Parameters
/// after `?` are allowed on all of them.
pub(crate) fn parse_log_target(value: &str) -> LogTarget<'_> {
    let (name, _) = value.split_once('?').unwrap_or((value, ""));
    match name {
        "stdout" | "/dev/stdout" => LogTarget::Stdout,
        "stderr" | "/dev/stderr" => LogTarget::Stderr,
        _ if value.starts_with("syslog://") => LogTarget::Syslog(value),
        _ => LogTarget::File(value),
    }
}

#[cfg(test)]
mod tests {
    use super::{LogTarget, parse_log_target};
    use pretty_assertions::assert_eq;

    #[test]
    fn test_parse_log_target() {
        assert_eq!(LogTarget::Stdout, parse_log_target("stdout"));
        assert_eq!(
            LogTarget::Stdout,
            parse_log_target("stdout?flush_timeout=1s")
        );
        assert_eq!(LogTarget::Stdout, parse_log_target("/dev/stdout"));
        assert_eq!(LogTarget::Stderr, parse_log_target("stderr"));
        assert_eq!(LogTarget::Stderr, parse_log_target("/dev/stderr"));
        assert_eq!(
            LogTarget::Syslog("syslog://10.0.0.1?protocol=tcp"),
            parse_log_target("syslog://10.0.0.1?protocol=tcp")
        );
        assert_eq!(
            LogTarget::File("/var/log/access.log?rolling=hourly"),
            parse_log_target("/var/log/access.log?rolling=hourly")
        );
        // only the exact names, not a file that happens to start with them
        assert_eq!(
            LogTarget::File("stdout.log"),
            parse_log_target("stdout.log")
        );
    }
}
