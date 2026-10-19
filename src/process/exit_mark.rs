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

//! Whether the run before this one ended as it should.
//!
//! A process that serves leaves a mark - its pid and when it started - and
//! takes it away when it is stopped: the moment a stop begins (SIGTERM),
//! not when it is over, since a supervisor ends a stop that takes longer
//! than it waits with a SIGKILL, and pingora waits out its grace period
//! however few requests are left; or when a fast stop (SIGINT) is done. A
//! mark that is still there when a process starts afresh is of a run that
//! did not end: it crashed, panicked, or was killed (out of memory), and
//! docker, systemd or whoever watches it started it again. That is told in
//! the log, as an `abnormal_exit` notification and on the home page of the
//! admin.
//!
//! A process started to take over from another (`-u`) is no fresh start:
//! the one before is still there and hands over, and the new process
//! writes its own mark over that one's. A process only ever takes away its
//! own mark, so the one before leaves that of the process it handed over
//! to, which tells if that one crashes.
//!
//! Each instance of a machine has a mark of its own: named after where its
//! configuration is, in the directory of its pid file.

use pingap_core::{NotificationData, NotificationLevel};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, UNIX_EPOCH};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
use tracing::{error, info, warn};

static LOG_TARGET: &str = "main::exit_mark";

/// The longest panic message that is kept: the mark is a small file.
const MAX_PANIC_LEN: usize = 1024;

/// The mark of a running process. One that could not be read is all zero.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Mark {
    pub pid: u32,
    /// When the process started, in seconds since the epoch, as the system
    /// has it: with the pid it is that process, and not one that has the
    /// pid now.
    pub started: u64,
    /// What the process panicked with, and where: written by the panic
    /// hook, on the way to the abort.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub panic: Option<String>,
}

impl Mark {
    /// What became of the run of this mark, in a sentence.
    pub fn describe(&self) -> String {
        let run = if self.pid == 0 {
            "the last run of pingap (its mark could not be read)".to_string()
        } else {
            let started = humantime::format_rfc3339_seconds(
                UNIX_EPOCH + Duration::from_secs(self.started),
            );
            format!(
                "the last run of pingap (pid {}, started {started})",
                self.pid
            )
        };
        match &self.panic {
            Some(panic) => format!("{run} ended with a panic: {panic}"),
            None => format!(
                "{run} did not end cleanly: it crashed, or was killed (out of memory, SIGKILL)"
            ),
        }
    }
}

/// Where the mark of one instance is.
#[derive(Debug, Clone)]
pub struct ExitMark {
    /// In the directory of the pid file, and in the temporary directory
    /// for a process that may not write there: the first that takes the
    /// mark has it, and both are looked at.
    paths: [PathBuf; 2],
}

impl ExitMark {
    /// The mark of the instance that runs on the configuration at `conf`,
    /// with its pid file at `pid_file`. Made before the process becomes a
    /// daemon, and of absolute paths: a daemon changes its directory.
    pub fn new(conf: &str, pid_file: &str) -> Self {
        let name = format!("pingap-{}.state", conf_id(conf));
        let dir = Path::new(pid_file)
            .parent()
            .filter(|dir| !dir.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let dir =
            std::path::absolute(dir).unwrap_or_else(|_| dir.to_path_buf());
        Self {
            paths: [dir.join(&name), std::env::temp_dir().join(&name)],
        }
    }

    /// The marks there are, and where. One that cannot be read is of a run
    /// that did not end, of which nothing more is known.
    fn read(&self) -> Vec<(PathBuf, Mark)> {
        let mut found: Vec<(PathBuf, Mark)> = vec![];
        for path in &self.paths {
            if !path.exists() || found.iter().any(|(at, _)| at == path) {
                continue;
            }
            found.push((path.clone(), read_mark(path).unwrap_or_default()));
        }
        found
    }

    /// Writes `mark` where it can be written, and says where.
    fn write(&self, mark: &Mark) -> Option<PathBuf> {
        self.paths
            .iter()
            .find(|path| write_mark(path, mark).is_ok())
            .cloned()
    }
}

/// What tells the configurations of a machine apart: where it is, as the
/// configuration is loaded from it (without the options after a `?`, a
/// path made absolute) and as the replacement of a restart is given it,
/// in a short hash. Stable from one build to the next, which the hasher of
/// the standard library is not.
fn conf_id(conf: &str) -> String {
    let (source, _) = conf.split_once('?').unwrap_or((conf, ""));
    let source = if source.contains("://") {
        source.to_string()
    } else {
        let resolved = pingap_util::resolve_path(source);
        std::fs::canonicalize(&resolved)
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or(resolved)
    };
    hex::encode(&Sha256::digest(source.as_bytes())[..4])
}

fn read_mark(path: &Path) -> Option<Mark> {
    let data = std::fs::read(path).ok()?;
    serde_json::from_slice(&data).ok()
}

/// Written to a file beside it and moved into place: a mark is never half
/// written, whatever stops the process. The file beside it is of this
/// process, which may write at the time another does.
fn write_mark(path: &Path, mark: &Mark) -> std::io::Result<()> {
    let data = serde_json::to_vec(mark).map_err(std::io::Error::other)?;
    let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)
}

/// When the process `pid` started, if it runs.
fn process_started(pid: u32) -> Option<u64> {
    let pid = Pid::from_u32(pid);
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::nothing(),
    );
    system.process(pid).map(|process| process.start_time())
}

/// Whether the process of `mark` runs: the pid is there, and it is the
/// process that started then.
fn runs(mark: &Mark, started_of: &impl Fn(u32) -> Option<u64>) -> bool {
    mark.pid != 0 && started_of(mark.pid) == Some(mark.started)
}

/// What a start makes of a mark it finds.
#[derive(Debug, PartialEq)]
enum Found {
    /// One that is no concern of this start: of the process it takes over
    /// from.
    Nothing,
    /// Of a run that did not end.
    Abnormal,
    /// Of another process that runs: another instance with the same mark.
    Running,
}

fn judge(
    mark: &Mark,
    own_pid: u32,
    upgrade: bool,
    started_of: impl Fn(u32) -> Option<u64>,
) -> Found {
    // The process before is handing over and still runs: its mark is
    // written over.
    if upgrade {
        return Found::Nothing;
    }
    // A pid that is this process's own is of a process that had it before:
    // the first process of a container is 1 every time.
    if mark.pid != own_pid && runs(mark, &started_of) {
        return Found::Running;
    }
    Found::Abnormal
}

/// Where this process wrote its mark.
static WRITTEN: OnceLock<PathBuf> = OnceLock::new();

/// The run before this one, where it did not end cleanly.
static ABNORMAL_EXIT: OnceLock<Mark> = OnceLock::new();

/// A panic has been put in the mark: the first is the one told.
static PANIC_RECORDED: AtomicBool = AtomicBool::new(false);

/// The run before this one, where it did not end cleanly: for the admin.
pub fn abnormal_exit() -> Option<Mark> {
    ABNORMAL_EXIT.get().cloned()
}

/// Puts what a panic is in the mark, before the process aborts (a release
/// build is `panic = "abort"`): the next start can say what it was. Then
/// the hook there was before, which writes it to stderr.
pub fn install_panic_hook() {
    let before = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if let Some(path) = WRITTEN.get()
            && !PANIC_RECORDED.swap(true, Ordering::Relaxed)
        {
            let message = info.payload_as_str().unwrap_or("Box<dyn Any>");
            let location = info
                .location()
                .map(|at| format!(" at {}:{}", at.file(), at.line()))
                .unwrap_or_default();
            record_panic(
                path,
                std::process::id(),
                &format!("{message}{location}"),
            );
        }
        before(info);
    }));
}

/// Into the mark of `pid` only: a process that panics while it hands over
/// is not to give its panic to the process that took over.
fn record_panic(path: &Path, pid: u32, panic: &str) {
    let Some(mut mark) = read_mark(path).filter(|mark| mark.pid == pid) else {
        return;
    };
    let mut panic = panic.to_string();
    if panic.len() > MAX_PANIC_LEN {
        let mut end = MAX_PANIC_LEN;
        while !panic.is_char_boundary(end) {
            end -= 1;
        }
        panic.truncate(end);
    }
    mark.panic = Some(panic);
    let _ = write_mark(path, &mark);
}

/// Takes the mark at `path` away if it is of `pid`: never that of the
/// process this one handed over to.
fn remove_own(path: &Path, pid: u32) {
    if read_mark(path).is_some_and(|mark| mark.pid == pid) {
        let _ = std::fs::remove_file(path);
    }
}

/// Takes the mark of this process away, at the end of a fast stop
/// (SIGINT), which does not say it begins.
pub fn remove_on_clean_exit() {
    if let Some(path) = WRITTEN.get() {
        remove_own(path, std::process::id());
    }
}

/// Reads the marks of the run before and writes the one of this process,
/// once the process runs, which for a daemon is after the fork that gives
/// it its pid; then waits for a stop to take it away as it begins.
pub struct ExitMarkService {
    pub mark: ExitMark,
    /// Started to take over from another process (`-u`).
    pub upgrade: bool,
}

#[async_trait::async_trait]
impl pingora::services::background::BackgroundService for ExitMarkService {
    async fn start(&self, mut shutdown: pingora::server::ShutdownWatch) {
        let pid = std::process::id();
        let mut abnormal: Option<Mark> = None;
        let mut running = false;
        for (path, mark) in self.mark.read() {
            match judge(&mark, pid, self.upgrade, process_started) {
                Found::Nothing => {},
                Found::Abnormal => {
                    // Told once: the mark goes, in either of the places.
                    let _ = std::fs::remove_file(&path);
                    if abnormal
                        .as_ref()
                        .is_none_or(|at| mark.started > at.started)
                    {
                        abnormal = Some(mark);
                    }
                },
                Found::Running => {
                    running = true;
                    warn!(
                        target: LOG_TARGET,
                        pid = mark.pid,
                        path = %path.display(),
                        "another pingap process runs with the same mark: this one leaves none, give the instances configurations of their own"
                    );
                },
            }
        }
        // Written ahead of the notification, which may take as long as the
        // webhook does: a stop meanwhile would leave the mark of the run
        // before to be told once more.
        if !running {
            let own = Mark {
                pid,
                started: process_started(pid)
                    .unwrap_or_else(pingap_core::now_sec),
                panic: None,
            };
            match self.mark.write(&own) {
                Some(path) => {
                    info!(target: LOG_TARGET, path = %path.display(), "the mark of the running process is written");
                    let _ = WRITTEN.set(path);
                },
                None => warn!(
                    target: LOG_TARGET,
                    paths = ?self.mark.paths,
                    "the mark of the running process could not be written: an abnormal exit of it will not be told"
                ),
            }
        }
        if let Some(mark) = abnormal {
            let message = mark.describe();
            error!(target: LOG_TARGET, pid = mark.pid, "{message}");
            let _ = ABNORMAL_EXIT.set(mark);
            crate::webhook::send_notification(NotificationData {
                category: "abnormal_exit".to_string(),
                level: NotificationLevel::Error,
                message,
                ..Default::default()
            })
            .await;
        }
        // `changed` only fails once the sender is gone, which is a stop as
        // well.
        let _ = shutdown.changed().await;
        if let Some(path) = WRITTEN.get() {
            remove_own(path, pid);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn mark(pid: u32, started: u64) -> Mark {
        Mark {
            pid,
            started,
            panic: None,
        }
    }

    #[test]
    fn test_judge() {
        let none = |_: u32| None;
        let runs_since = |since: u64| move |_: u32| Some(since);
        // the one before did not end
        assert_eq!(Found::Abnormal, judge(&mark(5, 100), 7, false, none));
        // nor did the one that could not be read
        assert_eq!(Found::Abnormal, judge(&Mark::default(), 7, false, none));
        // its pid is another process's now, started later
        assert_eq!(
            Found::Abnormal,
            judge(&mark(5, 100), 7, false, runs_since(200))
        );
        // the first process of a container, every time: its own pid
        assert_eq!(
            Found::Abnormal,
            judge(&mark(1, 100), 1, false, runs_since(100))
        );
        // another instance with the same mark, which runs
        assert_eq!(
            Found::Running,
            judge(&mark(5, 100), 7, false, runs_since(100))
        );
        // a take-over: the one before runs and hands over
        assert_eq!(
            Found::Nothing,
            judge(&mark(5, 100), 7, true, runs_since(100))
        );
    }

    /// A process takes away its own mark, and not the one of the process
    /// it handed over to: that one's crash is to be told.
    #[test]
    fn test_remove_own() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pingap-x.state");
        write_mark(&path, &mark(9, 300)).unwrap();
        remove_own(&path, 7);
        assert_eq!(true, path.exists());
        remove_own(&path, 9);
        assert_eq!(false, path.exists());
        // nothing there, nothing done
        remove_own(&path, 9);
    }

    #[test]
    fn test_mark_paths() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let pid_file = dir.path().join("pingap.pid");
        let pid_file = pid_file.to_string_lossy();
        let of = |conf: &str| ExitMark::new(conf, &pid_file);
        let a_conf = a.to_string_lossy().to_string();
        // in the directory of the pid file
        assert_eq!(dir.path(), of(&a_conf).paths[0].parent().unwrap());
        assert_eq!(
            std::env::temp_dir(),
            of(&a_conf).paths[1].parent().unwrap()
        );
        // one for each configuration
        assert_ne!(of(&a_conf).paths[0], of(&b.to_string_lossy()).paths[0]);
        // the same one however it is written, with options or without
        assert_eq!(
            of(&a_conf).paths[0],
            of(&a.join("../a").to_string_lossy()).paths[0]
        );
        assert_eq!(
            of(&a_conf).paths[0],
            of(&format!("{a_conf}?separation")).paths[0]
        );
        // an etcd address as it is, without its options
        assert_ne!(
            of("etcd://127.0.0.1:2379/a").paths[0],
            of("etcd://127.0.0.1:2379/b").paths[0]
        );
        assert_eq!(
            of("etcd://127.0.0.1:2379/a").paths[0],
            of("etcd://127.0.0.1:2379/a?timeout=10s").paths[0]
        );
        // a pid file in the working directory: made absolute
        let relative = ExitMark::new(&a_conf, "pingap.pid");
        assert_eq!(true, relative.paths[0].is_absolute());
    }

    #[test]
    fn test_mark_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pingap-x.state");
        let other = dir.path().join("other.state");
        let exit_mark = ExitMark {
            paths: [path.clone(), other.clone()],
        };
        assert_eq!(Vec::<(PathBuf, Mark)>::new(), exit_mark.read());
        assert_eq!(Some(path.clone()), exit_mark.write(&mark(7, 100)));
        assert_eq!(vec![(path.clone(), mark(7, 100))], exit_mark.read());
        // nothing beside it is left
        assert_eq!(1, std::fs::read_dir(dir.path()).unwrap().count());
        // both places are looked at
        write_mark(&other, &mark(5, 50)).unwrap();
        assert_eq!(
            vec![(path.clone(), mark(7, 100)), (other.clone(), mark(5, 50))],
            exit_mark.read()
        );

        // a panic, cut to a length, into the mark of the process only
        record_panic(&path, 8, "not mine");
        assert_eq!(None, read_mark(&path).unwrap().panic);
        record_panic(&path, 7, &"boom ".repeat(400));
        assert_eq!(
            MAX_PANIC_LEN,
            read_mark(&path).unwrap().panic.unwrap().len()
        );

        // one that cannot be read is of a run of which nothing is known
        std::fs::write(&path, b"{").unwrap();
        assert_eq!((path.clone(), Mark::default()), exit_mark.read()[0]);

        // the first place that takes it: here not the one in a directory
        // that is not there
        let exit_mark = ExitMark {
            paths: [dir.path().join("none/x.state"), path.clone()],
        };
        assert_eq!(Some(path.clone()), exit_mark.write(&mark(8, 1)));
    }

    #[test]
    fn test_describe() {
        let mut found = mark(42, 1_760_000_000);
        assert_eq!(
            "the last run of pingap (pid 42, started 2025-10-09T08:53:20Z) did not end cleanly: it crashed, or was killed (out of memory, SIGKILL)",
            found.describe()
        );
        found.panic = Some("boom at src/main.rs:1".to_string());
        assert_eq!(
            "the last run of pingap (pid 42, started 2025-10-09T08:53:20Z) ended with a panic: boom at src/main.rs:1",
            found.describe()
        );
        assert_eq!(
            "the last run of pingap (its mark could not be read) did not end cleanly: it crashed, or was killed (out of memory, SIGKILL)",
            Mark::default().describe()
        );
    }

    /// The process that runs the tests is one that runs, from when it
    /// started.
    #[test]
    fn test_process_started() {
        let pid = std::process::id();
        let started = process_started(pid).unwrap();
        assert_eq!(true, started > 0);
        assert_eq!(true, runs(&mark(pid, started), &process_started));
        assert_eq!(false, runs(&mark(pid, started + 1), &process_started));
        assert_eq!(false, runs(&mark(0, started), &process_started));
    }
}
