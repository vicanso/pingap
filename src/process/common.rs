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

use crate::webhook::send_notification;
use pingap_core::{NotificationData, NotificationLevel};
use std::io;
use std::path::PathBuf;
use std::process;
use std::process::{Command, Stdio};
use std::sync::LazyLock;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::Duration;
use tracing::{error, info};

static LOG_TARGET: &str = "main::process";

static START_TIME: LazyLock<Duration> =
    LazyLock::new(|| Duration::from_secs(pingap_core::now_sec()));

static ADMIN_ADDR: OnceLock<String> = OnceLock::new();

/// Sets the admin address for the application.
/// This address is used for administrative access and can only be set once.
///
/// # Arguments
/// * `addr` - The address string to use for admin access
pub fn set_admin_addr(addr: &str) {
    ADMIN_ADDR.get_or_init(|| addr.to_string());
}

/// Returns the currently configured admin address, if one is set.
///
/// Returns:
/// * `Option<String>` - The admin address if configured, None otherwise
pub fn get_admin_addr() -> Option<String> {
    ADMIN_ADDR.get().cloned()
}

/// Returns the process start time in seconds since startup.
///
/// Returns:
/// * `u64` - Number of seconds since the process started
pub fn get_start_time() -> u64 {
    START_TIME.as_secs()
}

#[derive(Debug, Default)]
pub struct RestartProcessCommand {
    pub exec_path: PathBuf,
    pub log_level: String,
    pub args: Vec<String>,
}

impl RestartProcessCommand {
    /// Spawns the replacement process **without waiting** for it to exit.
    ///
    /// The new process is started with `-d` (daemon) and `-u` (upgrade), so it
    /// daemonizes itself and takes over the listening sockets from the current
    /// process. We must NOT use `Command::output()` here: it blocks until the
    /// child exits and reads its stdout/stderr to EOF, which never happens for a
    /// long-running daemon, and it would keep this task blocked while the old
    /// process is being torn down. Detach stdio and return the child handle.
    fn exec(&self) -> io::Result<process::Child> {
        Command::new(&self.exec_path)
            .env("RUST_LOG", &self.log_level)
            .args(&self.args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
    }
}

static CMD: OnceLock<RestartProcessCommand> = OnceLock::new();

/// Sets the command configuration used for process restarts.
/// This configuration is stored statically and can only be set once.
///
/// # Arguments
/// * `data` - The restart command configuration to store
pub fn set_restart_process_command(data: RestartProcessCommand) {
    CMD.get_or_init(|| data);
}

static PROCESS_RESTAR_COUNT: LazyLock<AtomicU8> =
    LazyLock::new(|| AtomicU8::new(0));
static PROCESS_RESTARTING: LazyLock<AtomicBool> =
    LazyLock::new(|| AtomicBool::new(false));

/// Initiates an immediate process restart.
///
/// This function will:
/// 1. Check if a restart is already in progress
/// 2. Send a notification about the restart
/// 3. Spawn the replacement process (with `-u`, so it takes over the listeners)
/// 4. Send a SIGQUIT signal to the current process so it hands off the listening
///    sockets and exits gracefully
///
/// **Ordering matters.** Pingora's zero-downtime upgrade makes the *new* process
/// the fd receiver (it binds and listens on the upgrade socket, then `accept`s)
/// and the *old* process the fd sender (it `connect`s to that socket on SIGQUIT).
/// Both sides only retry the handshake for ~5s. If we signalled the old process
/// first and spawned the new one afterwards (the previous behaviour), the old
/// process could exhaust its retries and shut down before the new one finished
/// booting and bound the socket — leaving the old process exited and the new one
/// failing its bootstrap. So we start the new process first, then signal.
///
/// Note: pingora's fd transfer is **Linux only**. On other platforms
/// (e.g. macOS) the new `-u` process cannot acquire the listeners and exits;
/// use `--autoreload` (hot reload) for local development instead.
///
/// # Errors
/// Returns an error if:
/// - A restart is already in progress
/// - The restart command is not configured
/// - The restart command fails to spawn
#[cfg(unix)]
pub async fn restart_now() -> io::Result<()> {
    let restarting = PROCESS_RESTARTING.swap(true, Ordering::Relaxed);
    if restarting {
        error!(target: LOG_TARGET, "pingap is restarting now");
        return Err(std::io::Error::new(
            io::ErrorKind::InvalidInput,
            "Pingap is restarting",
        ));
    }
    let Some(cmd) = CMD.get() else {
        PROCESS_RESTARTING.store(false, Ordering::Relaxed);
        return Err(std::io::Error::new(
            io::ErrorKind::NotFound,
            "Command not found",
        ));
    };
    info!(target: LOG_TARGET, "pingap will restart");
    send_notification(NotificationData {
        category: "restart".to_string(),
        message: format!("Restart now, pid:{}", std::process::id()),
        ..Default::default()
    })
    .await;

    // Start the new process first so it can bind the upgrade socket and wait to
    // receive the listening fds ...
    let child = match cmd.exec() {
        Ok(child) => child,
        Err(e) => {
            PROCESS_RESTARTING.store(false, Ordering::Relaxed);
            return Err(e);
        },
    };
    info!(
        target: LOG_TARGET,
        new_pid = child.id(),
        "new pingap process spawned, sending sockets to it"
    );

    // ... then signal the current process to transfer its sockets and exit.
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(std::process::id() as i32),
        nix::sys::signal::SIGQUIT,
    )?;
    Ok(())
}

/// Initiates an immediate process restart (Windows systems - not supported)
#[cfg(windows)]
pub async fn restart_now() -> io::Result<()> {
    return Err(io::Error::new(
        io::ErrorKind::Other,
        "Not support restart".to_string(),
    ));
}

/// Schedules a process restart after a 60-second delay.
///
/// This function will:
/// 1. Increment the restart counter
/// 2. Wait 60 seconds
/// 3. Verify no other restart was requested during the wait
/// 4. Execute the restart if this is still the most recent restart request
///
/// If the restart fails, an error notification will be sent.
pub async fn restart() {
    let count = PROCESS_RESTAR_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    tokio::time::sleep(Duration::from_secs(60)).await;
    if count == PROCESS_RESTAR_COUNT.load(Ordering::Relaxed)
        && let Err(e) = restart_now().await
    {
        error!(
            target: LOG_TARGET,
            error = %e,
            "restart fail"
        );
        send_notification(NotificationData {
            level: NotificationLevel::Error,
            category: "restart_fail".to_string(),
            message: e.to_string(),
            ..Default::default()
        })
        .await;
    }
}
