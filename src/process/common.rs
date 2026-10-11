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
use pingap_config::PingapConfig;
use pingap_core::{NotificationData, NotificationLevel};
use std::io;
use std::path::PathBuf;
use std::process;
use std::process::{Command, Stdio};
use std::sync::LazyLock;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::Duration;
use tracing::{error, info, warn};

#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
    /// The directory this process was started in, which the replacement is
    /// started in as well. A daemon runs in `/`, and a replacement started
    /// from there resolved every relative path of the command line and the
    /// config - `--log=logs/pingap.log` for one - against `/`.
    pub current_dir: Option<PathBuf>,
    /// Unix socket the replacement connects to once it is ready for the
    /// listening sockets; lives next to the upgrade socket.
    pub ready_sock: PathBuf,
    /// How long to wait for that before abandoning the restart.
    pub ready_timeout: Duration,
    /// The pid file both generations share. The replacement's daemon writes
    /// its pid there as soon as it has forked, which lets the wait notice a
    /// daemon that died before it could report.
    pub pid_file: String,
    /// The upgrade socket this process hands its listening sockets over
    /// on, which the replacement is told to wait on, see
    /// [`UPGRADE_SOCK_ENV`].
    pub upgrade_sock: String,
}

impl RestartProcessCommand {
    /// Spawns the replacement process **without waiting** for it to exit.
    ///
    /// The new process is started with `-d` (daemon) and `-u` (upgrade), so it
    /// daemonizes itself and takes over the listening sockets from the current
    /// process. We must NOT use `Command::output()` here: it blocks until the
    /// child exits and reads its stdout/stderr to EOF, which never happens for a
    /// long-running daemon, and it would keep this task blocked while the old
    /// process is being torn down. Return the child handle instead.
    ///
    /// stdout/stderr are **inherited**, not discarded. Pingora only redirects a
    /// daemon's stderr when `basic.error_log` is configured; otherwise it keeps
    /// whatever it was given (`Stdio::keep()`). Handing the child `/dev/null`
    /// here therefore threw away every diagnostic the new process produced
    /// before its own logger was up - which is exactly the window where a
    /// failed hot upgrade dies.
    fn exec(&self) -> io::Result<process::Child> {
        self.command().spawn()
    }
    fn command(&self) -> Command {
        let mut command = Command::new(&self.exec_path);
        command
            .env(READY_SOCK_ENV, &self.ready_sock)
            .args(&self.args)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        // What this process was started with, where it was started with
        // one. Set to nothing for a process that had none, the replacement
        // took the empty value for a level and logged errors only: after
        // the first restart the application log was all but silent, the
        // access log lines that go to it included.
        if !self.log_level.trim().is_empty() {
            command.env("RUST_LOG", &self.log_level);
        }
        if !self.upgrade_sock.is_empty() {
            command.env(UPGRADE_SOCK_ENV, &self.upgrade_sock);
        }
        // A directory that is gone by now cannot be started in; the
        // replacement then starts where this process is, as before.
        if let Some(dir) = self.current_dir.as_ref().filter(|dir| dir.is_dir())
        {
            command.current_dir(dir);
        }
        command
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

/// Why a process is not one that can be restarted by handing its
/// listening sockets to a new one.
///
/// A restart starts the replacement as a daemon and lets this process
/// exit. That is a restart where this process is a daemon itself, found
/// through its pid file. Anywhere else whoever started it - a container,
/// a service manager, a shell - sees the process it started end, and
/// takes the service for ended with it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum NoRestart {
    /// pingora hands sockets from one process to another on Linux only.
    Platform,
    /// The first process of a container. When it exits the container
    /// does, and takes the replacement with it: the restart ended, some
    /// minutes later, with nothing running.
    Container,
    /// In the foreground, under whatever started it.
    Foreground,
}

impl NoRestart {
    /// What it is called for the page of the admin, which says it in the
    /// language of whoever is looking.
    pub fn code(&self) -> &'static str {
        match self {
            NoRestart::Platform => "platform",
            NoRestart::Container => "container",
            NoRestart::Foreground => "foreground",
        }
    }
    /// What it is, for the log and for the answer to a request.
    pub fn reason(&self) -> &'static str {
        match self {
            NoRestart::Platform => {
                "a restart hands the listening sockets to a new process, which is done on Linux only: stop and start pingap instead"
            },
            NoRestart::Container => {
                "pingap is the first process of a container, which ends when this process does: restart the container instead"
            },
            NoRestart::Foreground => {
                "pingap runs in the foreground, and a restart would leave a daemon behind while this process exits: restart it where it was started (the service, the container), or run it as a daemon (-d)"
            },
        }
    }
}

/// What keeps a process from being restarted by a hand-over, if anything
/// does: one that runs on `linux` or not, as a `daemon` or not, with
/// `pid`.
fn restart_obstacle(linux: bool, daemon: bool, pid: u32) -> Option<NoRestart> {
    if !linux {
        return Some(NoRestart::Platform);
    }
    if daemon {
        return None;
    }
    if pid == 1 {
        return Some(NoRestart::Container);
    }
    Some(NoRestart::Foreground)
}

static NO_RESTART: OnceLock<Option<NoRestart>> = OnceLock::new();

/// Notes whether this process can be restarted by a hand-over, from how
/// it was started. Once, before anything asks.
pub fn set_restart_mode(daemon: bool) {
    NO_RESTART.get_or_init(|| {
        restart_obstacle(cfg!(target_os = "linux"), daemon, std::process::id())
    });
}

/// Why this process cannot be restarted by a hand-over, where it cannot.
pub fn no_restart() -> Option<NoRestart> {
    NO_RESTART.get().copied().flatten()
}

static PROCESS_RESTAR_COUNT: LazyLock<AtomicU8> =
    LazyLock::new(|| AtomicU8::new(0));
static PROCESS_RESTARTING: LazyLock<AtomicBool> =
    LazyLock::new(|| AtomicBool::new(false));

/// Environment variable through which a restarting pingap tells its
/// replacement where to report readiness: set on the spawned process by
/// [`restart_now`], read by [`new_ready_notify_service`] in the new one.
pub const READY_SOCK_ENV: &str = "PINGAP_READY_SOCK";

/// Environment variable through which a restarting pingap tells its
/// replacement which upgrade socket it sends the listening sockets to.
/// The replacement waits there, whatever `basic.upgrade_sock` is by then.
pub const UPGRADE_SOCK_ENV: &str = "PINGAP_UPGRADE_SOCK";

/// The upgrade socket of the process that started this one for a restart,
/// `None` for a process that was started any other way.
pub fn handed_over_upgrade_sock() -> Option<String> {
    std::env::var(UPGRADE_SOCK_ENV)
        .ok()
        .filter(|path| !path.is_empty())
}

/// Default for `basic.restart_ready_timeout`.
pub const DEFAULT_RESTART_READY_TIMEOUT: Duration = Duration::from_secs(60);

/// An address a server listens on, as pingora is given it, and what
/// decides whether its socket can be bound.
#[derive(Debug, Clone, PartialEq)]
pub struct ListenAddress {
    pub addr: String,
    /// `SO_REUSEPORT`, as the server sets it.
    pub reuse_port: Option<bool>,
}

/// Works out what a process on a configuration listens on.
pub type PlannedListenAddresses =
    fn(&PingapConfig) -> Result<Vec<ListenAddress>, Box<dyn std::error::Error>>;

/// What this process listens on, and how the same is worked out for the
/// configuration its replacement would be started on.
#[cfg(unix)]
struct Listening {
    held: Vec<ListenAddress>,
    planned: PlannedListenAddresses,
}

#[cfg(unix)]
static LISTENING: OnceLock<Listening> = OnceLock::new();

/// Notes what this process listens on. Once, when its servers are made.
/// For a restart to go by, which there is none of elsewhere.
pub fn set_listen_addresses(
    held: Vec<ListenAddress>,
    planned: PlannedListenAddresses,
) {
    #[cfg(unix)]
    LISTENING.get_or_init(|| Listening { held, planned });
    #[cfg(not(unix))]
    let _ = (held, planned);
}

/// Binds a socket to `addr` the way pingora does for a listener, and
/// lets go of it at once. It never listens, so no connection reaches it.
#[cfg(unix)]
fn try_bind(
    addr: std::net::SocketAddr,
    reuse_port: Option<bool>,
) -> io::Result<()> {
    let socket = if addr.is_ipv4() {
        tokio::net::TcpSocket::new_v4()
    } else {
        tokio::net::TcpSocket::new_v6()
    }?;
    socket.set_reuseaddr(true)?;
    if let Some(reuse_port) = reuse_port {
        socket.set_reuseport(reuse_port)?;
    }
    socket.bind(addr)
}

/// Whether a socket on `released` can be what keeps `wanted` from being
/// bound: the same port, and the same address or all of them on one side.
#[cfg(unix)]
fn overlaps(
    released: &std::net::SocketAddr,
    wanted: &std::net::SocketAddr,
) -> bool {
    let (ours, theirs) =
        (released.ip().to_canonical(), wanted.ip().to_canonical());
    released.port() == wanted.port()
        && (ours == theirs || ours.is_unspecified() || theirs.is_unspecified())
}

/// The addresses among `wanted` that a replacement of the process which
/// listens on `held` could not listen on, each with the reason.
///
/// An address this process has is handed over, by the text it is written
/// as, and is not bound again. Every other one is bound by the
/// replacement, which can be tried from here: the same socket options,
/// the same user. One exception: an address that is in use where this
/// process gives one up with the restart, on the same port and an address
/// that overlaps. That may be this process itself, under another spelling
/// of the address, and it lets go of its sockets before the replacement
/// stops trying. What somebody else holds there as well is not seen.
#[cfg(unix)]
fn unbindable(held: &[ListenAddress], wanted: &[ListenAddress]) -> Vec<String> {
    use std::net::ToSocketAddrs;
    // The first one a name resolves to, which is the one pingora binds.
    let resolve =
        |name: &str| name.to_socket_addrs().map(|mut addrs| addrs.next());
    let kept = |addr: &str| wanted.iter().any(|item| item.addr == addr);
    let released: Vec<std::net::SocketAddr> = held
        .iter()
        .filter(|item| !kept(&item.addr))
        .filter_map(|item| resolve(&item.addr).ok().flatten())
        .collect();
    let mut tried: Vec<&str> = vec![];
    let mut failed = vec![];
    for listen in wanted {
        let name = listen.addr.as_str();
        if held.iter().any(|item| item.addr == name) || tried.contains(&name) {
            continue;
        }
        tried.push(name);
        let addr = match resolve(name) {
            Ok(Some(addr)) => addr,
            Ok(None) => {
                failed.push(format!("{name} (resolves to no address)"));
                continue;
            },
            Err(e) => {
                failed.push(format!("{name} ({e})"));
                continue;
            },
        };
        let Err(e) = try_bind(addr, listen.reuse_port) else {
            continue;
        };
        let ours = e.kind() == io::ErrorKind::AddrInUse
            && released.iter().any(|item| overlaps(item, &addr));
        if !ours {
            failed.push(format!("{name} ({e})"));
        }
    }
    failed
}

/// What the stored configuration listens on: the configuration a
/// replacement would be started on.
#[cfg(unix)]
async fn stored_listen_addresses(
    planned: PlannedListenAddresses,
) -> Result<Vec<ListenAddress>, String> {
    let manager = crate::config_manager::get_config_manager()
        .map_err(|e| e.to_string())?;
    let document = manager.load_all().await.map_err(|e| e.to_string())?;
    // Off this thread: a `$FILE:` reference is read from disk.
    tokio::task::spawn_blocking(move || {
        let config = document
            .to_running_config(pingap_config::MissingReference::Refuse)
            .map_err(|e| e.to_string())?;
        planned(&config).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Refuses a restart whose replacement could not listen on an address the
/// stored configuration adds: a port another program has, an address this
/// machine does not have, a port this user may not bind.
///
/// The replacement only finds out when it builds its listeners, and that
/// is after it has reported ready: this process had signalled itself by
/// then and closed its own listeners a few seconds later, while the
/// replacement gave up and exited. Nobody was left to serve, for one new
/// `addr` that could not be had.
///
/// It is a check ahead of time, not a reservation: what takes the port
/// between here and the replacement's own bind is still not seen.
#[cfg(unix)]
async fn check_listen_addresses() -> io::Result<()> {
    let Some(listening) = LISTENING.get() else {
        return Ok(());
    };
    let wanted = match stored_listen_addresses(listening.planned).await {
        Ok(wanted) => wanted,
        // The replacement reads the same and says what is wrong with it,
        // before it reports ready.
        Err(error) => {
            warn!(
                target: LOG_TARGET,
                error,
                "unable to read what the stored configuration listens on, restarting without that check"
            );
            return Ok(());
        },
    };
    let held = listening.held.clone();
    // Off this thread as well: an address given by name is looked up.
    let failed =
        tokio::task::spawn_blocking(move || unbindable(&held, &wanted))
            .await
            .map_err(io::Error::other)?;
    if failed.is_empty() {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        format!(
            "the stored configuration listens on {}, which cannot be bound here",
            failed.join(", ")
        ),
    ))
}

/// How often the wait looks at the spawned process and the pid file.
#[cfg(unix)]
const READY_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Initiates an immediate process restart.
///
/// This function will:
/// 1. Check if a restart is already in progress
/// 2. Send a notification about the restart
/// 3. Bind the readiness socket, then spawn the replacement process (with
///    `-d -u`, so it daemonizes and takes over the listeners) with the
///    socket's path in its environment
/// 4. Wait for the replacement to connect to that socket, which it does right
///    before its bootstrap asks this process for the listening sockets; abort
///    the restart if it exits, its daemon dies, or `restart_ready_timeout`
///    passes first (see [`wait_for_ready`])
/// 5. Send a SIGQUIT signal to the current process so it hands off the listening
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
    // Not started at all where it could only end with nothing running.
    if let Some(obstacle) = no_restart() {
        warn!(
            target: LOG_TARGET,
            reason = obstacle.reason(),
            "a restart is not something this process can do"
        );
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            obstacle.reason(),
        ));
    }
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
    // Before anything is announced or started.
    if let Err(e) = check_listen_addresses().await {
        PROCESS_RESTARTING.store(false, Ordering::Relaxed);
        error!(
            target: LOG_TARGET,
            error = %e,
            "a new listen address cannot be bound, not restarting"
        );
        return Err(e);
    }
    info!(target: LOG_TARGET, "pingap will restart");
    send_notification(NotificationData {
        category: "restart".to_string(),
        message: format!("Restart now, pid:{}", std::process::id()),
        ..Default::default()
    })
    .await;

    // Bind the readiness socket before spawning, so the replacement can never
    // report to nobody ...
    let listener = match ReadyListener::bind(&cmd.ready_sock) {
        Ok(listener) => listener,
        Err(e) => {
            PROCESS_RESTARTING.store(false, Ordering::Relaxed);
            error!(
                target: LOG_TARGET,
                path = %cmd.ready_sock.display(), error = %e,
                "unable to bind the readiness socket, not restarting"
            );
            return Err(e);
        },
    };
    // ... then start it, so it can bind the upgrade socket and wait to receive
    // the listening fds ...
    let child = match cmd.exec() {
        Ok(child) => child,
        Err(e) => {
            PROCESS_RESTARTING.store(false, Ordering::Relaxed);
            return Err(e);
        },
    };
    let new_pid = child.id();
    info!(
        target: LOG_TARGET,
        new_pid,
        "new pingap process spawned, sending sockets to it"
    );

    // A successful spawn only means `execve` worked. The signal below is a
    // point of no return: pingora stops accepting once its close timeout
    // elapses and exits when the grace period does, so signalling ourselves
    // next to a replacement that already died takes the whole service down -
    // several minutes later, which makes it look unrelated to the restart.
    if let Err(e) = wait_for_ready(
        listener,
        child,
        new_pid,
        cmd.ready_timeout,
        &cmd.pid_file,
    )
    .await
    {
        PROCESS_RESTARTING.store(false, Ordering::Relaxed);
        error!(
            target: LOG_TARGET,
            new_pid, error = %e,
            "new pingap process is not ready, keeping the current one"
        );
        return Err(e);
    }

    // ... then signal the current process to transfer its sockets and exit.
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(std::process::id() as i32),
        nix::sys::signal::SIGQUIT,
    )?;
    Ok(())
}

/// The listening end of the readiness channel. Bound before the replacement
/// is spawned; the socket file is removed again on drop, whichever way the
/// restart ends.
#[cfg(unix)]
struct ReadyListener {
    path: PathBuf,
    listener: tokio::net::UnixListener,
}

#[cfg(unix)]
impl ReadyListener {
    fn bind(path: &Path) -> io::Result<Self> {
        // A leftover from a restart that never completed would fail the bind.
        if let Err(e) = std::fs::remove_file(path)
            && e.kind() != io::ErrorKind::NotFound
        {
            return Err(e);
        }
        let listener = tokio::net::UnixListener::bind(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            listener,
        })
    }

    /// Waits for the replacement to connect and identify itself by pid.
    async fn accept(&self) -> io::Result<u32> {
        let (mut stream, _) = self.listener.accept().await?;
        let mut buf = [0u8; 32];
        let n = stream.read(&mut buf).await?;
        Ok(std::str::from_utf8(&buf[..n])
            .ok()
            .and_then(|pid| pid.trim().parse().ok())
            .unwrap_or_default())
    }
}

#[cfg(unix)]
impl Drop for ReadyListener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Waits until the replacement reports that it is ready for the listening
/// sockets, or until it is clear that it never will.
///
/// Three things end the wait. Success: the replacement connects to the
/// readiness socket. Failure: the spawned process exits non-zero, or the
/// daemon it forked - found through the shared pid file - is gone before it
/// reported, or `ready_timeout` passes. Waiting here cannot deadlock the
/// hand-over: the replacement reports *before* its bootstrap asks this process
/// for the sockets, and those only leave on SIGQUIT.
#[cfg(unix)]
async fn wait_for_ready(
    listener: ReadyListener,
    mut child: process::Child,
    new_pid: u32,
    ready_timeout: Duration,
    pid_file: &str,
) -> io::Result<()> {
    let deadline = tokio::time::Instant::now() + ready_timeout;
    let mut poll = tokio::time::interval(READY_POLL_INTERVAL);
    let mut spawned_exited = false;
    // One accept future for the whole wait. `select!` drops the losing
    // branch every round, and a fresh `accept()` per iteration could be
    // dropped by a poll tick between accepting the connection and reading
    // the pid from it, silently losing the report and timing out.
    let accept = listener.accept();
    tokio::pin!(accept);
    loop {
        tokio::select! {
            accepted = &mut accept => {
                let daemon_pid = accepted?;
                info!(
                    target: LOG_TARGET,
                    new_pid, daemon_pid,
                    "new pingap process is ready for the sockets"
                );
                return Ok(());
            },
            _ = poll.tick() => {
                if !spawned_exited {
                    match child.try_wait() {
                        Ok(Some(status)) if !status.success() => {
                            return Err(io::Error::other(format!(
                                "new process({new_pid}) exited with {status} before it was ready"
                            )));
                        },
                        // With `-d` the spawned process leaves as soon as it
                        // has forked the daemon; the pid file tracks it from
                        // here on.
                        Ok(Some(_)) => spawned_exited = true,
                        Ok(None) => {},
                        Err(e) => warn!(
                            target: LOG_TARGET,
                            new_pid, error = %e,
                            "unable to check the new pingap process"
                        ),
                    }
                } else if let Some(pid) = daemon_pid_from(pid_file)
                    && !process_is_running(pid)
                {
                    return Err(io::Error::other(format!(
                        "new daemon({pid}) exited before it was ready"
                    )));
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "new process({new_pid}) did not report readiness within {ready_timeout:?}"
                        ),
                    ));
                }
            },
        }
    }
}

/// The pid the replacement's daemon wrote to the shared pid file, if any and
/// if it is not this process's own (pingora renames the old file away before
/// forking, but be safe).
#[cfg(unix)]
fn daemon_pid_from(pid_file: &str) -> Option<i32> {
    let pid: i32 = std::fs::read_to_string(pid_file)
        .ok()?
        .trim()
        .parse()
        .ok()?;
    (pid != std::process::id() as i32).then_some(pid)
}

#[cfg(unix)]
fn process_is_running(pid: i32) -> bool {
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_ok()
}

/// Reports readiness to the pingap that spawned this one. Runs as a service
/// the bootstrap service depends on, so the report goes out right before this
/// process asks the old one for the listening sockets - which the old one
/// only sends once it has that report.
pub struct ReadyNotifyService {
    path: PathBuf,
}

/// The service to run before bootstrap when this process was started by a
/// restart, `None` for a normal start. The variable is left in place: a
/// restart from this process sets a fresh value on the process it spawns.
pub fn new_ready_notify_service() -> Option<ReadyNotifyService> {
    let path = std::env::var_os(READY_SOCK_ENV)?;
    Some(ReadyNotifyService {
        path: PathBuf::from(path),
    })
}

#[async_trait::async_trait]
impl pingora::services::background::BackgroundService for ReadyNotifyService {
    async fn start_with_ready_notifier(
        &self,
        _shutdown: pingora::server::ShutdownWatch,
        ready_notifier: pingora::services::ServiceReadyNotifier,
    ) {
        match notify_ready(&self.path).await {
            Ok(()) => info!(
                target: LOG_TARGET,
                path = %self.path.display(),
                "reported readiness to the previous pingap process"
            ),
            // Not fatal here: the old process decides what silence means
            // (it abandons the restart and keeps serving), and bootstrap
            // must still run for the failure to surface on this side.
            Err(e) => warn!(
                target: LOG_TARGET,
                path = %self.path.display(), error = %e,
                "unable to report readiness to the previous pingap process"
            ),
        }
        ready_notifier.notify_ready();
    }
}

#[cfg(unix)]
async fn notify_ready(path: &Path) -> io::Result<()> {
    let mut stream = tokio::net::UnixStream::connect(path).await?;
    stream
        .write_all(std::process::id().to_string().as_bytes())
        .await?;
    stream.shutdown().await
}

#[cfg(not(unix))]
async fn notify_ready(_path: &PathBuf) -> io::Result<()> {
    Err(io::Error::other("readiness reporting needs unix sockets"))
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    /// Short on purpose: AF_UNIX paths are capped at about 100 bytes and a
    /// TMPDIR can eat most of that.
    fn sock_path(tag: &str) -> PathBuf {
        PathBuf::from(format!(
            "/tmp/pingap-ready-{}-{tag}.sock",
            std::process::id()
        ))
    }

    #[tokio::test]
    async fn test_ready_channel_round_trip() {
        let path = sock_path("ok");
        let listener = ReadyListener::bind(&path).unwrap();
        // Stands in for the spawned process: alive for the whole wait.
        let child = Command::new("sleep").arg("5").spawn().unwrap();
        let new_pid = child.id();
        // Report and wait side by side, the way the two processes do.
        let (waited, reported) = tokio::join!(
            wait_for_ready(
                listener,
                child,
                new_pid,
                Duration::from_secs(5),
                "/nonexistent/pingap-test.pid",
            ),
            notify_ready(&path),
        );
        reported.expect("the report must go through");
        waited.expect("the report must end the wait");
        // The socket file does not outlive the wait.
        assert_eq!(false, path.exists());
    }

    /// Regression: the replacement was started wherever the old process
    /// happened to be - `/` for a daemon - and resolved its relative paths
    /// from there.
    #[test]
    fn test_replacement_starts_in_the_original_directory() {
        // And with the `RUST_LOG` this process had, or none: an empty one
        // is a level to the replacement, the one that logs errors only.
        let rust_log = |log_level: &str| {
            RestartProcessCommand {
                exec_path: PathBuf::from("pwd"),
                log_level: log_level.to_string(),
                ..Default::default()
            }
            .command()
            .get_envs()
            .find(|(name, _)| *name == "RUST_LOG")
            .map(|(_, value)| value.map(|value| value.to_os_string()))
        };
        assert_eq!(None, rust_log(""));
        assert_eq!(None, rust_log(" "));
        assert_eq!(Some(Some("debug".into())), rust_log("debug"));

        let dir = tempfile::tempdir().unwrap();
        let started_in = |current_dir: Option<PathBuf>| {
            let output = RestartProcessCommand {
                exec_path: PathBuf::from("pwd"),
                current_dir,
                ..Default::default()
            }
            .command()
            .stdout(Stdio::piped())
            .output()
            .unwrap();
            PathBuf::from(String::from_utf8_lossy(&output.stdout).trim())
                .canonicalize()
                .unwrap()
        };
        assert_eq!(
            dir.path().canonicalize().unwrap(),
            started_in(Some(dir.path().to_path_buf()))
        );
        // A directory that no longer exists does not fail the restart.
        let here = std::env::current_dir().unwrap().canonicalize().unwrap();
        assert_eq!(here, started_in(Some(dir.path().join("gone"))));
        assert_eq!(here, started_in(None));
    }

    /// Regression: a replacement that could not listen on a new address
    /// was only found out after the running process had given up its own.
    #[test]
    fn test_unbindable() {
        let listen = |addr: &str| ListenAddress {
            addr: addr.to_string(),
            reuse_port: None,
        };
        let none = Vec::<String>::new();
        // Somebody else has this one.
        let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = taken.local_addr().unwrap().port();
        let taken_addr = format!("127.0.0.1:{port}");
        // And any port is one that is free.
        let free_addr = "127.0.0.1:0";

        let held = [listen("127.0.0.1:6118")];
        // What is handed over is not bound, in use as it is.
        assert_eq!(
            none,
            unbindable(&[listen(&taken_addr)], &[listen(&taken_addr)])
        );
        assert_eq!(
            none,
            unbindable(&held, &[listen("127.0.0.1:6118"), listen(free_addr)])
        );
        // A port another program listens on, named once however often
        // it is asked for.
        let failed = unbindable(
            &held,
            &[listen(&taken_addr), listen(free_addr), listen(&taken_addr)],
        );
        assert_eq!(1, failed.len(), "{failed:?}");
        assert_eq!(true, failed[0].starts_with(&taken_addr), "{failed:?}");
        // An address this machine does not have (TEST-NET-1), and one
        // that is none.
        let failed =
            unbindable(&held, &[listen("192.0.2.1:6200"), listen("nowhere")]);
        assert_eq!(2, failed.len(), "{failed:?}");

        // In use where this process gives an address up, all of them on
        // that port here: that may be this process under another name,
        // which lets go of it.
        let every = listen(&format!("0.0.0.0:{port}"));
        assert_eq!(
            none,
            unbindable(std::slice::from_ref(&every), &[listen(&taken_addr)])
        );
        // Not so when that address is kept: the socket stays as it is,
        // and the new one next to it cannot be had.
        let failed = unbindable(
            std::slice::from_ref(&every),
            &[every.clone(), listen(&taken_addr)],
        );
        assert_eq!(1, failed.len(), "{failed:?}");
        // Nor when what is given up is another address on that port:
        // it is not what is in the way.
        let failed = unbindable(
            &[listen(&format!("127.0.0.2:{port}"))],
            &[listen(&taken_addr)],
        );
        assert_eq!(1, failed.len(), "{failed:?}");
        // Nor for an address that fails another way on that port.
        let failed = unbindable(
            std::slice::from_ref(&every),
            &[listen(&format!("192.0.2.1:{port}"))],
        );
        assert_eq!(1, failed.len(), "{failed:?}");
    }

    #[test]
    fn test_overlaps() {
        let addr = |text: &str| text.parse::<std::net::SocketAddr>().unwrap();
        let overlap = |a: &str, b: &str| overlaps(&addr(a), &addr(b));
        assert_eq!(true, overlap("127.0.0.1:80", "127.0.0.1:80"));
        assert_eq!(true, overlap("0.0.0.0:80", "127.0.0.1:80"));
        assert_eq!(true, overlap("127.0.0.1:80", "[::]:80"));
        assert_eq!(true, overlap("[::ffff:127.0.0.1]:80", "127.0.0.1:80"));
        assert_eq!(false, overlap("127.0.0.1:80", "127.0.0.2:80"));
        assert_eq!(false, overlap("127.0.0.1:80", "[::1]:80"));
        assert_eq!(false, overlap("0.0.0.0:80", "127.0.0.1:81"));
    }

    /// Regression: a restart asked of the first process of a container
    /// handed the sockets to a daemon and exited, which ended the
    /// container, the daemon included.
    #[test]
    fn test_restart_obstacle() {
        // A daemon on Linux, whatever its pid.
        assert_eq!(None, restart_obstacle(true, true, 4321));
        assert_eq!(None, restart_obstacle(true, true, 1));
        assert_eq!(
            Some(NoRestart::Container),
            restart_obstacle(true, false, 1)
        );
        assert_eq!(
            Some(NoRestart::Foreground),
            restart_obstacle(true, false, 4321)
        );
        // Nowhere else, as whatever.
        assert_eq!(Some(NoRestart::Platform), restart_obstacle(false, true, 7));
        assert_eq!(
            Some(NoRestart::Platform),
            restart_obstacle(false, false, 1)
        );
        for obstacle in [
            NoRestart::Platform,
            NoRestart::Container,
            NoRestart::Foreground,
        ] {
            assert_eq!(false, obstacle.code().is_empty());
            assert_eq!(false, obstacle.reason().is_empty());
        }
    }

    /// Regression: a replacement went by the `basic.upgrade_sock` of the
    /// stored configuration, and waited on a path the running process
    /// never sent to.
    #[test]
    fn test_replacement_is_told_the_upgrade_sock() {
        let told = |upgrade_sock: &str| {
            RestartProcessCommand {
                exec_path: PathBuf::from("pwd"),
                upgrade_sock: upgrade_sock.to_string(),
                ..Default::default()
            }
            .command()
            .get_envs()
            .find(|(name, _)| *name == UPGRADE_SOCK_ENV)
            .map(|(_, value)| value.map(|value| value.to_os_string()))
        };
        assert_eq!(None, told(""));
        assert_eq!(
            Some(Some("/run/pingap_upgrade.sock".into())),
            told("/run/pingap_upgrade.sock")
        );
    }

    #[tokio::test]
    async fn test_ready_wait_notices_an_early_exit() {
        let path = sock_path("exit");
        let listener = ReadyListener::bind(&path).unwrap();
        let child = Command::new("sh").args(["-c", "exit 3"]).spawn().unwrap();
        let new_pid = child.id();
        let err = wait_for_ready(
            listener,
            child,
            new_pid,
            Duration::from_secs(5),
            "/nonexistent/pingap-test.pid",
        )
        .await
        .expect_err("must fail");
        assert_eq!(
            true,
            err.to_string()
                .contains("exited with exit status: 3 before it was ready"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn test_ready_wait_times_out() {
        let path = sock_path("timeout");
        let listener = ReadyListener::bind(&path).unwrap();
        let child = Command::new("sleep").arg("5").spawn().unwrap();
        let new_pid = child.id();
        let err = wait_for_ready(
            listener,
            child,
            new_pid,
            Duration::from_millis(500),
            "/nonexistent/pingap-test.pid",
        )
        .await
        .expect_err("must time out");
        assert_eq!(io::ErrorKind::TimedOut, err.kind());
        assert_eq!(false, path.exists());
    }

    #[test]
    fn test_new_ready_notify_service_needs_the_env() {
        // The variable is never set in the test process.
        assert_eq!(true, new_ready_notify_service().is_none());
    }
}
