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

use crate::config::get_current_config;
use crate::util;
use crate::webhook;
use bytesize::ByteSize;
use memory_stats::memory_stats;
use once_cell::sync::Lazy;
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::io;
use std::path::PathBuf;
use std::process;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicU8, Ordering};
use std::time::Duration;
use sysinfo::MemoryRefreshKind;
use sysinfo::{RefreshKind, System};
use tracing::{error, info};

static START_TIME: Lazy<Duration> = Lazy::new(util::now);

static ADMIN_ADDR: OnceCell<String> = OnceCell::new();

static ACCEPTED: Lazy<AtomicU64> = Lazy::new(|| AtomicU64::new(0));
static PROCESSING: Lazy<AtomicI32> = Lazy::new(|| AtomicI32::new(0));

pub fn accept_request() {
    ACCEPTED.fetch_add(1, Ordering::Relaxed);
    PROCESSING.fetch_add(1, Ordering::Relaxed);
}

pub fn end_request() {
    PROCESSING.fetch_sub(1, Ordering::Relaxed);
}

pub fn get_processing_accepted() -> (i32, u64) {
    let processing = PROCESSING.load(Ordering::Relaxed);
    let accepted = ACCEPTED.load(Ordering::Relaxed);
    (processing, accepted)
}

#[derive(Serialize, Deserialize)]
pub struct ProcessSystemInfo {
    pub memory_mb: usize,
    pub memory: String,
    pub arch: String,
    pub cpus: usize,
    pub physical_cpus: usize,
    pub total_memory: String,
    pub used_memory: String,
    pub kernel: String,
    pub pid: u32,
    pub threads: usize,
    pub fd_count: usize,
    pub tcp_count: usize,
    pub tcp6_count: usize,
}

pub fn get_process_system_info() -> ProcessSystemInfo {
    let current_config = get_current_config();
    let data =
        std::fs::read(current_config.basic.get_pid_file()).unwrap_or_default();
    let mut pid = std::string::String::from_utf8_lossy(&data)
        .trim()
        .parse::<u32>()
        .unwrap_or_default();
    if pid == 0 {
        pid = process::id();
    }

    cfg_if::cfg_if! {
        if #[cfg(target_os = "linux")] {
            if let Ok(p) = procfs::process::Process::new(pid as i32) {
                let fd_count = p.fd_count().unwrap_or_default();
                let tcp_count = p.tcp().unwrap_or_default().len();
                let tcp6_count = p.tcp6().unwrap_or_default().len();
            }
        } else {
            let fd_count = 0;
            let tcp_count = 0;
            let tcp6_count =0;
        }
    }

    let mut threads = 0;
    let cpu_count = num_cpus::get();
    let mut default_threads = current_config.basic.threads.unwrap_or(1);
    if default_threads == 0 {
        default_threads = cpu_count;
    }
    for (_, server) in current_config.servers.iter() {
        let count = server.threads.unwrap_or(1);
        if count == 0 {
            threads += default_threads;
        } else {
            threads += count;
        }
    }

    let mut memory = "".to_string();
    let mut memory_mb = 0;
    if let Some(value) = memory_stats() {
        memory_mb = value.physical_mem / (1024 * 1024);
        memory = ByteSize(value.physical_mem as u64).to_string_as(true);
    }
    let cpus = num_cpus::get();
    let physical_cpus = num_cpus::get_physical();
    let kind = MemoryRefreshKind::new().with_ram();
    let mut sys =
        System::new_with_specifics(RefreshKind::new().with_memory(kind));
    sys.refresh_memory();

    ProcessSystemInfo {
        memory,
        memory_mb,
        arch: System::cpu_arch().unwrap_or_default(),
        cpus,
        physical_cpus,
        kernel: System::kernel_version().unwrap_or_default(),
        total_memory: ByteSize(sys.total_memory()).to_string_as(true),
        used_memory: ByteSize(sys.used_memory()).to_string_as(true),
        pid,
        threads,
        fd_count,
        tcp_count,
        tcp6_count,
    }
}

pub fn set_admin_addr(addr: &str) {
    ADMIN_ADDR.get_or_init(|| addr.to_string());
}

pub fn get_admin_addr() -> Option<String> {
    ADMIN_ADDR.get().cloned()
}

static HOST_NAME: Lazy<String> = Lazy::new(|| {
    hostname::get()
        .unwrap_or_default()
        .to_str()
        .unwrap_or_default()
        .to_string()
});

pub fn get_start_time() -> u64 {
    START_TIME.as_secs()
}

pub fn get_hostname() -> &'static str {
    HOST_NAME.as_str()
}

#[derive(Debug, Default)]
pub struct RestartProcessCommand {
    pub exec_path: PathBuf,
    pub log_level: String,
    pub args: Vec<String>,
}

impl RestartProcessCommand {
    fn exec(&self) -> io::Result<process::Output> {
        Command::new(&self.exec_path)
            .env("RUST_LOG", &self.log_level)
            .args(&self.args)
            .output()
    }
}

static CMD: OnceCell<RestartProcessCommand> = OnceCell::new();

pub fn set_restart_process_command(data: RestartProcessCommand) {
    CMD.get_or_init(|| data);
}

static PROCESS_RESTAR_COUNT: Lazy<AtomicU8> = Lazy::new(|| AtomicU8::new(0));
static PROCESS_RESTARTING: Lazy<AtomicBool> =
    Lazy::new(|| AtomicBool::new(false));

#[cfg(unix)]
pub fn restart_now() -> io::Result<process::Output> {
    let restarting = PROCESS_RESTARTING.swap(true, Ordering::Relaxed);
    if restarting {
        error!("pingap is restarting now");
        return Err(std::io::Error::new(
            io::ErrorKind::InvalidInput,
            "Pingap is restarting",
        ));
    }
    info!("pingap will restart");
    webhook::send(webhook::SendNotificationParams {
        category: webhook::NotificationCategory::Restart,
        msg: format!("Restart now, pid:{}", std::process::id()),
        ..Default::default()
    });
    if let Some(cmd) = CMD.get() {
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(std::process::id() as i32),
            nix::sys::signal::SIGQUIT,
        )?;
        cmd.exec()
    } else {
        Err(std::io::Error::new(
            io::ErrorKind::NotFound,
            "Command not found",
        ))
    }
}
#[cfg(windows)]
pub fn restart_now() -> io::Result<process::Output> {
    return Err(io::Error::new(
        io::ErrorKind::Other,
        "Not support restart".to_string(),
    ));
}

pub fn restart() {
    let count = PROCESS_RESTAR_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(60)).await;
        if count == PROCESS_RESTAR_COUNT.load(Ordering::Relaxed) {
            match restart_now() {
                Err(e) => {
                    error!(error = e.to_string(), "restart fail");
                    webhook::send(webhook::SendNotificationParams {
                        level: webhook::NotificationLevel::Error,
                        category: webhook::NotificationCategory::RestartFail,
                        msg: e.to_string(),
                        remark: None,
                    });
                },
                Ok(output) => {
                    info!("{output:?}");
                },
            }
        }
    });
}
