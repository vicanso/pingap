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

use crate::config::{get_config_hash, get_config_path, load_config};
use async_trait::async_trait;
use log::{error, info};
use once_cell::sync::Lazy;
use once_cell::sync::OnceCell;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use std::io;
use std::path::PathBuf;
use std::process;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::interval;

static START_TIME: Lazy<Duration> = Lazy::new(|| {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
});

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

pub fn get_hostname() -> String {
    HOST_NAME.to_string()
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

pub struct AutoRestart {}

fn validate_restart() -> Result<bool, Box<dyn std::error::Error>> {
    let conf = load_config(&get_config_path(), false)?;
    conf.validate()?;
    if conf.hash().unwrap_or_default() != get_config_hash() {
        return Ok(true);
    }
    Ok(false)
}

#[async_trait]
impl BackgroundService for AutoRestart {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let mut period = interval(Duration::from_secs(60));
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    break;
                }
                _ = period.tick() => {
                    match validate_restart() {
                       Ok(should_restart) => {
                           if should_restart {
                               if let Err(e) = restart() {
                                   error!("Restart fail: {e}");
                               }
                               break;
                           }
                       },
                       Err(e) => {
                           error!("auto restart validate fail, {e}");
                       }
                    }
                }
            }
        }
    }
}

static CMD: OnceCell<RestartProcessCommand> = OnceCell::new();

pub fn set_restart_process_command(data: RestartProcessCommand) {
    CMD.get_or_init(|| data);
}

static PROCESS_RESTARTING: Lazy<AtomicBool> = Lazy::new(|| AtomicBool::new(false));

pub fn restart() -> io::Result<process::Output> {
    let restarting = PROCESS_RESTARTING.swap(true, Ordering::Relaxed);
    if restarting {
        error!("pingap is restarting now");
        return Err(std::io::Error::new(
            io::ErrorKind::InvalidInput,
            "Pingap is restarting",
        ));
    }
    info!("pingap will restart");
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