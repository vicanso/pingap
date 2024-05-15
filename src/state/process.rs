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

use crate::config::{
    get_config_hash, get_config_path, get_current_config, load_config, PingapConf,
};
use crate::util;
use crate::webhook;
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
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::Duration;
use tokio::time::interval;

static START_TIME: Lazy<Duration> = Lazy::new(util::now);

pub static HOST_NAME_TAG: &str = "$HOSTNAME";

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

pub struct AutoRestart {
    pub interval: Duration,
}

async fn validate_restart() -> Result<(bool, PingapConf), Box<dyn std::error::Error>> {
    let conf = load_config(&get_config_path(), false).await?;
    conf.validate()?;
    if conf.hash().unwrap_or_default() != get_config_hash() {
        return Ok((true, conf));
    }
    Ok((false, conf))
}

#[async_trait]
impl BackgroundService for AutoRestart {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        if self.interval < Duration::from_secs(1) {
            return;
        }
        let mut period = interval(self.interval);
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    break;
                }
                _ = period.tick() => {
                    match validate_restart().await {
                       Ok((should_restart, conf)) => {
                           info!("Auto restart background service, should restart:{should_restart}");
                           if should_restart {
                               let diff_result = get_current_config().diff(conf);
                               if !diff_result.is_empty() {
                                    webhook::send(webhook::SendNotificationParams {
                                        level: webhook::NotificationLevel::Info,
                                        category: webhook::NotificationCategory::DiffConfig,
                                        msg: diff_result.join("\n"),
                                    });
                               }
                               restart();
                           }
                       },
                       Err(e) => {
                           error!("Auto restart validate fail, {e}");
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

static PROCESS_RESTAR_COUNT: Lazy<AtomicU8> = Lazy::new(|| AtomicU8::new(0));
static PROCESS_RESTARTING: Lazy<AtomicBool> = Lazy::new(|| AtomicBool::new(false));

pub fn restart_now() -> io::Result<process::Output> {
    let restarting = PROCESS_RESTARTING.swap(true, Ordering::Relaxed);
    if restarting {
        error!("Pingap is restarting now");
        return Err(std::io::Error::new(
            io::ErrorKind::InvalidInput,
            "Pingap is restarting",
        ));
    }
    info!("Pingap will restart");
    webhook::send(webhook::SendNotificationParams {
        level: webhook::NotificationLevel::Info,
        category: webhook::NotificationCategory::Restart,
        msg: format!("Restart now, pid:{}", std::process::id()),
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

pub fn restart() {
    let count = PROCESS_RESTAR_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(60)).await;
        if count == PROCESS_RESTAR_COUNT.load(Ordering::Relaxed) {
            match restart_now() {
                Err(e) => {
                    error!("Restart fail: {e}");
                    webhook::send(webhook::SendNotificationParams {
                        level: webhook::NotificationLevel::Error,
                        category: webhook::NotificationCategory::RestartFail,
                        msg: e.to_string(),
                    });
                }
                Ok(output) => {
                    info!("{output:?}");
                }
            }
        }
    });
}
