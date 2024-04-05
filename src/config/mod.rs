use log::info;
use once_cell::sync::Lazy;
use once_cell::sync::OnceCell;
use std::io;
use std::path::PathBuf;
use std::process;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod load;

pub use load::{load_config, save_config, LocationConf, PingapConf, ServerConf, UpstreamConf};

static CONFIG_PATH: OnceCell<String> = OnceCell::new();
pub fn set_config_path(conf_path: &str) {
    CONFIG_PATH.get_or_init(|| conf_path.to_string());
}

pub fn get_config_path() -> String {
    CONFIG_PATH.get_or_init(|| "".to_string()).to_owned()
}

static START_TIME: Lazy<Duration> = Lazy::new(|| {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
});

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

pub fn restart() -> io::Result<process::Output> {
    info!("pingap will restart now");
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
