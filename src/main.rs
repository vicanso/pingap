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

use crate::proxy::{Server, ServerConf};
use crate::state::get_start_time;
use clap::Parser;
use config::PingapConf;
use log::{error, info, Level};
use pingora::server;
use pingora::server::configuration::Opt;
use std::error::Error;
use std::io::Write;
use std::sync::Arc;

mod config;
mod http_extra;
mod plugin;
mod proxy;
mod serve;
mod state;
mod util;
mod webhook;

/// A reverse proxy like nginx.
#[derive(Parser, Debug, Default)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The config file or directory
    #[arg(short, long, default_value = ".")]
    conf: String,
    /// Whether should run this server in the background
    #[arg(short, long)]
    daemon: bool,
    /// Whether this server should try to upgrade from an running old server
    #[arg(short, long)]
    upgrade: bool,
    /// Test the configuration and exit
    ///
    /// This flag is useful for upgrading service where the user wants to make sure the new
    /// service can start before shutting down the old server process.
    #[arg(short, long)]
    test: bool,
    /// Log file path
    #[arg(long)]
    log: Option<String>,
    /// Admin server adddr
    #[arg(long)]
    admin: Option<String>,
}

fn new_server_conf(args: &Args, conf: &PingapConf) -> server::configuration::ServerConf {
    let mut server_conf = server::configuration::ServerConf {
        pid_file: format!("/tmp/{}.pid", util::get_pkg_name()),
        upgrade_sock: format!("/tmp/{}_upgrade.sock", util::get_pkg_name()),
        user: conf.user.clone(),
        group: conf.group.clone(),
        daemon: args.daemon,
        error_log: args.log.clone(),
        ..Default::default()
    };
    if let Some(value) = conf.grace_period {
        server_conf.grace_period_seconds = Some(value.as_secs());
    }
    if let Some(value) = conf.graceful_shutdown_timeout {
        server_conf.graceful_shutdown_timeout_seconds = Some(value.as_secs());
    }
    if let Some(upstream_keepalive_pool_size) = conf.upstream_keepalive_pool_size {
        server_conf.upstream_keepalive_pool_size = upstream_keepalive_pool_size;
    }
    if let Some(pid_file) = &conf.pid_file {
        server_conf.pid_file = pid_file.to_string();
    }
    if let Some(upgrade_sock) = &conf.upgrade_sock {
        server_conf.upgrade_sock = upgrade_sock.to_string();
    }
    if let Some(threads) = conf.threads {
        server_conf.threads = threads;
    }
    if let Some(work_stealing) = conf.work_stealing {
        server_conf.work_stealing = work_stealing
    }

    server_conf
}

fn run() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let conf = config::load_config(&args.conf, args.admin.is_some())?;
    conf.validate()?;
    let webhook_url = conf.webhook.clone().unwrap_or_default();
    let webhook_type = conf.webhook_type.clone().unwrap_or_default();
    let mut builder = env_logger::Builder::from_env(env_logger::Env::default());

    if let Some(log_level) = &conf.log_level {
        match log_level.to_lowercase().as_str() {
            "error" => builder.filter_level(log::LevelFilter::Error),
            "warn" => builder.filter_level(log::LevelFilter::Warn),
            "debug" => builder.filter_level(log::LevelFilter::Debug),
            _ => builder.filter_level(log::LevelFilter::Info),
        };
    } else if std::env::var(env_logger::DEFAULT_FILTER_ENV).is_err() {
        builder.filter_level(log::LevelFilter::Error);
    }

    builder
        .format(move |buf, record| {
            let msg = format!("{}", record.args());
            if !webhook_url.is_empty()
                && record.level() == Level::Warn
                && msg.contains("becomes unhealthy")
            {
                webhook::send(webhook::WebhookSendParams {
                    url: webhook_url.clone(),
                    category: "backend_unhealthy".to_string(),
                    webhook_type: webhook_type.clone(),
                    msg: format!("{}", record.args()),
                });
            }

            writeln!(
                buf,
                "{} {} {msg}",
                record.level(),
                chrono::Local::now().to_rfc3339(),
            )
        })
        .try_init()?;

    // return if test mode
    if args.test {
        info!("validate config success");
        return Ok(());
    }
    config::set_config_path(&args.conf);
    config::set_config_hash(&conf.hash);

    if let Ok(exec_path) = std::env::current_exe() {
        let mut cmd = state::RestartProcessCommand {
            exec_path,
            ..Default::default()
        };
        if let Ok(env) = std::env::var("RUST_LOG") {
            cmd.log_level = env;
        }
        let conf_path = util::resolve_path(&args.conf);

        let mut new_args = vec![
            format!("-c={conf_path}"),
            "-d".to_string(),
            "-u".to_string(),
        ];
        if let Some(log) = &args.log {
            new_args.push(format!("--log={log}"));
        }
        cmd.args = new_args;
        state::set_restart_process_command(cmd);
    }

    let opt = Opt {
        upgrade: args.upgrade,
        daemon: args.daemon,
        nocapture: false,
        test: false,
        conf: None,
    };
    let mut my_server = server::Server::new(Some(opt))?;
    my_server.configuration = Arc::new(new_server_conf(&args, &conf));
    my_server.sentry = conf.sentry.clone();
    my_server.bootstrap();

    let mut server_conf_list: Vec<ServerConf> = conf.into();
    if let Some(addr) = args.admin {
        server_conf_list.push(ServerConf {
            name: "admin".to_string(),
            admin: true,
            addr,
            ..Default::default()
        });
    }
    for server_conf in server_conf_list {
        let ps = Server::new(server_conf)?;
        let services = ps.run(&my_server.configuration)?;
        my_server.add_services(services.bg_services);
        my_server.add_service(services.lb);
    }
    info!("server is running");
    let _ = get_start_time();
    my_server.run_forever();
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        // avoid env logger is not init
        println!("{e}");
        error!("{e}");
    }
}
