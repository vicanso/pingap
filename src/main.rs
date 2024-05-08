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

use crate::acme::LetsEncryptService;
use crate::config::ETCD_PROTOCOL;
use crate::state::AutoRestart;
use clap::Parser;
use config::{PingapConf, ProxyPluginCategory, ProxyPluginConf};
use crossbeam_channel::Sender;
use log::{error, info};
use pingora::server;
use pingora::server::configuration::Opt;
use pingora::services::background::background_service;
use proxy::{Server, ServerConf};
use state::get_start_time;
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

mod acme;
mod config;
mod http_extra;
mod limit;
mod logger;
mod plugin;
mod proxy;
#[cfg(feature = "pyro")]
mod pyro;
mod state;
mod util;
mod webhook;

#[cfg(feature = "perf")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;
#[cfg(feature = "perf")]
mod perf;

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
    /// Admin node for config manager
    ///
    /// This flag is useful for config manager, it will only run as admin,
    /// not run the sevices of config.
    #[arg(long)]
    adminnode: bool,
    /// Whether this server should try to auto restart
    #[arg(long)]
    autorestart: bool,
}

fn new_server_conf(args: &Args, conf: &PingapConf) -> server::configuration::ServerConf {
    let basic_conf = &conf.basic;
    let mut server_conf = server::configuration::ServerConf {
        pid_file: format!("/tmp/{}.pid", util::get_pkg_name()),
        upgrade_sock: format!("/tmp/{}_upgrade.sock", util::get_pkg_name()),
        user: basic_conf.user.clone(),
        group: basic_conf.group.clone(),
        daemon: args.daemon,
        ..Default::default()
    };
    if let Some(value) = basic_conf.grace_period {
        server_conf.grace_period_seconds = Some(value.as_secs());
    }
    if let Some(value) = basic_conf.graceful_shutdown_timeout {
        server_conf.graceful_shutdown_timeout_seconds = Some(value.as_secs());
    }
    if let Some(upstream_keepalive_pool_size) = basic_conf.upstream_keepalive_pool_size {
        server_conf.upstream_keepalive_pool_size = upstream_keepalive_pool_size;
    }
    if let Some(pid_file) = &basic_conf.pid_file {
        server_conf.pid_file = pid_file.to_string();
    }
    if let Some(upgrade_sock) = &basic_conf.upgrade_sock {
        server_conf.upgrade_sock = upgrade_sock.to_string();
    }
    if let Some(threads) = basic_conf.threads {
        server_conf.threads = threads;
    }
    if let Some(work_stealing) = basic_conf.work_stealing {
        server_conf.work_stealing = work_stealing
    }

    server_conf
}

fn get_config(conf: String, admin: bool, s: Sender<Result<PingapConf, config::Error>>) {
    std::thread::spawn(move || {
        match tokio::runtime::Runtime::new() {
            Ok(rt) => {
                let send = async move {
                    let result = config::load_config(&conf, admin).await;
                    if let Err(e) = s.send(result) {
                        println!("sender fail, {e}");
                    }
                };
                rt.block_on(send);
            }
            Err(e) => {
                if let Err(e) = s.send(Err(config::Error::Invalid {
                    message: e.to_string(),
                })) {
                    println!("sender fail, {e}");
                }
            }
        };
    });
}

fn parse_admin_proxy_plugin(addr: &str) -> (ServerConf, String, ProxyPluginConf) {
    let arr: Vec<&str> = addr.split('@').collect();
    let mut addr = arr[0].to_string();
    let mut authorization = "".to_string();
    if arr.len() >= 2 {
        authorization = arr[0].trim().to_string();
        addr = arr[1].trim().to_string();
    }
    (
        ServerConf {
            name: "pingap:admin".to_string(),
            admin: true,
            addr,
            ..Default::default()
        },
        util::ADMIN_SERVER_PLUGIN.clone(),
        ProxyPluginConf {
            value: Some(format!("/ {authorization}")),
            category: ProxyPluginCategory::Admin,
            remark: Some("Admin serve".to_string()),
            step: None,
        },
    )
}

fn run_admin_node(args: Args) -> Result<(), Box<dyn Error>> {
    env_logger::Builder::from_env(env_logger::Env::default()).try_init()?;
    let (server_conf, name, proxy_plugin_info) =
        parse_admin_proxy_plugin(&args.admin.unwrap_or_default());

    if let Err(e) = plugin::init_proxy_plugins(vec![(name, proxy_plugin_info)]) {
        error!("init proxy plugins fail, {e}");
    }
    config::set_config_path(&args.conf);
    let mut my_server = server::Server::new(None)?;
    let ps = Server::new(server_conf)?;
    let services = ps.run(&my_server.configuration)?;
    my_server.add_services(services.bg_services);
    my_server.add_service(services.lb);

    my_server.bootstrap();
    info!("Admin node server is running");
    let _ = get_start_time();

    // TODO not process exit until pingora supports
    my_server.run_forever();
}

fn run() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    if args.adminnode && args.admin.is_some() {
        return run_admin_node(args);
    }

    let (s, r) = crossbeam_channel::bounded(0);
    get_config(args.conf.clone(), args.admin.is_some(), s);
    let conf = r.recv()??;
    conf.validate()?;
    let basic_conf = &conf.basic;
    config::set_current_config(&conf);
    config::set_app_name(&basic_conf.name.clone().unwrap_or_default());

    let webhook_url = basic_conf.webhook.clone().unwrap_or_default();
    webhook::set_web_hook(
        &webhook_url,
        &conf.basic.webhook_type.clone().unwrap_or_default(),
        &conf.basic.webhook_notifications.clone().unwrap_or_default(),
    );

    logger::logger_try_init(logger::LoggerParams {
        capacity: basic_conf.log_capacity.unwrap_or_default(),
        file: args.log.clone().unwrap_or_default(),
        level: basic_conf.log_level.clone().unwrap_or_default(),
    })?;

    // return if test mode
    if args.test {
        info!("Validate config success");
        return Ok(());
    }

    let auto_restart_check_interval = basic_conf
        .auto_restart_check_interval
        .map_or(Duration::from_secs(90), |item| item);

    #[cfg(feature = "perf")]
    info!("Enable feature perf");

    config::set_config_path(&args.conf);
    config::set_config_hash(&conf.hash().unwrap_or_default());

    if let Ok(exec_path) = std::env::current_exe() {
        let mut cmd = state::RestartProcessCommand {
            exec_path,
            ..Default::default()
        };
        if let Ok(env) = std::env::var("RUST_LOG") {
            cmd.log_level = env;
        }
        let conf_path = if args.conf.starts_with(ETCD_PROTOCOL) {
            args.conf.clone()
        } else {
            util::resolve_path(&args.conf)
        };

        let mut new_args = vec![
            format!("-c={conf_path}"),
            "-d".to_string(),
            "-u".to_string(),
        ];
        if let Some(log) = &args.log {
            new_args.push(format!("--log={log}"));
        }
        if let Some(admin) = &args.admin {
            new_args.push(format!("--admin={admin}"));
        }
        if args.autorestart {
            new_args.push("--autorestart".to_string());
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
    my_server.sentry.clone_from(&basic_conf.sentry);
    my_server.bootstrap();

    #[cfg(feature = "pyro")]
    if let Some(url) = &conf.basic.pyroscope {
        let _ = pyro::start_pyroscope(url)?;
    }

    let mut proxy_plugin_confs: Vec<(String, ProxyPluginConf)> = conf
        .proxy_plugins
        .iter()
        .map(|(name, value)| (name.to_string(), value.clone()))
        .collect();

    let mut server_conf_list: Vec<ServerConf> = conf.into();
    if let Some(addr) = args.admin {
        let (server_conf, name, proxy_plugin_info) = parse_admin_proxy_plugin(&addr);
        proxy_plugin_confs.push((name, proxy_plugin_info));
        server_conf_list.push(server_conf);
    }

    if let Err(e) = plugin::init_proxy_plugins(proxy_plugin_confs) {
        error!("init proxy plugins fail, {e}");
    }
    let mut domains = vec![];
    let mut exits_80_server = false;
    for serve_conf in server_conf_list.iter() {
        if serve_conf.addr.ends_with(":80") {
            exits_80_server = true;
        }
        if let Some(value) = &serve_conf.lets_encrypt {
            value.split(',').for_each(|item| {
                let v = item.trim().to_string();
                if !v.is_empty() && !domains.contains(&v) {
                    domains.push(v);
                }
            });
        }
    }
    // no server listen 80 and lets encrypt domains is not empty
    if !exits_80_server && !domains.is_empty() {
        server_conf_list.push(ServerConf {
            name: "lets encrypt".to_string(),
            addr: "0.0.0.0:80".to_string(),
            ..Default::default()
        });
    }

    for server_conf in server_conf_list {
        let listen_80_port = server_conf.addr.ends_with(":80");
        let mut ps = Server::new(server_conf)?;
        if !domains.is_empty() && listen_80_port {
            ps.enable_lets_encrypt();
        }
        let services = ps.run(&my_server.configuration)?;
        my_server.add_services(services.bg_services);
        my_server.add_service(services.lb);
    }

    if args.autorestart {
        my_server.add_service(background_service(
            "Auto Restart",
            AutoRestart {
                interval: auto_restart_check_interval,
            },
        ));
    }
    if !domains.is_empty() {
        my_server.add_service(background_service(
            "Lets encrypt",
            LetsEncryptService { domains },
        ));
    }

    if let Some(plugins) = plugin::list_proxy_plugins() {
        for (name, plugin) in plugins {
            info!(
                "Proxy plugin {name}, category:{}, step:{}",
                plugin.step(),
                plugin.category()
            );
        }
    }
    #[cfg(feature = "perf")]
    {
        my_server.add_service(background_service("Dhat heap", perf::DhatHeapService {}));
        my_server.add_service(background_service(
            "Dhat ad hoc ",
            perf::DhatAdHocService {},
        ));
    }

    info!("Server is running");
    let _ = get_start_time();

    // TODO not process exit until pingora supports
    my_server.run_forever();
}

fn main() {
    if let Err(e) = run() {
        println!("{e}");
        error!("{e}");
    }
}
