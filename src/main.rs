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

use acme::new_lets_encrypt_service;
use cache::new_storage_clear_service;
use certificate::{
    new_certificate_validity_service,
    new_self_signed_certificate_validity_service,
};
use clap::Parser;
use config::{get_config_storage, ETCD_PROTOCOL};
use config::{LoadConfigOptions, PingapConf};
use crossbeam_channel::Sender;
#[cfg(feature = "full")]
use otel::TracerService;
use pingora::server;
use pingora::server::configuration::Opt;
use pingora::services::background::background_service;
use proxy::{new_upstream_health_check_task, Server, ServerConf};
use service::new_simple_service_task;
use service::{
    new_auto_restart_service, new_observer_service,
    new_performance_metrics_log_service,
};
use state::{get_admin_addr, get_start_time, set_admin_addr};
use std::collections::HashMap;
use std::error::Error;
use std::ffi::OsString;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};

mod acme;
mod cache;
mod certificate;
mod config;
mod discovery;
mod health;
mod http_extra;
mod limit;
mod logger;

#[cfg(feature = "full")]
mod otel;
mod plugin;
mod proxy;
#[cfg(feature = "pyro")]
mod pyro;
#[cfg(feature = "full")]
mod sentry;
mod service;
mod state;
mod util;
mod webhook;

static TEMPLATE_CONFIG: &str = r###"
[basic]
log_level = "INFO"
name = "pingap"
pid_file = "/run/pingap.pid"

[locations.httpLocation]
path = "/"
upstream = "httpUpstream"

[servers.httpServer]
access_log = "combined"
addr = "0.0.0.0:80"
locations = ["httpLocation"]

[upstreams.httpUpstream]
addrs = ["127.0.0.1:5000"]
"###;

/// Command line arguments structure for the pingap.
/// A reverse proxy like nginx.
#[derive(Parser, Debug, Default)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The config file or directory path
    #[arg(short, long)]
    conf: String,
    /// Run server in background mode
    #[arg(short, long)]
    daemon: bool,
    /// Enable hot upgrade from a running old server instance
    #[arg(short, long)]
    upgrade: bool,
    /// Validate configuration without starting the server
    #[arg(short, long)]
    test: bool,
    /// Custom log file location
    #[arg(long)]
    log: Option<String>,
    /// Admin server address for management interface
    #[arg(long)]
    admin: Option<String>,
    /// Enable control panel mode (admin-only, no service running)
    #[arg(long)]
    cp: bool,
    /// Enable automatic server restart capability
    #[arg(short, long)]
    autorestart: bool,
    /// Enable automatic config reload capability
    #[arg(long)]
    autoreload: bool,
    /// Sync configuration to specified storage location
    #[arg(long)]
    sync: Option<String>,
    /// Output template configuration
    #[arg(long)]
    template: bool,
}

fn new_server_conf(
    args: &Args,
    conf: &PingapConf,
) -> server::configuration::ServerConf {
    let basic_conf = &conf.basic;
    let mut server_conf = server::configuration::ServerConf {
        pid_file: basic_conf.get_pid_file(),
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
    if let Some(upstream_keepalive_pool_size) =
        basic_conf.upstream_keepalive_pool_size
    {
        server_conf.upstream_keepalive_pool_size = upstream_keepalive_pool_size;
    }
    if let Some(upgrade_sock) = &basic_conf.upgrade_sock {
        server_conf.upgrade_sock = upgrade_sock.to_string();
    }
    if let Some(threads) = basic_conf.threads {
        server_conf.threads = threads.max(1);
    }
    if let Some(work_stealing) = basic_conf.work_stealing {
        server_conf.work_stealing = work_stealing
    }

    server_conf
}

fn get_config(admin: bool, s: Sender<Result<PingapConf, config::Error>>) {
    std::thread::spawn(move || {
        match tokio::runtime::Runtime::new() {
            Ok(rt) => {
                let send = async move {
                    let result = config::load_config(LoadConfigOptions {
                        replace_include: true,
                        admin,
                    })
                    .await;
                    if let Err(e) = s.send(result) {
                        // use println because log is not init
                        println!("sender fail, {e}");
                    }
                };
                rt.block_on(send);
            },
            Err(e) => {
                if let Err(e) = s.send(Err(config::Error::Invalid {
                    message: e.to_string(),
                })) {
                    // use println because log is not init
                    println!("sender fail, {e}");
                }
            },
        };
    });
}

fn sync_config(path: String, s: Sender<Result<(), config::Error>>) {
    std::thread::spawn(move || {
        match tokio::runtime::Runtime::new() {
            Ok(rt) => {
                let send = async move {
                    let result = config::sync_to_path(&path).await;
                    if let Err(e) = s.send(result) {
                        // use println because log is not init
                        println!("sender fail, {e}");
                    }
                };
                rt.block_on(send);
            },
            Err(e) => {
                if let Err(e) = s.send(Err(config::Error::Invalid {
                    message: e.to_string(),
                })) {
                    // use println because log is not init
                    println!("sender fail, {e}");
                }
            },
        };
    });
}

fn run_admin_node(args: Args) -> Result<(), Box<dyn Error>> {
    logger::logger_try_init(logger::LoggerParams {
        ..Default::default()
    })?;
    let (server_conf, name, proxy_plugin_info) =
        plugin::parse_admin_plugin(&args.admin.unwrap_or_default())?;

    if let Err(e) =
        plugin::try_init_plugins(&HashMap::from([(name, proxy_plugin_info)]))
    {
        error!(error = e.to_string(), "init plugins fail",);
    }
    config::try_init_config_storage(&args.conf)?;
    // config::set_config_path(&args.conf);
    let mut my_server = server::Server::new(None)?;
    let ps = Server::new(&server_conf)?;
    let services = ps.run(&my_server.configuration)?;
    my_server.add_service(services.lb);

    my_server.bootstrap();
    info!("Admin node server is running");
    let _ = get_start_time();

    // TODO not process exit until pingora supports
    my_server.run_forever();
}

fn parse_arguments() -> Args {
    let get_from_env = |key: &str| -> String {
        let k = format!("PINGAP_{key}").to_uppercase();
        if let Ok(value) = std::env::var(k) {
            value
        } else {
            "".to_string()
        }
    };
    let mut arr = vec![];
    let mut exist_config_argument = false;
    for arg in std::env::args_os() {
        for item in ["-c", "--conf"] {
            if arg == item
                || arg.to_string_lossy().starts_with(&format!("{item}="))
            {
                exist_config_argument = true;
            }
        }
        arr.push(arg);
    }
    if !exist_config_argument {
        let conf = get_from_env("conf");
        if !conf.is_empty() {
            arr.push(format!("-c={conf}").into());
        }
    }

    if arr.contains(&OsString::from_str("--template").unwrap_or_default()) {
        return Args {
            template: true,
            ..Default::default()
        };
    }
    let mut args = Args::parse_from(arr);

    if !args.daemon && !get_from_env("daemon").is_empty() {
        args.daemon = true;
    }
    if !args.upgrade && !get_from_env("upgrade").is_empty() {
        args.upgrade = true;
    }
    if args.log.is_none() {
        let log = get_from_env("log");
        if !log.is_empty() {
            args.log = Some(log);
        }
    }
    let mut addr = get_from_env("admin_addr");
    if args.admin.is_none() && !addr.is_empty() {
        let user = get_from_env("admin_user");
        let password = get_from_env("admin_password");
        if !user.is_empty() && !password.is_empty() {
            let data = format!("{user}:{password}");
            addr = format!("{}@{addr}", util::base64_encode(&data));
        }
        args.admin = Some(addr)
    }
    if !args.cp && !get_from_env("cp").is_empty() {
        args.cp = true;
    }

    if args.log.is_none() {
        let log = get_from_env("log");
        if !log.is_empty() {
            args.log = Some(log);
        }
    }

    if !args.autorestart && !get_from_env("autorestart").is_empty() {
        args.autorestart = true;
    }
    if !args.autoreload && !get_from_env("autoreload").is_empty() {
        args.autoreload = true;
    }

    args
}

fn run() -> Result<(), Box<dyn Error>> {
    let args = parse_arguments();

    // Handle template output request
    if args.template {
        println!("{TEMPLATE_CONFIG}");
        return Ok(());
    }

    // Set up admin node if specified
    if let Some(admin) = &args.admin {
        set_admin_addr(admin);
    }
    if args.cp && args.admin.is_some() {
        return run_admin_node(args);
    }

    // Initialize configuration
    config::try_init_config_storage(&args.conf)?;
    let (s, r) = crossbeam_channel::bounded(0);
    get_config(args.admin.is_some(), s);
    let conf = r.recv()??;

    // Initialize logging system
    let compression_task = logger::logger_try_init(logger::LoggerParams {
        capacity: conf.basic.log_buffered_size.unwrap_or_default().as_u64(),
        log: args.log.clone().unwrap_or_default(),
        level: conf.basic.log_level.clone().unwrap_or_default(),
        json: conf.basic.log_format_json.unwrap_or_default(),
    })?;

    // TODO a better way
    // since the cache will be initialized in validate function
    // so set the current conf first
    config::set_current_config(&conf);
    conf.validate()?;

    // sync config to other storage
    if let Some(sync_path) = args.sync {
        let (s, r) = crossbeam_channel::bounded(0);
        sync_config(sync_path, s);
        r.recv()??;
        info!("sync config success");
        return Ok(());
    }

    let basic_conf = &conf.basic;
    config::set_app_name(&basic_conf.name.clone().unwrap_or_default());

    let webhook_url = basic_conf.webhook.clone().unwrap_or_default();
    webhook::set_web_hook(
        &webhook_url,
        &conf.basic.webhook_type.clone().unwrap_or_default(),
        &conf.basic.webhook_notifications.clone().unwrap_or_default(),
    );

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

    proxy::try_init_upstreams(&conf.upstreams)?;
    proxy::try_init_locations(&conf.locations)?;
    proxy::try_init_server_locations(&conf.servers, &conf.locations)?;
    let certificates = conf.certificates.clone();

    let opt = Opt {
        upgrade: args.upgrade,
        daemon: args.daemon,
        nocapture: false,
        test: false,
        conf: None,
    };
    let mut my_server = server::Server::new(Some(opt))?;
    let server_conf = new_server_conf(&args, &conf);
    info!(
        pid_file = server_conf.pid_file,
        upgrade_sock = server_conf.upgrade_sock,
        user = server_conf.user,
        group = server_conf.group,
        threads = server_conf.threads,
        work_stealing = server_conf.work_stealing,
        grace_period_seconds = server_conf.grace_period_seconds,
        graceful_shutdown_timeout_seconds =
            server_conf.graceful_shutdown_timeout_seconds,
        upstream_keepalive_pool_size = server_conf.upstream_keepalive_pool_size,
        "server conf"
    );
    my_server.configuration = Arc::new(server_conf);
    #[cfg(feature = "full")]
    {
        let sentry_dsn = basic_conf.sentry.clone().unwrap_or_default();
        if !sentry_dsn.is_empty() {
            match sentry::new_sentry_options(&sentry_dsn) {
                Ok(opts) => {
                    my_server.sentry = Some(opts);
                },
                Err(e) => {
                    error!(error = e.to_string(), "sentry init fail");
                },
            }
        }
    }
    my_server.bootstrap();

    #[cfg(feature = "pyro")]
    if let Some(url) = &conf.basic.pyroscope {
        my_server.add_service(background_service(
            "PyroAgent",
            pyro::new_agent_service(url),
        ));
    }

    if let Err(e) = plugin::try_init_plugins(&conf.plugins) {
        error!(error = e.to_string(), "init plugins fail",);
    }

    let mut server_conf_list: Vec<ServerConf> = conf.into();

    if let Some(addr) = &get_admin_addr() {
        let (server_conf, _, _) = plugin::parse_admin_plugin(addr)?;
        if let Some(server) = server_conf_list
            .iter_mut()
            .find(|item| item.addr == server_conf.addr)
        {
            server.admin = true;
        } else {
            server_conf_list.push(server_conf);
        }
    }

    let mut exits_80_server = false;
    for serve_conf in server_conf_list.iter() {
        if serve_conf.addr.ends_with(":80") {
            exits_80_server = true;
        }
        #[cfg(feature = "full")]
        // add otlp service
        if let Some(otlp_exporter) = &serve_conf.otlp_exporter {
            my_server.add_service(background_service(
                &format!("Otlp:{}", serve_conf.name),
                TracerService::new(&serve_conf.name, otlp_exporter),
            ));
        }
    }

    let mut simple_tasks = vec![
        new_certificate_validity_service(),
        new_self_signed_certificate_validity_service(),
        new_performance_metrics_log_service(),
    ];
    if let Some(task) = new_storage_clear_service() {
        simple_tasks.push(task);
    }
    if let Some(compression_task) = compression_task {
        simple_tasks.push(compression_task);
    }

    let enabled_lets_encrypt = certificates.iter().any(|(_, certificate)| {
        let acme = certificate.acme.clone().unwrap_or_default();
        let domains = certificate.domains.clone().unwrap_or_default();
        !acme.is_empty() && !domains.is_empty()
    });

    if std::env::var("PINGAP_DISABLE_ACME")
        .unwrap_or_default()
        .is_empty()
    {
        if let Some(storage) = get_config_storage() {
            simple_tasks.push(new_lets_encrypt_service(storage));
        }
    }

    let (updated_certificates, errors) =
        proxy::try_update_certificates(&certificates);
    if !updated_certificates.is_empty() {
        info!(
            updated_certificates = updated_certificates.join(","),
            "init certificates success"
        );
    }
    if !errors.is_empty() {
        error!(error = errors, "parse certificate fail");
    }

    // no server listen 80 and lets encrypt domains is not empty
    if !exits_80_server && enabled_lets_encrypt {
        server_conf_list.push(ServerConf {
            name: "lets encrypt".to_string(),
            addr: "0.0.0.0:80".to_string(),
            ..Default::default()
        });
    }

    for server_conf in server_conf_list.iter() {
        let listen_80_port = server_conf.addr.ends_with(":80");
        let mut ps = Server::new(server_conf)?;
        if enabled_lets_encrypt && listen_80_port {
            ps.enable_lets_encrypt();
        }
        if let Some(service) = ps.get_prometheus_push_service() {
            simple_tasks.push(service);
        }
        let services = ps.run(&my_server.configuration)?;
        my_server.add_service(services.lb);
    }

    if args.autorestart || args.autoreload {
        let only_hot_reload = !args.autorestart;
        if config::support_observer() {
            my_server.add_service(background_service(
                "Observer",
                new_observer_service(
                    auto_restart_check_interval,
                    only_hot_reload,
                ),
            ));
        } else {
            my_server.add_service(background_service(
                "AutoRestart",
                new_auto_restart_service(
                    auto_restart_check_interval,
                    only_hot_reload,
                ),
            ));
        }
    }

    my_server.add_service(background_service(
        "SimpleTask",
        new_simple_service_task(
            "simpleTask",
            Duration::from_secs(60),
            simple_tasks,
        ),
    ));

    my_server.add_service(background_service(
        "UpstreamHc",
        new_upstream_health_check_task(Duration::from_secs(10)),
    ));

    info!("Server is running");
    let _ = get_start_time();

    // TODO not process exit until pingora supports
    my_server.run_forever();
}

fn main() {
    if let Err(e) = run() {
        println!("{e}");
        error!(error = e.to_string());
    }
}
