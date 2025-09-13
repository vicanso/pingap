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

use crate::locations::new_location_provider;
use crate::locations::try_init_locations;
use crate::plugin::new_plugin_provider;
use crate::server_locations::new_server_locations_provider;
use crate::server_locations::try_init_server_locations;
use crate::upstreams::new_upstream_provider;
use crate::upstreams::try_init_upstreams;
use bytes::BytesMut;
use clap::Parser;
use crossbeam_channel::Receiver;
use pingap_acme::new_lets_encrypt_service;
use pingap_cache::new_storage_clear_service;
use pingap_certificate::{
    new_certificate_validity_service,
    new_self_signed_certificate_validity_service,
};
use pingap_config::{get_config_storage, ETCD_PROTOCOL};
use pingap_config::{LoadConfigOptions, PingapConf};
use pingap_core::BackgroundTaskService;
#[cfg(feature = "imageoptim")]
#[allow(unused_imports)]
use pingap_imageoptim::ImageOptim;
use pingap_logger::parse_access_log_directive;
use pingap_logger::{new_async_logger, AsyncLoggerTask};
#[cfg(feature = "full")]
use pingap_otel::TracerService;
use pingap_performance::new_performance_metrics_log_service;
use pingap_plugin::get_plugin_factory;
use pingap_proxy::{parse_from_conf, Server, ServerConf};
use pingap_upstream::new_upstream_health_check_task;
use pingora::server;
use pingora::server::configuration::Opt;
use pingora::services::background::background_service;
use process::{
    get_admin_addr, get_start_time, new_auto_restart_service,
    new_observer_service, set_admin_addr,
};
use std::collections::HashMap;
use std::error::Error;
use std::ffi::OsString;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};

mod locations;
mod plugin;
mod process;
mod server_locations;
mod upstreams;
mod webhook;

// Avoid musl's default allocator due to lackluster performance
// https://nickb.dev/blog/default-musl-allocator-considered-harmful-to-performance
#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

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
    /// Default threads for each server
    #[arg(long)]
    threads: Option<usize>,
}

fn new_server_conf(
    args: &Args,
    conf: &PingapConf,
) -> server::configuration::ServerConf {
    let basic_conf = &conf.basic;
    let mut server_conf = server::configuration::ServerConf {
        pid_file: basic_conf.get_pid_file(),
        upgrade_sock: "/tmp/pingap_upgrade.sock".to_string(),
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
    if let Some(threads) = args.threads {
        server_conf.threads = threads.max(1);
    }
    if let Some(work_stealing) = basic_conf.work_stealing {
        server_conf.work_stealing = work_stealing
    }
    if let Some(listener_tasks_per_fd) = basic_conf.listener_tasks_per_fd {
        server_conf.listener_tasks_per_fd = listener_tasks_per_fd;
    }

    server_conf
}

fn get_config(
    admin: bool,
) -> Receiver<Result<PingapConf, pingap_config::Error>> {
    let (s, r) = crossbeam_channel::bounded(0);
    std::thread::spawn(move || {
        match tokio::runtime::Runtime::new() {
            Ok(rt) => {
                let send = async move {
                    let result =
                        pingap_config::load_config(LoadConfigOptions {
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
                if let Err(e) = s.send(Err(pingap_config::Error::Invalid {
                    message: e.to_string(),
                })) {
                    // use println because log is not init
                    println!("sender fail, {e}");
                }
            },
        };
    });
    r
}

fn sync_config(path: String) -> Receiver<Result<(), pingap_config::Error>> {
    let (s, r) = crossbeam_channel::bounded(0);
    std::thread::spawn(move || {
        match tokio::runtime::Runtime::new() {
            Ok(rt) => {
                let send = async move {
                    let result = pingap_config::sync_to_path(&path).await;
                    if let Err(e) = s.send(result) {
                        // use println because log is not init
                        println!("sender fail, {e}");
                    }
                };
                rt.block_on(send);
            },
            Err(e) => {
                if let Err(e) = s.send(Err(pingap_config::Error::Invalid {
                    message: e.to_string(),
                })) {
                    // use println because log is not init
                    println!("sender fail, {e}");
                }
            },
        };
    });
    r
}

fn new_access_logger(
    path: &str,
) -> Receiver<
    Result<
        (tokio::sync::mpsc::Sender<BytesMut>, AsyncLoggerTask),
        pingap_core::Error,
    >,
> {
    let file = path.to_string();
    let (s, r) = crossbeam_channel::bounded(0);
    std::thread::spawn(move || {
        match tokio::runtime::Runtime::new() {
            Ok(rt) => {
                let send = async move {
                    let result = new_async_logger(&file).await;
                    if let Err(e) = s.send(result) {
                        // use println because log is not init
                        println!("sender fail, {e}");
                    }
                };
                rt.block_on(send);
            },
            Err(e) => {
                if let Err(e) = s.send(Err(pingap_core::Error::Invalid {
                    message: e.to_string(),
                })) {
                    // use println because log is not init
                    println!("sender fail, {e}");
                }
            },
        };
    });
    r
}

fn run_admin_node(args: Args) -> Result<(), Box<dyn Error>> {
    pingap_logger::logger_try_init(pingap_logger::LoggerParams {
        ..Default::default()
    })?;
    let (server_conf, name, proxy_plugin_info) =
        plugin::parse_admin_plugin(&args.admin.unwrap_or_default())?;

    let (_, error) =
        plugin::try_init_plugins(&HashMap::from([(name, proxy_plugin_info)]));
    if !error.is_empty() {
        error!(error, "init plugins fail",);
    }
    pingap_config::try_init_config_storage(&args.conf)?;
    let opt = Opt {
        daemon: args.daemon,
        ..Default::default()
    };
    // config::set_config_path(&args.conf);
    let mut my_server = server::Server::new(Some(opt))?;
    let ps = Server::new(
        &server_conf,
        None,
        new_server_locations_provider(),
        new_location_provider(),
        new_upstream_provider(),
        new_plugin_provider(),
    )?;
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
            addr = format!("{}@{addr}", pingap_util::base64_encode(&data));
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
    pingap_config::try_init_config_storage(&args.conf)?;
    let r = get_config(args.admin.is_some());
    let conf = r.recv()??;

    // Initialize logging system
    let compression_task =
        pingap_logger::logger_try_init(pingap_logger::LoggerParams {
            capacity: conf.basic.log_buffered_size.unwrap_or_default().as_u64(),
            log: args.log.clone().unwrap_or_default(),
            level: conf.basic.log_level.clone().unwrap_or_default(),
            json: conf.basic.log_format_json.unwrap_or_default(),
        })?;

    // TODO a better way
    // since the cache will be initialized in validate function
    // so set the current conf first
    pingap_config::set_current_config(&conf);
    conf.validate()?;

    // sync config to other storage
    if let Some(sync_path) = args.sync {
        let r = sync_config(sync_path);
        r.recv()??;
        info!("sync config success");
        return Ok(());
    }

    let basic_conf = &conf.basic;

    let webhook_url = basic_conf.webhook.clone().unwrap_or_default();
    webhook::init_webhook_notification_sender(
        webhook_url,
        conf.basic.webhook_type.clone().unwrap_or_default(),
        conf.basic.webhook_notifications.clone().unwrap_or_default(),
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
        let mut cmd = process::RestartProcessCommand {
            exec_path,
            ..Default::default()
        };
        if let Ok(env) = std::env::var("RUST_LOG") {
            cmd.log_level = env;
        }
        let conf_path = if args.conf.starts_with(ETCD_PROTOCOL) {
            args.conf.clone()
        } else {
            pingap_util::resolve_path(&args.conf)
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
        process::set_restart_process_command(cmd);
    }

    try_init_upstreams(&conf.upstreams, webhook::get_webhook_sender())?;
    try_init_locations(&conf.locations)?;
    try_init_server_locations(&conf.servers, &conf.locations)?;
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
        listener_tasks_per_fd = server_conf.listener_tasks_per_fd,
        "server configuration"
    );
    my_server.configuration = Arc::new(server_conf);
    #[cfg(feature = "full")]
    {
        let sentry_dsn = basic_conf.sentry.clone().unwrap_or_default();
        if !sentry_dsn.is_empty() {
            match pingap_sentry::new_sentry_options(&sentry_dsn) {
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
            "pyro_agent",
            pingap_pyroscope::new_agent_service(url),
        ));
    }

    info!(
        "plugins" = get_plugin_factory().supported_plugins().join(","),
        "plugins are registered"
    );
    let (_, error) = plugin::try_init_plugins(&conf.plugins);
    if !error.is_empty() {
        error!(error, "init plugins fail",);
    }

    let mut server_conf_list: Vec<ServerConf> = parse_from_conf(conf.clone());

    if let Some(addr) = &get_admin_addr() {
        let (server_conf, _, plugin_conf) = plugin::parse_admin_plugin(addr)?;
        let path = if let Some(path) = plugin_conf.get("path") {
            path.to_string()
        } else {
            "".to_string()
        };
        info!(
            admin_addr = server_conf.addr,
            path, "admin plugin is created"
        );
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
                &format!("otlp:{}", serve_conf.name),
                TracerService::new(&serve_conf.name, otlp_exporter),
            ));
        }
    }

    let mut simple_background_service = BackgroundTaskService::new(
        "simple_background_service",
        Duration::from_secs(60),
        vec![
            (
                "validity_checker".to_string(),
                new_certificate_validity_service(webhook::get_webhook_sender()),
            ),
            (
                "self_signed_certificate_stale".to_string(),
                new_self_signed_certificate_validity_service(),
            ),
            (
                "performance_metrics".to_string(),
                new_performance_metrics_log_service(
                    new_location_provider(),
                    new_upstream_provider(),
                ),
            ),
        ],
    );

    if let Some(task) = new_storage_clear_service() {
        simple_background_service.add_task("storage_clear", task);
    }
    if let Some(compression_task) = compression_task {
        simple_background_service.add_task("log_compress", compression_task);
    }

    let enabled_http_challenge = certificates.iter().any(|(_, certificate)| {
        let acme = certificate.acme.clone().unwrap_or_default();
        let domains = certificate.domains.clone().unwrap_or_default();
        let dns_challenge = certificate.dns_challenge.unwrap_or_default();
        !acme.is_empty() && !domains.is_empty() && !dns_challenge
    });

    if std::env::var("PINGAP_DISABLE_ACME")
        .unwrap_or_default()
        .is_empty()
    {
        if let Some(storage) = get_config_storage() {
            simple_background_service.add_task(
                "lets_encrypt",
                new_lets_encrypt_service(
                    storage,
                    webhook::get_webhook_sender(),
                ),
            );
        }
    }

    let (updated_certificates, errors) =
        pingap_certificate::try_update_certificates(&certificates);
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
    if !exits_80_server && enabled_http_challenge {
        server_conf_list.push(ServerConf {
            name: "lets encrypt".to_string(),
            addr: "0.0.0.0:80".to_string(),
            ..Default::default()
        });
    }

    for server_conf in server_conf_list {
        let listen_80_port = server_conf.addr.ends_with(":80");
        let (_, log_path) =
            parse_access_log_directive(server_conf.access_log.as_ref());

        let access_logger = if let Some(log_path) = log_path {
            let r = new_access_logger(&log_path);
            let (tx, task) = r.recv()??;
            my_server.add_service(background_service("access_logger", task));
            Some(tx)
        } else {
            None
        };
        let mut ps = Server::new(
            &server_conf,
            access_logger,
            new_server_locations_provider(),
            new_location_provider(),
            new_upstream_provider(),
            new_plugin_provider(),
        )?;
        if enabled_http_challenge && listen_80_port {
            ps.enable_lets_encrypt();
        }
        if let Some(service) = ps.get_prometheus_push_service() {
            simple_background_service.add_task("prometheus_push", service);
        }
        let services = ps.run(&my_server.configuration)?;
        my_server.add_service(services.lb);
    }

    if args.autorestart || args.autoreload {
        let only_hot_reload = !args.autorestart;
        if pingap_config::support_observer() {
            my_server.add_service(background_service(
                "observer",
                new_observer_service(
                    auto_restart_check_interval,
                    only_hot_reload,
                ),
            ));
        } else {
            let auto_restart_task = new_auto_restart_service(
                auto_restart_check_interval,
                only_hot_reload,
            );
            my_server.add_service(background_service(
                &auto_restart_task.name(),
                auto_restart_task,
            ));
        }
    }

    my_server.add_service(background_service(
        &simple_background_service.name(),
        simple_background_service,
    ));

    let upstream_health_check_task = new_upstream_health_check_task(
        new_upstream_provider(),
        Duration::from_secs(10),
        webhook::get_webhook_sender(),
    );
    my_server.add_service(background_service(
        &upstream_health_check_task.name(),
        upstream_health_check_task,
    ));

    info!(
        daemon = args.daemon,
        upgrade = args.upgrade,
        auto_restart = args.autorestart,
        auto_reload = args.autoreload,
        control_plane = args.cp,
        "server is running"
    );
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
