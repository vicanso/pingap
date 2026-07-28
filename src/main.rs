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

use crate::certificates::{new_certificate_provider, try_update_certificates};
use crate::config_manager::{
    get_config_manager, try_init_config_manager, try_init_memory_config_manager,
};
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
use pingap_config::PingapConfig;
use pingap_config::{ConfigManager, ETCD_PROTOCOL};
use pingap_core::BackgroundTaskService;
#[cfg(feature = "imageoptim")]
#[allow(unused_imports)]
use pingap_imageoptim::ImageOptim;
use pingap_logger::parse_access_log_directive;
use pingap_logger::{
    AsyncLoggerTask, LogCompressParams, new_async_logger,
    new_log_compress_service,
};
#[cfg(feature = "full")]
use pingap_otel::TracerService;
use pingap_performance::new_performance_metrics_log_service;
use pingap_plugin::get_plugin_factory;
use pingap_proxy::{AppContext, Server, ServerConf, parse_from_conf};
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
use sysinfo::System;

use tracing::{error, info, warn};

mod certificates;
mod config_manager;
mod locations;
mod plugin;
mod process;
mod quick_start;
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

static LOG_TARGET: &str = "main";

const LONG_VERSION: &str =
    concat!(env!("CARGO_PKG_VERSION"), " (", env!("VERGEN_GIT_SHA"), ")");

/// Command line arguments structure for the pingap.
/// A reverse proxy like nginx.
#[derive(Parser, Debug, Default)]
#[command(author, version, about, long_version = LONG_VERSION, long_about = None)]
struct Args {
    /// The config file or directory path
    #[arg(short, long, required_unless_present = "upstream")]
    conf: Option<String>,
    /// Upstream addresses ("host:port", comma separated). Starts a proxy
    /// straight from the command line, without a config file
    #[arg(long, conflicts_with = "conf")]
    upstream: Option<String>,
    /// Domains served by the command line proxy (comma separated)
    #[arg(long, requires = "upstream", conflicts_with = "conf")]
    domain: Option<String>,
    /// TLS certificate for the command line proxy: a PEM file, or a directory
    /// containing one (fullchain.pem, cert.pem, tls.crt, ...)
    #[arg(long, requires = "upstream", conflicts_with = "conf")]
    cert: Option<String>,
    /// TLS private key for the command line proxy, defaults to the key found
    /// next to the certificate
    #[arg(long, requires = "cert", conflicts_with = "conf")]
    key: Option<String>,
    /// Listen address of the command line proxy, defaults to 0.0.0.0:443 with
    /// a certificate and 0.0.0.0:80 without
    #[arg(long, requires = "upstream", conflicts_with = "conf")]
    addr: Option<String>,
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
    #[arg(long, conflicts_with = "upstream")]
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
    /// Convert configuration to HCL format and output
    #[arg(long)]
    to_hcl: bool,
    /// Convert configuration to KDL format and output
    #[arg(long)]
    to_kdl: bool,
    /// Default threads for each server
    #[arg(long)]
    threads: Option<usize>,
}

fn new_server_config(
    args: &Args,
    conf: &PingapConfig,
) -> server::configuration::ServerConf {
    let basic_conf = &conf.basic;
    let mut server_conf = server::configuration::ServerConf {
        pid_file: basic_conf.get_pid_file(),
        upgrade_sock: "/tmp/pingap_upgrade.sock".to_string(),
        user: basic_conf.user.clone(),
        group: basic_conf.group.clone(),
        daemon: args.daemon,
        // Pingora only redirects the daemon's stderr when this is set;
        // otherwise it keeps the inherited one, which is `/dev/null` for a
        // process started by an auto restart.
        error_log: basic_conf.error_log.clone(),
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
    config_manager: Arc<ConfigManager>,
) -> Receiver<Result<PingapConfig, pingap_config::Error>> {
    let (s, r) = crossbeam_channel::bounded(0);
    std::thread::spawn(move || {
        match tokio::runtime::Runtime::new() {
            Ok(rt) => {
                let send = async move {
                    // Before the first read, and before anything can write:
                    // fold any layout left over from a previous `ConfigMode`
                    // into the current one. Failing here must not be fatal - a
                    // read only config directory holding a single old layout
                    // loads perfectly well, and used to.
                    match config_manager.migrate_layout().await {
                        Ok(retired) => {
                            for item in retired {
                                // use println because log is not init
                                println!("config layout migrated: {item}");
                            }
                        },
                        Err(e) => {
                            println!("config layout migration fail, {e}");
                        },
                    }
                    match config_manager.load_all().await {
                        Ok(config) => {
                            // TODO 原有的load config有admin模式
                            let result = config.to_pingap_config(true);
                            if let Err(e) = s.send(result) {
                                println!("sender fail, {e}");
                            }
                        },
                        Err(e) => {
                            if let Err(e) = s.send(Err(e)) {
                                println!("sender fail, {e}");
                            }
                        },
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

fn sync_config(
    config_manager: Arc<ConfigManager>,
    path: String,
) -> Receiver<Result<(), pingap_config::Error>> {
    let (s, r) = crossbeam_channel::bounded(0);
    std::thread::spawn(move || {
        match tokio::runtime::Runtime::new() {
            Ok(rt) => {
                let send = async move {
                    let result =
                        pingap_config::sync_to_path(config_manager, &path)
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
    let config_manager =
        try_init_config_manager(&args.conf.clone().unwrap_or_default())?;
    let opt = Opt {
        daemon: args.daemon,
        ..Default::default()
    };
    // config::set_config_path(&args.conf);
    let mut my_server = server::Server::new(Some(opt))?;
    let ctx = AppContext {
        server_locations_provider: new_server_locations_provider(),
        location_provider: new_location_provider(),
        upstream_provider: new_upstream_provider(),
        plugin_provider: new_plugin_provider(),
        certificate_provider: new_certificate_provider(),
        config_manager,
        logger: None,
    };
    let ps = Server::new(&server_conf, ctx)?;
    let services = ps.run(my_server.configuration.clone())?;
    my_server.add_service(services.lb);

    my_server.bootstrap();
    info!(target: LOG_TARGET, "Admin node server is running");
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
        // `--upstream` builds the config from the command line, it conflicts
        // with `-c`, so the PINGAP_CONF fallback must not be applied either.
        for item in ["-c", "--conf", "--upstream"] {
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

/// Dry-runs each configured plugin through the factory so `--test` reports bad
/// plugin configs, which `PingapConfig::validate` cannot check (the factory
/// lives in a higher layer). A category this build does not know — e.g. a
/// feature-gated plugin that was compiled out — is only warned about, matching
/// runtime behaviour; any other construction error is treated as fatal.
fn validate_plugins(config: &PingapConfig) -> Result<(), Box<dyn Error>> {
    let factory = pingap_plugin::get_plugin_factory();
    for (name, conf) in config.plugins.iter() {
        match factory.create(conf) {
            Ok(_) => {},
            Err(pingap_plugin::Error::NotFound { category }) => {
                warn!(
                    target: LOG_TARGET,
                    name = %name,
                    category = %category,
                    "plugin category is unavailable in this build, skipping validation"
                );
            },
            Err(e) => {
                return Err(format!("plugin \"{name}\" is invalid: {e}").into());
            },
        }
    }
    Ok(())
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

    let mut sys = System::new();
    sys.refresh_memory();
    pingap_cache::update_available_memory(sys.available_memory());

    // Initialize configuration. With `--upstream` the whole config is built
    // from the command line and kept in memory, so no config file is needed.
    let config_manager = if let Some(upstream) = &args.upstream {
        let mut config =
            quick_start::build_config(&quick_start::QuickStartParams {
                domains: args.domain.clone(),
                upstreams: upstream.clone(),
                cert: args.cert.clone(),
                key: args.key.clone(),
                addr: args.addr.clone(),
            })?;
        // Without a certificate the generated config asks let's encrypt for
        // one, and that has to survive a restart: issuing is rate limited.
        let acme_state_path = quick_start::acme_state_path(&config);
        if let Some(path) = &acme_state_path {
            let restored =
                quick_start::restore_acme_certificate(&mut config, path);
            // The logger is not initialized yet, but the operator needs to know
            // where the certificate is kept.
            println!(
                "acme state: {} ({})",
                path.to_string_lossy(),
                if restored {
                    "certificate restored"
                } else {
                    "no certificate yet, one will be requested"
                }
            );
        }
        try_init_memory_config_manager(
            &toml::to_string_pretty(&config)?,
            acme_state_path,
        )?
    } else {
        try_init_config_manager(&args.conf.clone().unwrap_or_default())?
    };

    let r = get_config(get_config_manager()?);
    // A broken config is fatal on its own, but not with `--admin`: the admin
    // server has to come up so the configuration can be repaired through it.
    // Starting on an empty config is indistinguishable from a healthy server
    // that simply has nothing configured, though, so the reason has to be
    // reported. This runs before the logger exists, hence stderr.
    let empty_config =
        |e: Box<dyn Error>| -> Result<PingapConfig, Box<dyn Error>> {
            if args.admin.is_none() {
                return Err(e);
            }
            eprintln!(
                "load config fail, starting with an empty config so it can be fixed through the admin server: {e}"
            );
            Ok(PingapConfig::default())
        };
    let config = match r.recv() {
        Ok(Ok(conf)) => conf,
        Ok(Err(e)) => empty_config(e.into())?,
        Err(e) => empty_config(e.into())?,
    };

    config_manager.set_current_config(config.clone());

    // Convert config to HCL and output
    if args.to_hcl {
        let toml_str = toml::to_string_pretty(&config)?;
        let hcl_str = pingap_config::hcl::convert_toml_to_hcl(&toml_str)?;
        println!("{hcl_str}");
        return Ok(());
    }

    // Convert config to KDL and output
    if args.to_kdl {
        let toml_str = toml::to_string_pretty(&config)?;
        let kdl_str = pingap_config::kdl::convert_toml_to_kdl(&toml_str)?;
        println!("{kdl_str}");
        return Ok(());
    }

    let mut application_log_paths = vec![];

    // Initialize logging system
    let (reload_handle, log_path) =
        pingap_logger::logger_try_init(pingap_logger::LoggerParams {
            capacity: config
                .basic
                .log_buffered_size
                .unwrap_or_default()
                .as_u64(),
            log: args.log.clone().unwrap_or_default(),
            level: config.basic.log_level.clone().unwrap_or_default(),
            json: config.basic.log_format_json.unwrap_or_default(),
        })?;
    if let Some(log_path) = log_path {
        application_log_paths.push(log_path);
    }

    // TODO a better way
    // since the cache will be initialized in validate function
    // so set the current conf first
    // pingap_config::set_current_config(&conf);
    config.validate()?;

    // sync config to other storage
    if let Some(sync_path) = args.sync {
        let r = sync_config(config_manager.clone(), sync_path);
        r.recv()??;
        info!(target: LOG_TARGET, "sync config success");
        return Ok(());
    }

    let basic_conf = &config.basic;

    let webhook_url = basic_conf.webhook.clone().unwrap_or_default();
    webhook::init_webhook_notification_sender(
        webhook_url,
        config.basic.webhook_type.clone().unwrap_or_default(),
        config
            .basic
            .webhook_notifications
            .clone()
            .unwrap_or_default(),
    );

    // return if test mode
    if args.test {
        validate_plugins(&config)?;
        info!(target: LOG_TARGET, "Validate config success");
        return Ok(());
    }

    let auto_restart_check_interval = basic_conf
        .auto_restart_check_interval
        .map_or(Duration::from_secs(90), |item| item);

    #[cfg(feature = "perf")]
    info!(target: LOG_TARGET, "Enable feature perf");

    if let Ok(exec_path) = std::env::current_exe() {
        let mut cmd = process::RestartProcessCommand {
            exec_path,
            ..Default::default()
        };
        if let Ok(env) = std::env::var("RUST_LOG") {
            cmd.log_level = env;
        }
        let mut new_args = vec!["-d".to_string(), "-u".to_string()];
        if let Some(conf) = &args.conf {
            let conf_path = if conf.starts_with(ETCD_PROTOCOL) {
                conf.clone()
            } else {
                pingap_util::resolve_path(conf)
            };
            new_args.push(format!("-c={conf_path}"));
        }
        // The command line proxy has no config file to point the new process
        // at, so pass the arguments it was built from instead.
        for (name, value) in [
            ("upstream", &args.upstream),
            ("domain", &args.domain),
            ("cert", &args.cert),
            ("key", &args.key),
            ("addr", &args.addr),
        ] {
            if let Some(value) = value {
                new_args.push(format!("--{name}={value}"));
            }
        }
        if let Some(log) = &args.log {
            new_args.push(format!("--log={log}"));
        }
        if let Some(admin) = &args.admin {
            new_args.push(format!("--admin={admin}"));
        }
        // Only on the command line: it overrides `basic.threads`, so leaving it
        // out silently drops the replacement process back to the configured
        // value, or to one thread.
        if let Some(threads) = args.threads {
            new_args.push(format!("--threads={threads}"));
        }
        // `--autoreload` is deliberately not forwarded: it is implied by
        // `--autorestart`, which the restarted process gets below.
        if args.autorestart {
            new_args.push("--autorestart".to_string());
        }
        cmd.args = new_args;
        process::set_restart_process_command(cmd);
    }

    try_init_upstreams(&config.upstreams, webhook::get_webhook_sender())?;
    try_init_locations(&config.locations)?;
    try_init_server_locations(&config.servers, &config.locations)?;
    let certificates = config.certificates.clone();

    let opt = Opt {
        upgrade: args.upgrade,
        daemon: args.daemon,
        nocapture: false,
        test: false,
        conf: None,
    };
    let server_conf = new_server_config(&args, &config);
    // The configuration has to be handed to the constructor, not assigned to
    // `my_server.configuration` afterwards. `Server::new` snapshots the
    // configuration it builds into a `Bootstrap`, and `Bootstrap` is what the
    // *receiving* half of a hot upgrade reads `upgrade_sock` from - a later
    // assignment never reaches it. The *sending* half reads
    // `Server::configuration` instead, so the two halves ended up looking for
    // each other on different sockets: the old process sent to our
    // `/tmp/pingap_upgrade.sock` while the new one listened on pingora's
    // default `/tmp/pingora_upgrade.sock`. Both then gave up, and the old
    // process shut down anyway because it had already signalled itself.
    let mut my_server =
        server::Server::new_with_opt_and_conf(Some(opt), server_conf);
    let server_conf = my_server.configuration.as_ref();
    info!(
        target: LOG_TARGET,
        pid_file = server_conf.pid_file,
        error_log = server_conf.error_log,
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
    #[cfg(feature = "full")]
    {
        let sentry_dsn = basic_conf.sentry.clone().unwrap_or_default();
        if !sentry_dsn.is_empty() {
            match pingap_sentry::new_sentry_options(&sentry_dsn) {
                Ok(opts) => {
                    my_server.set_sentry_config(opts);
                },
                Err(e) => {
                    error!(error = e.to_string(), "sentry init fail");
                },
            }
        }
    }
    my_server.bootstrap();

    #[cfg(feature = "pyro")]
    if let Some(url) = &config.basic.pyroscope {
        my_server.add_service(background_service(
            "pyro_agent",
            pingap_pyroscope::new_agent_service(url),
        ));
    }

    info!(
        target: LOG_TARGET,
        plugins = get_plugin_factory().supported_plugins().join(","),
        "plugins are registered"
    );
    let (_, error) = plugin::try_init_plugins(&config.plugins);
    if !error.is_empty() {
        error!(target: LOG_TARGET, error, "init plugins fail",);
    }

    let mut server_conf_list: Vec<ServerConf> = parse_from_conf(config.clone());

    if let Some(addr) = &get_admin_addr() {
        let (server_conf, _, plugin_conf) = plugin::parse_admin_plugin(addr)?;
        let path = if let Some(path) = plugin_conf.get("path") {
            path.to_string()
        } else {
            "".to_string()
        };
        info!(
            target: LOG_TARGET,
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
    let certificate_provider = new_certificate_provider();

    let mut simple_background_service = BackgroundTaskService::new(
        "simple_background_service",
        Duration::from_secs(60),
        vec![
            (
                "validity_checker".to_string(),
                new_certificate_validity_service(
                    certificate_provider.clone(),
                    webhook::get_webhook_sender(),
                ),
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
    simple_background_service.set_immediately(true);
    simple_background_service.set_initial_delay(Some(Duration::from_secs(3)));

    if let Some(task) = new_storage_clear_service() {
        simple_background_service.add_task("storage_clear", task);
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
        simple_background_service.add_task(
            "lets_encrypt",
            new_lets_encrypt_service(
                config_manager.clone(),
                certificate_provider.clone(),
                webhook::get_webhook_sender(),
            ),
        );
    }

    let (updated_certificates, errors) = try_update_certificates(&certificates);
    if !updated_certificates.is_empty() {
        info!(
            target: LOG_TARGET,
            updated_certificates = updated_certificates.join(","),
            "init certificates success"
        );
    }
    if !errors.is_empty() {
        error!(target: LOG_TARGET, error = errors, "parse certificate fail");
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
            application_log_paths.push(task.get_dir());
            my_server.add_service(background_service("access_logger", task));
            Some(tx)
        } else {
            None
        };
        let ctx = AppContext {
            server_locations_provider: new_server_locations_provider(),
            location_provider: new_location_provider(),
            upstream_provider: new_upstream_provider(),
            plugin_provider: new_plugin_provider(),
            certificate_provider: certificate_provider.clone(),
            config_manager: config_manager.clone(),
            logger: access_logger,
        };
        let mut ps = Server::new(&server_conf, ctx)?;
        if enabled_http_challenge && listen_80_port {
            ps.enable_lets_encrypt();
        }
        if let Some(service) = ps.get_prometheus_push_service() {
            simple_background_service.add_task("prometheus_push", service);
        }
        let services = ps.run(my_server.configuration.clone())?;
        my_server.add_service(services.lb);
    }

    let basic_config = &config.basic;
    if !application_log_paths.is_empty()
        && basic_config.log_compress_algorithm.is_some()
    {
        let mut params = LogCompressParams::new(application_log_paths);
        params.set_compression(
            basic_config
                .log_compress_algorithm
                .clone()
                .unwrap_or_default(),
        );
        params.set_level(basic_config.log_compress_level.unwrap_or_default());
        params.set_days_ago(
            basic_config.log_compress_days_ago.unwrap_or_default(),
        );
        params.set_time_point_hour(
            basic_config
                .log_compress_time_point_hour
                .unwrap_or_default(),
        );

        simple_background_service
            .add_task("log_compress", new_log_compress_service(params));
    }

    if args.autorestart || args.autoreload {
        let only_hot_reload = !args.autorestart;
        if config_manager.support_observer() {
            my_server.add_service(background_service(
                "observer",
                new_observer_service(
                    config_manager.clone(),
                    reload_handle,
                    auto_restart_check_interval,
                    only_hot_reload,
                ),
            ));
        } else {
            let auto_restart_task = new_auto_restart_service(
                config_manager.clone(),
                reload_handle,
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
        target: LOG_TARGET,
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
