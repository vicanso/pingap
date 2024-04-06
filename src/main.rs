use crate::config::get_start_time;
use crate::proxy::{Server, ServerConf};
use clap::Parser;
use config::PingapConf;
use log::{error, info};
use pingora::server;
use pingora::server::configuration::Opt;
use std::error::Error;
use std::io::Write;
use std::sync::Arc;

mod config;
mod http_extra;
mod proxy;
mod serve;
mod state;
mod utils;

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
        pid_file: format!("/tmp/{}.pid", utils::get_pkg_name()),
        upgrade_sock: format!("/tmp/{}_upgrade.sock", utils::get_pkg_name()),
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
    env_logger::Builder::from_env(env_logger::Env::default())
        .format(|buf, record| {
            writeln!(
                buf,
                "{} {} {}",
                record.level(),
                chrono::Local::now().to_rfc3339(),
                record.args()
            )
        })
        .try_init()?;

    let args = Args::parse();
    let conf = config::load_config(&args.conf, args.admin.is_some())?;
    conf.validate()?;
    // return if test mode
    if args.test {
        info!("validate config success");
        return Ok(());
    }
    config::set_config_path(&args.conf);

    if let Ok(exec_path) = std::env::current_exe() {
        let mut cmd = config::RestartProcessCommand {
            exec_path,
            ..Default::default()
        };
        if let Ok(env) = std::env::var("RUST_LOG") {
            cmd.log_level = env;
        }
        let conf_path = utils::resolve_path(&args.conf);

        let mut new_args = vec![
            format!("-c={conf_path}"),
            "-d".to_string(),
            "-u".to_string(),
        ];
        if let Some(log) = &args.log {
            new_args.push(format!("--log={log}"));
        }
        cmd.args = new_args;
        config::set_restart_process_command(cmd);
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
    if let Err(err) = run() {
        error!("{}", err.to_string());
    }
}
