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
mod proxy;
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
}

fn new_server_conf(args: &Args, conf: &PingapConf) -> server::configuration::ServerConf {
    let mut server_conf = server::configuration::ServerConf::default();
    server_conf.pid_file = format!("/tmp/{}.pid", utils::get_pkg_name());
    server_conf.upgrade_sock = format!("/tmp/{}.sock", utils::get_pkg_name());
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
    server_conf.user = conf.user.clone();
    server_conf.group = conf.group.clone();
    server_conf.daemon = args.daemon;
    server_conf.error_log = args.log.clone();

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
    let conf = config::load_config(&args.conf)?;
    conf.validate()?;
    // return if test mode
    if args.test {
        info!("validate config success");
        return Ok(());
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

    let server_conf_list: Vec<ServerConf> = conf.into();
    for server_conf in server_conf_list {
        let ps = Server::new(server_conf)?;
        let services = ps.run(&my_server.configuration);
        my_server.add_services(services.bg_services);
        my_server.add_service(services.lb);
    }
    info!("server is running");
    my_server.run_forever();
    Ok(())
}

fn main() {
    if let Err(err) = run() {
        error!("{}", err.to_string());
    }
}
