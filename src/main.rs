use crate::proxy::{Server, ServerConf};
use clap::Parser;
use log::{error, info};
use pingora::server;
use pingora::server::configuration::Opt;
use std::error::Error;
use std::io::Write;
use std::sync::Arc;

mod config;
mod proxy;

/// A reverse proxy like nginx.
#[derive(Parser, Debug, Default)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The config file or directory
    #[arg(short, long)]
    conf: String,
    /// Whether should run this server in the background
    #[arg(short, long)]
    daemon: bool,
    /// Whether this server should try to upgrade from an running old server
    #[arg(short, long)]
    upgrade: bool,
    /// Test the configuration and exit
    ///
    /// When this flag is set, calling `server.bootstrap()` will exit the process without errors
    ///
    /// This flag is useful for upgrading service where the user wants to make sure the new
    /// service can start before shutting down the old server process.
    #[arg(short, long)]
    test: Option<bool>,
    /// Log file path
    #[arg(long)]
    log: Option<String>,
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

    let opt = Opt {
        upgrade: args.upgrade,
        daemon: args.daemon,
        nocapture: false,
        test: false,
        conf: None,
    };
    let mut my_server = server::Server::new(Some(opt))?;
    {
        let mut conf = server::configuration::ServerConf::default();
        conf.daemon = args.daemon;
        conf.error_log = args.log;
        my_server.configuration = Arc::new(conf);
    }
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
