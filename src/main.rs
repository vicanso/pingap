use crate::proxy::{Server, ServerConf};
use clap::Parser;
use log::{error, info};
use pingora::server;
use pingora::server::configuration::Opt;
use std::error::Error;

mod config;
mod proxy;

/// A reverse proxy like nginx.
#[derive(Parser, Debug, Default)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The config file or directory
    #[arg(short, long)]
    conf: String,
}

fn run() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    let args = Args::parse();
    let conf = config::load_config(&args.conf)?;

    let opt = Opt {
        upgrade: false,
        daemon: false,
        nocapture: false,
        test: false,
        conf: None,
    };
    let mut my_server = server::Server::new(Some(opt))?;
    my_server.bootstrap();

    let server_conf_list: Vec<ServerConf> = conf.try_into()?;
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
