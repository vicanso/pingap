use crate::proxy::{Server, ServerConf};
use clap::Parser;
use pingora::server;
use pingora::server::configuration::Opt;

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

fn main() {
    env_logger::init();
    let args = Args::parse();
    let conf = config::load_config(&args.conf).unwrap();

    let opt = Opt {
        upgrade: false,
        daemon: false,
        nocapture: false,
        test: false,
        conf: None,
    };
    println!("{opt:?}");
    // opt.daemon = true;
    let mut my_server = server::Server::new(Some(opt)).unwrap();
    my_server.bootstrap();

    let server_conf_list: Vec<ServerConf> = conf.try_into().unwrap();
    for server_conf in server_conf_list {
        let ps = Server::new(server_conf).unwrap();
        let services = ps.run(&my_server.configuration);
        my_server.add_services(services.bg_services);
        my_server.add_service(services.lb);
    }
    println!("{}", std::process::id());
    my_server.run_forever();
}
