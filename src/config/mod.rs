use once_cell::sync::OnceCell;

mod load;

pub use load::{load_config, save_config, LocationConf, PingapConf, ServerConf, UpstreamConf};

static CONFIG_PATH: OnceCell<String> = OnceCell::new();
pub fn set_config_path(conf_path: &str) {
    CONFIG_PATH.get_or_init(|| conf_path.to_string());
}

pub fn get_config_path() -> String {
    CONFIG_PATH.get_or_init(|| "".to_string()).to_owned()
}
