pub fn split_to_two_trim(value: &str, pat: &str) -> Option<[String; 2]> {
    let arr: Vec<&str> = value.split(pat).collect();
    if arr.len() < 2 {
        return None;
    }
    let value = arr[1..].join(pat).trim().to_string();

    Some([arr[0].trim().to_string(), value])
}

const NAME: &str = env!("CARGO_PKG_NAME");
const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn get_pkg_name() -> &'static str {
    NAME
}

pub fn get_pkg_version() -> &'static str {
    VERSION
}
