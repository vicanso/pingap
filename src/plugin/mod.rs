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

use crate::process::get_admin_addr;
use ahash::AHashMap;
use arc_swap::ArcSwap;
use pingap_config::{PingapConfig, PluginConf};
use pingap_core::{Plugin, PluginProvider, PluginStep, Plugins};
use pingap_plugin::get_plugin_factory;
// Reuse the canonical plugin-config helpers instead of keeping a second copy.
// `get_hash_key` in particular MUST stay byte-identical to the one plugins use
// to compute their config key, otherwise hot-reload change detection breaks.
pub(crate) use pingap_plugin::{
    get_hash_key, get_int_conf, get_step_conf, get_str_conf, get_str_slice_conf,
};
use pingap_proxy::ServerConf;
use pingap_util::base64_encode;
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{error, info, warn};

mod admin;
mod stats;

/// UUID for the admin server plugin, generated at runtime
pub static ADMIN_SERVER_PLUGIN: &str = "pingap:admin";

static LOG_TARGET: &str = "main::plugin";

#[derive(Debug, PartialEq, Deserialize, Serialize, Default)]
struct AdminPluginParams {
    max_age: Option<String>,
}

/// Parses admin plugin configuration from an address string.
///
/// # Arguments
/// * `addr` - The address string to parse in URL format
///
/// # Returns
/// A tuple containing:
/// - ServerConf: The server configuration
/// - String: The plugin name
/// - PluginConf: The plugin configuration
///
/// # Errors
/// Returns Error::Invalid if URL parsing fails
pub fn parse_admin_plugin(
    addr: &str,
) -> Result<(ServerConf, String, PluginConf)> {
    let info = url::Url::from_str(&format!("http://{addr}")).map_err(|e| {
        Error::Invalid {
            category: "url".to_string(),
            message: e.to_string(),
        }
    })?;
    let mut addr = info.host_str().unwrap_or_default().to_string();
    addr = format!("{addr}:{}", info.port().unwrap_or(80));

    // The url parser keeps the user info percent-encoded. The password used
    // to be taken in that form, so `p=ss` became `p%3Dss` and the login
    // with the password as typed failed.
    let decode = |value: &str| {
        urlencoding::decode(value)
            .map(|value| value.to_string())
            .unwrap_or_else(|_| value.to_string())
    };
    let user = decode(info.username());
    let authorization = match info.password() {
        Some(pass) => base64_encode(format!("{user}:{}", decode(pass))),
        // No password: the user part is the base64 of `user:password`.
        // Anything else was dropped later on, which left the admin without
        // credentials and so without authentication (`--admin root@addr`).
        None => {
            if !user.is_empty() && !is_base64_credential(&user) {
                return Err(Error::Invalid {
                    category: "admin".to_string(),
                    message: "expect user:password@addr, or the base64 of user:password in place of the user".to_string(),
                });
            }
            user
        },
    };
    let mut path = info.path().to_string();
    if path.is_empty() {
        path = "/".to_string();
    }
    let params: AdminPluginParams =
        serde_qs::from_str(info.query().unwrap_or_default())
            .unwrap_or_default();
    let max_age = params.max_age.unwrap_or("2d".to_string());

    // Built as a table, not as formatted text: a `"` in the path or the
    // user info broke the toml, and the fallback was an empty plugin config.
    let mut conf = PluginConf::new();
    conf.insert("category".to_string(), "admin".into());
    conf.insert("path".to_string(), path.into());
    conf.insert("authorizations".to_string(), vec![authorization].into());
    conf.insert("max_age".to_string(), max_age.into());
    conf.insert("remark".to_string(), "Admin serve".into());
    Ok((
        ServerConf {
            name: "pingap:admin".to_string(),
            admin: true,
            addr,
            ..Default::default()
        },
        ADMIN_SERVER_PLUGIN.to_string(),
        conf,
    ))
}

fn is_base64_credential(value: &str) -> bool {
    let Ok(data) = pingap_util::base64_decode(value) else {
        return false;
    };
    String::from_utf8_lossy(&data)
        .split_once(':')
        .is_some_and(|(user, pass)| !user.is_empty() && !pass.is_empty())
}

/// Error types for plugin operations
#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Plugin {category} invalid, message: {message}"))]
    Invalid { category: String, message: String },
}
type Result<T, E = Error> = std::result::Result<T, E>;

/// Returns a list of built-in plugins with their default configurations.
///
/// Includes plugins for:
/// - Compression (gzip, br, zstd)
/// - Ping health check
/// - Stats reporting
/// - Request ID generation
/// - Accept-Encoding adjustment
pub fn get_builtin_proxy_plugins() -> Vec<(String, PluginConf)> {
    vec![
        // default level, gzip:6 br:6 zstd:3
        (
            "pingap:compression".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "compression"
gzip_level = 6
br_level = 6
zstd_level = 6
remark = "Compression for http, support zstd:6, br:6, gzip:6"
"###,
            )
            .unwrap_or_default(),
        ),
        (
            "pingap:compressionUpstream".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "compression"
gzip_level = 6
br_level = 6
zstd_level = 6 
mode = "upstream"
remark = "Compression for upstream response, support zstd:6, br:6, gzip:6"
"###,
            )
            .unwrap_or_default(),
        ),
        (
            "pingap:ping".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "ping"
path = "/ping"
remark = "Ping pong"
"###,
            )
            .unwrap_or_default(),
        ),
        (
            "pingap:stats".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "stats"
path = "/stats"
remark = "Get stats of server"
"###,
            )
            .unwrap_or_default(),
        ),
        (
            "pingap:requestId".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "request_id"
remark = "Generate a request id for service"
"###,
            )
            .unwrap_or_default(),
        ),
        (
            "pingap:acceptEncodingAdjustment".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "accept_encoding"
encodings = "zstd, br, gzip"
only_one_encoding = true
remark = "Adjust the accept encoding order and choose one encoding"
"###,
            )
            .unwrap_or_default(),
        ),
    ]
}

struct Provider {
    plugins: ArcSwap<Plugins>,
    /// Bumped on every `store`, so locations drop the plugin lists they
    /// resolved against the previous set.
    version: AtomicU64,
}

impl Provider {
    fn store(&self, data: Plugins) {
        self.plugins.store(Arc::new(data));
        self.version.fetch_add(1, Ordering::Release);
    }
}

static PLUGIN_PROVIDER: LazyLock<Arc<Provider>> = LazyLock::new(|| {
    Arc::new(Provider {
        plugins: ArcSwap::from_pointee(AHashMap::new()),
        version: AtomicU64::new(0),
    })
});

impl PluginProvider for Provider {
    fn get(&self, name: &str) -> Option<Arc<dyn Plugin>> {
        self.plugins.load().get(name).cloned()
    }

    fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }
}

pub fn new_plugin_provider() -> Arc<dyn PluginProvider> {
    PLUGIN_PROVIDER.clone()
}

/// A plugin category that only some builds have.
struct GatedCategory {
    category: &'static str,
    /// The cargo feature that brings it in.
    feature: &'static str,
    /// Whether a location may be served without it. An image that is not
    /// re-encoded is still the image; a request that is not checked
    /// against the country list is a request let through.
    optional: bool,
}

/// One config is often shared between builds, so a plugin of one of these
/// categories is not an error where the category is missing. What happens
/// to the locations that name it depends on `optional`.
const FEATURE_GATED_CATEGORIES: &[GatedCategory] = &[
    GatedCategory {
        category: "image_optim",
        feature: "imageoptim",
        optional: true,
    },
    GatedCategory {
        category: "geo_restriction",
        feature: "geo",
        optional: false,
    },
];

fn gated_category(category: &str) -> Option<&'static GatedCategory> {
    FEATURE_GATED_CATEGORIES
        .iter()
        .find(|gated| gated.category == category)
}

/// The gated category `err` is about, when all it says is that this build
/// was compiled without it. Any other unknown category is a mistake in the
/// config (`basic_auht`) and has to be reported as one.
fn unavailable_category(
    err: &pingap_plugin::Error,
) -> Option<&'static GatedCategory> {
    match err {
        pingap_plugin::Error::NotFound { category } => gated_category(category),
        _ => None,
    }
}

/// Whether `err` only says that this build was compiled without the
/// plugin's category.
pub fn is_unavailable_in_build(err: &pingap_plugin::Error) -> bool {
    unavailable_category(err).is_some()
}

/// Stands in for a plugin whose category this build was compiled without,
/// and does nothing. It keeps the name resolvable: a name that resolves to
/// nothing makes the location reject its requests (`MissingPlugin`).
struct UnavailablePlugin {
    hash_value: String,
}

impl Plugin for UnavailablePlugin {
    fn config_key(&self) -> std::borrow::Cow<'_, str> {
        std::borrow::Cow::Borrowed(&self.hash_value)
    }
}

/// Checks that every plugin a location names exists: defined in the config,
/// or one of the built-in `pingap:*` plugins.
///
/// A misspelled name used to pass `--test` and load, and the location then
/// served without that plugin.
pub fn validate_plugin_references(config: &PingapConfig) -> Result<()> {
    validate_plugin_names(config)?;
    validate_plugin_features(config)
}

/// The part of [`validate_plugin_references`] that holds for any build:
/// every plugin a location names is defined, or built in.
pub fn validate_plugin_names(config: &PingapConfig) -> Result<()> {
    let builtin: Vec<String> = get_builtin_proxy_plugins()
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    // The admin plugin is only there when this process was given `--admin`.
    let has_admin = get_admin_addr().is_some();
    for (location_name, location) in config.locations.iter() {
        for name in location.plugins.iter().flatten() {
            if config.plugins.contains_key(name)
                || builtin.contains(name)
                || (has_admin && name == ADMIN_SERVER_PLUGIN)
            {
                continue;
            }
            return Err(Error::Invalid {
                category: "location".to_string(),
                message: format!(
                    "plugin({name}) of location({location_name}) is not found"
                ),
            });
        }
    }
    Ok(())
}

/// The part of [`validate_plugin_references`] that depends on this build.
fn validate_plugin_features(config: &PingapConfig) -> Result<()> {
    // A plugin this build can not provide and a location can not go
    // without. Defining one is harmless, the config may be meant for
    // another build as well; naming it in a location is not.
    let supported = get_plugin_factory().supported_plugins();
    for (location_name, location) in config.locations.iter() {
        for name in location.plugins.iter().flatten() {
            let Some(gated) = config
                .plugins
                .get(name)
                .and_then(|conf| conf.get("category"))
                .and_then(|category| category.as_str())
                .and_then(gated_category)
            else {
                continue;
            };
            if gated.optional
                || supported.iter().any(|item| item == gated.category)
            {
                continue;
            }
            return Err(Error::Invalid {
                category: "location".to_string(),
                message: format!(
                    "plugin({name}) of location({location_name}) is a {} plugin, which needs a build with the {} feature",
                    gated.category, gated.feature
                ),
            });
        }
    }
    Ok(())
}

/// Parses plugin configurations and instantiates plugin instances.
///
/// # Arguments
/// * `configs` - Vector of (name, config) tuples for plugins to initialize
///
/// # Returns
/// The plugins that were built, and one error for each that was not.
pub fn parse_plugins(
    configs: Vec<(String, PluginConf)>,
) -> (Plugins, Vec<Error>) {
    let mut plugins: Plugins = AHashMap::new();
    let mut errors: Vec<Error> = vec![];
    for (name, conf) in configs.iter() {
        let name = name.to_string();
        let category = if let Some(value) = conf.get("category") {
            value.as_str().unwrap_or_default().to_string()
        } else {
            "".to_string()
        };
        if category.is_empty() {
            errors.push(Error::Invalid {
                category: "".to_string(),
                message: format!("category of {name} can not be empty"),
            });
            continue;
        }

        match get_plugin_factory().create(conf) {
            Ok(plugin) => {
                plugins.insert(name.clone(), plugin.clone());
            },
            Err(e) => match unavailable_category(&e) {
                Some(gated) if gated.optional => {
                    warn!(
                        target: LOG_TARGET,
                        name,
                        category,
                        feature = gated.feature,
                        "plugin category is unavailable in this build, the plugin does nothing"
                    );
                    plugins.insert(
                        name.clone(),
                        Arc::new(UnavailablePlugin {
                            hash_value: get_hash_key(conf),
                        }),
                    );
                },
                // Not loaded. A location naming it is refused by
                // `validate_plugin_references`, and rejects its requests if
                // it gets that far anyway.
                Some(gated) => {
                    warn!(
                        target: LOG_TARGET,
                        name,
                        category,
                        feature = gated.feature,
                        "plugin category is unavailable in this build, the plugin is not loaded"
                    );
                },
                None => {
                    errors.push(Error::Invalid {
                        category,
                        message: format!("create plugin {name} failed, {e}"),
                    });
                },
            },
        }
    }

    (plugins, errors)
}

/// Initializes or updates plugins based on configuration.
///
/// A plugin whose new config fails to build keeps its previous instance.
/// Dropping it left its locations without the plugin - without the
/// authentication, when that is what it was - for as long as the config
/// stayed broken. A plugin that never built has no instance to keep, and
/// the locations naming it reject their requests.
///
/// # Arguments
/// * `plugins` - HashMap of plugin names to configurations
///
/// # Returns
/// The names of the plugins that were created or updated, and the errors
/// joined into one message (empty when everything built).
pub fn try_init_plugins(
    plugins: &HashMap<String, PluginConf>,
) -> (Vec<String>, String) {
    let mut plugin_configs: Vec<(String, PluginConf)> = plugins
        .iter()
        .map(|(name, value)| (name.to_string(), value.clone()))
        .collect();

    // add admin plugin
    let mut errors = vec![];
    if let Some(addr) = &get_admin_addr() {
        match parse_admin_plugin(addr) {
            Ok((_, name, proxy_plugin_info)) => {
                plugin_configs.push((name, proxy_plugin_info));
            },
            Err(e) => {
                errors.push(e);
            },
        }
    }

    plugin_configs.extend(get_builtin_proxy_plugins());

    let mut pending_plugins = vec![];
    let mut plugins = AHashMap::new();
    let plugin_configs: Vec<(String, PluginConf)> = plugin_configs
        .into_iter()
        .filter(|(name, conf)| {
            let conf_hash_key = get_hash_key(conf);
            let mut exists = false;
            if let Some(plugin) = PLUGIN_PROVIDER.get(name) {
                exists = true;
                // exists plugin with same config
                if plugin.config_key() == conf_hash_key {
                    plugins.insert(name.to_string(), plugin);
                    return false;
                }
            }
            let step = get_step_conf(conf, PluginStep::Request).to_string();
            let category = if let Some(value) = conf.get("category") {
                value.as_str().unwrap_or_default().to_string()
            } else {
                "".to_string()
            };
            if exists {
                info!(target: LOG_TARGET, name, step, category, "plugin will be reloaded");
            } else {
                info!(target: LOG_TARGET, name, step, category, "plugin will be created");
            }
            pending_plugins.push(name.to_string());
            true
        })
        .collect();
    let (mut new_plugins, new_errors) = parse_plugins(plugin_configs);
    let mut updated_plugins = vec![];
    for name in pending_plugins {
        if let Some(plugin) = new_plugins.remove(&name) {
            plugins.insert(name.clone(), plugin);
            updated_plugins.push(name);
        } else if let Some(plugin) = PLUGIN_PROVIDER.get(&name) {
            warn!(
                target: LOG_TARGET,
                name,
                "plugin reload failed, the previous instance stays in use"
            );
            plugins.insert(name, plugin);
        }
    }
    errors.extend(new_errors);
    // A plugin that is no longer configured stays for now. Locations are
    // reloaded after the plugins, and until they are, one of them may still
    // name it: taken away here, that location answered 500 in between.
    // `remove_unconfigured_plugins` drops it once the locations are in.
    for (name, plugin) in PLUGIN_PROVIDER.plugins.load().iter() {
        if !plugins.contains_key(name) {
            plugins.insert(name.clone(), plugin.clone());
        }
    }
    PLUGIN_PROVIDER.store(plugins);
    let error = if !errors.is_empty() {
        let error = errors
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join(";");
        error!(target: LOG_TARGET, error, "parse plugins failed");
        error
    } else {
        "".to_string()
    };

    (updated_plugins, error)
}

/// Drops the plugins that `configs` no longer has, the second half of a
/// plugin reload: `try_init_plugins` keeps them until the locations that
/// named them are gone.
pub fn remove_unconfigured_plugins(configs: &HashMap<String, PluginConf>) {
    let builtin: Vec<String> = get_builtin_proxy_plugins()
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    let configured = |name: &String| {
        configs.contains_key(name)
            || builtin.contains(name)
            || name == ADMIN_SERVER_PLUGIN
    };
    let current = PLUGIN_PROVIDER.plugins.load();
    if current.keys().all(configured) {
        return;
    }
    let plugins: Plugins = current
        .iter()
        .filter(|(name, _)| configured(name))
        .map(|(name, plugin)| (name.clone(), plugin.clone()))
        .collect();
    PLUGIN_PROVIDER.store(plugins);
}

#[test]
pub fn initialize_test_plugins() {
    let plugins = HashMap::from([
        (
            "test:mock".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "mock"
path = "/mock"
status = 999
data = "abc"
"###,
            )
            .unwrap(),
        ),
        (
            "test:add_headers".to_string(),
            toml::from_str::<PluginConf>(
                r###"
category = "response_headers"
step = "response"
add_headers = [
"X-Service:1",
"X-Service:2",
]
set_headers = [
"X-Response-Id:123"
]
remove_headers = [
"Content-Type"
]
"###,
            )
            .unwrap(),
        ),
    ]);
    let (_, error) = try_init_plugins(&plugins);
    assert!(error.is_empty());

    // A reload that breaks one plugin and adds a broken one. Same test on
    // purpose: the provider is one global, and tests run in parallel.
    let mock = PLUGIN_PROVIDER.get("test:mock").unwrap();
    let mut broken = plugins.clone();
    broken.insert(
        "test:mock".to_string(),
        toml::from_str::<PluginConf>(
            r###"
category = "mock"
path = "/mock"
status = 999
data = "abc"
step = "response"
"###,
        )
        .unwrap(),
    );
    broken.insert(
        "test:typo".to_string(),
        toml::from_str::<PluginConf>(r#"category = "basic_auht""#).unwrap(),
    );
    let (updated, error) = try_init_plugins(&broken);
    assert!(updated.is_empty());
    assert!(error.contains("create plugin test:mock failed"));
    assert!(error.contains("create plugin test:typo failed"));
    // The plugin that was running stays, the very same instance.
    let kept = PLUGIN_PROVIDER.get("test:mock").unwrap();
    assert!(Arc::ptr_eq(&mock, &kept));
    // The one that never built is absent: its locations reject requests.
    assert!(PLUGIN_PROVIDER.get("test:typo").is_none());
    assert!(PLUGIN_PROVIDER.get("test:add_headers").is_some());

    // A plugin taken out of the config outlives the plugin reload, for the
    // locations that still name it, and goes once they have been reloaded.
    let mut fewer = plugins.clone();
    fewer.remove("test:add_headers");
    let version = PLUGIN_PROVIDER.version();
    let (_, error) = try_init_plugins(&fewer);
    assert!(error.is_empty());
    assert!(PLUGIN_PROVIDER.get("test:add_headers").is_some());
    remove_unconfigured_plugins(&fewer);
    assert!(PLUGIN_PROVIDER.get("test:add_headers").is_none());
    assert!(PLUGIN_PROVIDER.get("test:mock").is_some());
    assert!(PLUGIN_PROVIDER.get("pingap:requestId").is_some());
    assert!(PLUGIN_PROVIDER.version() > version);
    // Nothing to drop: the plugins are left as they are.
    let version = PLUGIN_PROVIDER.version();
    remove_unconfigured_plugins(&fewer);
    assert_eq!(version, PLUGIN_PROVIDER.version());
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn authorizations(conf: &PluginConf) -> Vec<String> {
        get_str_slice_conf(conf, "authorizations")
    }

    #[test]
    fn test_parse_admin_plugin() {
        let (server, name, conf) =
            parse_admin_plugin("pingap:123123@127.0.0.1:3018/pingap").unwrap();
        assert_eq!("127.0.0.1:3018", server.addr);
        assert_eq!(true, server.admin);
        assert_eq!(ADMIN_SERVER_PLUGIN, name);
        assert_eq!("/pingap", get_str_conf(&conf, "path"));
        assert_eq!("2d", get_str_conf(&conf, "max_age"));
        // spellchecker:off
        assert_eq!(vec!["cGluZ2FwOjEyMzEyMw=="], authorizations(&conf));

        // The base64 of `user:password` in place of the user.
        let (_, _, conf) =
            parse_admin_plugin("cGluZ2FwOjEyMzEyMw==@127.0.0.1:3018").unwrap();
        assert_eq!(vec!["cGluZ2FwOjEyMzEyMw=="], authorizations(&conf));
        // spellchecker:on

        // No credentials: the documented way to run without a password.
        let (_, _, conf) = parse_admin_plugin("127.0.0.1:3018").unwrap();
        assert_eq!(vec![""], authorizations(&conf));
        assert_eq!("/", get_str_conf(&conf, "path"));

        // The password is what was typed, not its percent-encoded form.
        for (addr, credential) in [
            ("root:p=ss@127.0.0.1:3018", "root:p=ss"),
            ("root:p%40ss@127.0.0.1:3018", "root:p@ss"),
            ("r%40t:a b@127.0.0.1:3018", "r@t:a b"),
        ] {
            let (_, _, conf) = parse_admin_plugin(addr).unwrap();
            assert_eq!(
                vec![base64_encode(credential)],
                authorizations(&conf),
                "{addr}"
            );
        }

        // A user without a password used to give an admin without
        // authentication.
        for addr in ["root@127.0.0.1:3018", "root:@127.0.0.1:3018"] {
            assert_eq!(
                "Plugin admin invalid, message: expect user:password@addr, or the base64 of user:password in place of the user",
                parse_admin_plugin(addr).unwrap_err().to_string(),
                "{addr}"
            );
        }
    }

    #[test]
    fn test_validate_plugin_references() {
        let validate = |plugins: &str| {
            let config = PingapConfig::new(
                format!(
                    r#"
[plugins.auth]
category = "basic_auth"

[locations.app]
plugins = {plugins}
"#
                )
                .as_bytes(),
                false,
            )
            .unwrap();
            validate_plugin_references(&config).map_err(|e| e.to_string())
        };
        assert_eq!(Ok(()), validate(r#"["auth"]"#));
        assert_eq!(Ok(()), validate(r#"["auth", "pingap:requestId"]"#));
        assert_eq!(Ok(()), validate("[]"));
        assert_eq!(
            "Plugin location invalid, message: plugin(auht) of location(app) is not found",
            validate(r#"["auht"]"#).unwrap_err()
        );
        // The `pingap:` prefix alone is not enough, the name has to exist.
        assert_eq!(
            "Plugin location invalid, message: plugin(pingap:requestid) of location(app) is not found",
            validate(r#"["pingap:requestid"]"#).unwrap_err()
        );
        // The admin plugin exists only in a process started with `--admin`,
        // which a test is not.
        assert_eq!(
            "Plugin location invalid, message: plugin(pingap:admin) of location(app) is not found",
            validate(r#"["pingap:admin"]"#).unwrap_err()
        );
    }

    #[test]
    fn test_unavailable_in_build() {
        let not_found = |category: &str| pingap_plugin::Error::NotFound {
            category: category.to_string(),
        };
        assert_eq!(true, is_unavailable_in_build(&not_found("image_optim")));
        assert_eq!(
            true,
            is_unavailable_in_build(&not_found("geo_restriction"))
        );
        // A misspelled category is a config error, not a build variant.
        assert_eq!(false, is_unavailable_in_build(&not_found("basic_auht")));
    }

    /// A gated plugin may be defined in any build. Whether a location may
    /// name it where it is missing depends on what the location loses.
    #[test]
    fn test_gated_plugin_references() {
        let validate = |category: &str, plugins: &str| {
            let config = PingapConfig::new(
                format!(
                    r#"
[plugins.gated]
category = "{category}"

[locations.app]
plugins = {plugins}
"#
                )
                .as_bytes(),
                false,
            )
            .unwrap();
            validate_plugin_references(&config).map_err(|e| e.to_string())
        };
        let supported = get_plugin_factory().supported_plugins();
        let has = |category: &str| supported.iter().any(|c| c == category);

        // Defined and not used: fine everywhere.
        assert_eq!(Ok(()), validate("geo_restriction", "[]"));
        assert_eq!(Ok(()), validate("image_optim", "[]"));
        // Images are served as they are without the optimizer.
        assert_eq!(Ok(()), validate("image_optim", r#"["gated"]"#));
        // Access control is not something to go without.
        let result = validate("geo_restriction", r#"["gated"]"#);
        if has("geo_restriction") {
            assert_eq!(Ok(()), result);
        } else {
            assert_eq!(
                "Plugin location invalid, message: plugin(gated) of location(app) is a geo_restriction plugin, which needs a build with the geo feature",
                result.unwrap_err()
            );
        }
    }
}
