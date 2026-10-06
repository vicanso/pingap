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

//! The checks a configuration passes before this process runs with it, and
//! before the admin stores it.
//!
//! `PingapConfig::validate` sees the entries and what they refer to. What
//! only building an entry finds - a regex that does not compile, a plugin
//! option of the wrong type, a key that is not the certificate's - is found
//! here, by building each entry the way startup does. `--test` runs all of
//! it; so does the admin, on the configuration a change would leave in the
//! storage, because a change it accepted and startup then refuses stops
//! every reload after it and the next cold start.

use crate::plugin;
use pingap_certificate::{TlsCertificate, validate_servers_tls_for_backend};
use pingap_config::{PingapConfig, PingapTomlConfig};
use std::error::Error;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::warn;

static LOG_TARGET: &str = "validate";

/// Set on a control panel node (`--cp`), which stores a configuration that
/// other machines run.
static CONTROL_PANEL: AtomicBool = AtomicBool::new(false);

/// Limits [`validate_stored`] to the checks that do not depend on this
/// machine. Building an upstream reads its `ca`, a plugin may read its
/// files, a certificate given as a path is read from disk, and the TLS
/// options a server may carry depend on how the binary was built: none of
/// that says anything about the nodes the configuration is for.
pub fn set_control_panel() {
    CONTROL_PANEL.store(true, Ordering::Relaxed);
}

/// Builds each location the way startup does, so `--test` reports what only
/// building one finds: a path or host regex that does not compile, a
/// rewrite rule with too many parts. `PingapConfig::validate` cannot do it,
/// the location type lives in a higher layer.
pub fn validate_locations(config: &PingapConfig) -> Result<(), Box<dyn Error>> {
    for (name, conf) in config.locations.iter() {
        pingap_location::Location::new(name, conf)
            .map_err(|e| format!("location \"{name}\" is invalid: {e}"))?;
    }
    Ok(())
}

/// Builds each upstream the way startup does. That is where an `alpn` that
/// is none of the known ones, a `ca` that does not load or a health check
/// with a bad parameter is found, and nothing is connected to or started
/// by it: checks and discovery only run from the background services.
pub fn validate_upstreams(config: &PingapConfig) -> Result<(), Box<dyn Error>> {
    for (name, conf) in config.upstreams.iter() {
        pingap_upstream::Upstream::new(name, conf, None)
            .map_err(|e| format!("upstream \"{name}\" is invalid: {e}"))?;
    }
    Ok(())
}

/// Dry-runs each configured plugin through the factory so `--test` reports bad
/// plugin configs, which `PingapConfig::validate` cannot check (the factory
/// lives in a higher layer). A feature-gated category that was compiled out
/// of this build is only warned about, matching runtime behaviour; any other
/// construction error, an unknown category included, is treated as fatal.
pub fn validate_plugins(config: &PingapConfig) -> Result<(), Box<dyn Error>> {
    let factory = pingap_plugin::get_plugin_factory();
    for (name, conf) in config.plugins.iter() {
        match factory.create(conf) {
            Ok(_) => {},
            Err(e) if plugin::is_unavailable_in_build(&e) => {
                warn!(
                    target: LOG_TARGET,
                    name = %name,
                    error = %e,
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

/// Loads each certificate that has both its parts the way the certificate
/// store does. `CertificateConf::validate` parses the certificate and the
/// key each on its own; that the key is the certificate's is only seen
/// when the two are loaded together.
pub fn validate_certificates(
    config: &PingapConfig,
) -> Result<(), Box<dyn Error>> {
    let given = |value: &Option<String>| {
        value.as_deref().is_some_and(|value| !value.is_empty())
    };
    for (name, conf) in config.certificates.iter() {
        if !given(&conf.tls_cert) || !given(&conf.tls_key) {
            continue;
        }
        TlsCertificate::try_from(conf)
            .map_err(|e| format!("certificate \"{name}\" is invalid: {e}"))?;
    }
    Ok(())
}

/// Everything that is found by building the entries of a configuration.
pub fn validate_built(config: &PingapConfig) -> Result<(), Box<dyn Error>> {
    validate_upstreams(config)?;
    validate_locations(config)?;
    validate_plugins(config)?;
    validate_certificates(config)
}

/// The checks of `--test` on a configuration as it is, or would be, stored.
///
/// This runs inside a process that is serving, on a configuration that may
/// yet be refused, so nothing it builds may reach the running state. The
/// one constructor that touches process-wide state is the `cache` plugin's
/// (its backends), hence the dry run. It also resolves names and reads
/// files: call it from the blocking pool, not from a worker thread.
pub fn validate_stored(
    config: &PingapTomlConfig,
) -> Result<(), Box<dyn Error>> {
    let config = config.to_pingap_config(true)?;
    config.validate()?;
    if CONTROL_PANEL.load(Ordering::Relaxed) {
        // Which plugins this build has says nothing about the builds the
        // configuration is for.
        plugin::validate_plugin_names(&config)?;
        return validate_locations(&config);
    }
    plugin::validate_plugin_references(&config)?;
    validate_servers_tls_for_backend(&config.servers)?;
    pingap_cache::dry_run(|| validate_built(&config))
}

/// The answer to a change the admin is about to store, for
/// [`pingap_config::ConfigManager::update_checked`].
///
/// A change is refused when the configuration it leads to does not pass
/// and the one in the storage does: the change is what broke it. A storage
/// that does not pass as it is takes the change: someone is repairing it
/// through the admin, an entry at a time, and each of those steps leaves it
/// broken until the last.
pub fn check_change(
    stored: &PingapTomlConfig,
    candidate: &PingapTomlConfig,
) -> Result<(), pingap_config::Error> {
    let Err(e) = validate_stored(candidate) else {
        return Ok(());
    };
    if validate_stored(stored).is_err() {
        return Ok(());
    }
    Err(pingap_config::Error::Invalid {
        message: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn toml_config(data: &str) -> PingapTomlConfig {
        PingapTomlConfig::from_toml(data).unwrap()
    }

    const VALID: &str = r#"
[upstreams.u1]
addrs = ["127.0.0.1:5000"]

[locations.l1]
upstream = "u1"
path = "/api"
"#;

    /// What `PingapConfig::validate` passes and startup refuses.
    #[test]
    fn test_validate_stored_builds_the_entries() {
        assert_eq!(true, validate_stored(&toml_config(VALID)).is_ok());

        let err = |extra: &str| {
            validate_stored(&toml_config(&format!("{VALID}{extra}")))
                .unwrap_err()
                .to_string()
        };
        // A regex that does not compile.
        let message =
            err("[locations.bad]\nupstream = \"u1\"\npath = \"~ ^/api/(\"\n");
        assert_eq!(
            true,
            message.starts_with("location \"bad\" is invalid"),
            "{message}"
        );
        // An option of the wrong type.
        let message = err(
            "[plugins.limiter]\ncategory = \"limit\"\ntype = \"inflight\"\ntag = \"ip\"\nmax = \"100\"\n",
        );
        assert_eq!(
            true,
            message.starts_with("plugin \"limiter\" is invalid"),
            "{message}"
        );
        // A reference to nothing.
        let message = err("[locations.lost]\nupstream = \"u2\"\n");
        assert_eq!(
            true,
            message.contains("upstream(u2) is not found"),
            "{message}"
        );
    }

    /// Checking a `cache` plugin leaves the cache backends alone: this
    /// runs in a serving process, on a configuration that may be refused.
    #[test]
    fn test_validate_stored_does_not_make_cache_backends() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("cache");
        let config = |extra: &str| {
            toml_config(&format!(
                "{VALID}[plugins.c]\ncategory = \"cache\"\ndirectory = \"{}?inactive=1m\"\nnamespace = \"web\"\nlock = \"7s\"\n{extra}",
                dir.display()
            ))
        };
        assert_eq!(true, validate_stored(&config("")).is_ok());
        assert_eq!(false, dir.exists());
        // One that is refused for another of its settings as well.
        let message = validate_stored(&config("max_ttl = \"oops\"\n"))
            .unwrap_err()
            .to_string();
        assert_eq!(
            true,
            message.starts_with("plugin \"c\" is invalid"),
            "{message}"
        );
        assert_eq!(false, dir.exists());
        // The setting of the backend itself is still checked.
        let broken = toml_config(&format!(
            "{VALID}[plugins.c]\ncategory = \"cache\"\ndirectory = \"{}?levels=9\"\n",
            dir.display()
        ));
        assert_eq!(true, validate_stored(&broken).is_err());
    }

    #[test]
    fn test_check_change() {
        let valid = toml_config(VALID);
        let broken = toml_config(&format!(
            "{VALID}[locations.bad]\nupstream = \"u1\"\npath = \"~ ^/api/(\"\n"
        ));
        // The change breaks a storage that was fine.
        let message = check_change(&valid, &broken).unwrap_err().to_string();
        assert_eq!(
            true,
            message.contains("location \"bad\" is invalid"),
            "{message}"
        );
        assert_eq!(true, check_change(&valid, &valid).is_ok());
        // A broken storage is being repaired: both the step that fixes it
        // and one that does not yet.
        assert_eq!(true, check_change(&broken, &valid).is_ok());
        assert_eq!(true, check_change(&broken, &broken).is_ok());
    }
}
