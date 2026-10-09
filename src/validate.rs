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
use pingap_config::{MissingReference, PingapConfig, PingapTomlConfig};
use std::error::Error;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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

/// `--strict`: what the configuration has that pingap does not read is an
/// error, where it is otherwise a warning.
static STRICT: AtomicBool = AtomicBool::new(false);

pub fn set_strict(strict: bool) {
    STRICT.store(strict, Ordering::Relaxed);
}

fn is_strict() -> bool {
    STRICT.load(Ordering::Relaxed)
}

/// The error of a configuration that has keys pingap does not read, when
/// it is held to having none.
fn refuse_unknown_keys(
    found: &[String],
    strict: bool,
) -> Result<(), Box<dyn Error>> {
    if found.is_empty() || !strict {
        return Ok(());
    }
    Err(format!(
        "the config has {} that pingap does not read, which --strict does not allow: {}",
        if found.len() == 1 { "a key" } else { "keys" },
        found.join("; ")
    )
    .into())
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

/// Builds each server the way startup does, up to where its listeners
/// would open their sockets. That is where the TLS settings of a server
/// are made: a `tls_min_version` that is no version, a cipher list the TLS
/// library does not take. `ServerConf::validate` reads neither, and a
/// configuration with one of them passed `--test` and failed the start.
///
/// Nothing is bound, logged to or started: the access log of a server is
/// opened by startup itself, not by the server.
pub fn validate_servers(config: &PingapConfig) -> Result<(), Box<dyn Error>> {
    if config.servers.is_empty() {
        return Ok(());
    }
    // What a server is handed and only uses once it serves.
    let pingora_conf =
        Arc::new(pingora::server::configuration::ServerConf::default());
    let config_manager =
        Arc::new(pingap_config::new_memory_config_manager("", None));
    for server_conf in pingap_proxy::parse_from_conf(config.clone()) {
        let name = server_conf.name.clone();
        // A sampler that is not known would be every request traced.
        #[cfg(feature = "tracing")]
        if let Some(otlp_exporter) = &server_conf.otlp_exporter {
            pingap_otel::validate_endpoint(otlp_exporter)
                .map_err(|e| format!("server \"{name}\" is invalid: {e}"))?;
        }
        let ctx = pingap_proxy::AppContext {
            logger: None,
            config_manager: config_manager.clone(),
            server_locations_provider:
                crate::server_locations::new_server_locations_provider(),
            location_provider: crate::locations::new_location_provider(),
            upstream_provider: crate::upstreams::new_upstream_provider(),
            plugin_provider: plugin::new_plugin_provider(),
            certificate_provider: crate::certificates::new_certificate_provider(
            ),
        };
        pingap_proxy::Server::new(&server_conf, ctx)
            .and_then(|server| server.check(pingora_conf.clone()))
            .map_err(|e| format!("server \"{name}\" is invalid: {e}"))?;
    }
    Ok(())
}

/// Everything that is found by building the entries of a configuration.
pub fn validate_built(config: &PingapConfig) -> Result<(), Box<dyn Error>> {
    validate_upstreams(config)?;
    validate_locations(config)?;
    validate_plugins(config)?;
    validate_certificates(config)?;
    validate_servers(config)
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
    validate_stored_as(config, is_strict())
}

/// [`validate_stored`], held to having no unknown keys or not.
fn validate_stored_as(
    config: &PingapTomlConfig,
    strict: bool,
) -> Result<(), Box<dyn Error>> {
    // What a reload would refuse is not stored through the admin either.
    refuse_unknown_keys(&config.unknown_keys(), strict)?;
    // With its references replaced, as a start reads it: an address that
    // comes from the environment is checked as the address it is. What a
    // control panel node can not look up says nothing about the machines
    // the configuration is for, and stays as it is written there.
    let control_panel = CONTROL_PANEL.load(Ordering::Relaxed);
    let config = config.to_running_config(if control_panel {
        MissingReference::Keep
    } else {
        MissingReference::Refuse
    })?;
    config.validate()?;
    if control_panel {
        // Which plugins this build has says nothing about the builds the
        // configuration is for.
        plugin::validate_plugin_names(&config)?;
        return validate_locations(&config);
    }
    plugin::validate_plugin_references(&config)?;
    validate_servers_tls_for_backend(&config.servers)?;
    pingap_cache::dry_run(|| validate_built(&config))
}

/// The hash of the unknown keys that were last reported.
static UNKNOWN_KEYS_REPORTED: AtomicU64 = AtomicU64::new(0);

/// Warns about what `document` has that pingap does not read, see
/// [`PingapTomlConfig::unknown_keys`]. The same findings are reported
/// once, however often the document is looked at: at startup, and then by
/// every pass of the reload that reads it again.
///
/// With `--strict` they are an error as well, every time: a start or a
/// `--test` fails on them, and a reload does not take the document.
pub fn check_unknown_keys(
    document: &PingapTomlConfig,
) -> Result<(), Box<dyn Error>> {
    let found = document.unknown_keys();
    let mut hasher = DefaultHasher::new();
    found.hash(&mut hasher);
    let hash = if found.is_empty() { 0 } else { hasher.finish() };
    if UNKNOWN_KEYS_REPORTED.swap(hash, Ordering::Relaxed) != hash {
        for message in found.iter() {
            warn!(target: LOG_TARGET, "config: {message}");
        }
    }
    refuse_unknown_keys(&found, is_strict())
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

    /// `--strict`: a key pingap does not read is an error, and a warning
    /// without it.
    #[test]
    fn test_strict_refuses_unknown_keys() {
        // spellchecker:off
        let document = toml_config(
            r#"
[upstreams.u1]
addrs = ["127.0.0.1:5000"]
read_timout = "3s"

[locations.l1]
upstream = "u1"
weigth = 10
"#,
        );
        let found = document.unknown_keys();
        assert_eq!(2, found.len(), "{found:?}");
        assert_eq!(true, refuse_unknown_keys(&found, false).is_ok());
        let refused =
            refuse_unknown_keys(&found, true).unwrap_err().to_string();
        assert_eq!(
            true,
            refused.starts_with("the config has keys that pingap does not read, which --strict does not allow: "),
            "{refused}"
        );
        // Each of them, so that one run names everything there is to fix.
        assert_eq!(true, refused.contains("read_timout"), "{refused}");
        assert_eq!(true, refused.contains("weigth"), "{refused}");
        // spellchecker:on
        // Nothing unknown is nothing to refuse.
        assert_eq!(
            true,
            refuse_unknown_keys(&toml_config(VALID).unknown_keys(), true)
                .is_ok()
        );

        // What the admin is asked to store is held to the same.
        assert_eq!(true, validate_stored_as(&document, false).is_ok());
        let refused =
            validate_stored_as(&document, true).unwrap_err().to_string();
        assert_eq!(true, refused.contains("--strict"), "{refused}");
        assert_eq!(true, validate_stored_as(&toml_config(VALID), true).is_ok());
    }

    /// What only building a server finds, and that building one for a
    /// check opens no socket.
    #[test]
    fn test_validate_servers() {
        // Taken while the check runs: a check that bound the address of
        // the server would fail on it.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let config = |extra: &str| {
            toml_config(&format!(
                "{VALID}\n[servers.web]\naddr = \"{addr}\"\nlocations = [\"l1\"]\n{extra}\n"
            ))
            .to_pingap_config(true)
            .unwrap()
        };
        validate_servers(&config("")).unwrap();
        validate_servers(&config("global_certificates = true")).unwrap();
        validate_servers(&config(
            "prometheus_metrics = \"/metrics\"\naccess_log = \"combined\"",
        ))
        .unwrap();
        // No server, nothing to build.
        validate_servers(&toml_config(VALID).to_pingap_config(true).unwrap())
            .unwrap();

        // The TLS settings are made by the server, and only the OpenSSL
        // backend takes these: with rustls they are refused before, by
        // `validate_servers_tls_for_backend`.
        #[cfg(feature = "openssl")]
        for (extra, part) in [
            (
                "tls_min_version = \"tlsv9\"",
                "tls version \"tlsv9\" is invalid",
            ),
            (
                "tls_max_version = \"1.3\"",
                "tls version \"1.3\" is invalid",
            ),
            ("tls_cipher_list = \"NOT-A-CIPHER\"", "set cipher list fail"),
            (
                "tls_ciphersuites = \"NOT_A_SUITE\"",
                "set cipher suites fail",
            ),
        ] {
            let message = validate_servers(&config(&format!(
                "global_certificates = true\n{extra}"
            )))
            .unwrap_err()
            .to_string();
            assert_eq!(
                true,
                message.starts_with("server \"web\" is invalid: "),
                "{message}"
            );
            assert_eq!(true, message.contains(part), "{message}");
            // And through what `--test` and the admin run.
            let message = validate_built(&config(&format!(
                "global_certificates = true\n{extra}"
            )))
            .unwrap_err()
            .to_string();
            assert_eq!(true, message.contains(part), "{message}");
        }
        // The listener was there all along.
        assert_eq!(addr, listener.local_addr().unwrap());
    }

    /// A value read from the environment or a file is checked as what it
    /// stands for, and one that names nothing is refused where the
    /// configuration is to run.
    #[test]
    fn test_validate_stored_reads_references() {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"127.0.0.1:5001\n").unwrap();
        let reference = format!("$FILE:{}", file.path().to_string_lossy());
        let document = |addr: &str| {
            toml_config(&format!(
                "[upstreams.u1]\naddrs = [\"{addr}\"]\n\n[locations.l1]\nupstream = \"u1\"\n"
            ))
        };
        validate_stored(&document(&reference)).unwrap();

        let message =
            validate_stored(&document("$ENV:PINGAP_NOT_SET_FOR_SURE"))
                .unwrap_err()
                .to_string();
        assert_eq!(
            "Invalid error upstream(u1): addrs[0]: environment variable PINGAP_NOT_SET_FOR_SURE is not set",
            message
        );
    }

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
