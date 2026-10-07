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

use super::restart;
use crate::certificates::{
    try_reload_certificate_files, try_update_certificates_except,
};
use crate::locations::try_init_locations;
use crate::plugin;
use crate::server_locations::try_init_server_locations;
use crate::upstreams::{remove_unconfigured_upstreams, try_update_upstreams};
use crate::webhook::{
    get_webhook_sender, reload_webhook_notification_sender, send_notification,
};
use arc_swap::{ArcSwap, ArcSwapOption};
use async_trait::async_trait;
use pingap_certificate::validate_servers_tls_for_backend;
use pingap_config::{
    CATEGORY_LOCATION, CATEGORY_PLUGIN, CATEGORY_UPSTREAM, CertificateConf,
    ConfigManager, Observer, PingapConfig, PingapTomlConfig,
};
use pingap_core::{
    BackgroundTask, BackgroundTaskService, Error as ServiceError,
    NotificationData, NotificationLevel,
};
use pingap_logger::LoggerReloadHandle;
use pingap_logger::new_env_filter;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};
use tokio::time::interval;
use tracing::{debug, error, info, warn};

static LOG_TARGET: &str = "main::auto_restart";

/// What the previous pass saw: the hash of the raw configuration document
/// and whether that pass was allowed to restart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LastSeen {
    hash: u64,
    restart_eligible: bool,
}

static LAST_SEEN: ArcSwapOption<LastSeen> = ArcSwapOption::const_empty();

/// The document that could last not be applied, and why.
#[derive(Debug)]
struct LastFailed {
    hash: u64,
    at: Instant,
    message: String,
}

static LAST_FAILED: ArcSwapOption<LastFailed> = ArcSwapOption::const_empty();

/// How long a document that could not be applied is left alone before it
/// is tried again as it is.
///
/// It is tried again because what stood in the way may pass by itself, a
/// name that did not resolve. It is not tried on every pass because most
/// of what stands in the way does not, and a pass means building every
/// upstream, location and plugin of the document: every ten seconds, with
/// the same error in the log each time, for as long as the document
/// stayed as it was.
const RETRY_FAILED_AFTER: Duration = Duration::from_secs(60);

/// Whether a pass over the document hashing to `hash` is one that failed
/// a moment ago and has no reason to go differently yet.
fn failed_recently(last: Option<&LastFailed>, hash: u64) -> bool {
    last.is_some_and(|last| {
        last.hash == hash && last.at.elapsed() < RETRY_FAILED_AFTER
    })
}

/// Loads the certificates whose files have changed.
///
/// A certificate given as a path is not in the configuration document, only
/// the path is. Replacing the file - what certbot does on every renewal -
/// changed nothing the check of the document could see, and the old
/// certificate was served until the next restart.
///
/// Run on every pass, whatever became of the document: a document that
/// does not load keeps the certificates it had, and their files may be
/// renewed all the same.
async fn reload_changed_certificate_files(config_manager: &ConfigManager) {
    let config = config_manager.get_current_config();
    let (updated, errors) = try_reload_certificate_files(&config.certificates);
    report_certificate_reload(updated, errors).await;
}

/// Logs and notifies what a reload of the certificates did.
async fn report_certificate_reload(updated: Vec<String>, errors: String) {
    if !updated.is_empty() {
        info!(
            target: LOG_TARGET,
            certificates = updated.join(","),
            "reload certificate success"
        );
        send_notification(NotificationData {
            category: "reload_config".to_string(),
            level: NotificationLevel::Info,
            message: format!("Certificate: {}", updated.join(", ")),
            ..Default::default()
        })
        .await;
    }
    if !errors.is_empty() {
        error!(
            target: LOG_TARGET,
            error = errors,
            "parse certificate fail"
        );
        send_notification(NotificationData {
            category: "parse_certificate_fail".to_string(),
            level: NotificationLevel::Error,
            message: errors,
            ..Default::default()
        })
        .await;
    }
}

fn raw_hash(raw: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    raw.hash(&mut hasher);
    hasher.finish()
}

/// Whether a pass over a document hashing to `hash` has nothing to do: the
/// document is the one the last pass already handled, and either that pass
/// could restart or this one cannot. A hot-reload-only pass may leave a
/// change behind that only a restart applies, so the next restart-eligible
/// pass still has to look at the same document.
fn should_skip(
    last: Option<&LastSeen>,
    hash: u64,
    hot_reload_only: bool,
) -> bool {
    last.is_some_and(|last| {
        last.hash == hash && (last.restart_eligible || hot_reload_only)
    })
}

/// Loads the configuration and, when it changed since the last pass,
/// applies it through `apply_config`. Returns `None` when there was nothing
/// new: the poll then costs one storage read and a hash instead of a parse,
/// a validation (which resolves every static upstream address) and a diff.
async fn diff_and_update_config(
    config_manager: Arc<ConfigManager>,
    hot_reload_only: bool,
) -> Result<Option<PingapConfig>, Box<dyn std::error::Error>> {
    let raw = config_manager.load_all_raw().await?;
    let hash = raw_hash(&raw);
    if should_skip(LAST_SEEN.load().as_deref(), hash, hot_reload_only) {
        debug!(target: LOG_TARGET, "config is unchanged");
        return Ok(None);
    }
    if failed_recently(LAST_FAILED.load().as_deref(), hash) {
        debug!(target: LOG_TARGET, "config is the one that just failed");
        return Ok(None);
    }
    let applied = async {
        let document = PingapTomlConfig::from_toml(&raw)?;
        crate::validate::check_unknown_keys(&document)?;
        let new_config = document.to_pingap_config(true)?;
        let restart_requested =
            apply_config(config_manager, &new_config, hot_reload_only).await?;
        Ok::<_, Box<dyn std::error::Error>>((new_config, restart_requested))
    }
    .await
    // As text: the error itself cannot be held while the notification
    // below is sent.
    .map_err(|e| e.to_string());
    let (new_config, restart_requested) = match applied {
        Ok(applied) => {
            LAST_FAILED.store(None);
            applied
        },
        Err(message) => {
            // Said when it is news: once for a document and what is wrong
            // with it, in the log and to the webhook. A document that
            // does not build used to be reported to the webhook when its
            // parts were replaced one by one; held back whole, it was
            // only in the log, and there on every pass.
            let repeated = LAST_FAILED.load().as_deref().is_some_and(|last| {
                last.hash == hash && last.message == message
            });
            LAST_FAILED.store(Some(Arc::new(LastFailed {
                hash,
                at: Instant::now(),
                message: message.clone(),
            })));
            if repeated {
                debug!(
                    target: LOG_TARGET,
                    error = message,
                    "update config still fails"
                );
                return Ok(None);
            }
            send_notification(NotificationData {
                category: "reload_config_fail".to_string(),
                level: NotificationLevel::Error,
                message: message.clone(),
                ..Default::default()
            })
            .await;
            return Err(message.into());
        },
    };
    // Recorded only after a pass that finished. An error - the document
    // does not parse, an address does not resolve - is retried on the next
    // tick, and a pass that asked for a restart is repeated by the next
    // restart-eligible tick in case the restart was abandoned.
    LAST_SEEN.store(Some(Arc::new(LastSeen {
        hash,
        restart_eligible: !hot_reload_only && !restart_requested,
    })));
    Ok(Some(new_config))
}

/// What a hot reload does with a change of the certificates.
struct CertificateChanges {
    /// The certificates once the reload is done.
    merged: HashMap<String, CertificateConf>,
    /// Whether any entry that is reloaded here changed.
    changed: bool,
    /// The entries the new configuration gives to ACME: not reloaded here.
    of_acme: HashSet<String>,
    /// Those of them whose settings changed, which only a restart applies.
    left: Vec<String>,
}

/// Splits a change of the certificates into the entries a hot reload takes
/// and the ones it leaves.
///
/// An entry the new configuration gives to ACME stays as it is, a new one
/// stays out: the ACME service reads its settings from the running
/// configuration and stores the certificate it orders into the same entry,
/// and what a server needs to answer its challenge is set up at start.
/// That write alone - `tls_cert` and `tls_key` of an entry that is
/// otherwise the same - is the service's own doing and nothing to report.
///
/// An entry that is no longer one of ACME, or no longer there, is reloaded
/// like any other. Left in the running configuration, the service went on
/// renewing it: over the certificate that was put in its place, or for an
/// entry that is not stored any more.
fn merge_certificates(
    current: &HashMap<String, CertificateConf>,
    new: &HashMap<String, CertificateConf>,
) -> CertificateChanges {
    let settings = |conf: Option<&CertificateConf>| {
        conf.map(|conf| CertificateConf {
            tls_cert: None,
            tls_key: None,
            ..conf.clone()
        })
    };
    let mut changes = CertificateChanges {
        merged: HashMap::with_capacity(new.len()),
        changed: false,
        of_acme: HashSet::new(),
        left: vec![],
    };
    let names: BTreeSet<&String> = current.keys().chain(new.keys()).collect();
    for name in names {
        let (before, after) = (current.get(name), new.get(name));
        if after.is_some_and(|conf| conf.is_acme()) {
            changes.of_acme.insert(name.clone());
            if settings(before) != settings(after) {
                changes.left.push(name.clone());
            }
            if let Some(conf) = before {
                changes.merged.insert(name.clone(), conf.clone());
            }
            continue;
        }
        changes.changed |= before != after;
        if let Some(conf) = after {
            changes.merged.insert(name.clone(), conf.clone());
        }
    }
    changes
}

/// Compares configurations and handles updates through hot reload or full restart
///
/// This function:
/// 1. Validates the new configuration
/// 2. Compares it with current config to find differences
/// 3. Attempts hot reload for supported changes:
///    - Server locations
///    - Upstream configurations
///    - Location definitions
///    - Plugin configurations
///    - Certificates, entry by entry: all but the ones of ACME
///    - Webhook settings (`webhook`, `webhook_type`, `webhook_notifications`,
///      `webhook_batch_window`, `webhook_batch_max_events`)
/// 4. Sends notifications for successful updates
/// 5. If hot_reload_only=false and there are non-hot-reloadable changes,
///    triggers a full server restart
///
/// Returns whether a restart was requested.
async fn apply_config(
    config_manager: Arc<ConfigManager>,
    new_config: &PingapConfig,
    hot_reload_only: bool,
) -> Result<bool, Box<dyn std::error::Error>> {
    // Off this thread: validating an upstream resolves the names among
    // its static addresses, with a blocking call.
    let checked = new_config.clone();
    tokio::task::spawn_blocking(move || {
        checked.validate().map_err(|e| e.to_string())?;
        validate_servers_tls_for_backend(&checked.servers)
            .map_err(|e| e.to_string())?;
        plugin::validate_plugin_references(&checked).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())??;
    let current_config: PingapConfig =
        config_manager.get_current_config().as_ref().clone();

    let (updated_category_list, original_diff_result) =
        current_config.diff(new_config);
    debug!(
        target: LOG_TARGET,
        updated_category_list = updated_category_list.join(","),
        original_diff_result = original_diff_result.join("\n"),
        "current config diff from new config"
    );
    // no update config
    if original_diff_result.is_empty() {
        return Ok(false);
    }

    // What only building an entry finds - a regex that does not compile,
    // a plugin option of the wrong type, an address that does not resolve
    // - before anything is replaced. The reload goes category by
    // category, and one that failed halfway used to leave the others
    // applied: locations routing to an upstream that was not there, or
    // naming a plugin that had not been built.
    let builds = [CATEGORY_UPSTREAM, CATEGORY_LOCATION, CATEGORY_PLUGIN];
    if updated_category_list
        .iter()
        .any(|category| builds.contains(&category.as_str()))
    {
        let checked = new_config.clone();
        tokio::task::spawn_blocking(move || {
            pingap_cache::dry_run(|| {
                crate::validate::validate_upstreams(&checked)?;
                crate::validate::validate_locations(&checked)?;
                crate::validate::validate_plugins(&checked)
            })
            .map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| e.to_string())??;
    }

    let mut reload_fail_messages = vec![];
    // The categories whose reload did not go through: they stay what
    // they are in the running configuration.
    let mut upstream_reload_failed = false;
    let mut plugin_reload_failed = false;
    let mut location_reload_failed = false;
    let mut server_location_reload_failed = false;
    let mut hot_reload_config = current_config.clone();
    {
        // hot reload first,
        // only validate server.locations, locations, upstreams and plugins
        let mut should_reload_server_location = false;
        let mut should_reload_upstream = false;
        let mut should_reload_location = false;
        let mut should_reload_plugin = false;

        // The webhook goes first, so the notifications for everything else
        // this change reloads already go out with the new settings.
        if reload_webhook_notification_sender(
            &mut hot_reload_config.basic,
            &new_config.basic,
        ) {
            info!(target: LOG_TARGET, "reload webhook success");
            send_notification(NotificationData {
                category: "reload_config".to_string(),
                level: NotificationLevel::Info,
                message: "Webhook is modified".to_string(),
                ..Default::default()
            })
            .await;
        }

        // update the values which can be hot reload
        // set server locations
        for (name, server) in new_config.servers.iter() {
            if let Some(clone_server_conf) =
                hot_reload_config.servers.get_mut(name)
                && server.locations != clone_server_conf.locations
            {
                clone_server_conf.locations.clone_from(&server.locations);
                should_reload_server_location = true;
            }
        }

        // set upstream, location and plugin value
        hot_reload_config.upstreams = new_config.upstreams.clone();
        hot_reload_config.locations = new_config.locations.clone();
        hot_reload_config.plugins = new_config.plugins.clone();
        // A storage entry does nothing by itself. What an entry includes
        // from it is already part of that entry here, and shows up as a
        // change of its own; the rest is what the ACME task keeps there,
        // its account and the tokens of an order. Counted as a change that
        // needs a restart, every token it wrote restarted the process in
        // the middle of the order, and a certificate that kept failing did
        // so again on each attempt, ten minutes apart.
        hot_reload_config.storages = new_config.storages.clone();

        // Certificates are taken entry by entry. One of ACME is left as
        // it is: its certificate is its service's to order and to store.
        // With a single such entry no certificate at all used to be
        // reloaded, the ones given in the configuration included, and
        // nothing said so.
        let certificates = merge_certificates(
            &current_config.certificates,
            &new_config.certificates,
        );
        hot_reload_config.certificates = certificates.merged;
        let certificates_of_acme = certificates.of_acme;
        let should_reload_certificate = certificates.changed;
        if !certificates.left.is_empty() {
            warn!(
                target: LOG_TARGET,
                certificates = certificates.left.join(","),
                "the change to a certificate of acme takes a restart to apply"
            );
        }

        for category in updated_category_list {
            match category.as_str() {
                CATEGORY_LOCATION => should_reload_location = true,
                CATEGORY_UPSTREAM => should_reload_upstream = true,
                CATEGORY_PLUGIN => should_reload_plugin = true,
                _ => {},
            };
        }

        let format_message = |name: &str, list: Vec<String>| -> String {
            if list.is_empty() {
                return format!("{name} is removed",);
            }
            if list.len() > 1 {
                return format!("{name}s({}) are modified", list.join(","));
            }
            format!("{name}({}) is modified", list.join(","))
        };

        if should_reload_upstream {
            match try_update_upstreams(
                &new_config.upstreams,
                get_webhook_sender(),
            )
            .await
            {
                Err(e) => {
                    upstream_reload_failed = true;
                    let error = e.to_string();
                    reload_fail_messages
                        .push(format!("upstream reload fail: {error}"));
                    error!(
                        target: LOG_TARGET,
                        error, "reload upstream fail"
                    );
                },
                Ok(updated_upstreams) => {
                    info!(target: LOG_TARGET, "reload upstream success");
                    send_notification(NotificationData {
                        category: "reload_config".to_string(),
                        level: NotificationLevel::Info,
                        message: format_message("Upstream", updated_upstreams),
                        ..Default::default()
                    })
                    .await;
                },
            };
        }
        // Plugins before locations: a location resolves its plugins by name,
        // and a name that is not loaded yet rejects the request.
        if should_reload_plugin {
            let (updated_plugins, error) =
                plugin::try_init_plugins(&new_config.plugins);
            if !updated_plugins.is_empty() {
                info!(target: LOG_TARGET, "reload plugin success");
                send_notification(NotificationData {
                    category: "reload_config".to_string(),
                    level: NotificationLevel::Info,
                    message: format_message("Plugin", updated_plugins),
                    ..Default::default()
                })
                .await;
            }
            if !error.is_empty() {
                plugin_reload_failed = true;
                error!(target: LOG_TARGET, error, "reload plugin fail");
                send_notification(NotificationData {
                    category: "reload_config_fail".to_string(),
                    level: NotificationLevel::Error,
                    message: error,
                    ..Default::default()
                })
                .await;
            }
        }
        if should_reload_location {
            match try_init_locations(&new_config.locations) {
                Err(e) => {
                    location_reload_failed = true;
                    let error = e.to_string();
                    reload_fail_messages
                        .push(format!("location reload fail: {error}",));
                    error!(
                        target: LOG_TARGET,
                        error, "reload location fail"
                    );
                },
                Ok(updated_locations) => {
                    info!(target: LOG_TARGET, "reload location success");
                    send_notification(NotificationData {
                        category: "reload_config".to_string(),
                        level: NotificationLevel::Info,
                        message: format_message("Location", updated_locations),
                        ..Default::default()
                    })
                    .await;
                },
            };
        }
        // The plugins this config no longer has were kept for the locations
        // that named them. Those locations are replaced now - unless their
        // reload failed, and then they still need the plugins.
        if should_reload_plugin && !location_reload_failed {
            plugin::remove_unconfigured_plugins(&new_config.plugins);
        }
        if should_reload_certificate {
            let (updated_certificates, errors) = try_update_certificates_except(
                &hot_reload_config.certificates,
                |name| certificates_of_acme.contains(name),
            );
            // Said when something was reloaded or taken out, not ahead of
            // the errors as if all of it had been.
            if !updated_certificates.is_empty() || errors.is_empty() {
                info!(target: LOG_TARGET, "reload certificate success");
                send_notification(NotificationData {
                    category: "reload_config".to_string(),
                    level: NotificationLevel::Info,
                    message: format_message(
                        "Certificate",
                        updated_certificates,
                    ),
                    ..Default::default()
                })
                .await;
            }
            if !errors.is_empty() {
                error!(
                    target: LOG_TARGET,
                    error = errors,
                    "parse certificate fail"
                );
                send_notification(NotificationData {
                    category: "parse_certificate_fail".to_string(),
                    level: NotificationLevel::Error,
                    message: errors,
                    ..Default::default()
                })
                .await;
            }
        }
        // A server's routes are an index built from its locations: which
        // hosts each one answers for, and in what order they are tried.
        // The index is rebuilt when the locations themselves change too,
        // not only when a server's list of them does. Left alone, it kept
        // routing by the hosts, paths and weights of before: a location
        // moved to another host answered 404 on the old host and on the
        // new one.
        //
        // Not when the locations could not be rebuilt: the index would be
        // made of the new lists and the old locations, with every name
        // that is not there yet left out of it.
        if (should_reload_server_location || should_reload_location)
            && !location_reload_failed
        {
            match try_init_server_locations(
                &new_config.servers,
                &new_config.locations,
            ) {
                Err(e) => {
                    server_location_reload_failed = true;
                    let error = e.to_string();
                    reload_fail_messages
                        .push(format!("server reload fail: {error}"));
                    error!(
                        target: LOG_TARGET,
                        error, "reload server fail"
                    );
                },
                Ok(updated_servers) => {
                    info!(
                        target: LOG_TARGET,
                        "reload server location success"
                    );
                    // The servers whose list of locations changed. A
                    // rebuild for a location's own change has none, and
                    // that change was reported above.
                    if should_reload_server_location {
                        send_notification(NotificationData {
                            category: "reload_config".to_string(),
                            level: NotificationLevel::Info,
                            message: format_message(
                                "Server Location",
                                updated_servers,
                            ),
                            ..Default::default()
                        })
                        .await;
                    }
                },
            };
        }
    }

    // The upstreams this configuration no longer has were kept for the
    // locations that routed to them. Those are replaced now - unless
    // their reload failed, and then they still need the upstreams.
    let routes_failed = location_reload_failed || server_location_reload_failed;
    if !upstream_reload_failed && !routes_failed {
        remove_unconfigured_upstreams(&new_config.upstreams);
    }

    // What is running: the new configuration where it was applied, the one
    // from before where it was not. `hot_reload_config` says what a hot
    // reload is able to apply, and decides below whether the rest takes a
    // restart. A category that failed used to be recorded as running all
    // the same, so the next change no longer showed it as one, and it was
    // not tried again with whatever that change put right.
    let mut running_config = hot_reload_config.clone();
    if upstream_reload_failed {
        running_config
            .upstreams
            .clone_from(&current_config.upstreams);
    }
    if plugin_reload_failed {
        running_config.plugins.clone_from(&current_config.plugins);
    }
    if location_reload_failed {
        running_config
            .locations
            .clone_from(&current_config.locations);
    }
    if routes_failed {
        for (name, server) in running_config.servers.iter_mut() {
            if let Some(current) = current_config.servers.get(name) {
                server.locations.clone_from(&current.locations);
            }
        }
    }

    let reload_fail_message = reload_fail_messages.join(";");

    if hot_reload_only {
        let (updated_category_list, original_diff_result) =
            current_config.diff(&hot_reload_config);
        debug!(
            target: LOG_TARGET,
            updated_category_list = updated_category_list.join(","),
            original_diff_result = original_diff_result.join("\n"),
            "current config diff from hot reload config"
        );
        // no update config
        if original_diff_result.is_empty() {
            return Ok(false);
        }
        // update current config to what is running now
        config_manager.set_current_config(running_config);
        if !original_diff_result.is_empty() {
            send_notification(NotificationData {
                category: "diff_config".to_string(),
                message: original_diff_result.join("\n").trim().to_string(),
                ..Default::default()
            })
            .await;
            if !reload_fail_message.is_empty() {
                send_notification(NotificationData {
                    category: "reload_config_fail".to_string(),
                    message: reload_fail_message.clone(),
                    ..Default::default()
                })
                .await;
            }
        }
        return Ok(false);
    }
    // restart mode
    // update current config to what is running now
    config_manager.set_current_config(running_config);

    // diff hot reload config and new config
    let (_, new_config_result) = hot_reload_config.diff(new_config);
    debug!(
        target: LOG_TARGET,
        new_config_result = new_config_result.join("\n"),
        "hot reload config diff from new config"
    );

    let mut should_restart = true;
    // no update other config update except hot reload config
    if new_config_result.is_empty() {
        should_restart = false;
    }

    if !original_diff_result.is_empty() {
        send_notification(NotificationData {
            category: "diff_config".to_string(),
            message: original_diff_result.join("\n").trim().to_string(),
            ..Default::default()
        })
        .await;
        if !reload_fail_message.is_empty() {
            send_notification(NotificationData {
                category: "reload_config_fail".to_string(),
                message: reload_fail_message.clone(),
                ..Default::default()
            })
            .await;
        }
    }
    if should_restart {
        restart().await;
    }
    Ok(should_restart)
}

/// AutoRestart service manages configuration updates on a schedule
///
/// The service alternates between hot reloads and full restarts based on:
/// - restart_unit: Determines frequency of full restarts vs hot reloads
/// - only_hot_reload: Forces hot reload only mode
/// - count: Tracks intervals to coordinate restart timing
struct AutoRestart {
    /// How many intervals to wait before allowing a full restart (vs hot reload)
    restart_unit: u32,
    /// If true, only perform hot reloads and never restart
    only_hot_reload: bool,
    /// Tracks if currently performing a hot reload
    running_hot_reload: AtomicBool,
    config_manager: Arc<ConfigManager>,
    log_reload_handle: LoggerReloadHandle,
    current_log_level: ArcSwap<String>,
}

/// Creates a new auto-restart service that checks for config changes periodically
pub fn new_auto_restart_service(
    config_manager: Arc<ConfigManager>,
    log_reload_handle: LoggerReloadHandle,
    interval: Duration,
    only_hot_reload: bool,
) -> BackgroundTaskService {
    let mut restart_unit = 1_u32;
    let unit = Duration::from_secs(10);
    if interval > unit {
        restart_unit = (interval.as_secs() / unit.as_secs()) as u32;
    }

    let current_log_level = config_manager
        .get_current_config()
        .basic
        .log_level
        .clone()
        .unwrap_or_default();

    let task = Box::new(AutoRestart {
        log_reload_handle,
        config_manager,
        running_hot_reload: AtomicBool::new(false),
        only_hot_reload,
        restart_unit,
        current_log_level: ArcSwap::from_pointee(current_log_level),
    });
    let name = "auto_restart";
    BackgroundTaskService::new_single(name, interval.min(unit), name, task)
}

/// ConfigObserverService provides real-time config file monitoring
///
/// This service:
/// 1. Watches the config file/storage for changes
/// 2. Triggers immediate hot reload when changes detected
/// 3. Can optionally perform full restarts if needed
/// 4. Runs continuously until server shutdown
///
/// The service uses tokio::select! to handle:
/// - Periodic checks (interval-based)
/// - File system events (real-time)
/// - Graceful shutdown signals
pub struct ConfigObserverService {
    config_manager: Arc<ConfigManager>,
    log_reload_handle: LoggerReloadHandle,
    current_log_level: ArcSwap<String>,
    /// How often to check for changes
    interval: Duration,
    /// If true, only perform hot reloads when changes detected
    only_hot_reload: bool,
    delay: AtomicU32,
}

const MIN_DELAY: u32 = 500;
const MAX_DELAY: u32 = 60 * 1000;
/// How long a watch has to last to count as one that worked.
const WATCH_HELD: Duration = Duration::from_secs(60);

pub fn new_observer_service(
    config_manager: Arc<ConfigManager>,
    log_reload_handle: LoggerReloadHandle,
    interval: Duration,
    only_hot_reload: bool,
) -> ConfigObserverService {
    let current_log_level = config_manager
        .get_current_config()
        .basic
        .log_level
        .clone()
        .unwrap_or_default();

    ConfigObserverService {
        config_manager,
        log_reload_handle,
        interval,
        only_hot_reload,
        current_log_level: ArcSwap::from_pointee(current_log_level),
        delay: AtomicU32::new(MIN_DELAY),
    }
}

static OBSERVER_NAME: &str = "configObserver";

/// What `ConfigObserverService::next_change` came back with.
enum WatchEvent {
    /// A watch was started. Whatever was written while nothing was
    /// watching has to be picked up now.
    Started,
    /// The watch reported a change.
    Changed,
    /// Nothing happened.
    Idle,
}

impl ConfigObserverService {
    /// Waits for the next event of the stored config. Without a watch it
    /// starts one first.
    ///
    /// An error is a watch that could not be started or that ended. The
    /// observer is dropped then, so the next call starts over; the caller
    /// waits in between.
    async fn next_change(
        &self,
        observer: &mut Option<Observer>,
    ) -> Result<WatchEvent, pingap_config::Error> {
        let Some(current) = observer.as_mut() else {
            *observer = Some(self.config_manager.observe().await?);
            return Ok(WatchEvent::Started);
        };
        match current.watch().await {
            Ok(true) => Ok(WatchEvent::Changed),
            Ok(false) => Ok(WatchEvent::Idle),
            Err(e) => {
                *observer = None;
                Err(e)
            },
        }
    }
}

#[async_trait]
impl BackgroundService for ConfigObserverService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        if !self.config_manager.support_observer() {
            return;
        }
        let period_human: humantime::Duration = self.interval.into();

        info!(
            target: LOG_TARGET,
            name = OBSERVER_NAME,
            interval = period_human.to_string(),
            "background service is running",
        );
        let mut period = interval(self.interval);

        // Created by `next_change`, and created again whenever the watch
        // ends. It used to be created here, once: a failure ended the whole
        // service, the periodic check included, and a watch that broke
        // later was never replaced.
        let mut observer = None;
        // When the current watch was started.
        let mut watching_since: Option<Instant> = None;

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    break;
                }
                _ = period.tick() => {
                    // fetch and diff update
                    // some change may be restart
                    if let Some(new_config) = run_diff_and_update_config(self.config_manager.clone(), self.only_hot_reload).await {
                        reload_log_level(
                            &self.log_reload_handle,
                            &self.current_log_level,
                            &new_config,
                        );
                    }
                }
                result = self.next_change(&mut observer) => {
                    let mut delay = self.delay.load(Ordering::Relaxed);
                    match result {
                        Ok(event) => {
                            match event {
                                // Starting a watch does not show that it
                                // works: one that can be started and then
                                // fails at once would come round every
                                // 500ms, a connection and a full config
                                // read each time, if this reset the delay.
                                WatchEvent::Started => {
                                    watching_since = Some(Instant::now());
                                },
                                // A change did come through it.
                                WatchEvent::Changed => {
                                    if delay > MIN_DELAY {
                                        self.delay.store(MIN_DELAY, Ordering::Relaxed);
                                    }
                                },
                                // The acknowledgement of the watch is one
                                // of these, and proves as little.
                                WatchEvent::Idle => {},
                            }
                            if matches!(event, WatchEvent::Idle) {
                                continue;
                            }
                            // only hot reload for observe updated
                            run_diff_and_update_config(self.config_manager.clone(), true).await;
                        },
                        Err(e) => {
                            error!(
                               target: LOG_TARGET,
                               error = %e,
                               "observe updated fail"
                            );
                            // A watch that held for a while was a working
                            // one, events or not: the backoff starts over.
                            let held = watching_since
                                .take()
                                .is_some_and(|since| since.elapsed() >= WATCH_HELD);
                            if held {
                                delay = MIN_DELAY;
                            }
                            tokio::time::sleep(Duration::from_millis(delay as u64)).await;
                            self.delay.store((delay * 2).min(MAX_DELAY), Ordering::Relaxed);
                        }
                    }
                }
            }
        }
    }
}

/// Helper function to run the config diff and update process
/// Logs any errors that occur during the update
async fn run_diff_and_update_config(
    config_manager: Arc<ConfigManager>,
    hot_reload_only: bool,
) -> Option<PingapConfig> {
    let new_config =
        match diff_and_update_config(config_manager.clone(), hot_reload_only)
            .await
        {
            Ok(new_config) => new_config,
            Err(e) => {
                error!(
                    target: LOG_TARGET,
                    error = %e,
                    "update config fail",
                );
                None
            },
        };
    // The document may be as it was while the files it points at are not.
    reload_changed_certificate_files(&config_manager).await;
    new_config
}

#[async_trait]
impl BackgroundTask for AutoRestart {
    async fn execute(&self, count: u32) -> Result<bool, ServiceError> {
        // Calculate if this iteration should be hot reload only.
        //
        // `restart_unit` is how many check ticks make one full config interval
        // (the service itself runs every min(interval, 10s)). Full restart is
        // offered when `count` is a multiple of `restart_unit`.
        //
        // When interval ≤ 10s, `restart_unit == 1`, so every tick after the
        // first is a full-restart opportunity — otherwise non-hot-reloadable
        // changes (server addr, threads, …) would never take effect.
        //
        // count=0 is always hot-reload-only so the first pass is gentle.
        let hot_reload_only = self.only_hot_reload
            || count == 0
            || !count.is_multiple_of(self.restart_unit);
        self.running_hot_reload
            .store(hot_reload_only, Ordering::Relaxed);
        if let Some(new_config) = run_diff_and_update_config(
            self.config_manager.clone(),
            hot_reload_only,
        )
        .await
        {
            reload_log_level(
                &self.log_reload_handle,
                &self.current_log_level,
                &new_config,
            );
        }
        Ok(true)
    }
}

/// Applies the log level of `new_config` when it differs from the one in
/// place, and remembers it so an unchanged level is not re-applied on the
/// next pass.
fn reload_log_level(
    handle: &LoggerReloadHandle,
    current: &ArcSwap<String>,
    new_config: &PingapConfig,
) {
    let new_level = new_config.basic.log_level.clone().unwrap_or_default();
    let current_level = current.load();
    if new_level == **current_level {
        return;
    }
    info!(
        target: LOG_TARGET,
        current_level = current_level.as_str(),
        new_level,
        "reload log level"
    );
    match handle.modify(|filter| *filter = new_env_filter(&new_level)) {
        Ok(()) => current.store(Arc::new(new_level)),
        Err(e) => error!(
            target: LOG_TARGET,
            error = %e,
            "reload log level fail"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{LastSeen, merge_certificates, should_skip};
    use pingap_config::CertificateConf;
    use pretty_assertions::assert_eq;
    use std::collections::HashMap;

    /// Regression: one certificate of ACME in the configuration and no
    /// certificate was hot reloaded, the ones given as PEM included.
    #[test]
    fn test_merge_certificates_goes_entry_by_entry() {
        let conf = |cert: &str, acme: bool| CertificateConf {
            domains: Some("example.com".to_string()),
            tls_cert: Some(cert.to_string()),
            tls_key: Some(cert.to_string()),
            acme: acme.then(|| "lets_encrypt".to_string()),
            ..Default::default()
        };
        let configs = |items: &[(&str, CertificateConf)]| {
            items
                .iter()
                .map(|(name, conf)| (name.to_string(), conf.clone()))
                .collect::<HashMap<_, _>>()
        };
        let current = configs(&[
            ("acme", conf("a1", true)),
            ("static", conf("s1", false)),
            ("gone", conf("g1", false)),
            ("was-acme", conf("w1", true)),
        ]);

        // Nothing changed.
        let changes = merge_certificates(&current, &current);
        assert_eq!(current, changes.merged);
        assert_eq!(false, changes.changed);
        assert_eq!(true, changes.left.is_empty());
        assert_eq!(2, changes.of_acme.len());

        let new = configs(&[
            // Renewed: what the ACME service itself stores.
            ("acme", conf("a2", true)),
            ("static", conf("s2", false)),
            ("added", conf("n1", false)),
            // No longer of ACME: reloaded, so that its service lets go.
            ("was-acme", conf("w2", false)),
            // Given to ACME, and a new one of ACME: both wait.
            ("gone", conf("g1", true)),
            ("new-acme", conf("", true)),
        ]);
        let changes = merge_certificates(&current, &new);
        assert_eq!(true, changes.changed);
        assert_eq!(
            configs(&[
                ("acme", conf("a1", true)),
                ("static", conf("s2", false)),
                ("added", conf("n1", false)),
                ("was-acme", conf("w2", false)),
                ("gone", conf("g1", false)),
            ]),
            changes.merged
        );
        assert_eq!(
            vec!["gone".to_string(), "new-acme".to_string()],
            changes.left
        );
        let mut of_acme: Vec<_> = changes.of_acme.into_iter().collect();
        of_acme.sort();
        assert_eq!(vec!["acme", "gone", "new-acme"], of_acme);

        // The last entry of ACME is taken out: reloaded like any other.
        // Left in the running configuration, its service went on renewing
        // a certificate that is not stored any more.
        let new = configs(&[("static", conf("s1", false))]);
        let changes = merge_certificates(&current, &new);
        assert_eq!(true, changes.changed);
        assert_eq!(new, changes.merged);
        assert_eq!(true, changes.left.is_empty());
        assert_eq!(true, changes.of_acme.is_empty());

        // The settings of an entry of ACME changed: said, and left.
        let mut new = current.clone();
        new.get_mut("acme").unwrap().domains =
            Some("example.com,www.example.com".to_string());
        let changes = merge_certificates(&current, &new);
        assert_eq!(false, changes.changed);
        assert_eq!(current, changes.merged);
        assert_eq!(vec!["acme".to_string()], changes.left);
    }

    #[test]
    fn test_failed_recently() {
        use std::time::{Duration, Instant};
        let failed = |ago: u64| super::LastFailed {
            hash: 1,
            at: Instant::now() - Duration::from_secs(ago),
            message: "no".to_string(),
        };
        assert_eq!(false, super::failed_recently(None, 1));
        // The same document, a moment ago: left alone.
        assert_eq!(true, super::failed_recently(Some(&failed(5)), 1));
        // Another document, or the same one a minute later: tried.
        assert_eq!(false, super::failed_recently(Some(&failed(5)), 2));
        assert_eq!(false, super::failed_recently(Some(&failed(61)), 1));
    }

    #[test]
    fn test_should_skip() {
        // Nothing seen yet: every pass runs.
        assert_eq!(false, should_skip(None, 1, true));
        assert_eq!(false, should_skip(None, 1, false));

        // A changed document runs whatever the last pass was.
        let hot_only = LastSeen {
            hash: 1,
            restart_eligible: false,
        };
        assert_eq!(false, should_skip(Some(&hot_only), 2, true));
        assert_eq!(false, should_skip(Some(&hot_only), 2, false));

        // Unchanged after a hot-reload-only pass: another hot-reload-only
        // pass has nothing to add, a restart-eligible one still has to look.
        assert_eq!(true, should_skip(Some(&hot_only), 1, true));
        assert_eq!(false, should_skip(Some(&hot_only), 1, false));

        // Unchanged after a restart-eligible pass that needed no restart:
        // nothing is left for either kind of pass.
        let settled = LastSeen {
            hash: 1,
            restart_eligible: true,
        };
        assert_eq!(true, should_skip(Some(&settled), 1, true));
        assert_eq!(true, should_skip(Some(&settled), 1, false));
    }
}
