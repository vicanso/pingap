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
    ConfigManager, FILE_REFERENCE_PREFIX, MissingReference, Observer,
    PingapConfig, PingapTomlConfig,
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
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
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

/// Whether the configuration could not be read from its storage the last
/// time it was tried.
static LOAD_FAILING: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Notes that the storage could not be read, and says whether that is
/// news: it could be read the time before. The poll and the watch of a
/// storage both come through here, and one of them is told so.
fn load_failure_is_news() -> bool {
    !LOAD_FAILING.swap(true, std::sync::atomic::Ordering::Relaxed)
}

/// Notes that the storage could be read.
fn load_succeeded() {
    LOAD_FAILING.store(false, std::sync::atomic::Ordering::Relaxed);
}

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
    let (updated, errors) = {
        // The certificates of the running configuration, while nobody
        // else is making another of it.
        let _guard = config_manager.lock_current_config().await;
        let config = config_manager.get_current_config();
        try_reload_certificate_files(&config.certificates)
    };
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
/// A document with `$FILE:` references is parsed on every pass all the
/// same, and those files are read: what they hold is a part of what may
/// have changed.
async fn diff_and_update_config(
    config_manager: Arc<ConfigManager>,
    hot_reload_only: bool,
) -> Result<Option<PingapConfig>, Box<dyn std::error::Error>> {
    let raw = match config_manager.load_all_raw().await {
        Ok(raw) => {
            load_succeeded();
            raw
        },
        Err(e) => {
            // A storage that can not be read - an etcd that is away, a
            // file whose permissions were changed - was a line in the log
            // at every pass and nothing else. It is said once, there and
            // to the webhook, when it starts: what is running goes on as
            // it is, and no change to the configuration is seen until
            // this is over.
            let message = format!("load config fail: {e}");
            if !load_failure_is_news() {
                debug!(
                    target: LOG_TARGET,
                    error = message,
                    "load config still fails"
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
    let mut hash = raw_hash(&raw);
    // A value that is read from a file changes without the document
    // changing: a secret rotated in place. What those files hold is a
    // part of what is compared, and read off this thread. A document that
    // does not parse has none of it, and says so itself below.
    if raw.contains(FILE_REFERENCE_PREFIX) {
        let text = raw.clone();
        hash ^= tokio::task::spawn_blocking(move || {
            PingapTomlConfig::from_toml(&text)
                .map(|document| document.referenced_files_hash())
                .unwrap_or_default()
        })
        .await
        .unwrap_or_default();
    }
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
        // Off this thread: a `$FILE:` reference is read from disk.
        let new_config = tokio::task::spawn_blocking(move || {
            document
                .to_running_config(MissingReference::Refuse)
                .map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| e.to_string())??;
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
            // Each pass that tried and was refused, also the repeated
            // ones that are not reported again below.
            pingap_performance::record_config_reload(false);
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

/// What this process does for the certificates of ACME.
#[derive(Clone, Copy)]
struct AcmeHere {
    /// Its ACME service runs. With `PINGAP_DISABLE_ACME` it does not, and
    /// nobody here orders a certificate or stores one.
    orders: bool,
    /// One of its servers listens on port 80, where a CA asks for the
    /// answer to an http-01 challenge. A listener is not something a
    /// reload adds.
    http_listener: bool,
}

static ACME_ORDERS: AtomicBool = AtomicBool::new(true);
static HTTP_CHALLENGE_LISTENER: AtomicBool = AtomicBool::new(false);

/// Notes what this process does for the certificates of ACME: whether its
/// ACME service runs, and whether a server of it listens on port 80. Once,
/// when its services and servers are made.
pub fn set_acme_here(orders: bool, http_listener: bool) {
    ACME_ORDERS.store(orders, Ordering::Relaxed);
    HTTP_CHALLENGE_LISTENER.store(http_listener, Ordering::Relaxed);
}

/// Whether this process only ever reloads (`--autoreload`): a change that
/// takes a restart then waits for somebody to make one.
static ONLY_HOT_RELOAD: AtomicBool = AtomicBool::new(false);

/// The certificates that were last told to be waiting for a restart.
static LEFT_REPORTED: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Notes the certificates that wait for a restart, and says whether they
/// are worth telling: there are some, and they are not the ones that were
/// told the last time. Every change to the configuration is a pass that
/// finds them still waiting.
fn left_is_news(left: &[String]) -> bool {
    let mut reported = LEFT_REPORTED.lock().unwrap_or_else(|e| e.into_inner());
    if reported.as_slice() == left {
        return false;
    }
    *reported = left.to_vec();
    !left.is_empty()
}

/// What a hot reload does with a change of the certificates.
struct CertificateChanges {
    /// The certificates once the reload is done.
    merged: HashMap<String, CertificateConf>,
    /// Whether the certificate store is to be brought up to date: an entry
    /// that is not in `kept` is not what it was.
    changed: bool,
    /// Whether that is so for an entry other than the ones in `handed`.
    changed_others: bool,
    /// The entries of ACME that are what they were. Their certificates
    /// are not loaded again here: what the store has under their names
    /// was put there by their service.
    kept: HashSet<String>,
    /// The entries the ACME service is handed with the settings they have
    /// now: new ones, ones that were given to it, and ones of its own
    /// whose settings changed. It looks at the ones it orders differently
    /// for at its next run.
    handed: Vec<String>,
    /// The entries that only a restart applies: their challenge is
    /// answered on port 80, and nothing listens there.
    left: Vec<String>,
}

/// Splits a change of the certificates into what a hot reload does with
/// each entry.
///
/// The ACME service reads the settings of its entries from the running
/// configuration at every run, and stores the certificate it orders into
/// the same entry. So an entry of ACME is taken with the settings the new
/// configuration has for it - a new one whole - and the service does the
/// rest. Such a change used to wait for a restart, with a warning in the
/// log of a process that never restarts by itself.
///
/// The certificate and the key of an entry that was the service's already
/// stay the running ones: what the storage holds was read a moment ago,
/// and the service may have renewed since. That write alone - `tls_cert`
/// and `tls_key` of an entry that is otherwise the same - is its own doing,
/// nothing to reload and nothing to report.
///
/// One thing a reload cannot give the service: a listener. An entry whose
/// challenge is answered over HTTP is left as it is, or left out, when no
/// server of this process is on port 80; the server that is added for it
/// when the process starts is not there.
///
/// An entry that is no longer one of ACME, or no longer there, is reloaded
/// like any other. Left in the running configuration, the service went on
/// renewing it: over the certificate that was put in its place, or for an
/// entry that is not stored any more.
///
/// And so is every entry where the service does not run: there is nobody
/// to hand it to, and nobody but the storage to have its certificate from.
/// The listener is missed there as well.
fn merge_certificates(
    current: &HashMap<String, CertificateConf>,
    new: &HashMap<String, CertificateConf>,
    acme: AcmeHere,
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
        changed_others: false,
        kept: HashSet::new(),
        handed: vec![],
        left: vec![],
    };
    let names: BTreeSet<&String> = current.keys().chain(new.keys()).collect();
    for name in names {
        let (before, after) = (current.get(name), new.get(name));
        let of_acme = after.filter(|conf| conf.is_acme());
        let same_settings = settings(before) == settings(after);
        // A listener that is not there is missed whoever orders: an
        // instance that does not order answers the challenges of the
        // ones that do, when they share a storage. What is running stays
        // as it is, and the change waits for a restart.
        let unanswered = of_acme.is_some_and(|conf| {
            conf.is_acme_http_challenge() && !acme.http_listener
        });
        if unanswered && !same_settings {
            changes.left.push(name.clone());
            if let Some(running) = before {
                if acme.orders && running.is_acme() {
                    changes.kept.insert(name.clone());
                }
                changes.merged.insert(name.clone(), running.clone());
            }
            continue;
        }
        let Some(conf) = of_acme.filter(|_| acme.orders) else {
            let changed = before != after;
            changes.changed |= changed;
            changes.changed_others |= changed;
            if let Some(conf) = after {
                changes.merged.insert(name.clone(), conf.clone());
            }
            continue;
        };
        // The same entry of ACME: what is running stays as it is.
        if same_settings {
            if let Some(running) = before {
                changes.kept.insert(name.clone());
                changes.merged.insert(name.clone(), running.clone());
            }
            continue;
        }
        changes.changed = true;
        changes.handed.push(name.clone());
        let merged = match before.filter(|running| running.is_acme()) {
            Some(running) => CertificateConf {
                tls_cert: running.tls_cert.clone(),
                tls_key: running.tls_key.clone(),
                ..conf.clone()
            },
            None => conf.clone(),
        };
        changes.merged.insert(name.clone(), merged);
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
///    - Certificates, entry by entry. One of ACME is handed to its service
///      with the settings it has now, see `merge_certificates`
///    - Webhook settings (`webhook`, `webhook_type`, `webhook_notifications`,
///      `webhook_batch_window`, `webhook_batch_max_events`,
///      `webhook_min_level`, `webhook_headers`, `webhook_secret`,
///      `webhook_template`, `webhook_retries`)
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
    // From here to where the running configuration is set: the ACME
    // service puts a certificate into its entry of that configuration, and
    // one that it put there while this reload went on was written over by
    // what the reload had read before, then ordered again.
    let running_guard = config_manager.lock_current_config().await;
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
        // Nor a certificate that waits for a restart: one that waits is
        // not in the running configuration as the storage has it.
        left_is_news(&[]);
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
    let mut certificate_reload_failed = false;
    // The entries of ACME this reload hands to their service.
    let mut handed_to_acme: Vec<String> = vec![];
    let mut hot_reload_config = current_config.clone();
    // What the references of the new configuration stood for goes with
    // its entries. Left behind, a value that was read from a file or the
    // environment was only kept out of the difference until the first
    // reload: the running configuration then held the new value and the
    // set of the old one.
    hot_reload_config
        .referenced
        .extend(new_config.referenced.iter().cloned());
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

        // Certificates are taken entry by entry. The certificate of an
        // entry of ACME is its service's to order and to store, and its
        // settings are what the service is handed here. With a single
        // such entry no certificate at all used to be reloaded, the ones
        // given in the configuration included, and nothing said so.
        let certificates = merge_certificates(
            &current_config.certificates,
            &new_config.certificates,
            AcmeHere {
                orders: ACME_ORDERS.load(Ordering::Relaxed),
                http_listener: HTTP_CHALLENGE_LISTENER.load(Ordering::Relaxed),
            },
        );
        hot_reload_config.certificates = certificates.merged;
        let certificates_kept = certificates.kept;
        let certificates_handed = certificates.handed;
        handed_to_acme.clone_from(&certificates_handed);
        let should_reload_certificate = certificates.changed;
        let certificates_changed_others = certificates.changed_others;
        let left_is_news = left_is_news(&certificates.left);
        if !certificates.left.is_empty() {
            let names = certificates.left.join(",");
            warn!(
                target: LOG_TARGET,
                certificates = names,
                "the http-01 challenge of a certificate of acme needs a server on port 80, which takes a restart to add"
            );
            // Who never restarts by itself is the one to be told: the
            // certificate is not ordered until somebody does it. Once,
            // not with every later change that finds it still waiting.
            if left_is_news && ONLY_HOT_RELOAD.load(Ordering::Relaxed) {
                send_notification(NotificationData {
                    category: "reload_config_fail".to_string(),
                    level: NotificationLevel::Warn,
                    message: format!(
                        "Certificate({names}) is ordered with the http-01 challenge, and no server listens on port 80: restart to apply"
                    ),
                    ..Default::default()
                })
                .await;
            }
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
                |name| certificates_kept.contains(name),
            );
            // The entries of ACME are told by themselves, and as what
            // they are: modified. Whether one is ordered for is its
            // service's to find, and to tell.
            if !certificates_handed.is_empty() {
                let names = certificates_handed.join(",");
                info!(
                    target: LOG_TARGET,
                    certificates = names,
                    "reload certificate of acme success"
                );
                send_notification(NotificationData {
                    category: "reload_config".to_string(),
                    level: NotificationLevel::Info,
                    message: format!(
                        "Certificate({names}) of acme is modified"
                    ),
                    ..Default::default()
                })
                .await;
            }
            let updated_certificates: Vec<String> = updated_certificates
                .into_iter()
                .filter(|name| !certificates_handed.contains(name))
                .collect();
            // Said when something was reloaded or taken out, not ahead of
            // the errors as if all of it had been.
            if !updated_certificates.is_empty()
                || (errors.is_empty() && certificates_changed_others)
            {
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
                certificate_reload_failed = true;
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
    running_config.prune_referenced();
    if routes_failed {
        for (name, server) in running_config.servers.iter_mut() {
            if let Some(current) = current_config.servers.get(name) {
                server.locations.clone_from(&current.locations);
            }
        }
    }

    let reload_fail_message = reload_fail_messages.join(";");
    // Every category that was to be reloaded was, certificates included.
    // The plugins and the certificates report what went wrong with them
    // on their own, and are not in the message above.
    let applied_whole = reload_fail_message.is_empty()
        && !upstream_reload_failed
        && !plugin_reload_failed
        && !location_reload_failed
        && !server_location_reload_failed
        && !certificate_reload_failed;

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
        // Said once the entries are running: the service looks for them
        // there.
        pingap_acme::hand_over(&handed_to_acme);
        // A reload that changed something, counted as it went: applied,
        // or with a part of it that did not go through. A pass that found
        // nothing to do is not one.
        pingap_performance::record_config_reload(applied_whole);
        if !original_diff_result.is_empty() {
            send_notification(NotificationData {
                category: "diff_config".to_string(),
                message: original_diff_result.join("\n").trim().to_string(),
                ..Default::default()
            })
            .await;
            if !reload_fail_message.is_empty() {
                // An error like the other failures of a reload: sent with
                // the default level, it was `info`, and a webhook that
                // only takes warnings and worse never heard of it.
                send_notification(NotificationData {
                    category: "reload_config_fail".to_string(),
                    level: NotificationLevel::Error,
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
    pingap_acme::hand_over(&handed_to_acme);

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
        // What is left for a restart is not counted as applied: the
        // restart is what applies it, and a pass that comes by again
        // while it has not happened would count the same change once
        // more. A part that did not go through is a failure either way.
        if !should_restart || !applied_whole {
            pingap_performance::record_config_reload(applied_whole);
        }
        send_notification(NotificationData {
            category: "diff_config".to_string(),
            message: original_diff_result.join("\n").trim().to_string(),
            ..Default::default()
        })
        .await;
        if !reload_fail_message.is_empty() {
            send_notification(NotificationData {
                category: "reload_config_fail".to_string(),
                level: NotificationLevel::Error,
                message: reload_fail_message.clone(),
                ..Default::default()
            })
            .await;
        }
    }
    drop(running_guard);
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

    ONLY_HOT_RELOAD.store(only_hot_reload, Ordering::Relaxed);
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

    ONLY_HOT_RELOAD.store(only_hot_reload, Ordering::Relaxed);
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
    use super::{AcmeHere, LastSeen, merge_certificates, should_skip};
    use pingap_config::CertificateConf;
    use pretty_assertions::assert_eq;
    use std::collections::{HashMap, HashSet};

    /// The ACME service runs, and a server listens on port 80.
    const HERE: AcmeHere = AcmeHere {
        orders: true,
        http_listener: true,
    };
    const NO_LISTENER: AcmeHere = AcmeHere {
        orders: true,
        http_listener: false,
    };

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

        let sorted = |names: &HashSet<String>| {
            let mut names: Vec<_> = names.iter().cloned().collect();
            names.sort();
            names
        };

        // Nothing changed.
        let changes = merge_certificates(&current, &current, HERE);
        assert_eq!(current, changes.merged);
        assert_eq!(false, changes.changed);
        assert_eq!(true, changes.left.is_empty());
        assert_eq!(true, changes.handed.is_empty());
        assert_eq!(vec!["acme", "was-acme"], sorted(&changes.kept));

        let new = configs(&[
            // Renewed: what the ACME service itself stores.
            ("acme", conf("a2", true)),
            ("static", conf("s2", false)),
            ("added", conf("n1", false)),
            // No longer of ACME: reloaded, so that its service lets go.
            ("was-acme", conf("w2", false)),
            // Given to ACME, and a new one of ACME: both are its
            // service's from here on, as they are written.
            ("gone", conf("g1", true)),
            ("new-acme", conf("", true)),
        ]);
        let changes = merge_certificates(&current, &new, HERE);
        assert_eq!(true, changes.changed);
        assert_eq!(true, changes.changed_others);
        assert_eq!(
            configs(&[
                ("acme", conf("a1", true)),
                ("static", conf("s2", false)),
                ("added", conf("n1", false)),
                ("was-acme", conf("w2", false)),
                ("gone", conf("g1", true)),
                ("new-acme", conf("", true)),
            ]),
            changes.merged
        );
        assert_eq!(true, changes.left.is_empty());
        assert_eq!(
            vec!["gone".to_string(), "new-acme".to_string()],
            changes.handed
        );
        // Only the one that is what it was is not loaded again.
        assert_eq!(vec!["acme"], sorted(&changes.kept));

        // The last entry of ACME is taken out: reloaded like any other.
        // Left in the running configuration, its service went on renewing
        // a certificate that is not stored any more.
        let new = configs(&[("static", conf("s1", false))]);
        let changes = merge_certificates(&current, &new, HERE);
        assert_eq!(true, changes.changed);
        assert_eq!(new, changes.merged);
        assert_eq!(true, changes.left.is_empty());
        assert_eq!(true, changes.kept.is_empty());
    }

    /// Regression: a change to an entry of ACME - its domains, a new
    /// entry - was left for a restart, which a process that only reloads
    /// never makes. A warning in its log was all there was.
    #[test]
    fn test_merge_certificates_hands_the_settings_to_acme() {
        let conf = |domains: &str, cert: &str| CertificateConf {
            domains: Some(domains.to_string()),
            tls_cert: Some(cert.to_string()),
            tls_key: Some(cert.to_string()),
            acme: Some("lets_encrypt".to_string()),
            ..Default::default()
        };
        let configs = |items: &[(&str, CertificateConf)]| {
            items
                .iter()
                .map(|(name, conf)| (name.to_string(), conf.clone()))
                .collect::<HashMap<_, _>>()
        };
        let current = configs(&[("site", conf("example.com", "running"))]);

        // The settings are the new ones. The certificate is the one that
        // is running, not what the storage held when it was read: the
        // service may have stored another since.
        let new = configs(&[(
            "site",
            conf("example.com,www.example.com", "as stored"),
        )]);
        let changes = merge_certificates(&current, &new, HERE);
        assert_eq!(
            configs(&[(
                "site",
                conf("example.com,www.example.com", "running")
            )]),
            changes.merged
        );
        assert_eq!(vec!["site".to_string()], changes.handed);
        // Loaded again, for the domains it has now.
        assert_eq!(true, changes.changed);
        assert_eq!(false, changes.changed_others);
        assert_eq!(true, changes.kept.is_empty());
        assert_eq!(true, changes.left.is_empty());

        // A certificate stored by the service, and nothing else: not a
        // change of the entry.
        let new = configs(&[("site", conf("example.com", "as stored"))]);
        let changes = merge_certificates(&current, &new, HERE);
        assert_eq!(current, changes.merged);
        assert_eq!(false, changes.changed);
        assert_eq!(true, changes.handed.is_empty());
        assert_eq!(1, changes.kept.len());

        // Nothing listens on port 80, and a listener is not something a
        // reload adds: the entry stays as it is, a new one stays out, and
        // both are named.
        let new = configs(&[
            ("site", conf("example.com,www.example.com", "as stored")),
            ("other", conf("other.test", "")),
        ]);
        let changes = merge_certificates(&current, &new, NO_LISTENER);
        assert_eq!(current, changes.merged);
        assert_eq!(false, changes.changed);
        assert_eq!(true, changes.handed.is_empty());
        assert_eq!(vec!["other".to_string(), "site".to_string()], changes.left);
        assert_eq!(1, changes.kept.len());

        // Where the ACME service does not run (`PINGAP_DISABLE_ACME`)
        // there is nobody to hand an entry to, and nobody but the storage
        // to have its certificate from: every entry is reloaded as it is
        // written.
        let changes = merge_certificates(
            &current,
            &new,
            AcmeHere {
                orders: false,
                http_listener: true,
            },
        );
        assert_eq!(new, changes.merged);
        assert_eq!(true, changes.changed);
        assert_eq!(true, changes.changed_others);
        assert_eq!(true, changes.handed.is_empty());
        assert_eq!(true, changes.left.is_empty());
        assert_eq!(true, changes.kept.is_empty());
        // The listener is missed there too: such a process answers the
        // challenges of the ones that order. But a certificate that the
        // storage has anew, for an entry that is otherwise the same, is
        // nothing a listener is needed for.
        let here = AcmeHere {
            orders: false,
            http_listener: false,
        };
        let changes = merge_certificates(&current, &new, here);
        assert_eq!(current, changes.merged);
        assert_eq!(false, changes.changed);
        assert_eq!(vec!["other".to_string(), "site".to_string()], changes.left);
        assert_eq!(true, changes.kept.is_empty());
        let renewed = configs(&[("site", conf("example.com", "as stored"))]);
        let changes = merge_certificates(&current, &renewed, here);
        assert_eq!(renewed, changes.merged);
        assert_eq!(true, changes.changed);
        assert_eq!(true, changes.left.is_empty());

        // The challenge that is answered through the DNS needs none.
        let dns = |domains: &str, cert: &str| CertificateConf {
            dns_challenge: Some(true),
            dns_provider: Some("cf".to_string()),
            ..conf(domains, cert)
        };
        let current = configs(&[("site", dns("example.com", "running"))]);
        let new = configs(&[
            ("site", dns("*.example.com", "as stored")),
            ("other", dns("other.test", "")),
        ]);
        let changes = merge_certificates(&current, &new, NO_LISTENER);
        assert_eq!(
            configs(&[
                ("site", dns("*.example.com", "running")),
                ("other", dns("other.test", "")),
            ]),
            changes.merged
        );
        assert_eq!(
            vec!["other".to_string(), "site".to_string()],
            changes.handed
        );
        assert_eq!(true, changes.left.is_empty());
    }

    /// The certificates that wait for a restart are told when they come
    /// to wait, not at every change to the configuration after that.
    #[test]
    fn test_left_is_news() {
        let names = |names: &[&str]| -> Vec<String> {
            names.iter().map(|name| name.to_string()).collect()
        };
        assert_eq!(false, super::left_is_news(&[]));
        assert_eq!(true, super::left_is_news(&names(&["a"])));
        assert_eq!(false, super::left_is_news(&names(&["a"])));
        assert_eq!(true, super::left_is_news(&names(&["a", "b"])));
        // None any more is nothing to tell, and the same one is news
        // when it waits again.
        assert_eq!(false, super::left_is_news(&[]));
        assert_eq!(true, super::left_is_news(&names(&["a"])));
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

    /// A storage that can not be read is said when that starts, not at
    /// every pass it lasts; and again the next time, after it could be.
    #[test]
    fn test_load_failure_is_news() {
        use super::{load_failure_is_news, load_succeeded};
        load_succeeded();
        assert_eq!(true, load_failure_is_news());
        assert_eq!(false, load_failure_is_news());
        assert_eq!(false, load_failure_is_news());
        load_succeeded();
        load_succeeded();
        assert_eq!(true, load_failure_is_news());
        assert_eq!(false, load_failure_is_news());
        load_succeeded();
    }
}
