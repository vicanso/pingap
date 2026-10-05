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
use crate::certificates::try_update_certificates;
use crate::locations::try_init_locations;
use crate::plugin;
use crate::server_locations::try_init_server_locations;
use crate::upstreams::try_update_upstreams;
use crate::webhook::{
    get_webhook_sender, reload_webhook_notification_sender, send_notification,
};
use arc_swap::{ArcSwap, ArcSwapOption};
use async_trait::async_trait;
use pingap_certificate::validate_servers_tls_for_backend;
use pingap_config::{
    CATEGORY_CERTIFICATE, CATEGORY_LOCATION, CATEGORY_PLUGIN,
    CATEGORY_UPSTREAM, ConfigManager, Observer, PingapConfig, PingapTomlConfig,
};
use pingap_core::{
    BackgroundTask, BackgroundTaskService, Error as ServiceError,
    NotificationData, NotificationLevel,
};
use pingap_logger::LoggerReloadHandle;
use pingap_logger::new_env_filter;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};
use tokio::time::interval;
use tracing::{debug, error, info};

static LOG_TARGET: &str = "main::auto_restart";

/// What the previous pass saw: the hash of the raw configuration document
/// and whether that pass was allowed to restart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LastSeen {
    hash: u64,
    restart_eligible: bool,
}

static LAST_SEEN: ArcSwapOption<LastSeen> = ArcSwapOption::const_empty();

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
    let new_config =
        PingapTomlConfig::from_toml(&raw)?.to_pingap_config(true)?;
    let restart_requested =
        apply_config(config_manager, &new_config, hot_reload_only).await?;
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
///    - Certificates (except ACME/Let's Encrypt)
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
    new_config.validate()?;
    validate_servers_tls_for_backend(&new_config.servers)?;
    plugin::validate_plugin_references(new_config)?;
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

    let mut reload_fail_messages = vec![];
    let mut hot_reload_config = current_config.clone();
    {
        // hot reload first,
        // only validate server.locations, locations, upstreams and plugins
        let mut should_reload_server_location = false;
        let mut should_reload_upstream = false;
        let mut should_reload_location = false;
        let mut should_reload_plugin = false;
        let mut should_reload_certificate = false;

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

        // acme will create a let's encrypt service
        // so it can't be reloaded.
        let mut exists_acme = false;
        for cert in new_config.certificates.values() {
            if cert.acme.is_some() {
                exists_acme = true;
            }
        }
        if !exists_acme {
            hot_reload_config.certificates = new_config.certificates.clone();
        }

        // new_config.certificates

        for category in updated_category_list {
            match category.as_str() {
                CATEGORY_LOCATION => should_reload_location = true,
                CATEGORY_UPSTREAM => should_reload_upstream = true,
                CATEGORY_PLUGIN => should_reload_plugin = true,
                // acme should be reload by let's encrypt service
                CATEGORY_CERTIFICATE if !exists_acme => {
                    should_reload_certificate = true;
                },
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
        let mut location_reload_failed = false;
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
            let (updated_certificates, errors) =
                try_update_certificates(&new_config.certificates);
            info!(target: LOG_TARGET, "reload certificate success");
            send_notification(NotificationData {
                category: "reload_config".to_string(),
                level: NotificationLevel::Info,
                message: format_message("Certificate", updated_certificates),
                ..Default::default()
            })
            .await;
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
        if should_reload_server_location || should_reload_location {
            match try_init_server_locations(
                &new_config.servers,
                &new_config.locations,
            ) {
                Err(e) => {
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
        // update current config to be hot reload config
        config_manager.set_current_config(hot_reload_config);
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
    // update current config to be hot reload config
    config_manager.set_current_config(hot_reload_config.clone());

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
    match diff_and_update_config(config_manager, hot_reload_only).await {
        Ok(new_config) => new_config,
        Err(e) => {
            error!(
                target: LOG_TARGET,
                error = %e,
                "update config fail",
            );
            None
        },
    }
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
    use super::{LastSeen, should_skip};
    use pretty_assertions::assert_eq;

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
