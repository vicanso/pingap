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
use crate::webhook::{get_webhook_sender, send_notification};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use pingap_config::{
    CATEGORY_CERTIFICATE, CATEGORY_LOCATION, CATEGORY_PLUGIN,
    CATEGORY_UPSTREAM, ConfigManager, PingapConfig,
};
use pingap_core::{
    BackgroundTask, BackgroundTaskService, Error as ServiceError,
    NotificationData, NotificationLevel,
};
use pingap_logger::LoggerReloadHandle;
use pingap_logger::new_env_filter;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, error, info};

static LOG_TARGET: &str = "main::auto_restart";

/// Compares configurations and handles updates through hot reload or full restart
///
/// This function:
/// 1. Loads and validates the new configuration
/// 2. Compares it with current config to find differences
/// 3. Attempts hot reload for supported changes:
///    - Server locations
///    - Upstream configurations
///    - Location definitions
///    - Plugin configurations
///    - Certificates (except ACME/Let's Encrypt)
/// 4. Sends notifications for successful updates
/// 5. If hot_reload_only=false and there are non-hot-reloadable changes,
///    triggers a full server restart
async fn diff_and_update_config(
    config_manager: Arc<ConfigManager>,
    hot_reload_only: bool,
) -> Result<PingapConfig, Box<dyn std::error::Error>> {
    let new_toml_config = config_manager.load_all().await?;
    let new_config = new_toml_config.to_pingap_config(true)?;
    new_config.validate()?;
    let current_config: PingapConfig =
        config_manager.get_current_config().as_ref().clone();

    let (updated_category_list, original_diff_result) =
        current_config.diff(&new_config);
    debug!(
        target: LOG_TARGET,
        updated_category_list = updated_category_list.join(","),
        original_diff_result = original_diff_result.join("\n"),
        "current config diff from new config"
    );
    // no update config
    if original_diff_result.is_empty() {
        return Ok(new_config);
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

        // update the values which can be hot reload
        // set server locations
        for (name, server) in new_config.servers.iter() {
            if let Some(clone_server_conf) =
                hot_reload_config.servers.get_mut(name)
            {
                if server.locations != clone_server_conf.locations {
                    clone_server_conf.locations.clone_from(&server.locations);
                    should_reload_server_location = true;
                }
            }
        }

        // set upstream, location and plugin value
        hot_reload_config.upstreams = new_config.upstreams.clone();
        hot_reload_config.locations = new_config.locations.clone();
        hot_reload_config.plugins = new_config.plugins.clone();

        // acme will create a let's encrypt service
        // so it can't be reloaded.
        let mut exists_acme = false;
        for (_, cert) in new_config.certificates.iter() {
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
                CATEGORY_CERTIFICATE => {
                    // acme should be reload by let's encrypt service
                    if !exists_acme {
                        should_reload_certificate = true;
                    }
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
        if should_reload_location {
            match try_init_locations(&new_config.locations) {
                Err(e) => {
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
        if should_reload_server_location {
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
            return Ok(new_config);
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
        return Ok(new_config);
    }
    // restart mode
    // update current config to be hot reload config
    config_manager.set_current_config(hot_reload_config.clone());

    // diff hot reload config and new config
    let (_, new_config_result) = hot_reload_config.diff(&new_config);
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
    Ok(new_config)
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

        let mut observer = match self.config_manager.observe().await {
            Ok(observer) => observer,
            Err(e) => {
                error!(
                    target: LOG_TARGET,
                    error = %e,
                    "create storage observe fail"
                );
                return;
            },
        };

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    break;
                }
                _ = period.tick() => {
                    // fetch and diff update
                    // some change may be restart
                    if let Some(new_config) = run_diff_and_update_config(self.config_manager.clone(), self.only_hot_reload).await {
                        let new_level = new_config
                            .basic
                            .log_level
                            .clone()
                            .unwrap_or_default();
                        let current_level = self.current_log_level.load().to_string();
                        if current_level != new_level {
                            info!(
                                target: LOG_TARGET,
                                current_level, new_level, "reload log level"
                            );
                            if let Err(e) = self
                                .log_reload_handle
                                .modify(|filter| *filter = new_env_filter(&new_level))
                            {
                                error!(
                                    target: LOG_TARGET,
                                    error = %e,
                                    "reload log level fail"
                                )
                            }
                        }
                    }
                }
                result = observer.watch() => {
                    let delay = self.delay.load(Ordering::Relaxed);
                    match result {
                        Ok(updated)  => {
                            if delay > MIN_DELAY {
                                self.delay.store(MIN_DELAY, Ordering::Relaxed);
                            }
                            if !updated {
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
                            tokio::time::sleep(Duration::from_millis(delay as u64)).await;
                            if delay < MAX_DELAY {
                               self.delay.store(delay * 2, Ordering::Relaxed);
                            }
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
        Ok(new_config) => Some(new_config),
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
        // Calculate if this iteration should be hot reload only
        // Uses modulo arithmetic with restart_unit to create a pattern like:
        // [hot reload, hot reload, full restart, hot reload, hot reload, full restart]
        // This helps spread out potentially disruptive full restarts
        let hot_reload_only = if self.only_hot_reload {
            true
        } else if count > 0 && self.restart_unit > 1 {
            count % self.restart_unit != 0 // Only do full restart when count divides evenly
        } else {
            true
        };
        self.running_hot_reload
            .store(hot_reload_only, Ordering::Relaxed);
        if let Some(new_config) = run_diff_and_update_config(
            self.config_manager.clone(),
            hot_reload_only,
        )
        .await
        {
            let new_level =
                new_config.basic.log_level.clone().unwrap_or_default();
            let current_level = self.current_log_level.load().to_string();
            if current_level != new_level {
                info!(
                    target: LOG_TARGET,
                    current_level, new_level, "reload log level"
                );
                if let Err(e) = self
                    .log_reload_handle
                    .modify(|filter| *filter = new_env_filter(&new_level))
                {
                    error!(
                        target: LOG_TARGET,
                        error = %e,
                        "reload log level fail"
                    )
                }
            }
        }
        Ok(true)
    }
}
