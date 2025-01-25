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

use super::LOG_CATEGORY;
use crate::config::{
    get_config_storage, get_current_config, load_config, set_current_config,
    LoadConfigOptions, PingapConf, CATEGORY_CERTIFICATE, CATEGORY_LOCATION,
    CATEGORY_PLUGIN, CATEGORY_UPSTREAM,
};
use crate::service::{CommonServiceTask, ServiceTask};
use crate::state::restart;
use crate::{plugin, proxy, webhook};
use async_trait::async_trait;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, error, info};

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
    hot_reload_only: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let new_config = load_config(LoadConfigOptions {
        replace_include: true,
        ..Default::default()
    })
    .await?;
    new_config.validate()?;
    let current_config: PingapConf = get_current_config().as_ref().clone();

    let (updated_category_list, original_diff_result) =
        current_config.diff(&new_config);
    debug!(
        updated_category_list = updated_category_list.join(","),
        original_diff_result = original_diff_result.join("\n"),
        "current config diff from new config"
    );
    // no update config
    if original_diff_result.is_empty() {
        return Ok(());
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
                    if !exists_acme {
                        should_reload_certificate = true;
                    }
                },
                _ => {},
            };
        }

        let format_message = |name: &str, list: Vec<String>| -> String {
            if list.len() > 1 {
                return format!(
                    "{name}s({}) are created or updated",
                    list.join(",")
                );
            }
            format!("{name}({}) is created or updated", list.join(","))
        };

        if should_reload_upstream {
            match proxy::try_update_upstreams(&new_config.upstreams).await {
                Err(e) => {
                    let error = e.to_string();
                    reload_fail_messages
                        .push(format!("upstream reload fail: {error}"));
                    error!(error, "reload upstream fail");
                },
                Ok(updated_upstreams) => {
                    info!("reload upstream success");
                    webhook::send_notification(
                        webhook::SendNotificationParams {
                            category:
                                webhook::NotificationCategory::ReloadConfig,
                            level: webhook::NotificationLevel::Info,
                            msg: format_message("Upstream", updated_upstreams),
                            ..Default::default()
                        },
                    )
                    .await;
                },
            };
        }
        if should_reload_location {
            match proxy::try_init_locations(&new_config.locations) {
                Err(e) => {
                    let error = e.to_string();
                    reload_fail_messages
                        .push(format!("location reload fail: {error}",));
                    error!(error, "reload location fail");
                },
                Ok(updated_locations) => {
                    info!("reload location success");
                    webhook::send_notification(
                        webhook::SendNotificationParams {
                            category:
                                webhook::NotificationCategory::ReloadConfig,
                            level: webhook::NotificationLevel::Info,
                            msg: format_message("Location", updated_locations),
                            ..Default::default()
                        },
                    )
                    .await;
                },
            };
        }
        if should_reload_plugin {
            match plugin::try_init_plugins(&new_config.plugins) {
                Err(e) => {
                    let error = e.to_string();
                    reload_fail_messages
                        .push(format!("plugin reload fail: {error}"));
                    error!(error, "reload plugin fail");
                },
                Ok(updated_plugins) => {
                    info!("reload plugin success");
                    webhook::send_notification(
                        webhook::SendNotificationParams {
                            category:
                                webhook::NotificationCategory::ReloadConfig,
                            level: webhook::NotificationLevel::Info,
                            msg: format_message("Plugin", updated_plugins),
                            ..Default::default()
                        },
                    )
                    .await;
                },
            };
        }
        if should_reload_certificate {
            let (updated_certificates, errors) =
                proxy::try_update_certificates(&new_config.certificates);
            info!("reload certificate success");
            webhook::send_notification(webhook::SendNotificationParams {
                category: webhook::NotificationCategory::ReloadConfig,
                level: webhook::NotificationLevel::Info,
                msg: format_message("Certificate", updated_certificates),
                ..Default::default()
            })
            .await;
            if !errors.is_empty() {
                error!(error = errors, "parse certificate fail");
                webhook::send_notification(webhook::SendNotificationParams {
                    category:
                        webhook::NotificationCategory::ParseCertificateFail,
                    level: webhook::NotificationLevel::Error,
                    msg: errors,
                    remark: None,
                })
                .await;
            }
        }
        if should_reload_server_location {
            match proxy::try_init_server_locations(
                &new_config.servers,
                &new_config.locations,
            ) {
                Err(e) => {
                    let error = e.to_string();
                    reload_fail_messages
                        .push(format!("server reload fail: {error}"));
                    error!(error, "reload server fail");
                },
                Ok(updated_servers) => {
                    info!("reload server location success");
                    webhook::send_notification(
                        webhook::SendNotificationParams {
                            category:
                                webhook::NotificationCategory::ReloadConfig,
                            level: webhook::NotificationLevel::Info,
                            msg: format_message(
                                "Server Location",
                                updated_servers,
                            ),
                            ..Default::default()
                        },
                    )
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
            updated_category_list = updated_category_list.join(","),
            original_diff_result = original_diff_result.join("\n"),
            "current config diff from hot reload config"
        );
        // no update config
        if original_diff_result.is_empty() {
            return Ok(());
        }
        // update current config to be hot reload config
        set_current_config(&hot_reload_config);
        if !original_diff_result.is_empty() {
            webhook::send_notification(webhook::SendNotificationParams {
                category: webhook::NotificationCategory::DiffConfig,
                msg: original_diff_result.join("\n").trim().to_string(),
                ..Default::default()
            })
            .await;
            if !reload_fail_message.is_empty() {
                webhook::send_notification(webhook::SendNotificationParams {
                    category: webhook::NotificationCategory::ReloadConfigFail,
                    msg: reload_fail_message.clone(),
                    remark: Some("reload config fail".to_string()),
                    ..Default::default()
                })
                .await;
            }
        }
        return Ok(());
    }
    // restart mode
    // update current config to be hot reload config
    set_current_config(&hot_reload_config);

    // diff hot reload config and new config
    let (_, new_config_result) = hot_reload_config.diff(&new_config);
    debug!(
        new_config_result = new_config_result.join("\n"),
        "hot reload config diff from new config"
    );

    let mut should_restart = true;
    // no update other config update except hot reload config
    if new_config_result.is_empty() {
        should_restart = false;
    }

    if !original_diff_result.is_empty() {
        webhook::send_notification(webhook::SendNotificationParams {
            category: webhook::NotificationCategory::DiffConfig,
            msg: original_diff_result.join("\n").trim().to_string(),
            ..Default::default()
        })
        .await;
        if !reload_fail_message.is_empty() {
            webhook::send_notification(webhook::SendNotificationParams {
                category: webhook::NotificationCategory::ReloadConfigFail,
                msg: reload_fail_message.clone(),
                remark: Some("reload config fail".to_string()),
                ..Default::default()
            })
            .await;
        }
    }
    if should_restart {
        restart().await;
    }
    Ok(())
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
    /// Counter for tracking intervals
    count: AtomicU32,
}

/// Creates a new auto-restart service that checks for config changes periodically
pub fn new_auto_restart_service(
    interval: Duration,
    only_hot_reload: bool,
) -> CommonServiceTask {
    let mut restart_unit = 1_u32;
    let unit = Duration::from_secs(10);
    if interval > unit {
        restart_unit = (interval.as_secs() / unit.as_secs()) as u32;
    }

    CommonServiceTask::new(
        interval.min(unit),
        AutoRestart {
            running_hot_reload: AtomicBool::new(false),
            only_hot_reload,
            restart_unit,
            count: AtomicU32::new(0),
        },
    )
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
    /// How often to check for changes
    interval: Duration,
    /// If true, only perform hot reloads when changes detected
    only_hot_reload: bool,
}

pub fn new_observer_service(
    interval: Duration,
    only_hot_reload: bool,
) -> ConfigObserverService {
    ConfigObserverService {
        interval,
        only_hot_reload,
    }
}

static OBSERVER_NAME: &str = "configObserver";

#[async_trait]
impl BackgroundService for ConfigObserverService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let Some(storage) = get_config_storage() else {
            return;
        };
        let period_human: humantime::Duration = self.interval.into();

        info!(
            category = LOG_CATEGORY,
            name = OBSERVER_NAME,
            interval = period_human.to_string(),
            "background service is running",
        );
        let mut period = interval(self.interval);

        let result = storage.observe().await;
        if let Err(e) = result {
            error!(error = e.to_string(), "create storage observe fail");
            return;
        }

        let mut observer = result.unwrap();

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    break;
                }
                _ = period.tick() => {
                    // fetch and diff update
                    // some change may be restart
                    run_diff_and_update_config(self.only_hot_reload).await;
                }
                result = observer.watch() => {
                    match result {
                       Ok(updated)  => {
                           if !updated {
                               continue
                           }
                           // only hot reload for observe updated
                           run_diff_and_update_config(true).await;
                       },
                       Err(e) => {
                           error!(error = e.to_string(), "observe updated fail");
                       }
                    }
                }
            }
        }
    }
}

/// Helper function to run the config diff and update process
/// Logs any errors that occur during the update
async fn run_diff_and_update_config(hot_reload_only: bool) {
    if let Err(e) = diff_and_update_config(hot_reload_only).await {
        error!(
            category = LOG_CATEGORY,
            error = e.to_string(),
            name = OBSERVER_NAME,
            "update config fail",
        )
    }
}

#[async_trait]
impl ServiceTask for AutoRestart {
    async fn run(&self) -> Option<bool> {
        // Calculate if this iteration should be hot reload only
        // Uses modulo arithmetic with restart_unit to create a pattern like:
        // [hot reload, hot reload, full restart, hot reload, hot reload, full restart]
        // This helps spread out potentially disruptive full restarts
        let count = self.count.fetch_add(1, Ordering::Relaxed);
        let hot_reload_only = if self.only_hot_reload {
            true
        } else if count > 0 && self.restart_unit > 1 {
            count % self.restart_unit != 0 // Only do full restart when count divides evenly
        } else {
            true
        };
        self.running_hot_reload
            .store(hot_reload_only, Ordering::Relaxed);
        run_diff_and_update_config(hot_reload_only).await;
        None
    }
    fn description(&self) -> String {
        if self.running_hot_reload.load(Ordering::Relaxed) {
            "hot reload detector".to_string()
        } else {
            "restart detector".to_string()
        }
    }
}
