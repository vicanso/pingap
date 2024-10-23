// Copyright 2024 Tree xie.
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

use crate::config::{
    get_config_storage, get_current_config, load_config, set_current_config,
    PingapConf, CATEGORY_CERTIFICATE, CATEGORY_LOCATION, CATEGORY_PLUGIN,
    CATEGORY_UPSTREAM,
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

async fn diff_and_update_config(
    hot_reload_only: bool,
) -> Result<(bool, Vec<String>, String), Box<dyn std::error::Error>> {
    let new_config = load_config(true, false).await?;
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
        return Ok((false, vec![], "".to_string()));
    }

    let mut reload_fail_messages = vec![];
    let mut hot_realod_config = current_config.clone();
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
                hot_realod_config.servers.get_mut(name)
            {
                if server.locations != clone_server_conf.locations {
                    clone_server_conf.locations.clone_from(&server.locations);
                    should_reload_server_location = true;
                }
            }
        }

        // set upstream, location and plugin value
        hot_realod_config.upstreams = new_config.upstreams.clone();
        hot_realod_config.locations = new_config.locations.clone();
        hot_realod_config.plugins = new_config.plugins.clone();

        // acem will create a let's encrypt service
        // so it can't be reloaded.
        let mut exists_acme = false;
        for (_, cert) in new_config.certificates.iter() {
            if cert.acme.is_some() {
                exists_acme = true;
            }
        }
        if !exists_acme {
            hot_realod_config.certificates = new_config.certificates.clone();
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
                    webhook::send(webhook::SendNotificationParams {
                        category: webhook::NotificationCategory::ReloadConfig,
                        level: webhook::NotificationLevel::Info,
                        msg: format_message("Upstream", updated_upstreams),
                        ..Default::default()
                    });
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
                    webhook::send(webhook::SendNotificationParams {
                        category: webhook::NotificationCategory::ReloadConfig,
                        level: webhook::NotificationLevel::Info,
                        msg: format_message("Location", updated_locations),
                        ..Default::default()
                    });
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
                    webhook::send(webhook::SendNotificationParams {
                        category: webhook::NotificationCategory::ReloadConfig,
                        level: webhook::NotificationLevel::Info,
                        msg: format_message("Plugin", updated_plugins),
                        ..Default::default()
                    });
                },
            };
        }
        if should_reload_certificate {
            let updated_certificates =
                proxy::init_certificates(&new_config.certificates);
            info!("reload certificate success");
            webhook::send(webhook::SendNotificationParams {
                category: webhook::NotificationCategory::ReloadConfig,
                level: webhook::NotificationLevel::Info,
                msg: format_message("Certificate", updated_certificates),
                ..Default::default()
            });
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
                    webhook::send(webhook::SendNotificationParams {
                        category: webhook::NotificationCategory::ReloadConfig,
                        level: webhook::NotificationLevel::Info,
                        msg: format_message("Server Location", updated_servers),
                        ..Default::default()
                    });
                },
            };
        }
    }

    let reload_fail_message = reload_fail_messages.join(";");

    if hot_reload_only {
        let (updated_category_list, original_diff_result) =
            current_config.diff(&hot_realod_config);
        debug!(
            updated_category_list = updated_category_list.join(","),
            original_diff_result = original_diff_result.join("\n"),
            "current config diff from hot realod config"
        );
        // no update config
        if original_diff_result.is_empty() {
            return Ok((false, vec![], reload_fail_message));
        }
        // update current config to be hot reload config
        set_current_config(&hot_realod_config);
        return Ok((false, original_diff_result, reload_fail_message));
    }
    // restart mode
    // update current config to be hot reload config
    set_current_config(&hot_realod_config);

    // diff hot reload config and new config
    let (_, new_config_result) = hot_realod_config.diff(&new_config);
    debug!(
        new_config_result = new_config_result.join("\n"),
        "hot reload config diff from new config"
    );

    let mut should_restart = true;
    // no update other config update except hot reload config
    if new_config_result.is_empty() {
        should_restart = false;
    }

    Ok((should_restart, original_diff_result, reload_fail_message))
}

struct AutoRestart {
    restart_unit: u32,
    only_hot_reload: bool,
    running_hot_reload: AtomicBool,
    count: AtomicU32,
}

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
        "Auto restart detector",
        interval.min(unit),
        AutoRestart {
            running_hot_reload: AtomicBool::new(false),
            only_hot_reload,
            restart_unit,
            count: AtomicU32::new(0),
        },
    )
}

pub struct ConfigObserverService {
    interval: Duration,
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

#[async_trait]
impl BackgroundService for ConfigObserverService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let Some(storage) = get_config_storage() else {
            return;
        };
        let period_human: humantime::Duration = self.interval.into();

        info!(
            name = "Config observer",
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
                // 逻辑并不完善，有可能因为变更处理中途又发生其它变更导致缺失
                // 因此还需配合fetch的形式比对
                _ = period.tick() => {
                    // fetch and diff update
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

async fn run_diff_and_update_config(hot_reload_only: bool) {
    match diff_and_update_config(hot_reload_only).await {
        Ok((should_restart, diff_result, reload_fail_message)) => {
            if !diff_result.is_empty() {
                // add more message for auto reload
                let remark = if !should_restart {
                    "Configuration has been hot reloaded".to_string()
                } else {
                    "Pingap will restart due to configuration updates"
                        .to_string()
                };
                webhook::send(webhook::SendNotificationParams {
                    category: webhook::NotificationCategory::DiffConfig,
                    msg: diff_result.join("\n").trim().to_string(),
                    remark: Some(remark),
                    ..Default::default()
                });
                if !reload_fail_message.is_empty() {
                    webhook::send(webhook::SendNotificationParams {
                        category:
                            webhook::NotificationCategory::ReloadConfigFail,
                        msg: reload_fail_message,
                        remark: Some("reload config fail".to_string()),
                        ..Default::default()
                    });
                }
            }

            if should_restart {
                restart();
            }
        },
        Err(e) => {
            error!(error = e.to_string(), "auto restart validate fail");
        },
    }
}

#[async_trait]
impl ServiceTask for AutoRestart {
    async fn run(&self) -> Option<bool> {
        let count = self.count.fetch_add(1, Ordering::Relaxed);
        let hot_reload_only = if self.only_hot_reload {
            true
        } else if count > 0 && self.restart_unit > 1 {
            count % self.restart_unit != 0
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
            "configuration hot reload detect".to_string()
        } else {
            "configuration restart detect".to_string()
        }
    }
}
