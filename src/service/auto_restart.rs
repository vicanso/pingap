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
    get_config_path, get_current_config, load_config, set_current_config,
    PingapConf, CATEGORY_LOCATION, CATEGORY_UPSTREAM,
};
use crate::service::{CommonServiceTask, ServiceTask};
use crate::state::restart;
use crate::{proxy, webhook};
use async_trait::async_trait;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tracing::{debug, error, info};

async fn diff_config(
    hot_reload_only: bool,
    current_config: PingapConf,
    new_config: PingapConf,
) -> Result<(bool, Vec<String>, Option<PingapConf>), Box<dyn std::error::Error>>
{
    let mut new_config = new_config;
    let mut should_reload_server_location = false;
    // update the values which can be hot reload
    if hot_reload_only {
        let mut clone_conf = current_config.clone();
        // set server locations
        for (name, server) in new_config.servers.iter() {
            if let Some(clone_server_conf) = clone_conf.servers.get_mut(name) {
                if server.locations != clone_server_conf.locations {
                    clone_server_conf.locations.clone_from(&server.locations);
                    should_reload_server_location = true;
                }
            }
        }

        // set upstream and location value
        clone_conf.upstreams = new_config.upstreams;
        clone_conf.locations = new_config.locations;
        new_config = clone_conf;
    }

    let (updated_category_list, original_diff_result) =
        current_config.diff(&new_config);
    debug!("updated_category_list: {updated_category_list:?}, original_diff_result: {original_diff_result:?}");

    // no update date
    if original_diff_result.is_empty() {
        return Ok((false, vec![], None));
    }

    let mut should_reload_upstream = false;
    let mut should_reload_location = false;
    let mut should_restart = false;

    for category in updated_category_list {
        match category.as_str() {
            CATEGORY_LOCATION => should_reload_location = true,
            CATEGORY_UPSTREAM => should_reload_upstream = true,
            // other value is updated (not locations)
            _ => should_restart = true,
        };
    }

    if should_reload_upstream {
        match proxy::try_update_upstreams(&new_config.upstreams).await {
            Err(e) => {
                error!(error = e.to_string(), "reload upstream fail");
            },
            Ok(()) => {
                info!("reload upstream success");
            },
        };
    }
    if should_reload_location {
        match proxy::try_init_locations(&new_config.locations) {
            Err(e) => {
                error!(error = e.to_string(), "reload location fail");
            },
            Ok(()) => {
                info!("reload location success");
            },
        };
    }
    if should_reload_server_location {
        match proxy::try_init_server_locations(
            &new_config.servers,
            &new_config.locations,
        ) {
            Err(e) => {
                error!(error = e.to_string(), "reload server fail");
            },
            Ok(()) => {
                info!("reload server location success");
            },
        };
    }

    Ok((should_restart, original_diff_result, Some(new_config)))
}

async fn hot_reload(
    hot_reload_only: bool,
) -> Result<(bool, Vec<String>), Box<dyn std::error::Error>> {
    let new_config = load_config(&get_config_path(), false).await?;
    new_config.validate()?;
    let current_config: PingapConf = get_current_config().as_ref().clone();
    let (should_restart, diff_result, result) =
        diff_config(hot_reload_only, current_config, new_config).await?;
    if let Some(config) = result {
        debug!(config = format!("{config:?}"), "set new current config");
        set_current_config(&config);
    }
    Ok((should_restart, diff_result))
}

struct AutoRestart {
    restart_unit: u32,
    only_hot_reload: bool,
    count: AtomicU32,
}

pub fn new_auto_restart_service(
    interval: Duration,
    only_hot_reload: bool,
) -> CommonServiceTask {
    let mut restart_unit = 1_u32;
    let unit = Duration::from_secs(30);
    if interval > unit {
        restart_unit = (interval.as_secs() / unit.as_secs()) as u32;
    }

    CommonServiceTask::new(
        "Auto restart checker",
        interval.min(unit),
        AutoRestart {
            only_hot_reload,
            restart_unit,
            count: AtomicU32::new(0),
        },
    )
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
        match hot_reload(hot_reload_only).await {
            Ok((should_restart, diff_result)) => {
                let diff_result: Vec<_> = diff_result
                    .iter()
                    .filter(|item| !item.trim().is_empty())
                    .map(|item| item.to_string())
                    .collect();
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
                }
                if should_restart {
                    restart();
                }
            },
            Err(e) => {
                error!(error = e.to_string(), "auto restart validate fail");
            },
        }
        None
    }
    fn description(&self) -> String {
        "pingap will be restart if config changed".to_string()
    }
}
