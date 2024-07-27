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

use crate::util;
use crate::{config::get_app_name, state};
use once_cell::sync::OnceCell;
use serde_json::{Map, Value};
use std::{fmt::Display, time::Duration};
use strum::EnumString;
use tracing::{error, info};

static WEBHOOK_URL: OnceCell<String> = OnceCell::new();
static WEBHOOK_CATEGORY: OnceCell<String> = OnceCell::new();
static WEBHOOK_NOTIFICATIONS: OnceCell<Vec<String>> = OnceCell::new();
pub fn set_web_hook(url: &str, category: &str, notifications: &[String]) {
    WEBHOOK_URL.get_or_init(|| url.to_string());
    WEBHOOK_CATEGORY.get_or_init(|| category.to_string());
    WEBHOOK_NOTIFICATIONS.get_or_init(|| notifications.to_owned());
}

pub enum NotificationLevel {
    Info,
    Warn,
    Error,
}

#[derive(PartialEq, Debug, Clone, EnumString, strum::Display)]
#[strum(serialize_all = "snake_case")]
pub enum NotificationCategory {
    BackendStatus,
    DifferentBackends,
    LetsEncrypt,
    DiffConfig,
    Restart,
    RestartFail,
    TlsValidity,
    ParseCertificateFail,
    ServiceDiscoverFail,
}

impl Display for NotificationLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            NotificationLevel::Error => "error",
            NotificationLevel::Warn => "warn",
            _ => "info",
        };
        write!(f, "{msg}")
    }
}

pub struct SendNotificationParams {
    pub category: NotificationCategory,
    pub level: NotificationLevel,
    pub msg: String,
    pub remark: Option<String>,
}

pub fn send(params: SendNotificationParams) {
    info!(
        category = params.category.to_string(),
        message = params.msg,
        "webhook notification"
    );
    let webhook_type = if let Some(value) = WEBHOOK_CATEGORY.get() {
        value.to_string()
    } else {
        "".to_string()
    };
    let url = if let Some(url) = WEBHOOK_URL.get() {
        url.to_string()
    } else {
        "".to_string()
    };
    if url.is_empty() {
        return;
    }
    let found = WEBHOOK_NOTIFICATIONS
        .get()
        .map(|arr| arr.contains(&params.category.to_string()));
    if !found.unwrap_or_default() {
        return;
    }
    std::thread::spawn(move || {
        if let Ok(rt) = tokio::runtime::Runtime::new() {
            let category = params.category.to_string();
            let level = params.level;
            let ip = util::local_ip_list().join(";");
            let remark = params.remark.unwrap_or_default();

            let send = async move {
                let client = reqwest::Client::new();
                let mut data = serde_json::Map::new();
                let hostname = state::get_hostname().clone();
                let name = get_app_name();
                let color_type = match level {
                    NotificationLevel::Error => "error",
                    NotificationLevel::Warn => "warning",
                    _ => "comment",
                };
                let content = format!(
                    r###" <font color="{color_type}">{name}({level})</font>
                    >hostname: {hostname}
                    >ip: {ip}
                    >category: {category}
                    >message: {}
                    >remark: {remark}"###,
                    params.msg
                );
                match webhook_type.to_lowercase().as_str() {
                    "wecom" => {
                        let mut markdown_data = Map::new();
                        markdown_data.insert(
                            "content".to_string(),
                            Value::String(content),
                        );
                        data.insert(
                            "msgtype".to_string(),
                            Value::String("markdown".to_string()),
                        );
                        data.insert(
                            "markdown".to_string(),
                            Value::Object(markdown_data),
                        );
                    },
                    "dingtalk" => {
                        let mut markdown_data = serde_json::Map::new();
                        markdown_data.insert(
                            "title".to_string(),
                            Value::String(category.to_string()),
                        );
                        markdown_data
                            .insert("text".to_string(), Value::String(content));
                        data.insert(
                            "msgtype".to_string(),
                            Value::String("markdown".to_string()),
                        );
                        data.insert(
                            "markdown".to_string(),
                            Value::Object(markdown_data),
                        );
                    },
                    _ => {
                        data.insert("name".to_string(), Value::String(name));
                        data.insert(
                            "level".to_string(),
                            Value::String(level.to_string()),
                        );
                        data.insert(
                            "hostname".to_string(),
                            Value::String(hostname),
                        );
                        data.insert("ip".to_string(), Value::String(ip));
                        data.insert(
                            "category".to_string(),
                            Value::String(category),
                        );
                        data.insert(
                            "message".to_string(),
                            Value::String(params.msg),
                        );
                    },
                }

                match client
                    .post(url)
                    .json(&data)
                    .timeout(Duration::from_secs(30))
                    .send()
                    .await
                {
                    Ok(res) => {
                        if res.status().as_u16() < 400 {
                            info!("send webhook success");
                        } else {
                            error!(
                                status = res.status().to_string(),
                                "send webhook fail"
                            );
                        }
                    },
                    Err(e) => {
                        error!(error = e.to_string(), "send webhook fail");
                    },
                };
            };
            rt.block_on(send);
        }
    });
}
