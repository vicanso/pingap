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

use crate::{config::get_app_name, state};
use log::{error, info};
use once_cell::sync::OnceCell;
use serde_json::{Map, Value};
use std::{fmt::Display, time::Duration};
use strum::EnumString;

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
    BackendUnhealthy,
    LetsEncrypt,
    DiffConfig,
    Restart,
    RestartFail,
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
}

pub fn send(params: SendNotificationParams) {
    info!(
        "Webhook notification, category:{}, message:{}",
        params.category, params.msg
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
            let ip = if let Ok(value) = local_ip_address::local_ip() {
                value.to_string()
            } else {
                "".to_string()
            };

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
                    >message: {}"###,
                    params.msg
                );
                match webhook_type.to_lowercase().as_str() {
                    "wecom" => {
                        let mut markdown_data = Map::new();
                        markdown_data.insert("content".to_string(), Value::String(content));
                        data.insert("msgtype".to_string(), Value::String("markdown".to_string()));
                        data.insert("markdown".to_string(), Value::Object(markdown_data));
                    }
                    "dingtalk" => {
                        let mut markdown_data = serde_json::Map::new();
                        markdown_data
                            .insert("title".to_string(), Value::String(category.to_string()));
                        markdown_data.insert("text".to_string(), Value::String(content));
                        data.insert("msgtype".to_string(), Value::String("markdown".to_string()));
                        data.insert("markdown".to_string(), Value::Object(markdown_data));
                    }
                    _ => {
                        data.insert("name".to_string(), Value::String(name));
                        data.insert("level".to_string(), Value::String(level.to_string()));
                        data.insert("hostname".to_string(), Value::String(hostname));
                        data.insert("ip".to_string(), Value::String(ip));
                        data.insert("category".to_string(), Value::String(category));
                        data.insert("message".to_string(), Value::String(params.msg));
                    }
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
                            info!("Send webhook success");
                        } else {
                            error!("Send webhook fail, status:{}", res.status());
                        }
                    }
                    Err(e) => {
                        error!("Send webhook fail, {e}");
                    }
                };
            };
            rt.block_on(send);
        }
    });
}
