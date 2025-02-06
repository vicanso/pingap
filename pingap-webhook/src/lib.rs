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

use async_trait::async_trait;
use once_cell::sync::OnceCell;
use pingora::lb::health_check::HealthObserve;
use pingora::lb::Backend;
use serde_json::{Map, Value};
use std::{fmt::Display, time::Duration};
use strum::EnumString;
use tracing::{error, info};

static WEBHOOK_URL: OnceCell<String> = OnceCell::new();
static WEBHOOK_CATEGORY: OnceCell<String> = OnceCell::new();
static WEBHOOK_NOTIFICATIONS: OnceCell<Vec<String>> = OnceCell::new();

pub const LOG_CATEGORY: &str = "webhook";

/// Sets the webhook configuration parameters
///
/// # Arguments
/// * `url` - The webhook endpoint URL
/// * `category` - The webhook category/type (e.g. "wecom", "dingtalk")
/// * `notifications` - List of notification categories to enable
pub fn set_web_hook(url: &str, category: &str, notifications: &[String]) {
    WEBHOOK_URL.get_or_init(|| url.to_string());
    WEBHOOK_CATEGORY.get_or_init(|| category.to_string());
    WEBHOOK_NOTIFICATIONS.get_or_init(|| notifications.to_owned());
}

#[derive(Default)]
pub enum NotificationLevel {
    #[default]
    Info,
    Warn,
    Error,
}

#[derive(PartialEq, Debug, Clone, EnumString, strum::Display, Default)]
#[strum(serialize_all = "snake_case")]
pub enum NotificationCategory {
    #[default]
    BackendStatus,
    LetsEncrypt,
    DiffConfig,
    Restart,
    RestartFail,
    ReloadConfig,
    ReloadConfigFail,
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

pub struct BackendObserveNotification {
    name: String,
}

#[async_trait]
impl HealthObserve for BackendObserveNotification {
    async fn observe(&self, backend: &Backend, healthy: bool) {
        let addr = backend.addr.to_string();
        let template = format!("upstream {}({addr}) becomes ", self.name);
        let info = if healthy {
            (NotificationLevel::Info, template + "healthy")
        } else {
            (NotificationLevel::Error, template + "unhealthy")
        };
        send_notification(SendNotificationParams {
            category: NotificationCategory::BackendStatus,
            level: info.0,
            msg: info.1,
            ..Default::default()
        })
        .await;
    }
}

/// Creates a new backend health observation notification handler
///
/// # Arguments
/// * `name` - Name of the backend service to monitor
pub fn new_backend_observe_notification(
    name: &str,
) -> Box<BackendObserveNotification> {
    Box::new(BackendObserveNotification {
        name: name.to_string(),
    })
}

/// Parameters for sending a notification
#[derive(Default)]
pub struct SendNotificationParams {
    pub category: NotificationCategory,
    pub level: NotificationLevel,
    pub msg: String,
    pub remark: Option<String>,
}

/// Sends a notification via configured webhook
///
/// Formats and sends the notification based on the webhook type (wecom, dingtalk, etc).
/// Will log success/failure and handle timeouts.
///
/// # Arguments
/// * `params` - The notification parameters including category, level, message and optional remark
pub async fn send_notification(params: SendNotificationParams) {
    info!(
        category = LOG_CATEGORY,
        notification = params.category.to_string(),
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
    let category = params.category.to_string();
    let level = params.level;
    let ip = pingap_util::local_ip_list().join(";");
    let remark = params.remark.unwrap_or_default();

    let client = reqwest::Client::new();
    let mut data = serde_json::Map::new();
    let hostname = hostname::get()
        .unwrap_or_default()
        .to_str()
        .unwrap_or_default()
        .to_string();
    // TODO get app name from config
    let name = "pingap".to_string();
    let color_type = match level {
        NotificationLevel::Error => "warning",
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
            markdown_data.insert("content".to_string(), Value::String(content));
            data.insert(
                "msgtype".to_string(),
                Value::String("markdown".to_string()),
            );
            data.insert("markdown".to_string(), Value::Object(markdown_data));
        },
        "dingtalk" => {
            let mut markdown_data = serde_json::Map::new();
            markdown_data.insert(
                "title".to_string(),
                Value::String(category.to_string()),
            );
            markdown_data.insert("text".to_string(), Value::String(content));
            data.insert(
                "msgtype".to_string(),
                Value::String("markdown".to_string()),
            );
            data.insert("markdown".to_string(), Value::Object(markdown_data));
        },
        _ => {
            data.insert("name".to_string(), Value::String(name));
            data.insert("level".to_string(), Value::String(level.to_string()));
            data.insert(
                "hostname".to_string(),
                Value::String(hostname.to_string()),
            );
            data.insert("ip".to_string(), Value::String(ip));
            data.insert("category".to_string(), Value::String(category));
            data.insert("message".to_string(), Value::String(params.msg));
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
                info!(category = LOG_CATEGORY, "send webhook success");
            } else {
                error!(
                    category = LOG_CATEGORY,
                    status = res.status().to_string(),
                    "send webhook fail"
                );
            }
        },
        Err(e) => {
            error!(
                category = LOG_CATEGORY,
                error = %e,
                "send webhook fail"
            );
        },
    };
}
