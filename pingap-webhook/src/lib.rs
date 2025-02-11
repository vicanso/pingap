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
use once_cell::sync::{Lazy, OnceCell};
use pingap_core::{
    Notification, NotificationData, NotificationLevel, NotificationSender,
};
use serde_json::{Map, Value};
use std::sync::Arc;
use std::time::Duration;
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

static WEBHOOK_NOTIFICATION_SENDER: Lazy<Arc<NotificationSender>> =
    Lazy::new(|| Arc::new(Box::new(WebhookNotificationSender {})));

pub fn get_webhook_notification_sender() -> Arc<NotificationSender> {
    WEBHOOK_NOTIFICATION_SENDER.clone()
}

pub struct WebhookNotificationSender {}

#[async_trait]
impl Notification for WebhookNotificationSender {
    async fn notify(&self, data: NotificationData) {
        send_notification(data).await;
    }
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

/// Sends a notification via configured webhook
///
/// Formats and sends the notification based on the webhook type (wecom, dingtalk, etc).
/// Will log success/failure and handle timeouts.
///
/// # Arguments
/// * `params` - The notification parameters including category, level, message and optional remark
pub async fn send_notification(params: NotificationData) {
    info!(
        category = LOG_CATEGORY,
        notification = params.category,
        title = params.title,
        message = params.message,
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
    let ip = local_ip_list().join(";");

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
            >message: {}"###,
        params.message
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
            data.insert("message".to_string(), Value::String(params.message));
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

/// Returns a list of non-loopback IP addresses (both IPv4 and IPv6) for the local machine
///
/// # Returns
/// A vector of IP addresses as strings
fn local_ip_list() -> Vec<String> {
    let mut ip_list = vec![];

    if let Ok(value) = local_ip_address::local_ip() {
        ip_list.push(value);
    }
    if let Ok(value) = local_ip_address::local_ipv6() {
        ip_list.push(value);
    }

    ip_list
        .iter()
        .filter(|item| !item.is_loopback())
        .map(|item| item.to_string())
        .collect()
}
