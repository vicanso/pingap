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
use pingap_core::{
    get_hostname, Notification, NotificationData, NotificationLevel,
};
use serde_json::{Map, Value};
use std::time::Duration;
use tracing::{error, info};

pub const LOG_CATEGORY: &str = "webhook";

pub struct WebhookNotificationSender {
    url: String,
    category: String,
    notifications: Vec<String>,
}

impl WebhookNotificationSender {
    pub fn new(
        url: String,
        category: String,
        notifications: Vec<String>,
    ) -> Self {
        Self {
            url,
            category,
            notifications,
        }
    }

    /// Sends a notification via configured webhook
    ///
    /// Formats and sends the notification based on the webhook type (wecom, dingtalk, etc).
    /// Will log success/failure and handle timeouts.
    ///
    /// # Arguments
    /// * `params` - The notification parameters including category, level, message and optional remark
    pub async fn send_notification(&self, params: NotificationData) {
        let title = &params.title;
        info!(
            category = LOG_CATEGORY,
            notification = params.category,
            title,
            message = params.message,
            "webhook notification"
        );
        let webhook_type = &self.category;
        let url = &self.url;
        if url.is_empty() {
            return;
        }
        let found = self.notifications.contains(&params.category.to_string());
        if !found {
            return;
        }
        let category = params.category.to_string();
        let level = params.level;
        let ip = local_ip_list().join(";");

        let client = reqwest::Client::new();
        let mut data = serde_json::Map::new();
        let hostname = get_hostname();
        // TODO get app name from config
        let name = "pingap".to_string();
        let color_type = match level {
            NotificationLevel::Error => "warning",
            NotificationLevel::Warn => "warning",
            _ => "comment",
        };
        let content = format!(
            r###" <font color="{color_type}">{name}({level})</font>
                >title: {title}
                >hostname: {hostname}
                >ip: {ip}
                >category: {category}
                >message: {}"###,
            params.message
        );
        match webhook_type.to_lowercase().as_str() {
            "wecom" => {
                let mut markdown_data = Map::new();
                markdown_data
                    .insert("content".to_string(), Value::String(content));
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
                    Value::String(hostname.to_string()),
                );
                data.insert("ip".to_string(), Value::String(ip));
                data.insert("category".to_string(), Value::String(category));
                data.insert(
                    "message".to_string(),
                    Value::String(params.message),
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
}

#[async_trait]
impl Notification for WebhookNotificationSender {
    async fn notify(&self, data: NotificationData) {
        self.send_notification(data).await;
    }
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
