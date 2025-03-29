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

use once_cell::sync::OnceCell;
use pingap_core::NotificationSender;
use pingap_webhook::WebhookNotificationSender;
use std::sync::Arc;

static WEBHOOK_NOTIFICATION_SENDER: OnceCell<Arc<NotificationSender>> =
    OnceCell::new();

pub fn init_webhook_notification_sender(
    url: String,
    category: String,
    notifications: Vec<String>,
) {
    let _ = WEBHOOK_NOTIFICATION_SENDER.set(Arc::new(Box::new(
        WebhookNotificationSender::new(url, category, notifications),
    )));
}

pub fn get_webhook_sender() -> Option<Arc<NotificationSender>> {
    WEBHOOK_NOTIFICATION_SENDER.get().cloned()
}
