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

use arc_swap::ArcSwap;
use async_trait::async_trait;
use pingap_config::BasicConf;
use pingap_core::{Notification, NotificationData, NotificationSender};
use pingap_webhook::WebhookNotificationSender;
use std::sync::{Arc, LazyLock};

/// The webhook in effect. Replaced as a whole when `webhook`, `webhook_type`
/// or `webhook_notifications` change, so a hot reload applies them.
static WEBHOOK: LazyLock<ArcSwap<WebhookNotificationSender>> =
    LazyLock::new(|| {
        ArcSwap::from_pointee(WebhookNotificationSender::new(
            String::new(),
            String::new(),
            vec![],
        ))
    });

/// What `get_webhook_sender` hands out. Upstreams, discovery and the
/// certificate checkers keep that `Arc` for as long as they live, so it cannot
/// be the webhook itself: this forwards each notification to whichever
/// webhook is in effect when it is sent.
struct CurrentWebhook;

#[async_trait]
impl Notification for CurrentWebhook {
    async fn notify(&self, data: NotificationData) {
        send_notification(data).await;
    }
}

static CURRENT_WEBHOOK: LazyLock<Arc<NotificationSender>> =
    LazyLock::new(|| Arc::new(Box::new(CurrentWebhook)));

/// Puts the webhook configured in `basic` into effect.
pub fn set_webhook_notification_sender(basic: &BasicConf) {
    WEBHOOK.store(Arc::new(WebhookNotificationSender::new(
        basic.webhook.clone().unwrap_or_default(),
        basic.webhook_type.clone().unwrap_or_default(),
        basic.webhook_notifications.clone().unwrap_or_default(),
    )));
}

/// Brings the webhook settings in `current` up to those in `new` and puts
/// them into effect. Returns `false`, changing nothing, if they already match.
pub fn reload_webhook_notification_sender(
    current: &mut BasicConf,
    new: &BasicConf,
) -> bool {
    if current.webhook == new.webhook
        && current.webhook_type == new.webhook_type
        && current.webhook_notifications == new.webhook_notifications
    {
        return false;
    }
    current.webhook.clone_from(&new.webhook);
    current.webhook_type.clone_from(&new.webhook_type);
    current
        .webhook_notifications
        .clone_from(&new.webhook_notifications);
    set_webhook_notification_sender(current);
    true
}

/// Always `Some`; the `Option` is what the consumers accept.
pub fn get_webhook_sender() -> Option<Arc<NotificationSender>> {
    Some(CURRENT_WEBHOOK.clone())
}

pub async fn send_notification(data: NotificationData) {
    // `load_full`, not `load`: a guard must not be held across the HTTP send.
    WEBHOOK.load_full().send_notification(data).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;

    /// A webhook endpoint that answers 200 and passes on each request body.
    async fn spawn_endpoint() -> (String, mpsc::UnboundedReceiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut request = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    request.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&request);
                    let Some((head, body)) = text.split_once("\r\n\r\n") else {
                        continue;
                    };
                    let content_length = head
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            if !name.eq_ignore_ascii_case("content-length") {
                                return None;
                            }
                            value.trim().parse::<usize>().ok()
                        })
                        .unwrap_or_default();
                    if body.len() >= content_length {
                        let _ = tx.send(body.to_string());
                        break;
                    }
                }
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
            }
        });
        (url, rx)
    }

    #[tokio::test]
    async fn test_reload_reaches_senders_handed_out_earlier() {
        let (url, mut bodies) = spawn_endpoint().await;
        let mut current = BasicConf {
            webhook: Some(url),
            webhook_notifications: Some(vec!["test_webhook_a".to_string()]),
            ..Default::default()
        };
        set_webhook_notification_sender(&current);
        // Taken before the reload, the way upstreams and discovery hold it.
        let sender = get_webhook_sender().unwrap();
        let notify = |category: &str| {
            sender.notify(NotificationData {
                category: category.to_string(),
                ..Default::default()
            })
        };

        // Not in the allow-list yet: nothing is posted.
        notify("test_webhook_b").await;
        assert_eq!(true, bodies.try_recv().is_err());

        let mut new = current.clone();
        new.webhook_notifications = Some(vec![
            "test_webhook_a".to_string(),
            "test_webhook_b".to_string(),
        ]);
        assert_eq!(
            true,
            reload_webhook_notification_sender(&mut current, &new)
        );
        assert_eq!(new.webhook_notifications, current.webhook_notifications);

        // The sender taken earlier now delivers the newly listed category.
        notify("test_webhook_b").await;
        let body = bodies.try_recv().expect("the category must be posted");
        assert_eq!(
            true,
            body.contains(r#""category":"test_webhook_b""#),
            "{body}"
        );

        // Nothing to do once the settings match.
        assert_eq!(
            false,
            reload_webhook_notification_sender(&mut current, &new)
        );
    }
}
