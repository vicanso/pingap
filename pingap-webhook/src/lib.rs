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
    Notification, NotificationData, NotificationLevel, get_hostname,
};
use serde_json::{Map, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::time::Instant;
use tracing::{error, info};

pub static LOG_TARGET: &str = "pingap::webhook";

/// Notifications that arrive no more than this far apart are merged into one
/// post. Each one extends the wait, so a burst goes out once it has been quiet
/// for this long.
pub const DEFAULT_BATCH_WINDOW: Duration = Duration::from_secs(10);
/// At most this many notifications go into one post; the batch goes out as
/// soon as it is full.
pub const DEFAULT_BATCH_MAX_EVENTS: usize = 5;

/// Notifications waiting to be posted together.
struct Batch {
    events: Vec<NotificationData>,
    /// When the batch goes out unless another notification extends it.
    deadline: Instant,
    /// Lets the task waiting on this batch tell whether the pending batch is
    /// still the one it was started for.
    id: u64,
}

struct Inner {
    url: String,
    category: String,
    notifications: Vec<String>,
    window: Duration,
    max_events: usize,
    pending: Mutex<Option<Batch>>,
    next_batch_id: AtomicU64,
}

pub struct WebhookNotificationSender {
    inner: Arc<Inner>,
}

impl WebhookNotificationSender {
    /// Creates a sender that merges bursts with the default policy
    /// ([`DEFAULT_BATCH_WINDOW`], [`DEFAULT_BATCH_MAX_EVENTS`]).
    pub fn new(
        url: String,
        category: String,
        notifications: Vec<String>,
    ) -> Self {
        Self::build(
            url,
            category,
            notifications,
            DEFAULT_BATCH_WINDOW,
            DEFAULT_BATCH_MAX_EVENTS,
        )
    }

    /// Changes the batching policy: notifications no more than `window` apart
    /// are merged, at most `max_events` per post. A zero `window` or a
    /// `max_events` of at most one posts every notification on its own,
    /// before `send_notification` returns.
    pub fn with_batch(self, window: Duration, max_events: usize) -> Self {
        Self::build(
            self.inner.url.clone(),
            self.inner.category.clone(),
            self.inner.notifications.clone(),
            window,
            max_events,
        )
    }

    /// Posts the batch still being collected, if there is one, without
    /// waiting for the window. Meant for shutdown, so the notifications of
    /// the last few seconds do not go down with the process.
    pub async fn flush(&self) {
        let pending = self.inner.lock_pending().take();
        if let Some(batch) = pending {
            self.inner.post(batch.events).await;
        }
    }

    fn build(
        url: String,
        category: String,
        notifications: Vec<String>,
        window: Duration,
        max_events: usize,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                url,
                category,
                notifications,
                window,
                max_events,
                pending: Mutex::new(None),
                next_batch_id: AtomicU64::new(0),
            }),
        }
    }

    /// Sends a notification via configured webhook
    ///
    /// Formats and sends the notification based on the webhook type (wecom, dingtalk, etc).
    /// Will log success/failure and handle timeouts.
    ///
    /// Notifications close together in time are merged into one post (see
    /// [`WebhookNotificationSender::with_batch`]); a batched notification is
    /// posted later, from a background task.
    ///
    /// # Arguments
    /// * `params` - The notification parameters including category, level, message and optional remark
    pub async fn send_notification(&self, params: NotificationData) {
        info!(
            target: LOG_TARGET,
            notification = params.category,
            title = params.title,
            message = params.message,
            "webhook notification"
        );
        let inner = &self.inner;
        if inner.url.is_empty() {
            return;
        }
        let found = inner.notifications.contains(&params.category);
        if !found {
            return;
        }
        if inner.window.is_zero() || inner.max_events <= 1 {
            inner.post(vec![params]).await;
            return;
        }

        let full = {
            let mut pending = inner.lock_pending();
            let full = match pending.as_mut() {
                Some(batch) => {
                    batch.events.push(params);
                    batch.deadline = Instant::now() + inner.window;
                    batch.events.len() >= inner.max_events
                },
                None => {
                    let id =
                        inner.next_batch_id.fetch_add(1, Ordering::Relaxed);
                    *pending = Some(Batch {
                        events: vec![params],
                        deadline: Instant::now() + inner.window,
                        id,
                    });
                    tokio::spawn(flush_when_quiet(inner.clone(), id));
                    false
                },
            };
            // Taken under the same lock, so the task waiting on the batch
            // cannot flush it a second time.
            if full { pending.take() } else { None }
        };
        if let Some(batch) = full {
            let inner = inner.clone();
            tokio::spawn(async move { inner.post(batch.events).await });
        }
    }
}

/// Posts the batch `id` once it has been quiet for the window. Started when
/// the batch is created; if the batch fills up first it is posted from
/// `send_notification` and this finds nothing left to do.
async fn flush_when_quiet(inner: Arc<Inner>, id: u64) {
    enum Step {
        Wait(Instant),
        Flush(Vec<NotificationData>),
        Done,
    }
    let mut deadline = Instant::now() + inner.window;
    loop {
        tokio::time::sleep_until(deadline).await;
        let step = {
            let mut pending = inner.lock_pending();
            let current = match pending.as_ref() {
                Some(batch) if batch.id == id => Some(batch.deadline),
                _ => None,
            };
            match current {
                None => Step::Done,
                Some(until) if until > Instant::now() => Step::Wait(until),
                Some(_) => Step::Flush(
                    pending
                        .take()
                        .map(|batch| batch.events)
                        .unwrap_or_default(),
                ),
            }
        };
        match step {
            Step::Wait(until) => deadline = until,
            Step::Flush(events) => {
                inner.post(events).await;
                return;
            },
            Step::Done => return,
        }
    }
}

/// Folds a batch into the one notification that gets posted. A batch of one
/// is posted as it is, so nothing changes for a notification that arrived on
/// its own.
fn merge(mut events: Vec<NotificationData>) -> Option<NotificationData> {
    if events.len() <= 1 {
        return events.pop();
    }
    let level = events
        .iter()
        .map(|event| event.level)
        .max()
        .unwrap_or_default();
    let mut categories: Vec<&str> = vec![];
    for event in events.iter() {
        if !categories.contains(&event.category.as_str()) {
            categories.push(&event.category);
        }
    }
    let category = categories.join(",");
    let same_title = events.iter().all(|event| event.title == events[0].title);
    let title = if same_title {
        events[0].title.clone()
    } else {
        format!("{} notifications", events.len())
    };
    let message = events
        .iter()
        .enumerate()
        .map(|(index, event)| {
            let mut line = format!(
                "{}. [{}] {}: ",
                index + 1,
                event.level,
                event.category
            );
            if !same_title && !event.title.is_empty() {
                line.push_str(&event.title);
                line.push_str(" - ");
            }
            line.push_str(&event.message);
            line
        })
        .collect::<Vec<_>>()
        .join("\n");
    Some(NotificationData {
        category,
        level,
        title,
        message,
    })
}

impl Inner {
    fn lock_pending(&self) -> MutexGuard<'_, Option<Batch>> {
        // A panic while the lock was held cannot have left a half-updated
        // batch worth protecting: at worst a notification is posted twice.
        self.pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    async fn post(&self, events: Vec<NotificationData>) {
        let count = events.len();
        let Some(params) = merge(events) else {
            return;
        };
        let title = &params.title;
        let webhook_type = &self.category;
        let url = &self.url;
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
                    info!(target: LOG_TARGET, count, "send webhook success");
                } else {
                    error!(
                        target: LOG_TARGET,
                        count,
                        status = res.status().to_string(),
                        "send webhook fail"
                    );
                }
            },
            Err(e) => {
                error!(
                    target: LOG_TARGET,
                    count,
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

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;

    fn event(
        category: &str,
        level: NotificationLevel,
        title: &str,
        message: &str,
    ) -> NotificationData {
        NotificationData {
            category: category.to_string(),
            level,
            title: title.to_string(),
            message: message.to_string(),
        }
    }

    /// A webhook endpoint that answers 200 and passes on each posted body.
    async fn spawn_endpoint() -> (String, mpsc::UnboundedReceiver<Value>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let url = format!("http://{}/", listener.local_addr().expect("addr"));
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
                        if let Ok(value) = serde_json::from_str(body) {
                            let _ = tx.send(value);
                        }
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

    async fn next_body(rx: &mut mpsc::UnboundedReceiver<Value>) -> Value {
        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("a webhook must be posted")
            .expect("endpoint alive")
    }

    fn field<'a>(body: &'a Value, name: &str) -> &'a str {
        body[name].as_str().unwrap_or_default()
    }

    #[test]
    fn test_merge() {
        // One notification is posted untouched.
        let single = merge(vec![event(
            "backend_status",
            NotificationLevel::Info,
            "T",
            "m",
        )])
        .expect("kept");
        assert_eq!("backend_status", single.category);
        assert_eq!("T", single.title);
        assert_eq!("m", single.message);
        assert_eq!(true, merge(vec![]).is_none());

        // Same title: kept; the level is the highest; categories are
        // listed once each, in order of first appearance.
        let merged = merge(vec![
            event("backend_status", NotificationLevel::Info, "T", "m1"),
            event("backend_status", NotificationLevel::Error, "T", "m2"),
            event("upstream_status", NotificationLevel::Warn, "T", "m3"),
        ])
        .expect("merged");
        assert_eq!("backend_status,upstream_status", merged.category);
        assert_eq!(NotificationLevel::Error, merged.level);
        assert_eq!("T", merged.title);
        assert_eq!(
            "1. [info] backend_status: m1\n2. [error] backend_status: m2\n3. [warn] upstream_status: m3",
            merged.message
        );

        // Different titles: counted in the title, and each non-empty title
        // travels with its own line.
        let merged = merge(vec![
            event("reload_config", NotificationLevel::Info, "", "m1"),
            event("backend_status", NotificationLevel::Info, "Changed", "m2"),
        ])
        .expect("merged");
        assert_eq!("2 notifications", merged.title);
        assert_eq!(
            "1. [info] reload_config: m1\n2. [info] backend_status: Changed - m2",
            merged.message
        );
    }

    #[tokio::test]
    async fn test_burst_is_merged_into_one_post() {
        let (url, mut bodies) = spawn_endpoint().await;
        let sender = WebhookNotificationSender::new(
            url,
            "normal".to_string(),
            vec!["a".to_string(), "b".to_string()],
        )
        .with_batch(Duration::from_millis(300), 5);

        sender
            .send_notification(event("a", NotificationLevel::Info, "T", "m1"))
            .await;
        // Not in the allow-list: dropped before batching, so not counted.
        sender
            .send_notification(event("c", NotificationLevel::Error, "T", "m2"))
            .await;
        sender
            .send_notification(event("b", NotificationLevel::Warn, "T", "m3"))
            .await;
        // Nothing goes out while the batch is still collecting.
        assert_eq!(true, bodies.try_recv().is_err());

        let body = next_body(&mut bodies).await;
        assert_eq!("a,b", field(&body, "category"));
        assert_eq!("warn", field(&body, "level"));
        assert_eq!("1. [info] a: m1\n2. [warn] b: m3", field(&body, "message"));
        // And only once.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(true, bodies.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_full_batch_is_posted_at_once() {
        let (url, mut bodies) = spawn_endpoint().await;
        let sender = WebhookNotificationSender::new(
            url,
            "normal".to_string(),
            vec!["a".to_string()],
        )
        .with_batch(Duration::from_millis(300), 5);

        for index in 1..=6 {
            sender
                .send_notification(event(
                    "a",
                    NotificationLevel::Info,
                    "T",
                    &format!("m{index}"),
                ))
                .await;
        }
        // The first five go out as soon as the fifth arrives ...
        let body = next_body(&mut bodies).await;
        assert_eq!(
            "1. [info] a: m1\n2. [info] a: m2\n3. [info] a: m3\n4. [info] a: m4\n5. [info] a: m5",
            field(&body, "message")
        );
        // ... and the sixth starts a batch of its own, posted as a plain
        // notification once the window passes.
        let body = next_body(&mut bodies).await;
        assert_eq!("m6", field(&body, "message"));
    }

    #[tokio::test]
    async fn test_gap_longer_than_window_is_not_merged() {
        let (url, mut bodies) = spawn_endpoint().await;
        let sender = WebhookNotificationSender::new(
            url,
            "normal".to_string(),
            vec!["a".to_string()],
        )
        .with_batch(Duration::from_millis(200), 5);

        sender
            .send_notification(event("a", NotificationLevel::Info, "T", "m1"))
            .await;
        tokio::time::sleep(Duration::from_millis(400)).await;
        sender
            .send_notification(event("a", NotificationLevel::Info, "T", "m2"))
            .await;

        assert_eq!("m1", field(&next_body(&mut bodies).await, "message"));
        assert_eq!("m2", field(&next_body(&mut bodies).await, "message"));
    }

    #[tokio::test]
    async fn test_batching_disabled_posts_before_returning() {
        let (url, mut bodies) = spawn_endpoint().await;
        let sender = WebhookNotificationSender::new(
            url,
            "normal".to_string(),
            vec!["a".to_string()],
        )
        .with_batch(Duration::ZERO, 5);

        sender
            .send_notification(event("a", NotificationLevel::Info, "T", "m1"))
            .await;
        let body = bodies.try_recv().expect("posted inline");
        assert_eq!("m1", field(&body, "message"));
    }

    #[tokio::test]
    async fn test_flush_posts_the_pending_batch_now() {
        let (url, mut bodies) = spawn_endpoint().await;
        let sender = WebhookNotificationSender::new(
            url,
            "normal".to_string(),
            vec!["a".to_string()],
        )
        .with_batch(Duration::from_secs(10), 5);

        sender
            .send_notification(event("a", NotificationLevel::Info, "T", "m1"))
            .await;
        sender
            .send_notification(event("a", NotificationLevel::Warn, "T", "m2"))
            .await;
        assert_eq!(true, bodies.try_recv().is_err());

        // Flushing posts the batch before it returns, long before the window.
        sender.flush().await;
        let body = bodies.try_recv().expect("posted by flush");
        assert_eq!("1. [info] a: m1\n2. [warn] a: m2", field(&body, "message"));

        // Nothing left: a second flush posts nothing, and the task that was
        // waiting on the window finds nothing either.
        sender.flush().await;
        assert_eq!(true, bodies.try_recv().is_err());
    }
}
