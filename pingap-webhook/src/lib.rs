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
use base64::{Engine, engine::general_purpose::STANDARD};
use pingap_core::{
    Notification, NotificationData, NotificationLevel, get_hostname,
    parse_notification_headers, parse_notification_level,
    parse_notification_retries,
};
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use serde_json::{Map, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::time::Instant;
use tracing::{error, info, warn};

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

/// What a webhook does beyond posting each notification to its url.
#[derive(Clone, Debug, Default)]
pub struct WebhookOptions {
    /// Notifications below this level are not sent.
    pub min_level: NotificationLevel,
    /// Headers of the request, beyond those it has anyway: the token a
    /// receiver asks for.
    pub headers: Vec<(HeaderName, HeaderValue)>,
    /// What a post is signed with. For `dingtalk` it is the secret of a
    /// robot with signing on, and adds `timestamp` and `sign` to the
    /// url. For a receiver of its own (any type but the two chats) the
    /// body is signed: `X-Pingap-Signature: sha256=<hex>`, the
    /// HMAC-SHA256 of the body under the secret.
    pub secret: Option<String>,
    /// The text of the message in place of the built-in one, with
    /// `{{name}}`, `{{level}}`, `{{title}}`, `{{hostname}}`, `{{ip}}`,
    /// `{{category}}`, `{{message}}` and `{{count}}` in it. For the two
    /// chats it is the markdown that is shown. For a receiver of its own
    /// it is the whole body, and what is put into it is escaped as the
    /// text of a JSON string.
    pub template: Option<String>,
    /// How many times a post that failed is tried again: one that was
    /// not answered, or answered with a `5xx` or a `429`.
    pub retries: u32,
}

impl WebhookOptions {
    /// The options as the configuration has them: `min_level` is `info`,
    /// `warn` or `error`, and each of `headers` is `Name: value`. An
    /// error says which of them is not that.
    pub fn parse(
        min_level: Option<&str>,
        headers: &[String],
        secret: Option<&str>,
        template: Option<&str>,
        retries: Option<u32>,
    ) -> Result<Self, String> {
        let min_level = parse_notification_level(min_level)?;
        let parsed = parse_notification_headers(headers)?;
        let retries = parse_notification_retries(retries)?;
        Ok(Self {
            min_level,
            headers: parsed,
            secret: secret
                .map(str::trim)
                .filter(|secret| !secret.is_empty())
                .map(str::to_string),
            template: template
                .filter(|template| !template.trim().is_empty())
                .map(str::to_string),
            retries,
        })
    }
}

struct Inner {
    url: String,
    category: String,
    notifications: Vec<String>,
    options: WebhookOptions,
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
            WebhookOptions::default(),
            DEFAULT_BATCH_WINDOW,
            DEFAULT_BATCH_MAX_EVENTS,
        )
    }

    /// Sets what the webhook does beyond posting: see [`WebhookOptions`].
    pub fn with_options(self, options: WebhookOptions) -> Self {
        Self::build(
            self.inner.url.clone(),
            self.inner.category.clone(),
            self.inner.notifications.clone(),
            options,
            self.inner.window,
            self.inner.max_events,
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
            self.inner.options.clone(),
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
        options: WebhookOptions,
        window: Duration,
        max_events: usize,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                url,
                category,
                notifications,
                options,
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
        if !found || params.level < inner.options.min_level {
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

    async fn post(self: &Arc<Self>, events: Vec<NotificationData>) {
        let count = events.len();
        let Some(params) = merge(events) else {
            return;
        };
        let message = Message {
            // TODO get app name from config
            name: "pingap".to_string(),
            level: params.level,
            title: params.title,
            hostname: get_hostname().to_string(),
            ip: local_ip_list().join(";"),
            category: params.category,
            message: params.message,
            count,
        };
        let kind = Kind::of(&self.category);
        let body = message.body(kind, self.options.template.as_deref());
        let client = reqwest::Client::new();
        let Some(reason) = self.try_post(&client, kind, &body, count, 0).await
        else {
            return;
        };
        // Said here, before the tries that follow are handed to a task
        // of their own: at a fast exit that task never runs, and a last
        // post that failed left no line at all.
        let mut delay = retry_delay(1);
        warn!(
            target: LOG_TARGET,
            count,
            reason,
            retry_in = ?delay,
            "send webhook fail, it is tried again"
        );
        // Whoever raised the notification - a health check, a reload,
        // the shutdown that posts the last batch - is not held up for
        // the minutes the tries may take.
        let inner = self.clone();
        tokio::spawn(async move {
            let mut tried = 1;
            loop {
                tokio::time::sleep(delay).await;
                let Some(reason) =
                    inner.try_post(&client, kind, &body, count, tried).await
                else {
                    return;
                };
                tried += 1;
                delay = retry_delay(tried);
                warn!(
                    target: LOG_TARGET,
                    count,
                    reason,
                    retry_in = ?delay,
                    "send webhook fail, it is tried again"
                );
            }
        });
    }

    /// One try at a post, the `tried`th after the first. `None` when
    /// there is no more to do, which is said in the log: it was sent, it
    /// was refused, or it failed for the last time. Why it failed, when
    /// it is to be tried again.
    async fn try_post(
        &self,
        client: &reqwest::Client,
        kind: Kind,
        body: &str,
        count: usize,
        tried: u32,
    ) -> Option<String> {
        match self.post_once(client, kind, body).await {
            Outcome::Sent => {
                info!(target: LOG_TARGET, count, "send webhook success");
                None
            },
            // Asking again gets the same answer.
            Outcome::Refused(reason) => {
                error!(target: LOG_TARGET, count, reason, "send webhook fail");
                None
            },
            Outcome::Failed(reason) if tried >= self.options.retries => {
                error!(
                    target: LOG_TARGET,
                    count,
                    reason,
                    tried,
                    "send webhook fail"
                );
                None
            },
            Outcome::Failed(reason) => Some(reason),
        }
    }

    /// The url of one post: for a `dingtalk` robot that asks for signed
    /// posts, with the time and the signature of that time.
    fn post_url(&self, kind: Kind, now_ms: u128) -> String {
        let Some(secret) = self
            .options
            .secret
            .as_deref()
            .filter(|_| kind == Kind::DingTalk)
        else {
            return self.url.clone();
        };
        let sign = STANDARD.encode(hmac_sha256::HMAC::mac(
            format!("{now_ms}\n{secret}"),
            secret,
        ));
        match reqwest::Url::parse(&self.url) {
            Ok(mut url) => {
                url.query_pairs_mut()
                    .append_pair("timestamp", &now_ms.to_string())
                    .append_pair("sign", &sign);
                url.to_string()
            },
            // Left to fail where it is sent, with what is wrong with it.
            Err(_) => self.url.clone(),
        }
    }

    async fn post_once(
        &self,
        client: &reqwest::Client,
        kind: Kind,
        body: &str,
    ) -> Outcome {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let mut headers = HeaderMap::new();
        headers
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if kind == Kind::Other
            && let Some(secret) = &self.options.secret
        {
            let signature = hmac_sha256::HMAC::mac(body, secret)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            if let Ok(value) =
                HeaderValue::from_str(&format!("sha256={signature}"))
            {
                headers.insert("x-pingap-signature", value);
            }
        }
        // Last, so that what is configured has the last word, on the
        // type of the body as well.
        for (name, value) in self.options.headers.iter() {
            headers.insert(name.clone(), value.clone());
        }
        let result = client
            .post(self.post_url(kind, now_ms))
            .headers(headers)
            .body(body.to_string())
            .timeout(Duration::from_secs(30))
            .send()
            .await;
        let response = match result {
            Ok(response) => response,
            // Without the url: the error names the address it was sent
            // to, and the key of a webhook is part of that.
            Err(e) => return Outcome::Failed(e.without_url().to_string()),
        };
        let status = response.status();
        if status.is_server_error() || status.as_u16() == 429 {
            return Outcome::Failed(format!("status {status}"));
        }
        if status.as_u16() >= 400 {
            return Outcome::Refused(format!("status {status}"));
        }
        if kind == Kind::Other {
            return Outcome::Sent;
        }
        // The two chats answer `200` whatever they made of the post, and
        // say in the body whether they took it: a key that is wrong, a
        // signature that does not match, too many messages a minute. Read
        // as sent, a webhook that had never delivered anything looked
        // fine in the log.
        let answer = response.text().await.unwrap_or_default();
        match chat_error(&answer) {
            Some(reason) => Outcome::Refused(reason),
            None => Outcome::Sent,
        }
    }
}

/// What a chat robot answered a post with, where that is an error:
/// `{"errcode":300001,"errmsg":"..."}`. An answer that is none of that
/// shape counts as sent, as it did.
fn chat_error(answer: &str) -> Option<String> {
    let value: Value = serde_json::from_str(answer).ok()?;
    let code = value.get("errcode")?.as_i64()?;
    if code == 0 {
        return None;
    }
    let message = value
        .get("errmsg")
        .and_then(|message| message.as_str())
        .unwrap_or_default();
    Some(format!("errcode {code}: {message}"))
}

/// How long to wait before a post is tried for the `tried`th time more:
/// a second, then two, four... and no more than five minutes.
fn retry_delay(tried: u32) -> Duration {
    // A test does not wait for seconds: the same steps, a thousand times
    // as fast.
    if cfg!(test) {
        return Duration::from_millis(retry_delay_secs(tried));
    }
    Duration::from_secs(retry_delay_secs(tried))
}

fn retry_delay_secs(tried: u32) -> u64 {
    (1u64 << tried.saturating_sub(1).min(16)).min(300)
}

/// How a post ended.
#[derive(Debug, PartialEq)]
enum Outcome {
    Sent,
    /// Not delivered, and trying again may do it.
    Failed(String),
    /// Not taken by the receiver, for what the post is.
    Refused(String),
}

/// Whose format a webhook posts in.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Kind {
    WeCom,
    DingTalk,
    /// A receiver of the user's own, which gets the fields as JSON.
    Other,
}

impl Kind {
    fn of(webhook_type: &str) -> Self {
        match webhook_type.to_lowercase().as_str() {
            "wecom" => Kind::WeCom,
            "dingtalk" => Kind::DingTalk,
            _ => Kind::Other,
        }
    }
}

/// What is posted, as the parts a template is made of.
struct Message {
    name: String,
    level: NotificationLevel,
    title: String,
    hostname: String,
    ip: String,
    category: String,
    message: String,
    count: usize,
}

impl Message {
    /// What stands for `{{name}}` in a template.
    fn part(&self, name: &str) -> Option<String> {
        Some(match name {
            "name" => self.name.clone(),
            "level" => self.level.to_string(),
            "title" => self.title.clone(),
            "hostname" => self.hostname.clone(),
            "ip" => self.ip.clone(),
            "category" => self.category.clone(),
            "count" => self.count.to_string(),
            "message" => self.message.clone(),
            _ => return None,
        })
    }

    /// `template` with each `{{part}}` replaced, as `escape` has it.
    ///
    /// In one pass over the template: what is put in is not looked
    /// through again. Replaced one part after the other, a title that
    /// read `{{message}}` had the message put where the title belonged.
    fn render(&self, template: &str, escape: fn(&str) -> String) -> String {
        let mut text =
            String::with_capacity(template.len() + self.message.len());
        let mut rest = template;
        while let Some(start) = rest.find("{{") {
            text.push_str(&rest[..start]);
            let after = &rest[start + 2..];
            let part = after
                .find("}}")
                .and_then(|end| Some((end, self.part(&after[..end])?)));
            match part {
                Some((end, value)) => {
                    text.push_str(&escape(&value));
                    rest = &after[end + 2..];
                },
                // Not one of the parts: it stands as it is written.
                None => {
                    text.push_str("{{");
                    rest = after;
                },
            }
        }
        text.push_str(rest);
        text
    }

    /// The body of the post for a webhook of `kind`.
    fn body(&self, kind: Kind, template: Option<&str>) -> String {
        // The markdown of a chat message: the template as it is filled
        // in, or the one that is built in.
        let markdown = || match template {
            Some(template) => self.render(template, |text| text.to_string()),
            None => {
                let color_type = match self.level {
                    NotificationLevel::Error => "warning",
                    NotificationLevel::Warn => "warning",
                    _ => "comment",
                };
                format!(
                    r###" <font color="{color_type}">{}({})</font>
                >title: {}
                >hostname: {}
                >ip: {}
                >category: {}
                >message: {}"###,
                    self.name,
                    self.level,
                    self.title,
                    self.hostname,
                    self.ip,
                    self.category,
                    self.message
                )
            },
        };
        let mut data = Map::new();
        match kind {
            Kind::WeCom => {
                let mut markdown_data = Map::new();
                markdown_data
                    .insert("content".to_string(), Value::String(markdown()));
                data.insert(
                    "msgtype".to_string(),
                    Value::String("markdown".to_string()),
                );
                data.insert(
                    "markdown".to_string(),
                    Value::Object(markdown_data),
                );
            },
            Kind::DingTalk => {
                let mut markdown_data = Map::new();
                markdown_data.insert(
                    "title".to_string(),
                    Value::String(self.category.clone()),
                );
                markdown_data
                    .insert("text".to_string(), Value::String(markdown()));
                data.insert(
                    "msgtype".to_string(),
                    Value::String("markdown".to_string()),
                );
                data.insert(
                    "markdown".to_string(),
                    Value::Object(markdown_data),
                );
            },
            Kind::Other => {
                // The body is the template's to say, whole: what goes
                // into it is escaped for the JSON string it stands in.
                if let Some(template) = template {
                    return self.render(template, |text| {
                        let quoted =
                            Value::String(text.to_string()).to_string();
                        quoted[1..quoted.len() - 1].to_string()
                    });
                }
                data.insert(
                    "name".to_string(),
                    Value::String(self.name.clone()),
                );
                // The two chat formats have it in their text; this one
                // left it out, though every notification has one.
                data.insert(
                    "title".to_string(),
                    Value::String(self.title.clone()),
                );
                data.insert(
                    "level".to_string(),
                    Value::String(self.level.to_string()),
                );
                data.insert(
                    "hostname".to_string(),
                    Value::String(self.hostname.clone()),
                );
                data.insert("ip".to_string(), Value::String(self.ip.clone()));
                data.insert(
                    "category".to_string(),
                    Value::String(self.category.clone()),
                );
                data.insert(
                    "message".to_string(),
                    Value::String(self.message.clone()),
                );
            },
        }
        Value::Object(data).to_string()
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
        // Regression: the generic payload had no title.
        assert_eq!("T", field(&body, "title"));
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

    /// An endpoint that answers each post with the next of `answers` -
    /// the last of them from then on - and passes on what it was sent:
    /// the head of the request, and its body.
    async fn spawn_scripted(
        answers: Vec<(u16, &'static str)>,
    ) -> (String, mpsc::UnboundedReceiver<(String, String)>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let url = format!(
            "http://{}/hook?key=k1",
            listener.local_addr().expect("addr")
        );
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut count = 0;
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
                        let _ = tx.send((head.to_string(), body.to_string()));
                        break;
                    }
                }
                let (status, answer) = answers[count.min(answers.len() - 1)];
                count += 1;
                let _ = stream
                    .write_all(
                        format!(
                            "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}",
                            answer.len()
                        )
                        .as_bytes(),
                    )
                    .await;
            }
        });
        (url, rx)
    }

    fn options(
        min_level: Option<&str>,
        headers: &[&str],
        secret: Option<&str>,
        template: Option<&str>,
        retries: Option<u32>,
    ) -> Result<WebhookOptions, String> {
        let headers: Vec<String> =
            headers.iter().map(|item| item.to_string()).collect();
        WebhookOptions::parse(min_level, &headers, secret, template, retries)
    }

    #[test]
    fn test_webhook_options() {
        let parsed = options(None, &[], None, None, None).expect("defaults");
        assert_eq!(NotificationLevel::Info, parsed.min_level);
        assert_eq!(0, parsed.retries);
        assert_eq!(true, parsed.secret.is_none() && parsed.template.is_none());
        let parsed = options(
            Some(" warn "),
            &["Authorization: Bearer t0ken", "X-Team:ops"],
            Some(" s3cret "),
            Some("{{title}}"),
            Some(3),
        )
        .expect("valid");
        assert_eq!(NotificationLevel::Warn, parsed.min_level);
        assert_eq!("Bearer t0ken", parsed.headers[0].1);
        assert_eq!("x-team", parsed.headers[1].0.as_str());
        assert_eq!(Some("s3cret"), parsed.secret.as_deref());
        // nothing is no secret and no template
        let parsed =
            options(Some(""), &[], Some("  "), Some(" "), None).expect("valid");
        assert_eq!(true, parsed.secret.is_none() && parsed.template.is_none());

        for (result, message) in [
            (
                options(Some("fatal"), &[], None, None, None),
                "webhook_min_level(fatal) should be info, warn or error",
            ),
            (
                options(
                    None,
                    &["Authorization Bearer t0ken"],
                    None,
                    None,
                    None,
                ),
                "webhook_headers: \"Authorization\" should be",
            ),
            (
                options(None, &["X Y: t0ken"], None, None, None),
                "webhook_headers: \"X\" should be",
            ),
            (
                options(None, &[], None, None, Some(11)),
                "webhook_retries(11) should be at most 10",
            ),
        ] {
            let error = result.expect_err("invalid");
            assert_eq!(true, error.contains(message), "{error}");
        }
        // The value of a header is a credential: an error names the
        // header and not what it was set to.
        for header in ["X Y: t0ken", "Authorization Bearer t0ken"] {
            let error = options(None, &[header], None, None, None)
                .expect_err("invalid");
            assert_eq!(false, error.contains("t0ken"), "{error}");
        }
    }

    #[tokio::test]
    async fn test_min_level() {
        let (url, mut posts) = spawn_scripted(vec![(200, "")]).await;
        let sender = WebhookNotificationSender::new(
            url,
            "normal".to_string(),
            vec!["a".to_string()],
        )
        .with_options(
            options(Some("warn"), &[], None, None, None).expect("valid"),
        )
        .with_batch(Duration::ZERO, 1);
        sender
            .send_notification(event(
                "a",
                NotificationLevel::Info,
                "T",
                "quiet",
            ))
            .await;
        assert_eq!(true, posts.try_recv().is_err());
        sender
            .send_notification(event("a", NotificationLevel::Warn, "T", "loud"))
            .await;
        let (_, body) = posts.try_recv().expect("posted");
        assert_eq!(true, body.contains("loud"), "{body}");
        sender
            .send_notification(event(
                "a",
                NotificationLevel::Error,
                "T",
                "louder",
            ))
            .await;
        assert_eq!(true, posts.try_recv().is_ok());
    }

    /// A receiver of one's own: the headers it asks for, a body of one's
    /// own making, and a signature of that body.
    #[tokio::test]
    async fn test_headers_template_and_signature() {
        let (url, mut posts) = spawn_scripted(vec![(200, "")]).await;
        let sender = WebhookNotificationSender::new(
            url,
            "normal".to_string(),
            vec!["a".to_string()],
        )
        .with_options(
            options(
                None,
                &["Authorization: Bearer t0ken", "X-Team: ops"],
                Some("s3cret"),
                Some(
                    r#"{"text":"[{{level}}] {{title}}: {{message}}","source":"{{name}}@{{hostname}}","tags":["{{category}}"],"count":{{count}}}"#,
                ),
                None,
            )
            .expect("valid"),
        )
        .with_batch(Duration::ZERO, 1);
        sender
            .send_notification(event(
                "a",
                NotificationLevel::Error,
                "Backend \"api\" down",
                "line 1\nline 2 {{title}}",
            ))
            .await;
        let (head, body) = posts.try_recv().expect("posted");
        let head = head.to_lowercase();
        assert_eq!(
            true,
            head.contains("authorization: bearer t0ken"),
            "{head}"
        );
        assert_eq!(true, head.contains("x-team: ops"), "{head}");
        assert_eq!(
            true,
            head.contains("content-type: application/json"),
            "{head}"
        );
        // What a message says stays text: its quotes and line feeds do
        // not end the string it is put into, and a `{{part}}` in it is
        // not filled in.
        let value: Value = serde_json::from_str(&body).expect("json");
        assert_eq!(
            "[error] Backend \"api\" down: line 1\nline 2 {{title}}",
            field(&value, "text")
        );
        assert_eq!("a", value["tags"][0].as_str().unwrap_or_default());
        assert_eq!(1, value["count"].as_i64().unwrap_or_default());
        assert_eq!(
            true,
            field(&value, "source").starts_with("pingap@"),
            "{body}"
        );
        let signature = hmac_sha256::HMAC::mac(&body, "s3cret")
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(
            true,
            head.contains(&format!("x-pingap-signature: sha256={signature}")),
            "{head}"
        );
    }

    /// The two chats: the template is the markdown, a `dingtalk` robot
    /// gets its time and signature, and what they answer is read.
    #[tokio::test]
    async fn test_chat_webhooks() {
        let (url, mut posts) = spawn_scripted(vec![
            (200, r#"{"errcode":0,"errmsg":"ok"}"#),
            (200, r#"{"errcode":310000,"errmsg":"sign not match"}"#),
        ])
        .await;
        let sender = WebhookNotificationSender::new(
            url.clone(),
            "dingtalk".to_string(),
            vec!["a".to_string()],
        )
        .with_options(
            options(
                None,
                &[],
                Some("SECabc"),
                Some("**{{title}}**\n\n{{message}}"),
                None,
            )
            .expect("valid"),
        );
        let inner = &sender.inner;
        // The url of a post: the key it had, the time, and the
        // signature of that time under the secret.
        let now_ms = 1_791_532_800_000u128;
        let signed = inner.post_url(Kind::DingTalk, now_ms);
        let sign = STANDARD.encode(hmac_sha256::HMAC::mac(
            format!("{now_ms}\nSECabc"),
            "SECabc",
        ));
        let parsed = reqwest::Url::parse(&signed).expect("url");
        let query: Vec<(String, String)> = parsed
            .query_pairs()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect();
        assert_eq!(
            vec![
                ("key".to_string(), "k1".to_string()),
                ("timestamp".to_string(), now_ms.to_string()),
                ("sign".to_string(), sign),
            ],
            query
        );
        // Only that robot signs a url.
        assert_eq!(url, inner.post_url(Kind::WeCom, now_ms));
        assert_eq!(url, inner.post_url(Kind::Other, now_ms));

        let message = Message {
            name: "pingap".to_string(),
            level: NotificationLevel::Warn,
            title: "T".to_string(),
            hostname: "h".to_string(),
            ip: "1.1.1.1".to_string(),
            category: "a".to_string(),
            message: "m \"quoted\"".to_string(),
            count: 1,
        };
        let template = inner.options.template.as_deref();
        let body = message.body(Kind::DingTalk, template);
        let value: Value = serde_json::from_str(&body).expect("json");
        assert_eq!("markdown", field(&value, "msgtype"));
        assert_eq!(
            "**T**\n\nm \"quoted\"",
            value["markdown"]["text"].as_str().unwrap_or_default()
        );
        let body = message.body(Kind::WeCom, template);
        let value: Value = serde_json::from_str(&body).expect("json");
        assert_eq!(
            "**T**\n\nm \"quoted\"",
            value["markdown"]["content"].as_str().unwrap_or_default()
        );
        // Without a template, the text that is built in.
        let body = message.body(Kind::WeCom, None);
        assert_eq!(true, body.contains(">title: T"), "{body}");
        // A template is filled in once. What a part says is not looked
        // through for parts again, whichever part it is, and what is no
        // part stands as it was written.
        let tricky = Message {
            title: "{{message}} {{count}}".to_string(),
            message: "{{title}}".to_string(),
            ..message
        };
        assert_eq!(
            "{{message}} {{count}}|{{title}}|1|{{other}}|{{ {{title",
            tricky.render(
                "{{title}}|{{message}}|{{count}}|{{other}}|{{ {{title",
                |text| text.to_string()
            )
        );

        // Taken, and then not: `200` both times, and the body says which.
        let client = reqwest::Client::new();
        assert_eq!(
            Outcome::Sent,
            inner.post_once(&client, Kind::DingTalk, &body).await
        );
        let (head, _) = posts.try_recv().expect("posted");
        assert_eq!(true, head.contains("&timestamp="), "{head}");
        assert_eq!(true, head.contains("&sign="), "{head}");
        assert_eq!(
            Outcome::Refused("errcode 310000: sign not match".to_string()),
            inner.post_once(&client, Kind::DingTalk, &body).await
        );

        assert_eq!(None, chat_error(""));
        assert_eq!(None, chat_error("ok"));
        assert_eq!(None, chat_error(r#"{"errcode":0}"#));
        assert_eq!(
            Some("errcode 93000: invalid webhook url".to_string()),
            chat_error(r#"{"errcode":93000,"errmsg":"invalid webhook url"}"#)
        );
    }

    /// A post that failed is tried again as often as is asked for, when
    /// trying again can help.
    #[tokio::test]
    async fn test_retries() {
        assert_eq!(
            vec![1, 2, 4, 8, 256, 300, 300],
            [1, 2, 3, 4, 9, 10, 40]
                .iter()
                .map(|tried| retry_delay_secs(*tried))
                .collect::<Vec<_>>()
        );
        let post = async |answers: Vec<(u16, &'static str)>, retries: u32| {
            let (url, mut posts) = spawn_scripted(answers).await;
            let sender = WebhookNotificationSender::new(
                url,
                "normal".to_string(),
                vec!["a".to_string()],
            )
            .with_options(
                options(None, &[], None, None, Some(retries)).expect("valid"),
            )
            .with_batch(Duration::ZERO, 1);
            sender
                .send_notification(event(
                    "a",
                    NotificationLevel::Info,
                    "T",
                    "m",
                ))
                .await;
            // The first try is made before that returns, the others
            // behind it: they are waited for here, and then a little
            // longer for one that should not come.
            let mut count = 0;
            let mut quiet = 0;
            while quiet < 6 {
                tokio::time::sleep(Duration::from_millis(50)).await;
                quiet += 1;
                while posts.try_recv().is_ok() {
                    count += 1;
                    quiet = 0;
                }
            }
            count
        };
        // Not answered well twice, then taken: three posts.
        assert_eq!(3, post(vec![(503, ""), (429, ""), (200, "")], 2).await);
        // No more often than is asked for, and not at all by default.
        assert_eq!(3, post(vec![(503, "")], 2).await);
        assert_eq!(1, post(vec![(503, "")], 0).await);
        // What the receiver will not take is not sent again.
        assert_eq!(1, post(vec![(400, ""), (200, "")], 2).await);
        assert_eq!(1, post(vec![(404, "")], 2).await);
    }
}
