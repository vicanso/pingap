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
use http::{HeaderName, HeaderValue};
use std::fmt::Display;

/// Variants are declared from least to most severe so the derived `Ord`
/// ranks them: a merged batch reports the highest level in it.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum NotificationLevel {
    #[default]
    Info,
    Warn,
    Error,
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

#[derive(Default, Clone, Debug)]
pub struct NotificationData {
    /// The category of the notification, used for grouping or filtering notifications
    pub category: String,
    /// The severity level of the notification (Info, Warn, Error)
    pub level: NotificationLevel,
    /// The title or subject of the notification
    pub title: String,
    /// The detailed message content of the notification
    pub message: String,
}

/// The most a notification that could not be delivered is sent again.
/// Each wait is twice the one before, from a second: ten of them are a
/// quarter of an hour, by which time it is news no longer.
pub const NOTIFICATION_MAX_RETRIES: u32 = 10;

/// The level below which notifications are not sent, as the
/// configuration names it (`webhook_min_level`): `info`, `warn` or
/// `error`, and `info` where it names none.
pub fn parse_notification_level(
    value: Option<&str>,
) -> Result<NotificationLevel, String> {
    match value.map(str::trim).unwrap_or_default() {
        "" | "info" => Ok(NotificationLevel::Info),
        "warn" => Ok(NotificationLevel::Warn),
        "error" => Ok(NotificationLevel::Error),
        other => Err(format!(
            "webhook_min_level({other}) should be info, warn or error"
        )),
    }
}

/// The headers of the request a notification is sent with, as the
/// configuration has them (`webhook_headers`): each `Name: value`.
///
/// An error names the header and not its value, which is a token as
/// often as not.
pub fn parse_notification_headers(
    headers: &[String],
) -> Result<Vec<(HeaderName, HeaderValue)>, String> {
    let mut parsed = Vec::with_capacity(headers.len());
    for item in headers {
        // Its first word: an entry without a colon is all value from
        // there on, `Authorization Bearer ...`.
        let invalid = || {
            let name = item.split([':', ' ', '\t']).next().unwrap_or_default();
            format!("webhook_headers: {name:?} should be `Name: value`")
        };
        let (name, value) = item.split_once(':').ok_or_else(invalid)?;
        let name = HeaderName::from_bytes(name.trim().as_bytes())
            .map_err(|_| invalid())?;
        let value =
            HeaderValue::from_str(value.trim()).map_err(|_| invalid())?;
        parsed.push((name, value));
    }
    Ok(parsed)
}

/// How often a notification that could not be delivered is sent again,
/// as the configuration has it (`webhook_retries`): not at all where it
/// says nothing.
pub fn parse_notification_retries(value: Option<u32>) -> Result<u32, String> {
    let retries = value.unwrap_or_default();
    if retries > NOTIFICATION_MAX_RETRIES {
        return Err(format!(
            "webhook_retries({retries}) should be at most {NOTIFICATION_MAX_RETRIES}"
        ));
    }
    Ok(retries)
}

/// The `webhook_type` of a notification that is published to ntfy.
pub const NOTIFICATION_TYPE_NTFY: &str = "ntfy";

/// Whether `webhook_type` names ntfy.
pub fn is_ntfy_notification(webhook_type: &str) -> bool {
    webhook_type
        .trim()
        .eq_ignore_ascii_case(NOTIFICATION_TYPE_NTFY)
}

/// Where a notification for ntfy goes.
#[derive(Debug, Clone, PartialEq)]
pub struct NtfyTarget {
    /// The url the message is posted to as JSON, which ntfy takes at the
    /// root of the server and nowhere else: the url of the topic without
    /// its last part.
    pub url: String,
    /// The topic, which the JSON names.
    pub topic: String,
}

/// The names ntfy keeps for itself, and takes no message for.
const NTFY_RESERVED_TOPICS: [&str; 10] = [
    "docs", "static", "file", "app", "metrics", "account", "settings",
    "signup", "login", "v1",
];

/// What follows a topic in the urls ntfy has for reading one, and for
/// publishing with a GET: the url of a subscription is not the one of
/// its topic.
const NTFY_TOPIC_SUFFIXES: [&str; 8] = [
    "json", "sse", "raw", "ws", "auth", "publish", "send", "trigger",
];

/// The server and the topic of a notification for ntfy, as the
/// configuration has them (`webhook`): the url of the topic,
/// `https://ntfy.sh/mytopic`. A user and a password in it, and what
/// follows a `?`, stay with the server.
///
/// Read with the parser the post is sent with, so that what is taken
/// here is a url there as well. An error does not repeat the url: on a
/// server that is open to everybody the name of a topic is all that
/// keeps it to oneself.
pub fn parse_ntfy_url(url: &str) -> Result<NtfyTarget, String> {
    let invalid = |what: &str| {
        format!(
            "webhook: the url of ntfy {what}, it should be the url of a topic like https://ntfy.sh/mytopic"
        )
    };
    let mut parsed =
        url::Url::parse(url.trim()).map_err(|_| invalid("is not a url"))?;
    if !["http", "https"].contains(&parsed.scheme())
        || parsed.host_str().is_none_or(str::is_empty)
    {
        return Err(invalid("is neither http nor https"));
    }
    // Sent nowhere, so what stood there as a part of the topic was not
    // one.
    if parsed.fragment().is_some() {
        return Err(invalid("has a part after a #"));
    }
    let mut parts: Vec<String> = parsed
        .path()
        .split('/')
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect();
    let topic = parts.pop().ok_or_else(|| invalid("names no topic"))?;
    // What ntfy takes for the name of a topic.
    let valid = topic.len() <= 64
        && topic
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !valid {
        return Err(invalid(
            "ends with what is no topic (letters, digits, - and _, at most 64)",
        ));
    }
    if NTFY_RESERVED_TOPICS.contains(&topic.as_str()) {
        return Err(invalid("ends with a name ntfy keeps for itself"));
    }
    if !parts.is_empty() && NTFY_TOPIC_SUFFIXES.contains(&topic.as_str()) {
        return Err(invalid(
            "is the one of a subscription or of a publish by GET, not of the topic itself",
        ));
    }
    let mut path = String::from("/");
    for part in parts {
        path.push_str(&part);
        path.push('/');
    }
    parsed.set_path(&path);
    Ok(NtfyTarget {
        url: parsed.to_string(),
        topic,
    })
}

/// Trait for sending notifications
///
/// Implementers of this trait can send notifications with different delivery methods
/// (email, SMS, push notification, etc.)
#[async_trait]
pub trait Notification {
    async fn notify(&self, data: NotificationData);
}

/// Type alias for a boxed Notification trait object that can be shared between threads
pub type NotificationSender = Box<dyn Notification + Send + Sync>;

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_notification_level() {
        let level = NotificationLevel::Error;
        assert_eq!(level.to_string(), "error");
        let level = NotificationLevel::Warn;
        assert_eq!(level.to_string(), "warn");
        let level = NotificationLevel::Info;
        assert_eq!(level.to_string(), "info");
    }

    #[test]
    fn test_parse_ntfy_url() {
        let target = |url: &str| {
            let target = parse_ntfy_url(url).unwrap();
            (target.url, target.topic)
        };
        let of = |url: &str, topic: &str| (url.to_string(), topic.to_string());
        assert_eq!(
            of("https://ntfy.sh/", "my_topic-1"),
            target("https://ntfy.sh/my_topic-1")
        );
        assert_eq!(
            of("https://ntfy.sh/", "alerts"),
            target(" HTTPS://ntfy.sh/alerts/ ")
        );
        // A server of one's own: below a path, with a port, a user and a
        // password, and a token in the query.
        assert_eq!(
            of("http://127.0.0.1:2586/push/", "alerts"),
            target("http://127.0.0.1:2586/push/alerts")
        );
        assert_eq!(
            of("http://[::1]:2586/", "alerts"),
            target("http://[::1]:2586/alerts")
        );
        assert_eq!(
            of(
                "https://me:s3%40cret@ntfy.example.com/?auth=QmFzaWM",
                "alerts"
            ),
            target("https://me:s3%40cret@ntfy.example.com/alerts?auth=QmFzaWM")
        );
        // A name that is one of a subscription only after a topic.
        assert_eq!(
            of("https://ntfy.sh/", "json"),
            target("https://ntfy.sh/json")
        );

        for (url, reason) in [
            ("https://ntfy.sh", "names no topic"),
            ("https://ntfy.sh/", "names no topic"),
            ("https://ntfy.sh/my topic", "is no topic"),
            ("https://ntfy.sh/my.topic", "is no topic"),
            ("ntfy.sh/alerts", "is not a url"),
            ("/alerts", "is not a url"),
            ("https://ntfy.sh:port/alerts", "is not a url"),
            ("https://me:pa/ss@ntfy.sh/alerts", "is not a url"),
            ("ftp://ntfy.sh/alerts", "is neither http nor https"),
            ("https://ntfy.sh/alerts#prod", "has a part after a #"),
            ("https://ntfy.sh/app", "keeps for itself"),
            ("https://ntfy.sh/v1", "keeps for itself"),
            ("https://ntfy.sh/alerts/json", "of a subscription"),
            ("https://ntfy.sh/alerts/publish", "of a subscription"),
        ] {
            let error = parse_ntfy_url(url).unwrap_err();
            assert_eq!(true, error.contains(reason), "{url}: {error}");
            // The topic is as good as a password.
            assert_eq!(false, error.contains("alerts"), "{error}");
        }
        let long = format!("https://ntfy.sh/{}", "a".repeat(65));
        assert_eq!(true, parse_ntfy_url(&long).is_err());

        assert_eq!(true, is_ntfy_notification("ntfy"));
        assert_eq!(true, is_ntfy_notification(" Ntfy "));
        assert_eq!(false, is_ntfy_notification("normal"));
        assert_eq!(false, is_ntfy_notification(""));
    }
}
