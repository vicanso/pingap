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

    #[test]
    fn test_notification_level() {
        let level = NotificationLevel::Error;
        assert_eq!(level.to_string(), "error");
        let level = NotificationLevel::Warn;
        assert_eq!(level.to_string(), "warn");
        let level = NotificationLevel::Info;
        assert_eq!(level.to_string(), "info");
    }
}
