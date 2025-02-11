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
use std::fmt::Display;

#[derive(Default)]
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

#[derive(Default)]
pub struct NotificationData {
    pub category: String,
    pub level: NotificationLevel,
    pub title: String,
    pub message: String,
}

#[async_trait]
pub trait Notification {
    async fn notify(&self, data: NotificationData);
}

pub type NotificationSender = Box<dyn Notification + Send + Sync>;
