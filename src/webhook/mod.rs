// Copyright 2024 Tree xie.
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

use crate::state;
use log::{error, info};
use serde_json::{Map, Value};
use std::time::Duration;

pub struct WebhookSendParams {
    pub url: String,
    pub webhook_type: String,
    pub category: String,
    pub msg: String,
}

pub fn send(params: WebhookSendParams) {
    std::thread::spawn(move || {
        if let Ok(rt) = tokio::runtime::Runtime::new() {
            let category = params.category;
            let send = async move {
                let client = reqwest::Client::new();
                let mut data = serde_json::Map::new();
                let hostname = state::get_hostname().clone();
                let content = format!(
                    r###"Pingap Warnning
                    >hostname: {hostname}
                    >category: {category}
                    >message: {}
                    "###,
                    params.msg
                );
                match params.webhook_type.to_lowercase().as_str() {
                    "wecom" => {
                        let mut markdown_data = Map::new();
                        markdown_data.insert("content".to_string(), Value::String(content));
                        data.insert("msgtype".to_string(), Value::String("markdown".to_string()));
                        data.insert("markdown".to_string(), Value::Object(markdown_data));
                    }
                    "dingtalk" => {
                        let mut markdown_data = serde_json::Map::new();
                        markdown_data
                            .insert("title".to_string(), Value::String(category.to_string()));
                        markdown_data.insert("text".to_string(), Value::String(content));
                        data.insert("msgtype".to_string(), Value::String("markdown".to_string()));
                        data.insert("markdown".to_string(), Value::Object(markdown_data));
                    }
                    _ => {
                        data.insert("category".to_string(), Value::String(category));
                        data.insert("message".to_string(), Value::String(params.msg));
                        data.insert("hostname".to_string(), Value::String(hostname));
                    }
                }

                match client
                    .post(&params.url)
                    .json(&data)
                    .timeout(Duration::from_secs(30))
                    .send()
                    .await
                {
                    Ok(res) => {
                        if res.status().as_u16() < 400 {
                            info!("Send webhook success");
                        } else {
                            error!("Send webhook fail, status:{}", res.status());
                        }
                    }
                    Err(e) => {
                        error!("Send webhook fail, {e}");
                    }
                };
            };
            rt.block_on(send);
        }
    });
}
