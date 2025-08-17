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

use super::{AcmeDnsTask, Error};
use async_trait::async_trait;
use serde::Deserialize;
use tokio::sync::Mutex;

type Result<T, E = Error> = std::result::Result<T, E>;

const CF_API_ENDPOINT: &str = "https://api.cloudflare.com/client/v4";

#[derive(Deserialize, Debug)]
struct ApiResponse<T> {
    success: bool,
    result: T,
    errors: Vec<serde_json::Value>,
}
#[derive(Deserialize, Debug)]
struct Zone {
    id: String,
    name: String,
}
#[derive(Deserialize, Debug)]
struct DnsRecord {
    id: String,
}

/// Get the zone id of the domain
async fn get_zone_id(api_token: &str, domain_name: &str) -> Result<String> {
    let client = reqwest::Client::new();
    let url = format!("{CF_API_ENDPOINT}/zones");

    let response = client
        .get(url)
        .query(&[("name", domain_name)])
        .bearer_auth(api_token)
        .send()
        .await
        .map_err(|e| Error::Fail {
            category: "cf".to_string(),
            message: e.to_string(),
        })?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.map_err(|e| Error::Fail {
            category: "cf".to_string(),
            message: e.to_string(),
        })?;
        return Err(Error::Fail {
            category: "cf".to_string(),
            message: format!("API Error: {status} - {body}"),
        });
    }

    let api_response: ApiResponse<Vec<Zone>> =
        response.json().await.map_err(|e| Error::Fail {
            category: "cf".to_string(),
            message: e.to_string(),
        })?;

    if !api_response.success {
        return Err(Error::Fail {
            category: "cf".to_string(),
            message: format!("API returned failure: {:?}", api_response.errors),
        });
    }

    // get the zone id of the domain
    api_response
        .result
        .into_iter()
        .find(|zone| zone.name == domain_name)
        .map(|zone| zone.id)
        .ok_or(Error::Fail {
            category: "cf".to_string(),
            message: format!("not found zone id for domain '{domain_name}'"),
        })
}

async fn add_cf_dns_record(
    api_token: &str,
    zone_id: &str,
    record_name: &str,
    content: &str,
) -> Result<String> {
    let client = reqwest::Client::new();
    let url = format!("{CF_API_ENDPOINT}/zones/{zone_id}/dns_records");

    // create a txt record
    let body = serde_json::json!({
        "type": "TXT",
        "name": record_name,
        "content": content,
        "ttl": 120
    });

    let response = client
        .post(url)
        .bearer_auth(api_token)
        .json(&body)
        .send()
        .await
        .map_err(|e| Error::Fail {
            category: "cf".to_string(),
            message: e.to_string(),
        })?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.map_err(|e| Error::Fail {
            category: "cf".to_string(),
            message: e.to_string(),
        })?;
        return Err(Error::Fail {
            category: "cf".to_string(),
            message: format!("API Error: {status} - {body}"),
        });
    }

    let api_response: ApiResponse<DnsRecord> =
        response.json().await.map_err(|e| Error::Fail {
            category: "cf".to_string(),
            message: e.to_string(),
        })?;

    if !api_response.success {
        return Err(Error::Fail {
            category: "cf".to_string(),
            message: format!("API returned failure: {:?}", api_response.errors),
        });
    }

    Ok(api_response.result.id)
}

async fn delete_cf_dns_record(
    api_token: &str,
    zone_id: &str,
    record_id: &str,
) -> Result<()> {
    let client = reqwest::Client::new();
    let url =
        format!("{CF_API_ENDPOINT}/zones/{zone_id}/dns_records/{record_id}");

    let response = client
        .delete(url)
        .bearer_auth(api_token)
        .send()
        .await
        .map_err(|e| Error::Fail {
            category: "cf".to_string(),
            message: e.to_string(),
        })?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.map_err(|e| Error::Fail {
            category: "cf".to_string(),
            message: e.to_string(),
        })?;
        return Err(Error::Fail {
            category: "cf".to_string(),
            message: format!("API Error: {status} - {body}"),
        });
    }

    let api_response: ApiResponse<serde_json::Value> =
        response.json().await.map_err(|e| Error::Fail {
            category: "cf".to_string(),
            message: e.to_string(),
        })?;

    if !api_response.success {
        return Err(Error::Fail {
            category: "cf".to_string(),
            message: format!("API returned failure: {:?}", api_response.errors),
        });
    }

    Ok(())
}

pub(crate) struct CfDnsTask {
    api_token: String,
    zone: Mutex<String>,
    record: Mutex<String>,
}

impl CfDnsTask {
    pub fn new(api_token: &str) -> Self {
        Self {
            api_token: api_token.to_string(),
            zone: Mutex::new(String::new()),
            record: Mutex::new(String::new()),
        }
    }
}

#[async_trait]
impl AcmeDnsTask for CfDnsTask {
    async fn add_txt_record(&self, domain: &str, value: &str) -> Result<()> {
        let (_, domain_name) = domain.split_once(".").ok_or(Error::Fail {
            category: "cf".to_string(),
            message: format!("invalid domain '{domain}'"),
        })?;
        let zone_id = get_zone_id(&self.api_token, domain_name).await?;
        let mut zone = self.zone.lock().await;
        *zone = zone_id.clone();
        let record_id =
            add_cf_dns_record(&self.api_token, &zone_id, domain, value).await?;
        let mut record = self.record.lock().await;
        *record = record_id;
        Ok(())
    }
    async fn done(&self) -> Result<()> {
        let mut zone = self.zone.lock().await;
        let mut record = self.record.lock().await;
        delete_cf_dns_record(&self.api_token, &zone, &record).await?;
        *zone = String::new();
        *record = String::new();
        Ok(())
    }
}
