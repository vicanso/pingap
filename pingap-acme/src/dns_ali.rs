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
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha1::Sha1;
use std::collections::BTreeMap;
use tokio::sync::Mutex;
use url::form_urlencoded::byte_serialize;

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Deserialize, Debug)]
struct AddRecordResponse {
    #[serde(rename = "RecordId")]
    record_id: String,
}

const ALI_API_ENDPOINT: &str = "https://alidns.aliyuncs.com/";
fn percent_encode(input: &str) -> String {
    byte_serialize(input.as_bytes()).collect()
}

/// Aliyun API request
async fn ali_api_request(
    access_key_id: &str,
    access_key_secret: &str,
    // btree is ordered map
    params: &mut BTreeMap<&str, String>,
) -> Result<String> {
    // add all common params
    params.insert("Format", "JSON".to_string());
    params.insert("Version", "2015-01-09".to_string());
    params.insert("AccessKeyId", access_key_id.to_string());
    params.insert("SignatureMethod", "HMAC-SHA1".to_string());
    params.insert("SignatureVersion", "1.0".to_string());
    params.insert(
        "Timestamp",
        Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
    );
    params.insert("SignatureNonce", uuid::Uuid::new_v4().to_string());

    // construct canonicalized query string
    let canonicalized_query_string = params
        .iter()
        .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
        .collect::<Vec<String>>()
        .join("&");

    // construct string to sign
    let string_to_sign = format!(
        "GET&{}&{}",
        percent_encode("/"),
        percent_encode(&canonicalized_query_string)
    );

    // calculate signature
    let signing_key = format!("{access_key_secret}&");
    type HmacSha1 = Hmac<Sha1>;
    let mut mac =
        HmacSha1::new_from_slice(signing_key.as_bytes()).map_err(|e| {
            Error::Fail {
                category: "aliyun".to_string(),
                message: e.to_string(),
            }
        })?;
    mac.update(string_to_sign.as_bytes());
    let signature = STANDARD.encode(mac.finalize().into_bytes());

    // assemble final request url and send request
    let request_url = format!(
        "{}?{}&Signature={}",
        ALI_API_ENDPOINT,
        canonicalized_query_string,
        percent_encode(&signature)
    );

    let client = reqwest::Client::new();
    let response =
        client
            .get(&request_url)
            .send()
            .await
            .map_err(|e| Error::Fail {
                category: "aliyun".to_string(),
                message: e.to_string(),
            })?;

    if response.status().is_success() {
        Ok(response.text().await.map_err(|e| Error::Fail {
            category: "aliyun".to_string(),
            message: e.to_string(),
        })?)
    } else {
        let status = response.status();
        let error_body = response.text().await.map_err(|e| Error::Fail {
            category: "aliyun".to_string(),
            message: e.to_string(),
        })?;
        Err(Error::Fail {
            category: "aliyun".to_string(),
            message: format!("API Error: {status} - {error_body}"),
        })
    }
}

/// add a dns txt record
async fn add_ali_dns_record(
    access_key_id: &str,
    access_key_secret: &str,
    domain: &str,
    value: &str,
) -> Result<AddRecordResponse> {
    let mut params = BTreeMap::new();
    let (rr, domain_name) = domain.split_once(".").ok_or(Error::Fail {
        category: "aliyun".to_string(),
        message: "invalid domain".to_string(),
    })?;
    params.insert("Action", "AddDomainRecord".to_string());
    params.insert("DomainName", domain_name.to_string());
    params.insert("RR", rr.to_string());
    params.insert("Type", "TXT".to_string());
    params.insert("Value", value.to_string());

    let response_body =
        ali_api_request(access_key_id, access_key_secret, &mut params).await?;
    let response: AddRecordResponse = serde_json::from_str(&response_body)
        .map_err(|e| Error::Fail {
            category: "aliyun".to_string(),
            message: e.to_string(),
        })?;
    Ok(response)
}

async fn delete_record_by_id(
    access_key_id: &str,
    access_key_secret: &str,
    record_id: &str,
) -> Result<String> {
    let mut params = BTreeMap::new();
    params.insert("Action", "DeleteDomainRecord".to_string());
    params.insert("RecordId", record_id.to_string());

    ali_api_request(access_key_id, access_key_secret, &mut params).await
}

pub(crate) struct AliDnsTask {
    access_key_id: String,
    access_key_secret: String,
    records: Mutex<Vec<String>>,
}

impl AliDnsTask {
    pub fn new(access_key_id: &str, access_key_secret: &str) -> Self {
        Self {
            access_key_id: access_key_id.to_string(),
            access_key_secret: access_key_secret.to_string(),
            records: Mutex::new(vec![]),
        }
    }
}

#[async_trait]
impl AcmeDnsTask for AliDnsTask {
    async fn add_txt_record(&self, domain: &str, value: &str) -> Result<()> {
        let response = add_ali_dns_record(
            &self.access_key_id,
            &self.access_key_secret,
            domain,
            value,
        )
        .await?;
        let mut records = self.records.lock().await;
        records.push(response.record_id);
        Ok(())
    }

    async fn done(&self) -> Result<()> {
        let mut records = self.records.lock().await;
        for record in records.iter() {
            delete_record_by_id(
                &self.access_key_id,
                &self.access_key_secret,
                record,
            )
            .await?;
        }
        records.clear();
        Ok(())
    }
}
