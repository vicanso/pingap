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
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha1::Sha1;
use std::collections::BTreeMap;
use tokio::sync::Mutex;
use url::Url;
use url::form_urlencoded::byte_serialize;

type Result<T, E = Error> = std::result::Result<T, E>;

fn new_error(err: impl ToString) -> Error {
    Error::Fail {
        category: "ali".to_string(),
        message: err.to_string(),
    }
}

#[derive(Deserialize, Debug)]
struct AddRecordResponse {
    #[serde(rename = "RecordId")]
    record_id: String,
}

fn percent_encode(input: &str) -> String {
    byte_serialize(input.as_bytes()).collect()
}

/// Aliyun API request
async fn ali_api_request(
    endpoint: &str,
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
        HmacSha1::new_from_slice(signing_key.as_bytes()).map_err(new_error)?;
    mac.update(string_to_sign.as_bytes());
    let signature = STANDARD.encode(mac.finalize().into_bytes());

    // assemble final request url and send request
    let request_url = format!(
        "{endpoint}?{canonicalized_query_string}&Signature={}",
        percent_encode(&signature)
    );

    let client = reqwest::Client::new();
    let response = client.get(&request_url).send().await.map_err(new_error)?;

    if response.status().is_success() {
        Ok(response.text().await.map_err(new_error)?)
    } else {
        let status = response.status();
        let error_body = response.text().await.map_err(new_error)?;
        Err(new_error(format!("API Error: {status} - {error_body}")))
    }
}

/// add a dns txt record
async fn add_ali_dns_record(
    endpoint: &str,
    access_key_id: &str,
    access_key_secret: &str,
    domain: &str,
    value: &str,
) -> Result<AddRecordResponse> {
    let mut params = BTreeMap::new();
    let (rr, domain_name) =
        domain.split_once(".").ok_or(new_error("invalid domain"))?;
    params.insert("Action", "AddDomainRecord".to_string());
    params.insert("DomainName", domain_name.to_string());
    params.insert("RR", rr.to_string());
    params.insert("Type", "TXT".to_string());
    params.insert("Value", value.to_string());

    let response_body = ali_api_request(
        endpoint,
        access_key_id,
        access_key_secret,
        &mut params,
    )
    .await?;
    let response: AddRecordResponse =
        serde_json::from_str(&response_body).map_err(new_error)?;
    Ok(response)
}

async fn delete_ali_dns_record(
    endpoint: &str,
    access_key_id: &str,
    access_key_secret: &str,
    record_id: &str,
) -> Result<String> {
    let mut params = BTreeMap::new();
    params.insert("Action", "DeleteDomainRecord".to_string());
    params.insert("RecordId", record_id.to_string());

    ali_api_request(endpoint, access_key_id, access_key_secret, &mut params)
        .await
}

pub(crate) struct AliDnsTask {
    access_key_id: String,
    access_key_secret: String,
    endpoint: String,
    record: Mutex<String>,
}

impl AliDnsTask {
    pub fn new(url: &str) -> Result<Self> {
        let info = Url::parse(url).map_err(new_error)?;
        let endpoint = info.origin().ascii_serialization();
        let mut access_key_id = "".to_string();
        let mut access_key_secret = "".to_string();
        for (k, v) in info.query_pairs() {
            match k.as_ref() {
                "access_key_id" => {
                    access_key_id = v.to_string();
                },
                "access_key_secret" => {
                    access_key_secret = v.to_string();
                },
                _ => {},
            }
        }
        if access_key_id.is_empty() || access_key_secret.is_empty() {
            return Err(new_error(
                "access_key_id or access_key_secret is required",
            ));
        }

        Ok(Self {
            access_key_id,
            access_key_secret,
            endpoint,
            record: Mutex::new(String::new()),
        })
    }
}

#[async_trait]
impl AcmeDnsTask for AliDnsTask {
    async fn add_txt_record(&self, domain: &str, value: &str) -> Result<()> {
        let response = add_ali_dns_record(
            &self.endpoint,
            &self.access_key_id,
            &self.access_key_secret,
            domain,
            value,
        )
        .await?;
        let mut record = self.record.lock().await;
        *record = response.record_id;
        Ok(())
    }

    async fn done(&self) -> Result<()> {
        let mut record = self.record.lock().await;
        delete_ali_dns_record(
            &self.endpoint,
            &self.access_key_id,
            &self.access_key_secret,
            &record,
        )
        .await?;
        *record = String::new();
        Ok(())
    }
}
