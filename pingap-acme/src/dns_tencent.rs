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
use chrono::Utc;
use hmac::{Hmac, Mac};
use reqwest::header::{CONTENT_TYPE, HOST};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use url::Url;

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Deserialize, Debug)]
struct TencentError {
    #[serde(rename = "Code")]
    code: String,
    #[serde(rename = "Message")]
    message: String,
}

#[derive(Deserialize, Debug)]
struct TencentResponse<T> {
    #[serde(rename = "Response")]
    response: TencentResponseInner<T>,
}

#[derive(Deserialize, Debug)]
struct TencentResponseInner<T> {
    #[serde(rename = "Error")]
    error: Option<TencentError>,
    #[serde(flatten)]
    data: Option<T>,
}
#[derive(Deserialize, Debug)]
struct CreateRecordResponse {
    #[serde(rename = "RecordId")]
    record_id: u64,
}

const SERVICE: &str = "dnspod";
const API_VERSION: &str = "2021-03-23";

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC key error");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

fn new_error(err: impl ToString) -> Error {
    Error::Fail {
        category: "tencent".to_string(),
        message: err.to_string(),
    }
}

async fn tencent_cloud_api_request(
    host: &str,
    endpoint: &str,
    secret_id: &str,
    secret_key: &str,
    action: &str,
    payload_str: &str,
) -> Result<String> {
    let timestamp = Utc::now().timestamp();
    let date = Utc::now().format("%Y-%m-%d").to_string();

    // canonical request
    let http_request_method = "POST";
    let canonical_uri = "/";
    let canonical_query_string = "";
    let hashed_request_payload = sha256_hex(payload_str.as_bytes());

    let canonical_headers =
        format!("content-type:application/json; charset=utf-8\nhost:{host}\n",);
    let signed_headers = "content-type;host";

    let canonical_request = format!(
        "{http_request_method}\n{canonical_uri}\n{canonical_query_string}\n{canonical_headers}\n{signed_headers}\n{hashed_request_payload}",
    );

    let algorithm = "TC3-HMAC-SHA256";
    let credential_scope = format!("{date}/{SERVICE}/tc3_request");
    let hashed_canonical_request = sha256_hex(canonical_request.as_bytes());

    let string_to_sign = format!(
        "{algorithm}\n{timestamp}\n{credential_scope}\n{hashed_canonical_request}",
    );

    let secret_date =
        hmac_sha256(format!("TC3{secret_key}").as_bytes(), date.as_bytes());
    let secret_service = hmac_sha256(&secret_date, SERVICE.as_bytes());
    let secret_signing = hmac_sha256(&secret_service, "tc3_request".as_bytes());
    let signature =
        hex::encode(hmac_sha256(&secret_signing, string_to_sign.as_bytes()));

    // authorization header
    let authorization = format!(
        "{algorithm} Credential={secret_id}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
    );

    let client = reqwest::Client::new();

    let response = client
        .post(endpoint)
        .header(HOST, host)
        .header(CONTENT_TYPE, "application/json; charset=utf-8")
        .header("X-TC-Action", action)
        .header("X-TC-Version", API_VERSION)
        .header("X-TC-Timestamp", timestamp.to_string())
        .header("Authorization", authorization)
        .body(payload_str.to_string())
        .send()
        .await
        .map_err(new_error)?;

    let status = response.status();
    if status.is_success() {
        let body = response.text().await.map_err(new_error)?;
        // check error
        let parsed_resp: TencentResponse<serde_json::Value> =
            serde_json::from_str(&body).map_err(new_error)?;
        if let Some(error) = parsed_resp.response.error {
            return Err(new_error(format!(
                "Tencent API Error: {} - {}",
                error.code, error.message
            )));
        }
        Ok(body)
    } else {
        let body = response.text().await.map_err(new_error)?;
        Err(new_error(format!("HTTP Error: {status} - {body}")))
    }
}

async fn add_tencent_dns_record(
    host: &str,
    endpoint: &str,
    access_key_id: &str,
    access_key_secret: &str,
    domain: &str,
    value: &str,
) -> Result<u64> {
    let (rr, domain_name) =
        domain.split_once(".").ok_or(new_error("invalid domain"))?;

    let payload = serde_json::json!({
        "Domain": domain_name,
        "SubDomain": rr,
        "RecordType": "TXT",
        "RecordLine": "默认",
        "Value": value,
        "TTL": 600
    });
    let body = tencent_cloud_api_request(
        host,
        endpoint,
        access_key_id,
        access_key_secret,
        "CreateRecord",
        &payload.to_string(),
    )
    .await
    .map_err(new_error)?;
    let resp: TencentResponse<CreateRecordResponse> =
        serde_json::from_str(&body).map_err(new_error)?;
    if let Some(data) = resp.response.data {
        return Ok(data.record_id);
    }
    Err(new_error("add dns fail, response is invalid"))
}

async fn delete_tencent_dns_record(
    host: &str,
    endpoint: &str,
    access_key_id: &str,
    access_key_secret: &str,
    domain: &str,
    record_id: u64,
) -> Result<()> {
    let (_, domain_name) =
        domain.split_once(".").ok_or(new_error("invalid domain"))?;
    let payload = serde_json::json!({
        "Domain": domain_name,
        "RecordId": record_id
    });
    tencent_cloud_api_request(
        host,
        endpoint,
        access_key_id,
        access_key_secret,
        "DeleteRecord",
        &payload.to_string(),
    )
    .await?;
    Ok(())
}

pub(crate) struct TencentDnsTask {
    host: String,
    endpoint: String,
    access_key_id: String,
    access_key_secret: String,
    domain: Mutex<String>,
    record: Mutex<u64>,
}

impl TencentDnsTask {
    pub fn new(url: &str) -> Result<Self> {
        let info = Url::parse(url).map_err(new_error)?;
        let endpoint = info.origin().ascii_serialization();
        let host = info
            .host()
            .map(|host| host.to_string())
            .ok_or(new_error("host is required"))?;
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
                "access_key_id and access_key_secret are required",
            ));
        }
        Ok(Self {
            host,
            endpoint,
            access_key_id,
            access_key_secret,
            domain: Mutex::new(String::new()),
            record: Mutex::new(0),
        })
    }
}

#[async_trait]
impl AcmeDnsTask for TencentDnsTask {
    async fn add_txt_record(&self, domain: &str, value: &str) -> Result<()> {
        let record_id = add_tencent_dns_record(
            &self.host,
            &self.endpoint,
            &self.access_key_id,
            &self.access_key_secret,
            domain,
            value,
        )
        .await?;
        let mut acme_domain = self.domain.lock().await;
        *acme_domain = domain.to_string();
        let mut record = self.record.lock().await;
        *record = record_id;
        Ok(())
    }
    async fn done(&self) -> Result<()> {
        let mut domain = self.domain.lock().await;
        let mut record = self.record.lock().await;
        delete_tencent_dns_record(
            &self.host,
            &self.endpoint,
            &self.access_key_id,
            &self.access_key_secret,
            &domain,
            *record,
        )
        .await?;
        *domain = String::new();
        *record = 0;
        Ok(())
    }
}
