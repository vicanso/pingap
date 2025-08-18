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
use reqwest::header::{HeaderMap, HeaderName, CONTENT_TYPE, HOST};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::str::FromStr;
use tokio::sync::Mutex;

type Result<T, E = Error> = std::result::Result<T, E>;

fn new_error(err: impl ToString) -> Error {
    Error::Fail {
        category: "huawei".to_string(),
        message: err.to_string(),
    }
}

#[derive(Deserialize, Debug)]
struct Zone {
    id: String,
    name: String,
}
#[derive(Deserialize, Debug)]
struct ZonesResponse {
    zones: Vec<Zone>,
}
#[derive(Deserialize, Debug)]
struct Recordset {
    id: String,
}
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

async fn huawei_cloud_api_request(
    ak: &str,
    sk: &str,
    region: &str,
    method: reqwest::Method,
    uri: &str,
    query: &str,
    payload_str: &str,
) -> Result<String> {
    let host = format!("dns.{region}.myhuaweicloud.com");
    let endpoint = format!("https://{host}");
    let timestamp = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let http_method = method.as_str();
    let canonical_uri = uri;
    let canonical_query_string = query;
    let mut headers_to_sign = BTreeMap::new();
    headers_to_sign.insert("host", host.as_str());
    headers_to_sign.insert("x-sdk-date", &timestamp);
    let content_type_header = "application/json";
    if method == reqwest::Method::POST || method == reqwest::Method::PUT {
        headers_to_sign.insert("content-type", content_type_header);
    }
    let canonical_headers = headers_to_sign
        .iter()
        .map(|(k, v)| format!("{}:{}\n", k, v.trim()))
        .collect::<String>();
    let signed_headers = headers_to_sign
        .keys()
        .copied()
        .collect::<Vec<&str>>()
        .join(";");
    let hashed_request_payload = sha256_hex(payload_str.as_bytes());
    let canonical_request = format!(
        "{http_method}\n{canonical_uri}\n{canonical_query_string}\n{canonical_headers}\n{signed_headers}\n{hashed_request_payload}");
    let algorithm = "SDK-HMAC-SHA256";
    let hashed_canonical_request = sha256_hex(canonical_request.as_bytes());
    let string_to_sign =
        format!("{algorithm}\n{timestamp}\n{hashed_canonical_request}");
    let mut mac =
        Hmac::<Sha256>::new_from_slice(sk.as_bytes()).map_err(new_error)?;
    mac.update(string_to_sign.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());
    let authorization = format!(
        "{algorithm} Access={ak}, SignedHeaders={signed_headers}, Signature={signature}"
    );
    let mut headers = HeaderMap::new();
    headers.insert(HOST, host.parse().map_err(new_error)?);
    headers.insert("X-Sdk-Date", timestamp.parse().map_err(new_error)?);
    headers.insert(
        HeaderName::from_str("Authorization").map_err(new_error)?,
        authorization.parse().map_err(new_error)?,
    );
    if method == reqwest::Method::POST || method == reqwest::Method::PUT {
        headers.insert(
            CONTENT_TYPE,
            content_type_header.parse().map_err(new_error)?,
        );
    }
    let mut full_url = format!("{endpoint}{uri}");
    if !query.is_empty() {
        full_url.push('?');
        full_url.push_str(query);
    }
    let client = reqwest::Client::new();
    let response = client
        .request(method, &full_url)
        .headers(headers)
        .body(payload_str.to_string())
        .send()
        .await
        .map_err(new_error)?;
    let status = response.status();
    let body = response.text().await.map_err(new_error)?;
    if status.is_success() {
        Ok(body)
    } else {
        Err(new_error(format!("API Error: {status} - {body}")))
    }
}

async fn get_huawei_zone_id(
    ak: &str,
    sk: &str,
    region: &str,
    root_domain: &str,
) -> Result<String> {
    let query = format!("name={root_domain}");
    let uri_for_request = "/v2/zones";
    let uri_for_signature = "/v2/zones/";
    let host = format!("dns.{region}.myhuaweicloud.com");
    let endpoint = format!("https://{host}");
    let timestamp = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let canonical_request_for_sig = {
        let mut headers_to_sign = BTreeMap::new();
        headers_to_sign.insert("host", host.as_str());
        headers_to_sign.insert("x-sdk-date", &timestamp);
        let canonical_headers = headers_to_sign
            .iter()
            .map(|(k, v)| format!("{}:{}\n", k, v.trim()))
            .collect::<String>();
        let signed_headers = headers_to_sign
            .keys()
            .copied()
            .collect::<Vec<&str>>()
            .join(";");
        let hashed_payload = sha256_hex("".as_bytes());
        format!("GET\n{uri_for_signature}\n{query}\n{canonical_headers}\n{signed_headers}\n{hashed_payload}")
    };
    let algorithm = "SDK-HMAC-SHA256";
    let hashed_canonical_request =
        sha256_hex(canonical_request_for_sig.as_bytes());
    let string_to_sign =
        format!("{algorithm}\n{timestamp}\n{hashed_canonical_request}");
    let mut mac =
        Hmac::<Sha256>::new_from_slice(sk.as_bytes()).map_err(new_error)?;
    mac.update(string_to_sign.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());
    let authorization = format!(
        "{algorithm} Access={ak}, SignedHeaders=host;x-sdk-date, Signature={signature}"
    );
    let mut headers = HeaderMap::new();
    headers.insert(HOST, host.parse().map_err(new_error)?);
    headers.insert("X-Sdk-Date", timestamp.parse().map_err(new_error)?);
    headers.insert(
        HeaderName::from_str("Authorization").map_err(new_error)?,
        authorization.parse().map_err(new_error)?,
    );
    let full_url_for_request = format!("{endpoint}{uri_for_request}?{query}");
    let client = reqwest::Client::new();
    let response = client
        .get(&full_url_for_request)
        .headers(headers)
        .send()
        .await
        .map_err(new_error)?;
    let status = response.status();
    let body = response.text().await.map_err(new_error)?;
    if !status.is_success() {
        return Err(new_error(format!(
            "API Error after fix: {status} - {body}"
        )));
    }
    let resp: ZonesResponse = serde_json::from_str(&body).map_err(new_error)?;
    resp.zones
        .into_iter()
        .find(|z| z.name == format!("{root_domain}."))
        .map(|z| z.id)
        .ok_or_else(|| new_error(format!("zone for {root_domain} not found")))
}

async fn add_huawei_dns_record(
    access_key_id: &str,
    access_key_secret: &str,
    region: &str,
    zone_id: &str,
    full_record_name: &str,
    value: &str,
) -> Result<String> {
    // Apply the same contradictory URI logic as get_huawei_zone_id
    let uri_for_request = format!("/v2/zones/{zone_id}/recordsets");
    let uri_for_signature = format!("/v2/zones/{zone_id}/recordsets/");

    let txt_value_formatted = format!("\"{value}\"");
    let payload = json!({
        "name": full_record_name,
        "type": "TXT",
        "ttl": 300,
        "records": [txt_value_formatted]
    });
    let payload_str = payload.to_string();

    // Manually build the signature and request, just like in get_huawei_zone_id
    let host = format!("dns.{region}.myhuaweicloud.com");
    let endpoint = format!("https://{host}");
    let timestamp = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();

    let canonical_request_for_sig = {
        let mut headers_to_sign = BTreeMap::new();
        headers_to_sign.insert("host", host.as_str());
        headers_to_sign.insert("x-sdk-date", &timestamp);
        headers_to_sign.insert("content-type", "application/json");
        let canonical_headers = headers_to_sign
            .iter()
            .map(|(k, v)| format!("{}:{}\n", k, v.trim()))
            .collect::<String>();
        let signed_headers = headers_to_sign
            .keys()
            .copied()
            .collect::<Vec<&str>>()
            .join(";");
        let hashed_payload = sha256_hex(payload_str.as_bytes());
        format!("POST\n{uri_for_signature}\n\n{canonical_headers}\n{signed_headers}\n{hashed_payload}")
    };

    let algorithm = "SDK-HMAC-SHA256";
    let hashed_canonical_request =
        sha256_hex(canonical_request_for_sig.as_bytes());
    let string_to_sign =
        format!("{algorithm}\n{timestamp}\n{hashed_canonical_request}");
    let mut mac = Hmac::<Sha256>::new_from_slice(access_key_secret.as_bytes())
        .map_err(new_error)?;
    mac.update(string_to_sign.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    let authorization = format!(
        "{algorithm} Access={access_key_id}, SignedHeaders=content-type;host;x-sdk-date, Signature={signature}"
    );

    let mut headers = HeaderMap::new();
    headers.insert(HOST, host.parse().map_err(new_error)?);
    headers.insert("X-Sdk-Date", timestamp.parse().map_err(new_error)?);
    headers
        .insert(CONTENT_TYPE, "application/json".parse().map_err(new_error)?);
    headers.insert(
        HeaderName::from_str("Authorization").map_err(new_error)?,
        authorization.parse().map_err(new_error)?,
    );

    let full_url_for_request = format!("{endpoint}{uri_for_request}");

    let client = reqwest::Client::new();
    let response = client
        .post(&full_url_for_request)
        .headers(headers)
        .body(payload_str)
        .send()
        .await
        .map_err(new_error)?;

    let status = response.status();
    let body = response.text().await.map_err(new_error)?;
    if !status.is_success() {
        return Err(new_error(format!(
            "API Error after final fix: {status} - {body}"
        )));
    }

    let resp: Recordset = serde_json::from_str(&body).map_err(new_error)?;
    Ok(resp.id)
}

// The delete function acts on a specific resource ID, not a collection.
// It should NOT have the trailing slash. The general request function is fine for this.
async fn delete_huawei_dns_record(
    access_key_id: &str,
    access_key_secret: &str,
    region: &str,
    zone_id: &str,
    recordset_id: &str,
) -> Result<String> {
    let uri = format!("/v2/zones/{zone_id}/recordsets/{recordset_id}");
    huawei_cloud_api_request(
        access_key_id,
        access_key_secret,
        region,
        reqwest::Method::DELETE,
        &uri,
        "",
        "",
    )
    .await
}

// [The rest of the file (extract_root_domain, HuaweiDnsTask struct and impl) is unchanged and correct.]
fn extract_root_domain(full_domain: &str) -> Result<String> {
    let parts: Vec<&str> =
        full_domain.trim_end_matches('.').split('.').collect();
    if parts.len() < 2 {
        return Err(new_error(format!("Invalid domain: {full_domain}")));
    }
    Ok(parts
        .iter()
        .rev()
        .take(2)
        .rev()
        .cloned()
        .collect::<Vec<&str>>()
        .join("."))
}
#[derive(Default)]
struct TxtRecordInfo {
    zone_id: String,
    record_id: String,
}
pub(crate) struct HuaweiDnsTask {
    access_key_id: String,
    access_key_secret: String,
    region: String,
    txt_record_info: Mutex<TxtRecordInfo>,
}
impl HuaweiDnsTask {
    pub fn new(
        access_key_id: &str,
        access_key_secret: &str,
        region: &str,
    ) -> Self {
        Self {
            access_key_id: access_key_id.to_string(),
            access_key_secret: access_key_secret.to_string(),
            region: region.to_string(),
            txt_record_info: Mutex::new(TxtRecordInfo::default()),
        }
    }
}
#[async_trait]
impl AcmeDnsTask for HuaweiDnsTask {
    async fn add_txt_record(&self, domain: &str, value: &str) -> Result<()> {
        let root_domain = extract_root_domain(domain)?;
        let zone_id = get_huawei_zone_id(
            &self.access_key_id,
            &self.access_key_secret,
            &self.region,
            &root_domain,
        )
        .await?;
        let full_record_name = format!("{domain}.");
        let record_id = add_huawei_dns_record(
            &self.access_key_id,
            &self.access_key_secret,
            &self.region,
            &zone_id,
            &full_record_name,
            value,
        )
        .await?;
        let mut info = self.txt_record_info.lock().await;
        info.zone_id = zone_id;
        info.record_id = record_id;
        Ok(())
    }
    async fn done(&self) -> Result<()> {
        let mut info = self.txt_record_info.lock().await;
        if info.record_id.is_empty() {
            return Ok(());
        }
        delete_huawei_dns_record(
            &self.access_key_id,
            &self.access_key_secret,
            &self.region,
            &info.zone_id,
            &info.record_id,
        )
        .await?;
        info.zone_id.clear();
        info.record_id.clear();
        Ok(())
    }
}
