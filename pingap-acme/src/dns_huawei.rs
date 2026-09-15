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
use hmac::{Hmac, KeyInit, Mac};
use reqwest::header::{CONTENT_TYPE, HOST, HeaderMap, HeaderName};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::str::FromStr;
use tokio::sync::Mutex;
use url::Url;

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
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

struct HuaweiAuthParams {
    host: String,
    endpoint: String,
    access_key_id: String,
    access_key_secret: String,
}

/// One signed request to the Huawei Cloud DNS API (SDK-HMAC-SHA256).
///
/// `sign_uri` is the path as it goes into the canonical request; Huawei
/// signs collection paths with a trailing slash (`/v2/zones/`) while the
/// request itself goes without, and a single resource (`.../recordsets/<id>`)
/// is signed as requested. The three calls below used to each carry their
/// own copy of this signing code.
async fn huawei_cloud_api_request(
    client: &reqwest::Client,
    params: &HuaweiAuthParams,
    method: reqwest::Method,
    uri: &str,
    sign_uri: &str,
    query: &str,
    payload_str: &str,
) -> Result<String> {
    let host = params.host.as_str();
    let timestamp = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let with_body =
        method == reqwest::Method::POST || method == reqwest::Method::PUT;
    let content_type = "application/json";
    let mut headers_to_sign = BTreeMap::new();
    headers_to_sign.insert("host", host);
    headers_to_sign.insert("x-sdk-date", &timestamp);
    if with_body {
        headers_to_sign.insert("content-type", content_type);
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
    let hashed_payload = sha256_hex(payload_str.as_bytes());
    let canonical_request = format!(
        "{}\n{sign_uri}\n{query}\n{canonical_headers}\n{signed_headers}\n{hashed_payload}",
        method.as_str()
    );
    let algorithm = "SDK-HMAC-SHA256";
    let string_to_sign = format!(
        "{algorithm}\n{timestamp}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let mut mac =
        Hmac::<Sha256>::new_from_slice(params.access_key_secret.as_bytes())
            .map_err(new_error)?;
    mac.update(string_to_sign.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());
    let authorization = format!(
        "{algorithm} Access={}, SignedHeaders={signed_headers}, Signature={signature}",
        params.access_key_id
    );

    let mut headers = HeaderMap::new();
    headers.insert(HOST, host.parse().map_err(new_error)?);
    headers.insert("X-Sdk-Date", timestamp.parse().map_err(new_error)?);
    headers.insert(
        HeaderName::from_str("Authorization").map_err(new_error)?,
        authorization.parse().map_err(new_error)?,
    );
    if with_body {
        headers.insert(CONTENT_TYPE, content_type.parse().map_err(new_error)?);
    }
    let mut full_url = format!("{}{uri}", params.endpoint);
    if !query.is_empty() {
        full_url.push('?');
        full_url.push_str(query);
    }
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
    client: &reqwest::Client,
    params: &HuaweiAuthParams,
    root_domain: &str,
) -> Result<String> {
    let body = huawei_cloud_api_request(
        client,
        params,
        reqwest::Method::GET,
        "/v2/zones",
        "/v2/zones/",
        &format!("name={root_domain}"),
        "",
    )
    .await?;
    let resp: ZonesResponse = serde_json::from_str(&body).map_err(new_error)?;
    resp.zones
        .into_iter()
        .find(|z| z.name == format!("{root_domain}."))
        .map(|z| z.id)
        .ok_or_else(|| new_error(format!("zone for {root_domain} not found")))
}

async fn add_huawei_dns_record(
    client: &reqwest::Client,
    params: &HuaweiAuthParams,
    zone_id: &str,
    full_record_name: &str,
    value: &str,
) -> Result<String> {
    let payload = json!({
        "name": full_record_name,
        "type": "TXT",
        "ttl": 300,
        "records": [format!("\"{value}\"")]
    });
    let body = huawei_cloud_api_request(
        client,
        params,
        reqwest::Method::POST,
        &format!("/v2/zones/{zone_id}/recordsets"),
        &format!("/v2/zones/{zone_id}/recordsets/"),
        "",
        &payload.to_string(),
    )
    .await?;
    let resp: Recordset = serde_json::from_str(&body).map_err(new_error)?;
    Ok(resp.id)
}

async fn delete_huawei_dns_record(
    client: &reqwest::Client,
    params: &HuaweiAuthParams,
    zone_id: &str,
    recordset_id: &str,
) -> Result<String> {
    let uri = format!("/v2/zones/{zone_id}/recordsets/{recordset_id}");
    huawei_cloud_api_request(
        client,
        params,
        reqwest::Method::DELETE,
        &uri,
        &uri,
        "",
        "",
    )
    .await
}

/// The registrable domain that names the zone: `example.co.uk` for
/// `_acme-challenge.sub.example.co.uk`, resolved against the public suffix
/// list. Taking the last two labels, as before, named `co.uk`.
fn extract_root_domain(full_domain: &str) -> Result<String> {
    let name = full_domain.trim_end_matches('.');
    psl::domain_str(name)
        .filter(|domain| domain.contains('.'))
        .map(str::to_string)
        .ok_or_else(|| new_error(format!("Invalid domain: {full_domain}")))
}

#[derive(Default)]
struct TxtRecordInfo {
    zone_id: String,
    record_id: String,
}
pub(crate) struct HuaweiDnsTask {
    /// One client for the task: the calls share its connection pool.
    client: reqwest::Client,
    params: HuaweiAuthParams,
    txt_record_info: Mutex<TxtRecordInfo>,
}
impl HuaweiDnsTask {
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
            client: reqwest::Client::new(),
            params: HuaweiAuthParams {
                host,
                endpoint,
                access_key_id,
                access_key_secret,
            },
            txt_record_info: Mutex::new(TxtRecordInfo::default()),
        })
    }
}
#[async_trait]
impl AcmeDnsTask for HuaweiDnsTask {
    async fn add_txt_record(&self, domain: &str, value: &str) -> Result<()> {
        let root_domain = extract_root_domain(domain)?;
        let zone_id =
            get_huawei_zone_id(&self.client, &self.params, &root_domain)
                .await?;
        let full_record_name = format!("{domain}.");
        let record_id = add_huawei_dns_record(
            &self.client,
            &self.params,
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
            &self.client,
            &self.params,
            &info.zone_id,
            &info.record_id,
        )
        .await?;
        info.zone_id.clear();
        info.record_id.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::extract_root_domain;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_extract_root_domain() {
        assert_eq!(
            "example.com",
            extract_root_domain("_acme-challenge.sub.example.com").unwrap()
        );
        assert_eq!(
            "example.co.uk",
            extract_root_domain("_acme-challenge.example.co.uk.").unwrap()
        );
        assert_eq!("example.com", extract_root_domain("example.com").unwrap());
        assert_eq!(true, extract_root_domain("com").is_err());
        assert_eq!(true, extract_root_domain("localhost").is_err());
    }
}
