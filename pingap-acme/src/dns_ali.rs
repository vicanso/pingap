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

use super::{AcmeDnsTask, Error, LOG_TARGET, split_record_name};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use sha1::Sha1;
use std::collections::BTreeMap;
use tokio::sync::Mutex;
use tracing::{info, warn};
use url::Url;

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

/// What Aliyun says of a record that is there already: one of the same
/// name, type and value. A second value under a name is no duplicate.
const DUPLICATE_RECORD: &str = "DomainRecordDuplicate";

/// The `Code` of what Aliyun answers a request it refuses with.
fn error_code(body: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct ErrorResponse {
        #[serde(rename = "Code")]
        code: String,
    }
    serde_json::from_str::<ErrorResponse>(body)
        .ok()
        .map(|response| response.code)
}

/// A request Aliyun refused: the error, and the code it was refused with.
struct ApiError {
    code: Option<String>,
    error: Box<Error>,
}

impl From<Error> for ApiError {
    fn from(error: Error) -> Self {
        Self {
            code: None,
            error: Box::new(error),
        }
    }
}

#[derive(Deserialize, Debug)]
struct DomainRecord {
    #[serde(rename = "RecordId")]
    record_id: String,
    #[serde(rename = "Value")]
    value: String,
}

#[derive(Deserialize, Debug, Default)]
struct DomainRecords {
    #[serde(rename = "Record", default)]
    record: Vec<DomainRecord>,
}

#[derive(Deserialize, Debug)]
struct DescribeRecordsResponse {
    #[serde(rename = "DomainRecords", default)]
    domain_records: DomainRecords,
}

/// Aliyun's signature encoding: RFC 3986 unreserved characters as they
/// are, everything else `%XX` - a space is `%20`, not `+`, and `*` is
/// `%2A`. The form encoder used before got those two wrong.
fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
        {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Aliyun API request
async fn ali_api_request(
    client: &reqwest::Client,
    endpoint: &str,
    access_key_id: &str,
    access_key_secret: &str,
    // btree is ordered map
    params: &mut BTreeMap<&str, String>,
) -> std::result::Result<String, ApiError> {
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

    // Without the url in the error: it has the access key id and the
    // signature of the request in its query.
    let response = client
        .get(&request_url)
        .send()
        .await
        .map_err(|e| new_error(e.without_url()))?;

    if response.status().is_success() {
        Ok(response.text().await.map_err(new_error)?)
    } else {
        let status = response.status();
        let error_body = response.text().await.map_err(new_error)?;
        Err(ApiError {
            code: error_code(&error_body),
            error: Box::new(new_error(format!(
                "API Error: {status} - {error_body}"
            ))),
        })
    }
}

/// add a dns txt record
async fn add_ali_dns_record(
    client: &reqwest::Client,
    endpoint: &str,
    access_key_id: &str,
    access_key_secret: &str,
    domain: &str,
    value: &str,
) -> std::result::Result<AddRecordResponse, ApiError> {
    let mut params = BTreeMap::new();
    let (rr, domain_name) = split_record_name(domain)?;
    params.insert("Action", "AddDomainRecord".to_string());
    params.insert("DomainName", domain_name.to_string());
    params.insert("RR", rr.to_string());
    params.insert("Type", "TXT".to_string());
    params.insert("Value", value.to_string());

    let response_body = ali_api_request(
        client,
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

/// The id of the TXT record of `domain` that holds `value`, where there
/// is one.
async fn find_ali_dns_record(
    client: &reqwest::Client,
    endpoint: &str,
    access_key_id: &str,
    access_key_secret: &str,
    domain: &str,
    value: &str,
) -> Result<Option<String>> {
    let mut params = BTreeMap::new();
    let (_, domain_name) = split_record_name(domain)?;
    params.insert("Action", "DescribeSubDomainRecords".to_string());
    params.insert("SubDomain", domain.trim_end_matches('.').to_string());
    params.insert("DomainName", domain_name.to_string());
    params.insert("Type", "TXT".to_string());
    params.insert("PageSize", "100".to_string());

    let response_body = ali_api_request(
        client,
        endpoint,
        access_key_id,
        access_key_secret,
        &mut params,
    )
    .await
    .map_err(|e| *e.error)?;
    let response: DescribeRecordsResponse =
        serde_json::from_str(&response_body).map_err(new_error)?;
    Ok(response
        .domain_records
        .record
        .into_iter()
        .find(|record| record.value == value)
        .map(|record| record.record_id))
}

async fn delete_ali_dns_record(
    client: &reqwest::Client,
    endpoint: &str,
    access_key_id: &str,
    access_key_secret: &str,
    record_id: &str,
) -> Result<String> {
    let mut params = BTreeMap::new();
    params.insert("Action", "DeleteDomainRecord".to_string());
    params.insert("RecordId", record_id.to_string());

    ali_api_request(
        client,
        endpoint,
        access_key_id,
        access_key_secret,
        &mut params,
    )
    .await
    .map_err(|e| *e.error)
}

pub(crate) struct AliDnsTask {
    /// One client for the task: the calls share its connection pool.
    client: reqwest::Client,
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
            client: reqwest::Client::new(),
            access_key_id,
            access_key_secret,
            endpoint,
            record: Mutex::new(String::new()),
        })
    }
}

#[async_trait]
impl AcmeDnsTask for AliDnsTask {
    /// Adds the record, or takes over the one that is there already.
    ///
    /// A record with this very value is one an order before this one put
    /// there and did not get to remove: the process was stopped, or the
    /// order ran out of time. The CA hands out the challenge of an order
    /// it has not seen finished again, so the next order asks for the same
    /// value - and Aliyun refuses a record that exists. That was the end
    /// of every order from then on, for as long as the CA kept the
    /// challenge, which is days. The record is what the CA is to find, so
    /// it is used as it is, and removed with the others when the order is
    /// done.
    async fn add_txt_record(&self, domain: &str, value: &str) -> Result<()> {
        let added = add_ali_dns_record(
            &self.client,
            &self.endpoint,
            &self.access_key_id,
            &self.access_key_secret,
            domain,
            value,
        )
        .await;
        let record_id = match added {
            Ok(response) => response.record_id,
            Err(e) if e.code.as_deref() == Some(DUPLICATE_RECORD) => {
                let found = find_ali_dns_record(
                    &self.client,
                    &self.endpoint,
                    &self.access_key_id,
                    &self.access_key_secret,
                    domain,
                    value,
                )
                .await;
                match found {
                    Ok(Some(record_id)) => {
                        info!(
                            target: LOG_TARGET,
                            domain,
                            record_id,
                            "the dns txt record is there already, taking it over"
                        );
                        record_id
                    },
                    // It is there all the same, Aliyun has said so: the
                    // order goes on, and this record is left behind.
                    found => {
                        warn!(
                            target: LOG_TARGET,
                            domain,
                            error = found.err().map(|e| e.to_string()),
                            "the dns txt record is there already and was not found to take over: it will not be removed"
                        );
                        String::new()
                    },
                }
            },
            Err(e) => return Err(*e.error),
        };
        let mut record = self.record.lock().await;
        *record = record_id;
        Ok(())
    }

    async fn done(&self) -> Result<()> {
        let mut record = self.record.lock().await;
        if record.is_empty() {
            return Ok(());
        }
        delete_ali_dns_record(
            &self.client,
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

#[cfg(test)]
mod tests {
    use super::{AcmeDnsTask, AliDnsTask, percent_encode};
    use pretty_assertions::assert_eq;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// What Aliyun answered on 2026-10-11 to a record that was there.
    const DUPLICATE: &str = r#"{"RequestId":"01A128E3-0720-58A4-9D8E-721FB0EDA53D","HostId":"alidns.aliyuncs.com","Code":"DomainRecordDuplicate","Message":"The DNS record already exists.","Recommend":"https://api.aliyun.com/troubleshoot?q=DomainRecordDuplicate&product=Alidns&requestId=01A128E3-0720-58A4-9D8E-721FB0EDA53D"}"#;

    /// An Aliyun that has two records of `_acme-challenge.example.com`
    /// already, `left-behind` among them, and says of every call what was
    /// asked: the action and the parameter that names its record.
    async fn aliyun() -> (String, Arc<Mutex<Vec<String>>>) {
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "http://{}/?access_key_id=id&access_key_secret=secret",
            listener.local_addr().unwrap()
        );
        let calls = Arc::new(Mutex::new(vec![]));
        let seen = calls.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let seen = seen.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    let head = String::from_utf8_lossy(&buf[..n]).to_string();
                    let target = head.split(' ').nth(1).unwrap_or_default();
                    let query = target.split_once('?').map_or("", |(_, q)| q);
                    let param = |name: &str| {
                        url::form_urlencoded::parse(query.as_bytes())
                            .find(|(key, _)| key == name)
                            .map(|(_, value)| value.to_string())
                            .unwrap_or_default()
                    };
                    let action = param("Action");
                    let (status, body) = match action.as_str() {
                        "AddDomainRecord" => {
                            seen.lock().unwrap().push(format!(
                                "add {}.{} {}",
                                param("RR"),
                                param("DomainName"),
                                param("Value")
                            ));
                            match param("Value").as_str() {
                                "left-behind" | "nowhere" => {
                                    ("400 Bad Request", DUPLICATE.to_string())
                                },
                                "refused" => (
                                    "404 Not Found",
                                    r#"{"Code":"InvalidAccessKeyId.NotFound","Message":"Specified access key is not found."}"#.to_string(),
                                ),
                                _ => (
                                    "200 OK",
                                    r#"{"RequestId":"r","RecordId":"1001"}"#
                                        .to_string(),
                                ),
                            }
                        },
                        "DescribeSubDomainRecords"
                            if param("SubDomain").contains("locked") =>
                        {
                            seen.lock()
                                .unwrap()
                                .push(format!("find {}", param("SubDomain")));
                            (
                                "403 Forbidden",
                                r#"{"Code":"Forbidden.RAM","Message":"User not authorized to operate on the specified resource."}"#.to_string(),
                            )
                        },
                        "DescribeSubDomainRecords" => {
                            seen.lock().unwrap().push(format!(
                                "find {} in {}",
                                param("SubDomain"),
                                param("DomainName")
                            ));
                            (
                                "200 OK",
                                r#"{"TotalCount":2,"PageSize":100,"RequestId":"r","DomainRecords":{"Record":[{"RR":"_acme-challenge","Status":"ENABLE","Value":"of-the-other-name","RecordId":"2001","Type":"TXT","DomainName":"example.com","TTL":600},{"RR":"_acme-challenge","Status":"ENABLE","Value":"left-behind","RecordId":"2002","Type":"TXT","DomainName":"example.com","TTL":600}]},"PageNumber":1}"#.to_string(),
                            )
                        },
                        "DeleteDomainRecord" => {
                            seen.lock()
                                .unwrap()
                                .push(format!("delete {}", param("RecordId")));
                            (
                                "200 OK",
                                r#"{"RequestId":"r","RecordId":"x"}"#
                                    .to_string(),
                            )
                        },
                        _ => ("400 Bad Request", "{}".to_string()),
                    };
                    let _ = stream
                        .write_all(
                            format!(
                                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                body.len()
                            )
                            .as_bytes(),
                        )
                        .await;
                });
            }
        });
        (url, calls)
    }

    /// A record that is there already is taken over, and removed when the
    /// order is done.
    ///
    /// Regression: an order that was stopped after it had added its
    /// record - the process restarted, the order ran out of time - left
    /// it behind. The CA hands out the challenge of an unfinished order
    /// again, so the next order asked for the same value, Aliyun refused
    /// the record as a duplicate, and so it went for every order after
    /// that until the CA let go of the challenge, days later.
    #[tokio::test]
    async fn test_add_takes_over_a_record_that_is_there() {
        let name = "_acme-challenge.example.com";
        let (url, calls) = aliyun().await;
        let took = |calls: &Arc<Mutex<Vec<String>>>| {
            std::mem::take(&mut *calls.lock().unwrap())
        };
        // Straight to the address it is given, whatever proxy the
        // environment of the test run names.
        let new_task = |url: &str| {
            let mut task = AliDnsTask::new(url).unwrap();
            task.client =
                reqwest::Client::builder().no_proxy().build().unwrap();
            task
        };

        // As ever: added, and removed by the id it was given.
        let task = new_task(&url);
        task.add_txt_record(name, "fresh").await.unwrap();
        task.done().await.unwrap();
        assert_eq!(
            vec![
                "add _acme-challenge.example.com fresh".to_string(),
                "delete 1001".to_string(),
            ],
            took(&calls)
        );

        // There already: looked for by its value among the records of
        // the name (the other name of the certificate has one too), and
        // removed like one of this order's own.
        let task = new_task(&url);
        task.add_txt_record(name, "left-behind").await.unwrap();
        task.done().await.unwrap();
        assert_eq!(
            vec![
                "add _acme-challenge.example.com left-behind".to_string(),
                "find _acme-challenge.example.com in example.com".to_string(),
                "delete 2002".to_string(),
            ],
            took(&calls)
        );
        // Done once: a second call has nothing left to remove.
        task.done().await.unwrap();
        assert_eq!(true, took(&calls).is_empty());

        // Said to be there and not found: the order goes on all the
        // same, and nothing is removed that this task cannot name.
        let task = new_task(&url);
        task.add_txt_record(name, "nowhere").await.unwrap();
        task.done().await.unwrap();
        assert_eq!(
            vec![
                "add _acme-challenge.example.com nowhere".to_string(),
                "find _acme-challenge.example.com in example.com".to_string(),
            ],
            took(&calls)
        );

        // And where the key may add and remove records and not list
        // them, the same: the takeover is a convenience, the order is
        // not to depend on it.
        let locked = "_acme-challenge.locked.example.com";
        let task = new_task(&url);
        task.add_txt_record(locked, "left-behind").await.unwrap();
        task.done().await.unwrap();
        assert_eq!(
            vec![
                "add _acme-challenge.locked.example.com left-behind"
                    .to_string(),
                "find _acme-challenge.locked.example.com".to_string(),
            ],
            took(&calls)
        );

        // Any other refusal is one.
        let task = new_task(&url);
        let error = task.add_txt_record(name, "refused").await.unwrap_err();
        assert_eq!(
            true,
            error.to_string().contains("InvalidAccessKeyId.NotFound"),
            "{error}"
        );
        task.done().await.unwrap();
        assert_eq!(
            vec!["add _acme-challenge.example.com refused".to_string()],
            took(&calls)
        );
    }

    #[test]
    fn test_percent_encode() {
        assert_eq!("abc-_.~", percent_encode("abc-_.~"));
        assert_eq!("a%20b%2Ac", percent_encode("a b*c"));
        assert_eq!(
            "2024-01-01T00%3A00%3A00Z",
            percent_encode("2024-01-01T00:00:00Z")
        );
        assert_eq!("%2F%3D%26", percent_encode("/=&"));
    }
}
