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

//! Generic HTTP webhook DNS-01 provider.
//!
//! Posts JSON `{action, domain, fqdn, record, zone, value}` to a user-operated
//! HTTP endpoint (`action = "present"` to add the TXT record and
//! `action = "cleanup"` to remove it), enabling any DNS provider without
//! compiling vendor SDKs into the Pingap binary.

use super::{AcmeDnsTask, Error, split_record_name};
use async_trait::async_trait;
use serde::Serialize;
use std::time::Duration;
use tokio::sync::Mutex;
use url::Url;

type Result<T, E = Error> = std::result::Result<T, E>;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

fn new_error(err: impl ToString) -> Error {
    Error::Fail {
        category: "webhook".to_string(),
        message: err.to_string(),
    }
}

#[derive(Debug, Serialize)]
struct WebhookPayload<'a> {
    action: &'a str,
    domain: &'a str,
    fqdn: String,
    record: String,
    zone: String,
    value: &'a str,
}

/// Generic HTTP webhook task implementing [`AcmeDnsTask`].
pub struct WebhookDnsTask {
    endpoint: String,
    auth_header: Option<(String, String)>,
    client: reqwest::Client,
    records: Mutex<Vec<(String, String)>>,
}

impl WebhookDnsTask {
    /// Builds a webhook DNS task from `dns_service_url`.
    ///
    /// Recognized query parameters (stripped from the forwarded URL):
    /// - `token`: optional credential sent as `Authorization: Bearer <token>`
    ///   (or `<header>: <token>` when `header` is also provided)
    /// - `header`: optional HTTP header name used with `token`
    /// - `timeout`: optional request timeout (e.g. `15s`, default `30s`)
    pub fn new(service_url: &str) -> Result<Self> {
        let mut parsed = Url::parse(service_url).map_err(new_error)?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none()
        {
            return Err(new_error(format!(
                "webhook dns_service_url must be an http or https url: {service_url}"
            )));
        }

        let mut token = None;
        let mut header_name = None;
        let mut timeout = DEFAULT_TIMEOUT;
        let mut kept_query: Vec<(String, String)> = Vec::new();

        for (k, v) in parsed.query_pairs() {
            match k.as_ref() {
                "token" => {
                    if !v.is_empty() {
                        token = Some(v.into_owned());
                    }
                },
                "header" => {
                    if !v.trim().is_empty() {
                        header_name = Some(v.trim().to_string());
                    }
                },
                "timeout" => {
                    if !v.trim().is_empty() {
                        timeout = pingap_util::parse_duration(v.trim())
                            .map_err(new_error)?;
                    }
                },
                _ => kept_query.push((k.into_owned(), v.into_owned())),
            }
        }

        if kept_query.is_empty() {
            parsed.set_query(None);
        } else {
            parsed.query_pairs_mut().clear().extend_pairs(kept_query);
        }

        let auth_header = token.map(|secret| match header_name {
            Some(name) => (name, secret),
            None => ("Authorization".to_string(), format!("Bearer {secret}")),
        });

        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(new_error)?;

        Ok(Self {
            endpoint: parsed.into(),
            auth_header,
            client,
            records: Mutex::new(Vec::new()),
        })
    }

    async fn post_action(
        &self,
        action: &str,
        domain: &str,
        value: &str,
    ) -> Result<()> {
        let trimmed = domain.trim_end_matches('.');
        let fqdn = format!("{trimmed}.");
        let (record, zone) = match split_record_name(trimmed) {
            Ok((record, zone)) => (record.to_string(), zone.to_string()),
            Err(_) => {
                // Non-public-suffix domains (e.g. internal `.test` / `.local`)
                // still carry the full record name so custom webhooks can act.
                let stripped =
                    trimmed.strip_prefix("_acme-challenge.").unwrap_or(trimmed);
                ("_acme-challenge".to_string(), stripped.to_string())
            },
        };
        let payload = WebhookPayload {
            action,
            domain: trimmed,
            fqdn,
            record,
            zone,
            value,
        };
        let mut req = self.client.post(&self.endpoint).json(&payload);
        if let Some((name, val)) = &self.auth_header {
            req = req.header(name, val);
        }
        let resp = req.send().await.map_err(new_error)?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(new_error(format!(
                "webhook {action} failed with {status}: {body}"
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl AcmeDnsTask for WebhookDnsTask {
    async fn add_txt_record(&self, domain: &str, value: &str) -> Result<()> {
        self.post_action("present", domain, value).await?;
        self.records
            .lock()
            .await
            .push((domain.to_string(), value.to_string()));
        Ok(())
    }

    async fn done(&self) -> Result<()> {
        let records = std::mem::take(&mut *self.records.lock().await);
        let mut first_err = None;
        for (domain, value) in records {
            if let Err(err) = self.post_action("cleanup", &domain, &value).await
                && first_err.is_none()
            {
                first_err = Some(err);
            }
        }
        if let Some(err) = first_err {
            return Err(err);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn spawn_mock_webhook(
        status: &'static str,
    ) -> (String, Arc<Mutex<Vec<(String, String)>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let captured_clone = captured.clone();

        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let captured = captured_clone.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    let raw = String::from_utf8_lossy(&buf[..n]).to_string();
                    let (head, body) =
                        raw.split_once("\r\n\r\n").unwrap_or((&raw, ""));
                    captured
                        .lock()
                        .await
                        .push((head.to_string(), body.to_string()));
                    let resp = format!(
                        "HTTP/1.1 {status}\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                });
            }
        });

        (format!("http://{addr}/acme"), captured)
    }

    #[tokio::test]
    async fn test_webhook_dns_present_and_cleanup() {
        let (base_url, captured) = spawn_mock_webhook("200 OK").await;
        let url = format!("{base_url}?token=secret123&env=prod&timeout=5s");
        let task = WebhookDnsTask::new(&url).unwrap();
        assert_eq!(format!("{base_url}?env=prod"), task.endpoint);

        task.add_txt_record("_acme-challenge.app.example.com", "digest-abc")
            .await
            .unwrap();
        task.done().await.unwrap();

        let requests = captured.lock().await;
        assert_eq!(2, requests.len());

        assert!(requests[0].0.contains("POST /acme?env=prod HTTP/1.1"));
        assert!(
            requests[0]
                .0
                .to_ascii_lowercase()
                .contains("authorization: bearer secret123")
        );
        let present: serde_json::Value =
            serde_json::from_str(&requests[0].1).unwrap();
        assert_eq!("present", present["action"]);
        assert_eq!("_acme-challenge.app.example.com", present["domain"]);
        assert_eq!("_acme-challenge.app.example.com.", present["fqdn"]);
        assert_eq!("_acme-challenge.app", present["record"]);
        assert_eq!("example.com", present["zone"]);
        assert_eq!("digest-abc", present["value"]);

        let cleanup: serde_json::Value =
            serde_json::from_str(&requests[1].1).unwrap();
        assert_eq!("cleanup", cleanup["action"]);
        assert_eq!("digest-abc", cleanup["value"]);
    }

    #[tokio::test]
    async fn test_webhook_dns_custom_header_and_error() {
        let (base_url, captured) =
            spawn_mock_webhook("500 Internal Server Error").await;
        let url = format!("{base_url}?token=key42&header=X-Api-Key");
        let task = WebhookDnsTask::new(&url).unwrap();
        let err = task
            .add_txt_record("_acme-challenge.example.com", "val")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("500"), "{err}");

        let requests = captured.lock().await;
        assert_eq!(1, requests.len());
        assert!(
            requests[0]
                .0
                .to_ascii_lowercase()
                .contains("x-api-key: key42")
        );
    }

    #[test]
    fn test_webhook_dns_rejects_invalid_url() {
        assert_eq!(true, WebhookDnsTask::new("ftp://example.com").is_err());
        assert_eq!(true, WebhookDnsTask::new("not-a-url").is_err());
    }
}
