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

use super::{get_certificate_info, Cert, Error, Result};
use crate::http_extra::HttpResponse;
use crate::service::{CommonServiceTask, ServiceTask};
use crate::state::{restart_now, State};
use crate::util;
use crate::webhook;
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use http::StatusCode;
use instant_acme::{
    Account, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder, OrderStatus,
};
use once_cell::sync::OnceCell;
use pingora::proxy::Session;
use rcgen::{Certificate, CertificateParams, DistinguishedName};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tracing::{error, info};

static LETS_ENCRYPT: OnceCell<Mutex<HashMap<String, String>>> = OnceCell::new();

fn get_lets_encrypt() -> &'static Mutex<HashMap<String, String>> {
    LETS_ENCRYPT.get_or_init(|| Mutex::new(HashMap::new()))
}
struct LetsEncryptService {
    certificate_file: PathBuf,
    domains: Vec<String>,
}

/// Create a Let's Encrypt service to periodically detect and update https certificates
pub fn new_lets_encrypt_service(
    certificate_file: PathBuf,
    domains: Vec<String>,
) -> CommonServiceTask {
    let mut domains = domains;
    // sort domain order
    domains.sort();

    CommonServiceTask::new(
        "LetsEncrypt",
        Duration::from_secs(30 * 60),
        LetsEncryptService {
            certificate_file,
            domains,
        },
    )
}

#[async_trait]
impl ServiceTask for LetsEncryptService {
    async fn run(&self) -> Option<bool> {
        let domains = &self.domains;
        let should_renew_now = if let Ok(cert) = get_lets_encrypt_cert(&self.certificate_file) {
            !cert.valid() || domains.join(",") != cert.domains.join(",")
        } else {
            true
        };
        if should_renew_now {
            info!(domains = domains.join(","), "renew cert from let's encrypt");
            match new_lets_encrypt(&self.certificate_file, domains).await {
                Ok(()) => {
                    info!(domains = domains.join(","), "renew cert success");
                    if let Err(e) = restart_now() {
                        error!(
                            error = e.to_string(),
                            domains = domains.join(","),
                            "restart fail"
                        );
                    }
                }
                Err(e) => error!(
                    error = e.to_string(),
                    domains = domains.join(","),
                    "renew cert fail"
                ),
            };
        }
        None
    }
    fn description(&self) -> String {
        format!("domains: {:?}", self.domains)
    }
}

/// Get the cert from filea and convert it to cert struct.
pub fn get_lets_encrypt_cert(path: &PathBuf) -> Result<Cert> {
    if !path.exists() {
        return Err(Error::NotFound {
            message: "cert file not found".to_string(),
        });
    }
    let buf = std::fs::read(path).map_err(|e| Error::Io { source: e })?;
    let cert: Cert = serde_json::from_slice(&buf).map_err(|e| Error::SerdeJson { source: e })?;
    Ok(cert)
}

/// The proxy plugin for lets encrypt http-01.
pub async fn handle_lets_encrypt(session: &mut Session, ctx: &mut State) -> pingora::Result<bool> {
    let path = session.req_header().uri.path();
    if path.starts_with("/.well-known/acme-challenge/") {
        let value = {
            let data = get_lets_encrypt().lock().await;
            let v = data
                .get(path)
                .ok_or_else(|| util::new_internal_error(400, "token not found".to_string()))?;
            v.clone()
        };
        ctx.response_body_size = HttpResponse {
            status: StatusCode::OK,
            body: value.into(),
            ..Default::default()
        }
        .send(session)
        .await?;
        return Ok(true);
    }
    Ok(false)
}

/// Get the new cert from lets encrypt for all domains.
/// The cert will be saved if success.
async fn new_lets_encrypt(certificate_file: &PathBuf, domains: &[String]) -> Result<()> {
    let mut domains: Vec<String> = domains.to_vec();
    domains.sort();
    info!(domains = domains.join(","), "acme form let's encrypt");
    let (account, _) = Account::create(
        &NewAccount {
            contact: &[],
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        LetsEncrypt::Production.url(),
        None,
    )
    .await
    .map_err(|e| Error::Instant { source: e })?;

    // let identifier = Identifier::Dns(opts.name);
    let mut order = account
        .new_order(&NewOrder {
            identifiers: &domains
                .iter()
                .map(|item| Identifier::Dns(item.to_owned()))
                .collect::<Vec<Identifier>>(),
        })
        .await
        .map_err(|e| Error::Instant { source: e })?;

    let state = order.state();
    if !matches!(state.status, OrderStatus::Pending) {
        return Err(Error::Fail {
            message: format!("order is not pending, staus: {:?}", state.status),
        });
    }

    let authorizations = order
        .authorizations()
        .await
        .map_err(|e| Error::Instant { source: e })?;
    let mut challenges = Vec::with_capacity(authorizations.len());

    for authz in &authorizations {
        info!(
            status = format!("{:?}", authz.status),
            "acme from let's encrypt"
        );
        match authz.status {
            instant_acme::AuthorizationStatus::Pending => {}
            instant_acme::AuthorizationStatus::Valid => continue,
            _ => todo!(),
        }

        let challenge = authz
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Http01)
            .ok_or_else(|| Error::NotFound {
                message: "Http01 challenge not found".to_string(),
            })?;

        let instant_acme::Identifier::Dns(identifier) = &authz.identifier;

        let key_auth = order.key_authorization(challenge);

        // http://<你的域名>/.well-known/acme-challenge/<TOKEN>
        let well_known_path = format!("/.well-known/acme-challenge/{}", challenge.token);
        info!(well_known_path, "let's encrypt well known path",);

        let mut map = get_lets_encrypt().lock().await;
        map.insert(well_known_path, key_auth.as_str().to_string());

        challenges.push((identifier, &challenge.url));
    }
    for (_, url) in &challenges {
        order
            .set_challenge_ready(url)
            .await
            .map_err(|e| Error::Instant { source: e })?;
    }

    let mut tries = 1u8;
    let mut delay = Duration::from_millis(250);

    let detail_url = authorizations.first();

    let state = loop {
        let state = order.state();
        info!(status = format!("{:?}", state.status), "get order status");
        if let OrderStatus::Ready | OrderStatus::Invalid | OrderStatus::Valid = state.status {
            break state;
        }
        order
            .refresh()
            .await
            .map_err(|e| Error::Instant { source: e })?;

        delay *= 2;
        tries += 1;
        match tries < 10 {
            true => info!(delay = format!("{delay:?}"), "Order is not ready, waiting"),
            false => {
                return Err(Error::Fail {
                    message: format!(
                        "Giving up: order is not ready. For details, see the url: {detail_url:?}"
                    ),
                });
            }
        }
        tokio::time::sleep(delay).await;
    };
    if state.status == OrderStatus::Invalid {
        return Err(Error::Fail {
            message: format!("order is invalid, check {detail_url:?}"),
        });
    }
    let mut names = Vec::with_capacity(challenges.len());
    for (identifier, _) in challenges {
        names.push(identifier.to_owned());
    }

    let mut params = CertificateParams::new(names.clone());
    params.distinguished_name = DistinguishedName::new();
    let cert = Certificate::from_params(params).map_err(|e| Error::Rcgen { source: e })?;
    let csr = cert
        .serialize_request_der()
        .map_err(|e| Error::Rcgen { source: e })?;

    order
        .finalize(&csr)
        .await
        .map_err(|e| Error::Instant { source: e })?;
    let cert_chain_pem = loop {
        match order
            .certificate()
            .await
            .map_err(|e| Error::Instant { source: e })?
        {
            Some(cert_chain_pem) => break cert_chain_pem,
            None => tokio::time::sleep(Duration::from_secs(1)).await,
        }
    };
    let mut not_before = cert.get_params().not_before.unix_timestamp();
    let now = util::now().as_secs() as i64;
    // default expired time set 90 days
    let mut not_after = now + 90 * 24 * 3600;
    if let Ok(info) = get_certificate_info(cert_chain_pem.as_bytes()) {
        not_before = info.not_before;
        not_after = info.not_after;
    }

    let mut f = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(certificate_file)
        .await
        .map_err(|e| Error::Io { source: e })?;
    let info = Cert {
        domains: domains.to_vec(),
        not_after,
        not_before,
        pem: STANDARD.encode(cert_chain_pem.as_bytes()),
        key: STANDARD.encode(cert.serialize_private_key_pem().as_bytes()),
    };
    let buf = serde_json::to_vec(&info).map_err(|e| Error::SerdeJson { source: e })?;
    f.write(&buf).await.map_err(|e| Error::Io { source: e })?;
    info!(
        certificate_file = format!("{certificate_file:?}"),
        "write certificate success"
    );
    webhook::send(webhook::SendNotificationParams {
        level: webhook::NotificationLevel::Info,
        category: webhook::NotificationCategory::LetsEncrypt,
        msg: "Generate new cert from lets encrypt".to_string(),
    });

    Ok(())
}
