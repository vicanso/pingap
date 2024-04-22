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

use crate::http_extra::HttpResponse;
use crate::state::State;
use crate::util;

use super::{CertInfo, Error, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use bytes::Bytes;
use http::StatusCode;
use instant_acme::{
    Account, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder, OrderStatus,
};
use log::{error, info};
use once_cell::sync::OnceCell;
use pingora::proxy::Session;
use pingora::{server::ShutdownWatch, services::background::BackgroundService};
use rcgen::{Certificate, CertificateParams, DistinguishedName};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

static LETS_ENCRYPT: OnceCell<Mutex<HashMap<String, String>>> = OnceCell::new();

fn get_lets_encrypt() -> &'static Mutex<HashMap<String, String>> {
    LETS_ENCRYPT.get_or_init(|| Mutex::new(HashMap::new()))
}

pub struct LetsEncryptService {
    pub domains: Vec<String>,
}

#[async_trait]
impl BackgroundService for LetsEncryptService {
    async fn start(&self, mut _shutdown: ShutdownWatch) {
        if let Err(e) = lets_encrypt(&self.domains).await {
            error!("lets encrypt, {e}");
        }
    }
}

fn get_lets_encrypt_cert_file(domains: &[String]) -> Result<PathBuf> {
    let tmp = dirs::template_dir().ok_or(Error::Fail {
        message: "get temp dir fail".to_string(),
    })?;
    Ok(tmp.join(format!("{}.json", domains.join("_"))))
}

pub async fn get_lets_encrypt_cert(domains: &[String]) -> Result<CertInfo> {
    let path = get_lets_encrypt_cert_file(domains)?;
    if !path.exists() {
        return Err(Error::NotFound {
            message: "cert file not found".to_string(),
        });
    }
    let buf = fs::read(&path).await.map_err(|e| Error::Io { source: e })?;
    let cert: CertInfo =
        serde_json::from_slice(&buf).map_err(|e| Error::SerdeJson { source: e })?;
    Ok(cert)
}

pub async fn handle_lets_encrypt(session: &mut Session, _ctx: &mut State) -> pingora::Result<bool> {
    let path = session.req_header().uri.path();
    if path.starts_with("/.well-known/acme-challenge/") {
        let value = {
            let data = get_lets_encrypt().lock().await;
            let v = data
                .get(path)
                .ok_or_else(|| util::new_internal_error(400, "token not found".to_string()))?;
            v.clone()
        };
        HttpResponse {
            status: StatusCode::OK,
            body: Bytes::from(value),
            ..Default::default()
        }
        .send(session)
        .await?;
        return Ok(true);
    }
    Ok(false)
}

async fn lets_encrypt(domains: &[String]) -> Result<()> {
    let path = get_lets_encrypt_cert_file(domains)?;

    let (account, _) = Account::create(
        &NewAccount {
            contact: &[],
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        LetsEncrypt::Staging.url(),
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
        // TODO return err
    }

    let authorizations = order
        .authorizations()
        .await
        .map_err(|e| Error::Instant { source: e })?;
    let mut challenges = Vec::with_capacity(authorizations.len());

    for authz in &authorizations {
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
        let well_nkown_path = format!("/.well-known/acme-challenge/{}", challenge.token);

        let mut map = get_lets_encrypt().lock().await;
        map.insert(well_nkown_path, key_auth.as_str().to_string());

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
        info!("Order state: {:?}", state.status);
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
            true => info!("order is not ready, waiting {delay:?}"),
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
    let not_after = cert.get_params().not_after.unix_timestamp();
    let not_before = cert.get_params().not_before.unix_timestamp();

    let mut f = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path)
        .await
        .map_err(|e| Error::Io { source: e })?;
    let info = CertInfo {
        not_after,
        not_before,
        pem: STANDARD.encode(cert_chain_pem.as_bytes()),
        key: STANDARD.encode(cert.serialize_private_key_pem().as_bytes()),
    };
    let buf = serde_json::to_vec(&info).map_err(|e| Error::SerdeJson { source: e })?;
    f.write(&buf).await.map_err(|e| Error::Io { source: e })?;
    info!("write cert success, {path:?}");

    Ok(())
}
