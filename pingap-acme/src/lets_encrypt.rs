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

use super::{get_token_path, Error, Result, LOG_CATEGORY};
use instant_acme::{
    Account, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus,
};
use pingap_certificate::rcgen;
use pingap_certificate::{try_update_certificates, Certificate};
use pingap_config::{
    get_current_config, set_current_config, ConfigStorage, LoadConfigOptions,
    PingapConf, CATEGORY_CERTIFICATE,
};
use pingap_core::Error as ServiceError;
use pingap_core::HttpResponse;
use pingap_core::SimpleServiceTaskFuture;
use pingap_core::{Ctx, NotificationData, NotificationLevel};
use pingap_webhook::send_notification;
use pingora::http::StatusCode;
use pingora::proxy::Session;
use std::time::Duration;
use substring::Substring;
use tracing::{error, info};

static WELL_KNOWN_PATH_PREFIX: &str = "/.well-known/acme-challenge/";

/// Updates the certificate for the given name and domains using Let's Encrypt.
/// This function will:
/// 1. Generate a new certificate from Let's Encrypt
/// 2. Update the configuration with the new certificate
/// 3. Save the updated configuration
async fn update_certificate_lets_encrypt(
    storage: &'static (dyn ConfigStorage + Sync + Send),
    name: &str,
    domains: &[String],
) -> Result<PingapConf> {
    // get new certificate from lets encrypt
    let (pem, key) = new_lets_encrypt(storage, domains, true).await?;
    let mut conf = storage
        .load_config(LoadConfigOptions {
            ..Default::default()
        })
        .await
        .map_err(|e| Error::Fail {
            category: "load_config".to_string(),
            message: e.to_string(),
        })?;

    if let Some(cert) = conf.certificates.get_mut(name) {
        cert.tls_cert = Some(pem);
        cert.tls_key = Some(key);
    }
    storage
        .save_config(&conf, CATEGORY_CERTIFICATE, Some(name))
        .await
        .map_err(|e| Error::Fail {
            category: "save_config".to_string(),
            message: e.to_string(),
        })?;

    Ok(conf)
}

/// Periodically checks and updates certificates that need renewal.
/// A certificate needs renewal if:
/// - It is invalid or expired
/// - The configured domains have changed
/// - The certificate cannot be loaded
///
/// The check runs every UPDATE_INTERVAL iterations to avoid excessive checks.
async fn do_update_certificates(
    count: u32,
    storage: &'static (dyn ConfigStorage + Sync + Send),
    params: &[(String, Vec<String>)],
) -> Result<bool, ServiceError> {
    const UPDATE_INTERVAL: u32 = 10;
    if count % UPDATE_INTERVAL != 0 {
        return Ok(false);
    }

    for (name, domains) in params.iter() {
        let should_renew = match get_lets_encrypt_certificate(name) {
            Ok(certificate) => {
                // check if certificate is valid or domains changed
                let needs_renewal = !certificate.valid();
                let domains_changed = {
                    let mut sorted_domains = domains.clone();
                    let mut cert_domains = certificate.domains.clone();
                    sorted_domains.sort();
                    cert_domains.sort();
                    sorted_domains != cert_domains
                };
                needs_renewal || domains_changed
            },
            Err(e) => {
                error!(
                    category = LOG_CATEGORY,
                    error = %e,
                    name,
                    "failed to get certificate"
                );
                true
            },
        };

        if !should_renew {
            info!(
                category = LOG_CATEGORY,
                domains = domains.join(","),
                name,
                "certificate still valid"
            );
            continue;
        }

        if let Err(e) = renew_certificate(storage, name, domains).await {
            error!(
                category = LOG_CATEGORY,
                error = %e,
                domains = domains.join(","),
                name,
                "certificate renewal failed, will retry later"
            );
        }
    }
    Ok(true)
}

async fn renew_certificate(
    storage: &'static (dyn ConfigStorage + Sync + Send),
    name: &str,
    domains: &[String],
) -> Result<()> {
    let conf = update_certificate_lets_encrypt(storage, name, domains).await?;
    set_current_config(&conf);
    handle_successful_renewal(domains, &conf).await;
    Ok(())
}

async fn handle_successful_renewal(domains: &[String], conf: &PingapConf) {
    info!(
        category = LOG_CATEGORY,
        domains = domains.join(","),
        "renew certificate success"
    );

    send_notification(NotificationData {
        category: "lets_encrypt".to_string(),
        title: "Generate new cert from let's encrypt".to_string(),
        message: format!("Domains: {domains:?}"),
        ..Default::default()
    })
    .await;

    let (_, error) = try_update_certificates(&conf.certificates);
    if !error.is_empty() {
        error!(
            category = LOG_CATEGORY,
            error = error,
            "parse certificate fail"
        );
        send_notification(NotificationData {
            category: "parse_certificate_fail".to_string(),
            level: NotificationLevel::Error,
            message: error,
            ..Default::default()
        })
        .await;
    }
}

/// Create a Let's Encrypt service to generate the certificate,
/// and regenerate if the certificate is invalid or will be expired.
pub fn new_lets_encrypt_service(
    storage: &'static (dyn ConfigStorage + Sync + Send),
) -> (String, SimpleServiceTaskFuture) {
    let task: SimpleServiceTaskFuture = Box::new(move |count: u32| {
        Box::pin({
            async move {
                let mut params = vec![];
                for (name, certificate) in
                    get_current_config().certificates.iter()
                {
                    let acme = certificate.acme.clone().unwrap_or_default();
                    let domains =
                        certificate.domains.clone().unwrap_or_default();
                    if acme.is_empty() || domains.is_empty() {
                        continue;
                    }
                    params.push((
                        name.to_string(),
                        domains
                            .split(',')
                            .map(|item| item.to_string())
                            .collect(),
                    ));
                }
                do_update_certificates(count, storage, &params).await
            }
        })
    });
    ("lets_encrypt".to_string(), task)
}

/// Get the cert from file and convert it to certificate struct.
pub fn get_lets_encrypt_certificate(name: &str) -> Result<Certificate> {
    let binding = get_current_config();
    let Some(cert) = binding.certificates.get(name) else {
        return Err(Error::NotFound {
            message: "cert not found".to_string(),
        });
    };
    Certificate::new(
        cert.tls_cert.clone().unwrap_or_default().as_str(),
        cert.tls_key.clone().unwrap_or_default().as_str(),
    )
    .map_err(|e| Error::Fail {
        category: "new_certificate".to_string(),
        message: e.to_string(),
    })
}

/// Handles the HTTP-01 challenge verification for Let's Encrypt.
/// This function:
/// 1. Intercepts requests to /.well-known/acme-challenge/
/// 2. Extracts the challenge token from the URL path
/// 3. Loads the pre-stored token response from storage
/// 4. Returns the token response to validate domain ownership
pub async fn handle_lets_encrypt(
    storage: &'static (dyn ConfigStorage + Sync + Send),
    session: &mut Session,
    _ctx: &mut Ctx,
) -> pingora::Result<bool> {
    let path = session.req_header().uri.path();
    // lets encrypt acme challenge path
    if path.starts_with(WELL_KNOWN_PATH_PREFIX) {
        // token auth
        let token = path.substring(WELL_KNOWN_PATH_PREFIX.len(), path.len());

        let value =
            storage.load(&get_token_path(token)).await.map_err(|e| {
                error!(
                    category = LOG_CATEGORY,
                    error = %e,
                    token,
                    "load http-01 token fail"
                );
                pingora::Error::because(
                    pingora::ErrorType::HTTPStatus(500),
                    e.to_string(),
                    pingora::Error::new(pingora::ErrorType::InternalError),
                )
            })?;
        info!(
            category = LOG_CATEGORY,
            token, "let't encrypt http-01 success"
        );
        HttpResponse {
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

/// Generates a new certificate from Let's Encrypt for the given domains.
/// The ACME protocol flow:
/// 1. Creates/retrieves an ACME account with Let's Encrypt
/// 2. Creates a new order for the domains to be certified
/// 3. For each domain:
///    - Gets the HTTP-01 challenge details
///    - Stores the challenge token response
///    - Notifies Let's Encrypt that the challenge is ready
/// 4. Waits for Let's Encrypt to verify domain ownership
/// 5. Generates a CSR (Certificate Signing Request)
/// 6. Submits the CSR and retrieves the signed certificate
///
/// Returns a tuple of (certificate_chain_pem, private_key_pem)
async fn new_lets_encrypt(
    storage: &'static (dyn ConfigStorage + Sync + Send),
    domains: &[String],
    production: bool,
) -> Result<(String, String)> {
    let mut domains: Vec<String> = domains.to_vec();
    // sort domain for comparing later
    domains.sort();
    info!(
        category = LOG_CATEGORY,
        domains = domains.join(","),
        "acme from let's encrypt"
    );
    let url = if production {
        LetsEncrypt::Production.url()
    } else {
        LetsEncrypt::Staging.url()
    };
    let (account, _) = Account::create(
        &NewAccount {
            contact: &[],
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        url,
        None,
    )
    .await
    .map_err(|e| Error::Instant {
        category: "create_account".to_string(),
        source: e,
    })?;

    let mut order = account
        .new_order(&NewOrder {
            identifiers: &domains
                .iter()
                .map(|item| Identifier::Dns(item.to_owned()))
                .collect::<Vec<Identifier>>(),
        })
        .await
        .map_err(|e| Error::Instant {
            category: "new_order".to_string(),
            source: e,
        })?;

    let state = order.state();
    if !matches!(state.status, OrderStatus::Pending) {
        return Err(Error::Fail {
            message: format!(
                "order is not pending, status: {:?}",
                state.status
            ),
            category: "order_status".to_string(),
        });
    }

    let authorizations =
        order.authorizations().await.map_err(|e| Error::Instant {
            category: "authorizations".to_string(),
            source: e,
        })?;
    let mut challenges = Vec::with_capacity(authorizations.len());

    for authz in &authorizations {
        info!(
            category = LOG_CATEGORY,
            status = format!("{:?}", authz.status),
            "authorization from let's encrypt"
        );
        match authz.status {
            instant_acme::AuthorizationStatus::Pending => {},
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
        storage
            .save(
                &get_token_path(&challenge.token),
                key_auth.as_str().as_bytes(),
            )
            .await
            .map_err(|e| Error::Fail {
                category: "save_token".to_string(),
                message: e.to_string(),
            })?;

        info!(
            category = LOG_CATEGORY,
            token = challenge.token,
            "let's encrypt well known path",
        );

        challenges.push((identifier, &challenge.url));
    }
    // set challenge ready for verification
    for (_, url) in &challenges {
        order
            .set_challenge_ready(url)
            .await
            .map_err(|e| Error::Instant {
                category: "set_challenge_ready".to_string(),
                source: e,
            })?;
    }

    // get order state, retry later if fail
    let mut tries = 1u8;
    let mut delay = Duration::from_millis(250);
    let detail_url = authorizations.first();
    let state = loop {
        let state = order.state();
        info!(
            category = LOG_CATEGORY,
            status = format!("{:?}", state.status),
            "get order status"
        );
        if let OrderStatus::Ready | OrderStatus::Invalid | OrderStatus::Valid =
            state.status
        {
            break state;
        }
        order.refresh().await.map_err(|e| Error::Instant {
            category: "refresh_order".to_string(),
            source: e,
        })?;

        delay *= 2;
        tries += 1;
        match tries < 10 {
            true => info!(
                category = LOG_CATEGORY,
                delay = format!("{delay:?}"),
                "order is not ready, waiting"
            ),
            false => {
                return Err(Error::Fail {
                    category: "retry_too_many".to_string(),
                    message: format!(
                        "order is not ready, detail url: {detail_url:?}"
                    ),
                });
            },
        }
        tokio::time::sleep(delay).await;
    };
    if state.status == OrderStatus::Invalid {
        return Err(Error::Fail {
            category: "order_invalid".to_string(),
            message: format!("order is invalid, detail url: {detail_url:?}"),
        });
    }

    // generate certificate
    let mut names = Vec::with_capacity(challenges.len());
    for (identifier, _) in challenges {
        names.push(identifier.to_owned());
    }
    let mut params =
        rcgen::CertificateParams::new(names.clone()).map_err(|e| {
            Error::Rcgen {
                category: "new_params".to_string(),
                source: e,
            }
        })?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let private_key = rcgen::KeyPair::generate().map_err(|e| Error::Rcgen {
        category: "generate_key_pair".to_string(),
        source: e,
    })?;
    let csr =
        params
            .serialize_request(&private_key)
            .map_err(|e| Error::Rcgen {
                category: "serialize_request".to_string(),
                source: e,
            })?;
    order
        .finalize(csr.der())
        .await
        .map_err(|e| Error::Instant {
            category: "order_finalize".to_string(),
            source: e,
        })?;
    let cert_chain_pem = loop {
        match order.certificate().await.map_err(|e| Error::Instant {
            category: "order_certificate".to_string(),
            source: e,
        })? {
            Some(cert_chain_pem) => break cert_chain_pem,
            None => tokio::time::sleep(Duration::from_secs(1)).await,
        }
    };

    Ok((cert_chain_pem, private_key.serialize_pem()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingap_config::FileStorage;
    use pretty_assertions::assert_eq;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_new_lets_encrypt() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().to_string_lossy().to_string();
        // Create storage and leak it to extend its lifetime to 'static
        let storage = Box::leak(Box::new(FileStorage::new(&path).unwrap()));
        let result =
            new_lets_encrypt(storage, &["pingap.io".to_string()], false).await;

        assert_eq!(true, result.is_err());

        // it will be fail as order invalid because http-01 challenge is not valid
        // TODO find another way to test this
        assert_eq!(true, result.is_err());
    }
}
