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

use super::{get_value_from_env, AcmeDnsTask, Error, Result, LOG_CATEGORY};
use crate::dns_ali::AliDnsTask;
use crate::dns_cf::CfDnsTask;
use crate::dns_huawei::HuaweiDnsTask;
use crate::dns_manual::ManualDnsTask;
use crate::dns_tencent::TencentDnsTask;
use async_trait::async_trait;
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::Resolver;
use instant_acme::{
    Account, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus, RetryPolicy,
};
use pingap_certificate::CertificateProvider;
use pingap_certificate::{
    parse_certificates, parse_leaf_chain_certificates, Certificate,
};
use pingap_config::{Category, CertificateConf, ConfigManager, PingapConfig};
use pingap_core::BackgroundTask;
use pingap_core::Error as ServiceError;
use pingap_core::HttpResponse;
use pingap_core::{
    Ctx, NotificationData, NotificationLevel, NotificationSender,
};
use pingora::http::StatusCode;
use pingora::proxy::Session;
use scopeguard::defer;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Once;
use std::time::Duration;
use substring::Substring;
use tracing::{error, info};

static WELL_KNOWN_PATH_PREFIX: &str = "/.well-known/acme-challenge/";

// Initialize crypto provider once
static INIT: Once = Once::new();

fn ensure_crypto_provider() {
    INIT.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

/// Updates the certificate for the given name and domains using Let's Encrypt.
/// This function will:
/// 1. Generate a new certificate from Let's Encrypt
/// 2. Update the configuration with the new certificate
/// 3. Save the updated configuration
async fn update_certificate_lets_encrypt(
    config_manager: Arc<ConfigManager>,
    params: UpdateCertificateParams,
) -> Result<()> {
    // get new certificate from lets encrypt
    let (pem, key) =
        new_lets_encrypt(config_manager.clone(), true, params.clone()).await?;

    let cert: Option<CertificateConf> = config_manager
        .get(Category::Certificate, &params.name)
        .await
        .map_err(|e| Error::Fail {
            category: "load_config".to_string(),
            message: e.to_string(),
        })?;
    if let Some(mut cert) = cert {
        cert.tls_cert = Some(pem);
        cert.tls_key = Some(key);
        config_manager
            .update(Category::Certificate, &params.name, &cert)
            .await
            .map_err(|e| Error::Fail {
                category: "save_config".to_string(),
                message: e.to_string(),
            })?;
    }
    Ok(())
}

/// File cache parameters
#[derive(Debug, Clone)]
struct UpdateCertificateParams {
    name: String,
    domains: Vec<String>,
    buffer_days: u16,
    dns_challenge: bool,
    dns_provider: String,
    dns_service_url: String,
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
    config_manager: Arc<ConfigManager>,
    params: &[UpdateCertificateParams],
    provider: Arc<dyn CertificateProvider>,
    sender: Option<Arc<NotificationSender>>,
) -> Result<bool, ServiceError> {
    if params.is_empty() {
        return Ok(false);
    }
    const UPDATE_INTERVAL: u32 = 10;
    if count % UPDATE_INTERVAL != 0 {
        return Ok(false);
    }
    let config = config_manager.get_current_config();
    for item in params.iter() {
        let name = &item.name;
        let domains = &item.domains;
        let is_manual =
            item.dns_provider == "manual" || item.dns_provider.is_empty();
        // manual dns challenge is only run once
        if item.dns_challenge && is_manual && count > 0 {
            continue;
        }

        let should_renew = match get_lets_encrypt_certificate(&config, name) {
            Ok(Some(certificate)) => {
                // check if certificate is valid or domains changed
                let needs_renewal = !certificate.valid(item.buffer_days);
                let domains_changed = {
                    let mut sorted_domains = domains.clone();
                    let mut cert_domains = certificate.domains.clone();
                    sorted_domains.sort();
                    cert_domains.sort();
                    sorted_domains != cert_domains
                };
                needs_renewal || domains_changed
            },
            Ok(None) => true,
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

        if let Err(e) = renew_certificate(
            config_manager.clone(),
            item.clone(),
            provider.clone(),
            sender.clone(),
        )
        .await
        {
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
    config_manager: Arc<ConfigManager>,
    params: UpdateCertificateParams,
    provider: Arc<dyn CertificateProvider>,
    sender: Option<Arc<NotificationSender>>,
) -> Result<()> {
    update_certificate_lets_encrypt(config_manager.clone(), params.clone())
        .await?;
    handle_successful_renewal(
        &params.domains,
        config_manager,
        provider,
        sender,
    )
    .await?;
    Ok(())
}

fn try_update_certificates(
    provider: Arc<dyn CertificateProvider>,
    certificate_configs: &HashMap<String, CertificateConf>,
) -> (Vec<String>, String) {
    let (new_certs, errors) = parse_certificates(certificate_configs);
    let old_certs = provider.list();
    let updated_certificates: Vec<String> = new_certs
        .iter()
        .filter(|(name, cert)| {
            old_certs
                .get(*name)
                .is_none_or(|old_cert| old_cert.hash_key != cert.hash_key)
        })
        .map(|(name, _)| name.clone())
        .collect();

    let error_messages: Vec<String> = errors
        .into_iter()
        .map(|(name, msg)| format!("{}({})", msg, name))
        .collect();

    provider.store(new_certs);
    (updated_certificates, error_messages.join(";"))
}

async fn handle_successful_renewal(
    domains: &[String],
    config_manager: Arc<ConfigManager>,
    provider: Arc<dyn CertificateProvider>,
    sender: Option<Arc<NotificationSender>>,
) -> Result<()> {
    info!(
        category = LOG_CATEGORY,
        domains = domains.join(","),
        "renew certificate success"
    );
    let toml_config =
        config_manager.load_all().await.map_err(|e| Error::Fail {
            category: "load_config".to_string(),
            message: e.to_string(),
        })?;
    let config =
        toml_config
            .to_pingap_config(true)
            .map_err(|e| Error::Fail {
                category: "convert_config".to_string(),
                message: e.to_string(),
            })?;
    if let Some(sender) = &sender {
        sender
            .notify(NotificationData {
                category: "lets_encrypt".to_string(),
                title: "Generate new cert from let's encrypt".to_string(),
                message: format!("Domains: {domains:?}"),
                ..Default::default()
            })
            .await;
    }

    let (_, error) = try_update_certificates(provider, &config.certificates);
    if !error.is_empty() {
        error!(
            category = LOG_CATEGORY,
            error = error,
            "parse certificate fail"
        );
        if let Some(sender) = &sender {
            sender
                .notify(NotificationData {
                    category: "parse_certificate_fail".to_string(),
                    level: NotificationLevel::Error,
                    message: error,
                    ..Default::default()
                })
                .await;
        }
    } else {
        // update certificate success
        // so set the current config
        config_manager.set_current_config(config);
    }
    Ok(())
}

struct LetsEncryptTask {
    config_manager: Arc<ConfigManager>,
    certificate_provider: Arc<dyn CertificateProvider>,
    sender: Option<Arc<NotificationSender>>,
    running: AtomicBool,
}

#[async_trait]
impl BackgroundTask for LetsEncryptTask {
    async fn execute(&self, count: u32) -> Result<bool, ServiceError> {
        if self.running.swap(true, Ordering::Relaxed) {
            return Ok(true);
        }
        defer!(self.running.store(false, Ordering::Relaxed););
        let mut params = vec![];
        let config = self.config_manager.get_current_config();

        for (name, certificate) in config.certificates.iter() {
            let acme = certificate.acme.clone().unwrap_or_default();
            let domains = certificate.domains.clone().unwrap_or_default();
            if acme.is_empty() || domains.is_empty() {
                continue;
            }
            let dns_service_url = get_value_from_env(
                &certificate.dns_service_url.clone().unwrap_or_default(),
            );

            params.push(UpdateCertificateParams {
                name: name.to_string(),
                buffer_days: certificate.buffer_days.unwrap_or_default(),
                domains: domains
                    .split(',')
                    .map(|item| item.trim().to_string())
                    .filter(|item| !item.is_empty())
                    .collect(),
                dns_challenge: certificate.dns_challenge.unwrap_or_default(),
                dns_provider: certificate
                    .dns_provider
                    .clone()
                    .unwrap_or_default(),
                dns_service_url,
            });
        }
        do_update_certificates(
            count,
            self.config_manager.clone(),
            &params,
            self.certificate_provider.clone(),
            self.sender.clone(),
        )
        .await?;
        Ok(true)
    }
}

/// Create a Let's Encrypt service to generate the certificate,
/// and regenerate if the certificate is invalid or will be expired.
pub fn new_lets_encrypt_service(
    config_manager: Arc<ConfigManager>,
    certificate_provider: Arc<dyn CertificateProvider>,
    sender: Option<Arc<NotificationSender>>,
) -> Box<dyn BackgroundTask> {
    Box::new(LetsEncryptTask {
        config_manager,
        certificate_provider,
        sender,
        running: AtomicBool::new(false),
    })
}

/// Get the cert from file and convert it to certificate struct.
fn get_lets_encrypt_certificate(
    config: &PingapConfig,
    name: &str,
) -> Result<Option<Certificate>> {
    let Some(cert) = config.certificates.get(name) else {
        return Err(Error::NotFound {
            message: "cert not found".to_string(),
        });
    };

    let pem = cert.tls_cert.clone().unwrap_or_default();
    let key = cert.tls_key.clone().unwrap_or_default();
    if pem.is_empty() || key.is_empty() {
        return Ok(None);
    }

    let (cert, _) = parse_leaf_chain_certificates(
        cert.tls_cert.clone().unwrap_or_default().as_str(),
        cert.tls_key.clone().unwrap_or_default().as_str(),
    )
    .map_err(|e| Error::Fail {
        category: "new_certificate".to_string(),
        message: e.to_string(),
    })?;
    Ok(Some(cert))
}

/// Handles the HTTP-01 challenge verification for Let's Encrypt.
/// This function:
/// 1. Intercepts requests to /.well-known/acme-challenge/
/// 2. Extracts the challenge token from the URL path
/// 3. Loads the pre-stored token response from storage
/// 4. Returns the token response to validate domain ownership
pub async fn handle_lets_encrypt(
    config_manager: Arc<ConfigManager>,
    session: &mut Session,
    _ctx: &mut Ctx,
) -> pingora::Result<bool> {
    let path = session.req_header().uri.path();
    // lets encrypt acme challenge path
    if path.starts_with(WELL_KNOWN_PATH_PREFIX) {
        // token auth
        let token = path.substring(WELL_KNOWN_PATH_PREFIX.len(), path.len());

        let value: Option<String> = config_manager
            .get(Category::Storage, token)
            .await
            .map_err(|e| {
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
            body: value.unwrap_or_default().into(),
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
    config_manager: Arc<ConfigManager>,
    production: bool,
    params: UpdateCertificateParams,
) -> Result<(String, String)> {
    let mut domains: Vec<String> = params.domains.to_vec();
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
    ensure_crypto_provider();

    let (account, _) = Account::builder()
        .map_err(|e| Error::Instant {
            category: "create_account".to_string(),
            source: e,
        })?
        .create(
            &NewAccount {
                contact: &[],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            url.to_string(),
            None,
        )
        .await
        .map_err(|e| Error::Instant {
            category: "create_account".to_string(),
            source: e,
        })?;

    let mut order = account
        .new_order(&NewOrder::new(
            &domains
                .iter()
                .map(|item| Identifier::Dns(item.to_owned()))
                .collect::<Vec<Identifier>>(),
        ))
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

    let mut authorizations = order.authorizations();

    let mut dns_tasks = vec![];

    while let Some(result) = authorizations.next().await {
        let mut authz = result.map_err(|e| Error::Instant {
            category: "authorizations".to_string(),
            source: e,
        })?;
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

        let mut challenge = if params.dns_challenge {
            let challenge =
                authz.challenge(ChallengeType::Dns01).ok_or_else(|| {
                    Error::NotFound {
                        message: "Dns01 challenge not found".to_string(),
                    }
                })?;
            let mut identifier = challenge.identifier().to_string();
            if identifier.starts_with("*.") {
                identifier =
                    identifier.substring(2, identifier.len()).to_string();
            }
            let dns_txt_value = challenge.key_authorization().dns_value();
            let acme_dns_name = format!("_acme-challenge.{identifier}");
            let task: Box<dyn AcmeDnsTask> = match params.dns_provider.as_str()
            {
                "ali" => Box::new(AliDnsTask::new(&params.dns_service_url)?),
                "cf" => Box::new(CfDnsTask::new(&params.dns_service_url)?),
                "tencent" => {
                    Box::new(TencentDnsTask::new(&params.dns_service_url)?)
                },
                "huawei" => {
                    Box::new(HuaweiDnsTask::new(&params.dns_service_url)?)
                },
                _ => Box::new(ManualDnsTask::new(config_manager.clone())),
            };

            info!(
                category = LOG_CATEGORY,
                dns_provider = params.dns_provider,
                "start add dns txt record for {acme_dns_name}"
            );
            task.add_txt_record(&acme_dns_name, &dns_txt_value).await?;
            info!(
                category = LOG_CATEGORY,
                dns_provider = params.dns_provider,
                "add dns txt record success for {acme_dns_name}"
            );
            let resolver = Resolver::builder_with_config(
                ResolverConfig::default(),
                TokioConnectionProvider::default(),
            )
            .build();
            // dns txt record may take a while to propagate, so we need to retry
            for i in 0..10 {
                tokio::time::sleep(Duration::from_secs(10)).await;
                info!(
                    category = LOG_CATEGORY,
                    "lookup dns txt record of {acme_dns_name}, times:{i}"
                );
                if let Ok(response) =
                    resolver.lookup(&acme_dns_name, RecordType::TXT).await
                {
                    let txt_records: Vec<String> = response
                        .record_iter()
                        .filter_map(|record| {
                            record.data().as_txt().map(|data| data.to_string())
                        })
                        .collect();
                    let matched = txt_records.contains(&dns_txt_value);
                    info!(
                        category = LOG_CATEGORY,
                        "get dns txt records: {:?}, matched: {matched}",
                        txt_records
                    );
                    if matched {
                        break;
                    }
                }
            }
            dns_tasks.push(task);
            challenge
        } else {
            let challenge =
                authz.challenge(ChallengeType::Http01).ok_or_else(|| {
                    Error::NotFound {
                        message: "Http01 challenge not found".to_string(),
                    }
                })?;

            let key_auth = challenge.key_authorization();
            config_manager
                .update(
                    Category::Storage,
                    &challenge.token,
                    &key_auth.as_str().to_string(),
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
            challenge
        };
        challenge.set_ready().await.map_err(|e| Error::Instant {
            category: "set_challenge_ready".to_string(),
            source: e,
        })?;
    }

    let retry = RetryPolicy::default().timeout(Duration::from_secs(60));

    let status =
        order.poll_ready(&retry).await.map_err(|e| Error::Instant {
            category: "poll_ready".to_string(),
            source: e,
        })?;

    if status != OrderStatus::Ready {
        return Err(Error::Fail {
            category: "poll_ready".to_string(),
            message: format!("unexpected order status: {status:?}"),
        });
    }

    for task in dns_tasks.iter() {
        // ignore done error
        if let Err(err) = task.done().await {
            error!(
                category = LOG_CATEGORY,
                error = err.to_string(),
                "remove acme dns text record fail"
            );
        }
    }

    let private_key_pem =
        order.finalize().await.map_err(|e| Error::Instant {
            category: "finalize".to_string(),
            source: e,
        })?;
    let cert_chain_pem =
        order
            .poll_certificate(&retry)
            .await
            .map_err(|e| Error::Instant {
                category: "poll_certificate".to_string(),
                source: e,
            })?;

    Ok((cert_chain_pem, private_key_pem))
}
