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

use super::{AcmeDnsTask, Error, LOG_TARGET, Result, get_value_from_env};
use crate::dns_ali::AliDnsTask;
use crate::dns_cf::CfDnsTask;
use crate::dns_huawei::HuaweiDnsTask;
use crate::dns_manual::ManualDnsTask;
use crate::dns_tencent::TencentDnsTask;
use async_trait::async_trait;
use hickory_resolver::Resolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::system_conf::read_system_conf;
use instant_acme::{
    Account, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus, RetryPolicy,
};
use pingap_certificate::CertificateProvider;
use pingap_certificate::{
    Certificate, parse_certificates, parse_leaf_chain_certificates,
};
use pingap_config::{
    Category, CertificateConf, ConfigManager, DNS_PROVIDER_MANUAL,
    PingapConfig, StorageConf, normalize_dns_provider,
};
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
use std::sync::Arc;
use std::sync::Once;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use substring::Substring;
use tracing::{error, info, warn};

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
/// 1. Verify the certificate configuration can be addressed for saving
/// 2. Generate a new certificate from Let's Encrypt
/// 3. Update the configuration with the new certificate
async fn update_certificate_lets_encrypt(
    config_manager: Arc<ConfigManager>,
    params: UpdateCertificateParams,
) -> Result<()> {
    // Resolve the certificate conf BEFORE talking to the CA, and treat a miss
    // as an error. `get` addresses the conf by its canonical file
    // (`certificates.toml` / `certificates/<name>.toml`), while the loader
    // accepts any layout it can glob - so a certificate defined in a combined
    // file starts up fine but cannot be found here. This used to be a silent
    // `if let Some`, which dropped the freshly issued certificate on the
    // floor: renewal logged success, no error anywhere, every handshake
    // failed with "no match certificate", and the next cycle re-issued from
    // scratch until Let's Encrypt's duplicate-certificate rate limit cut it
    // off. Checking first also means a config that cannot take the
    // certificate never burns an issuance against that rate limit.
    let cert: Option<CertificateConf> = config_manager
        .get(Category::Certificate, &params.name)
        .await
        .map_err(|e| Error::Fail {
            category: "load_config".to_string(),
            message: e.to_string(),
        })?;
    let Some(mut cert) = cert else {
        return Err(Error::Fail {
            category: "save_config".to_string(),
            message: format!(
                "certificate({}) is not stored where this config layout saves it, so the issued certificate could not be persisted. Pingap normalizes the layout at startup; restart to migrate, or move the [certificates.{}] section into its canonical file.",
                params.name, params.name
            ),
        });
    };

    // get new certificate from lets encrypt
    let (pem, key) =
        new_lets_encrypt(config_manager.clone(), true, params.clone()).await?;

    cert.tls_cert = Some(pem);
    cert.tls_key = Some(key);
    config_manager
        .update(Category::Certificate, &params.name, &cert)
        .await
        .map_err(|e| Error::Fail {
            category: "save_config".to_string(),
            message: e.to_string(),
        })?;
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
    if !count.is_multiple_of(UPDATE_INTERVAL) {
        return Ok(false);
    }
    let config = config_manager.get_current_config();
    for item in params.iter() {
        let name = &item.name;
        let domains = &item.domains;
        let is_manual = item.dns_provider == DNS_PROVIDER_MANUAL;
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
                    target: LOG_TARGET,
                    error = %e,
                    name,
                    "failed to get certificate"
                );
                true
            },
        };

        if !should_renew {
            info!(
                target: LOG_TARGET,
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
                target: LOG_TARGET,
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
        target: LOG_TARGET,
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
        error!(target: LOG_TARGET, error = error, "parse certificate fail");
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
                // Normalized once here so the match below only ever sees a
                // canonical name. `validate` rejects anything unrecognised, so
                // the fallback is only reached for `manual` / unset.
                dns_provider: normalize_dns_provider(
                    &certificate.dns_provider.clone().unwrap_or_default(),
                )
                .unwrap_or(DNS_PROVIDER_MANUAL)
                .to_string(),
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

        // Hourly (the service ticks once a minute), and never on the first
        // cycle: during a rolling upgrade an old instance may still be mid
        // order, and its tokens - written by a version without `created_at` -
        // are exactly the ones the ageless rule below would remove.
        if count > 0 && count.is_multiple_of(TOKEN_CLEAR_INTERVAL) {
            match clear_stale_http_tokens(
                &self.config_manager,
                pingap_core::now_sec(),
            )
            .await
            {
                Ok(0) => {},
                Ok(removed) => {
                    info!(
                        target: LOG_TARGET,
                        removed, "clear stale http-01 challenge tokens"
                    );
                },
                Err(e) => {
                    error!(
                        target: LOG_TARGET,
                        error = %e,
                        "clear stale http-01 challenge tokens fail"
                    );
                },
            }
        }
        Ok(true)
    }
}

/// The remark every http-01 token is stored with; the cleanup below uses it to
/// tell tokens apart from storage entries a person created.
static HTTP_01_TOKEN_REMARK: &str = "let's encrypt http-01 token";
/// How old a token has to be before cleanup may touch it. Validation completes
/// within minutes of `set_ready`, whichever instance wrote the token, so a day
/// is far outside any window in which another process could still need it.
const HTTP_01_TOKEN_MAX_AGE: u64 = 24 * 3600;
/// Cleanup cadence in service cycles (one cycle per minute).
const TOKEN_CLEAR_INTERVAL: u32 = 60;

/// Removes http-01 challenge tokens that no validation can still be using.
///
/// Tokens used to be stored and never deleted, piling up in the storage
/// category forever (one file per token in the separated layout). Removal is
/// by age rather than on order completion so it stays safe across processes:
/// deleting a day old token cannot sabotage an in-flight validation, no matter
/// which instance wrote it. A token without `created_at` predates the field
/// and is removed too - by the time this runs (an hour after start at the
/// earliest) no older-version instance can still be waiting on it.
async fn clear_stale_http_tokens(
    config_manager: &Arc<ConfigManager>,
    now: u64,
) -> Result<u32> {
    let config = config_manager.load_all().await.map_err(|e| Error::Fail {
        category: "load_config".to_string(),
        message: e.to_string(),
    })?;
    let mut removed = 0;
    for (name, value) in config.storages.iter().flatten() {
        let Ok(conf) = value.clone().try_into::<StorageConf>() else {
            continue;
        };
        // The remark decides what is a token; entries people created through
        // the admin panel carry their own remarks and are never touched.
        if conf.remark.as_deref() != Some(HTTP_01_TOKEN_REMARK) {
            continue;
        }
        let stale = conf.created_at.is_none_or(|created_at| {
            now.saturating_sub(created_at) > HTTP_01_TOKEN_MAX_AGE
        });
        if !stale {
            continue;
        }
        match config_manager.delete(Category::Storage, name).await {
            Ok(()) => {
                info!(
                    target: LOG_TARGET,
                    token = name.as_str(),
                    "remove stale http-01 challenge token"
                );
                removed += 1;
            },
            Err(e) => {
                // Keep going: the next hourly run retries whatever failed.
                error!(
                    target: LOG_TARGET,
                    error = %e,
                    token = name.as_str(),
                    "remove stale http-01 challenge token fail"
                );
            },
        }
    }
    Ok(removed)
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

        // The token is attacker-controlled and used directly as a storage
        // lookup key. ACME HTTP-01 tokens are base64url strings, so reject
        // anything else up front: this blocks path traversal (`../certificate/
        // foo` and percent-encoded variants) and returns a clean 404 rather
        // than a storage error.
        if !is_valid_challenge_token(token) {
            HttpResponse {
                status: StatusCode::NOT_FOUND,
                ..Default::default()
            }
            .send(session)
            .await?;
            return Ok(true);
        }

        let value: Option<StorageConf> = config_manager
            .get(Category::Storage, token)
            .await
            .map_err(|e| {
                error!(
                    target: LOG_TARGET,
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
        // The validation request normally comes from the CA; the address
        // tells scanner probes and misrouted requests apart from real ones.
        let remote_addr = pingap_core::get_remote_addr(session)
            .map(|(addr, port)| format!("{addr}:{port}"))
            .unwrap_or_default();
        let Some(value) = value else {
            // A token this instance never stored (or stored by a previous
            // order). Serving an empty 200 here - the old behaviour - could
            // never pass validation anyway, but it logged "success" and left
            // the CA reporting a key authorization mismatch that nothing on
            // this side accounted for. A 404 with a warning names the failure
            // where it happens.
            warn!(
                target: LOG_TARGET,
                token,
                remote_addr,
                "let's encrypt http-01 token not found"
            );
            HttpResponse {
                status: StatusCode::NOT_FOUND,
                ..Default::default()
            }
            .send(session)
            .await?;
            return Ok(true);
        };
        info!(
            target: LOG_TARGET,
            token,
            remote_addr,
            "let's encrypt http-01 challenge token served"
        );
        HttpResponse {
            status: StatusCode::OK,
            body: value.value.into(),
            ..Default::default()
        }
        .send(session)
        .await?;
        return Ok(true);
    }
    Ok(false)
}

/// ACME HTTP-01 tokens are base64url strings; anything else is rejected so the
/// token cannot be abused as a storage lookup key for path traversal.
fn is_valid_challenge_token(token: &str) -> bool {
    !token.is_empty()
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
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
        target: LOG_TARGET,
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

    let mut dns_tasks = vec![];

    let result = (async {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result.map_err(|e| Error::Instant {
                category: "authorizations".to_string(),
                source: e,
            })?;
            info!(
                target: LOG_TARGET,
                status = format!("{:?}", authz.status),
                "authorization from let's encrypt"
            );
            match authz.status {
                instant_acme::AuthorizationStatus::Pending => {},
                instant_acme::AuthorizationStatus::Valid => continue,
                // Invalid / Revoked / Deactivated / Expired: surface an error
                // instead of panicking the renewal background task.
                _ => {
                    return Err(Error::Fail {
                        category: "authorization_status".to_string(),
                        message: format!(
                            "unexpected authorization status: {:?}",
                            authz.status
                        ),
                    });
                },
            }

            let mut challenge = if params.dns_challenge {
                let challenge = authz
                    .challenge(ChallengeType::Dns01)
                    .ok_or_else(|| Error::NotFound {
                        message: "Dns01 challenge not found".to_string(),
                    })?;
                let mut identifier = challenge.identifier().to_string();
                if identifier.starts_with("*.") {
                    identifier =
                        identifier.substring(2, identifier.len()).to_string();
                }
                let dns_txt_value = challenge.key_authorization().dns_value();
                let acme_dns_name = format!("_acme-challenge.{identifier}");
                let task: Box<dyn AcmeDnsTask> = match params
                    .dns_provider
                    .as_str()
                {
                    "ali" => {
                        Box::new(AliDnsTask::new(&params.dns_service_url)?)
                    },
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
                    target: LOG_TARGET,
                    dns_provider = params.dns_provider,
                    dns_txt_value,
                    "start add dns txt record for {acme_dns_name}"
                );
                task.add_txt_record(&acme_dns_name, &dns_txt_value).await?;
                info!(
                    target: LOG_TARGET,
                    dns_provider = params.dns_provider,
                    dns_txt_value,
                    "add dns txt record success for {acme_dns_name}"
                );
                // The system resolver, like everything else on this host uses;
                // the previous hardcoded default (Google public DNS) is only
                // the fallback when the system configuration is unreadable.
                let (resolver_config, mut resolver_options) =
                    read_system_conf().unwrap_or_else(|e| {
                        warn!(
                            target: LOG_TARGET,
                            error = %e,
                            "read system dns conf fail, use default resolver"
                        );
                        (ResolverConfig::default(), ResolverOpts::default())
                    });
                // No caching: the first lookup runs before the record has
                // propagated, and a cached NXDOMAIN (negative TTL is the SOA
                // minimum - often 600s, longer than this whole loop) would be
                // replayed for every remaining attempt, so the check could
                // never see the record appear.
                resolver_options.cache_size = 0;
                let mut resolver_builder = Resolver::builder_with_config(
                    resolver_config,
                    TokioRuntimeProvider::default(),
                );
                *resolver_builder.options_mut() = resolver_options;
                let resolver =
                    resolver_builder.build().map_err(|e| Error::Fail {
                        category: "build_resolver".to_string(),
                        message: e.to_string(),
                    })?;
                // dns txt record may take a while to propagate, so we need to retry
                let mut confirmed = false;
                for i in 0..10 {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    info!(
                        target: LOG_TARGET,
                        "lookup dns txt record of {acme_dns_name}, times:{i}"
                    );
                    match resolver.lookup(&acme_dns_name, RecordType::TXT).await
                    {
                        Ok(response) => {
                            let txt_records: Vec<String> = response
                                .answers()
                                .iter()
                                .filter_map(|record| match &record.data {
                                    hickory_resolver::proto::rr::RData::TXT(
                                        txt,
                                    ) => Some(txt.to_string()),
                                    _ => None,
                                })
                                .collect();
                            let matched =
                                txt_records.contains(&dns_txt_value);
                            // The name accumulates stale values when earlier
                            // runs were killed before their cleanup, so a
                            // `matched: false` is only interpretable next to
                            // the value this run is actually waiting for.
                            info!(
                                target: LOG_TARGET,
                                expected = dns_txt_value,
                                "get dns txt records: {:?}, matched: {matched}",
                                txt_records
                            );
                            if matched {
                                confirmed = true;
                                break;
                            }
                        },
                        // Expected on the early attempts - NXDOMAIN until the
                        // record propagates - but it has to be visible: these
                        // errors were silently swallowed before, which made a
                        // check that never succeeded look like one that never
                        // ran.
                        Err(e) => {
                            warn!(
                                target: LOG_TARGET,
                                error = %e,
                                "lookup dns txt record of {acme_dns_name} fail"
                            );
                        },
                    }
                }
                if !confirmed {
                    // Not fatal by design: this check watches propagation from
                    // this host's viewpoint, while the CA resolves against the
                    // authoritative servers itself - so proceed and let it
                    // decide. Say so, though, or a validation failure right
                    // after looks inexplicable.
                    warn!(
                        target: LOG_TARGET,
                        expected = dns_txt_value,
                        "dns txt record of {acme_dns_name} was not confirmed, proceeding to let the CA validate"
                    );
                }
                dns_tasks.push(task);
                challenge
            } else {
                let challenge = authz
                    .challenge(ChallengeType::Http01)
                    .ok_or_else(|| Error::NotFound {
                        message: "Http01 challenge not found".to_string(),
                    })?;

                let identifier = challenge.identifier().to_string();
                let key_auth = challenge.key_authorization();
                config_manager
                    .update(
                        Category::Storage,
                        &challenge.token,
                        &StorageConf {
                            value: key_auth.as_str().to_string(),
                            category: "config".to_string(),
                            secret: None,
                            remark: Some(HTTP_01_TOKEN_REMARK.to_string()),
                            // Tokens are never deleted on completion (another
                            // process may still be serving them); the age
                            // based cleanup keys off this instead.
                            created_at: Some(pingap_core::now_sec()),
                        },
                    )
                    .await
                    .map_err(|e| Error::Fail {
                        category: "save_token".to_string(),
                        message: e.to_string(),
                    })?;
                // The identifier ties the token to its authorization: an
                // order for apex + wildcard runs several of these, and a
                // later validation failure names the domain, not the token.
                info!(
                    target: LOG_TARGET,
                    token = challenge.token,
                    identifier,
                    "save let's encrypt http-01 challenge token",
                );
                challenge
            };
            challenge.set_ready().await.map_err(|e| Error::Instant {
                category: "set_challenge_ready".to_string(),
                source: e,
            })?;
        }

        let status = order
            .poll_ready(
                &RetryPolicy::default().timeout(Duration::from_secs(60)),
            )
            .await
            .map_err(|e| Error::Instant {
                category: "poll_ready".to_string(),
                source: e,
            })?;

        if status != OrderStatus::Ready {
            return Err(Error::Fail {
                category: "poll_ready".to_string(),
                message: format!("unexpected order status: {status:?}"),
            });
        }
        Ok(())
    })
    .await;

    for task in dns_tasks.iter() {
        // ignore done error
        if let Err(err) = task.done().await {
            error!(
                target: LOG_TARGET,
                error = err.to_string(),
                "remove acme dns text record fail"
            );
        }
    }
    result?;

    let private_key_pem =
        order.finalize().await.map_err(|e| Error::Instant {
            category: "finalize".to_string(),
            source: e,
        })?;
    let cert_chain_pem = order
        .poll_certificate(
            &RetryPolicy::default().timeout(Duration::from_secs(60)),
        )
        .await
        .map_err(|e| Error::Instant {
            category: "poll_certificate".to_string(),
            source: e,
        })?;

    Ok((cert_chain_pem, private_key_pem))
}

#[cfg(test)]
mod tests {
    use super::is_valid_challenge_token;
    use super::{UpdateCertificateParams, update_certificate_lets_encrypt};
    use pingap_config::new_file_config_manager;
    use std::sync::Arc;

    /// Issue #213: a certificate defined in a combined file loads and serves,
    /// but cannot be addressed by the canonical key the save path uses. That
    /// used to be a silent no-op AFTER issuance - success logged, certificate
    /// dropped, re-issued every cycle until the CA's rate limit. It must be a
    /// loud error, and it must fire BEFORE an issuance is burned (which is
    /// also what makes this testable offline: reaching the CA would be a
    /// network call).
    #[tokio::test]
    async fn test_renewal_fails_loudly_when_conf_is_not_addressable() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("combined.toml"),
            "[certificates.panel]\ndomains = \"example.com\"\nacme = \"lets_encrypt\"\n",
        )
        .unwrap();
        let manager = Arc::new(
            new_file_config_manager(dir.path().to_string_lossy().as_ref())
                .unwrap(),
        );

        let err = update_certificate_lets_encrypt(
            manager,
            UpdateCertificateParams {
                name: "panel".to_string(),
                domains: vec!["example.com".to_string()],
                buffer_days: 30,
                dns_challenge: false,
                dns_provider: "".to_string(),
                dns_service_url: "".to_string(),
            },
        )
        .await
        .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("panel"), "{message}");
        assert!(message.contains("could not be persisted"), "{message}");
    }

    #[tokio::test]
    async fn test_clear_stale_http_tokens() {
        use super::{HTTP_01_TOKEN_REMARK, clear_stale_http_tokens};
        use pingap_config::{Category, StorageConf};

        let dir = tempfile::TempDir::new().unwrap();
        let manager = Arc::new(
            new_file_config_manager(&format!(
                "{}?separation=true",
                dir.path().to_string_lossy()
            ))
            .unwrap(),
        );
        let now = 1_800_000_000_u64;
        let token = |created_at: Option<u64>, remark: &str| StorageConf {
            category: "config".to_string(),
            value: "key-auth".to_string(),
            secret: None,
            remark: Some(remark.to_string()),
            created_at,
        };
        // Older than a day: removable.
        manager
            .update(
                Category::Storage,
                "stale",
                &token(Some(now - 25 * 3600), HTTP_01_TOKEN_REMARK),
            )
            .await
            .unwrap();
        // Fresh: an in-flight validation on any instance may still need it.
        manager
            .update(
                Category::Storage,
                "fresh",
                &token(Some(now - 60), HTTP_01_TOKEN_REMARK),
            )
            .await
            .unwrap();
        // No created_at: written before the field existed - removable.
        manager
            .update(
                Category::Storage,
                "legacy",
                &token(None, HTTP_01_TOKEN_REMARK),
            )
            .await
            .unwrap();
        // A person's storage entry: wrong remark, never touched however old.
        manager
            .update(
                Category::Storage,
                "user-data",
                &token(Some(now - 999 * 3600), "my secret"),
            )
            .await
            .unwrap();

        let removed = clear_stale_http_tokens(&manager, now).await.unwrap();
        assert_eq!(2, removed);

        let left = manager.load_all().await.unwrap();
        let left = left.storages.unwrap();
        assert!(left.contains_key("fresh"));
        assert!(left.contains_key("user-data"));
        assert!(!left.contains_key("stale"));
        assert!(!left.contains_key("legacy"));

        // Nothing left to do on the next run.
        assert_eq!(0, clear_stale_http_tokens(&manager, now).await.unwrap());
    }

    #[test]
    fn test_is_valid_challenge_token() {
        // Well-formed base64url tokens are accepted.
        assert!(is_valid_challenge_token("abcXYZ0123_-"));

        // Empty, traversal and percent-encoded tokens are rejected.
        assert!(!is_valid_challenge_token(""));
        assert!(!is_valid_challenge_token("../certificate/foo"));
        assert!(!is_valid_challenge_token("..%2Fcertificate"));
        assert!(!is_valid_challenge_token("a.b"));
        assert!(!is_valid_challenge_token("a/b"));
    }
}
