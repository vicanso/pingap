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

use super::{AcmeDnsTask, Error, LOG_TARGET, Result, dns_service_url_from_env};
use crate::dns_ali::AliDnsTask;
use crate::dns_cf::CfDnsTask;
use crate::dns_huawei::HuaweiDnsTask;
use crate::dns_manual::{MANUAL_DNS_REMARK, ManualDnsTask};
use crate::dns_tencent::TencentDnsTask;
use async_trait::async_trait;
use hickory_resolver::Resolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::system_conf::read_system_conf;
use instant_acme::{
    Account, AccountBuilder, AccountCredentials, ChallengeType,
    ExternalAccountKey, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus, RetryPolicy,
};
use pingap_certificate::CertificateProvider;
use pingap_certificate::{
    Certificate, parse_leaf_chain_certificates, update_certificates,
};
use pingap_config::{
    Category, CertificateConf, ConfigManager, DNS_PROVIDER_MANUAL,
    PingapConfig, StorageConf, acme_contacts, decode_eab_hmac,
    normalize_dns_provider,
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
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;
#[cfg(feature = "openssl")]
use std::sync::Once;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

static WELL_KNOWN_PATH_PREFIX: &str = "/.well-known/acme-challenge/";

/// ACME talks rustls even when the proxy TLS backend is OpenSSL, so the
/// process still needs a CryptoProvider. Prefer the shared installer when
/// the rustls backend owns it; otherwise install aws-lc-rs here once.
fn ensure_crypto_provider() {
    #[cfg(feature = "tls-rustls")]
    {
        pingap_certificate::install_default_crypto_provider();
    }
    #[cfg(feature = "openssl")]
    {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let _ =
                rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }
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
    //
    // A storage that takes no writes at all comes first: a directory of hcl
    // or kdl files is read but never written, and the lookup below misses
    // there as well, with advice about layouts that does not apply.
    config_manager.ensure_writable().map_err(|e| Error::Fail {
        category: "save_config".to_string(),
        message: e.to_string(),
    })?;
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
        new_lets_encrypt(config_manager.clone(), params.clone()).await?;

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

/// Where a certificate is ordered, and as whom: Let's Encrypt, as an
/// account that says nothing of itself, unless the certificate's entry
/// says otherwise.
#[derive(Clone, Default, PartialEq)]
struct AcmeServer {
    /// The directory url of the CA; Let's Encrypt's production
    /// environment when `None`.
    directory: Option<String>,
    /// A PEM file with the root the CA's own certificate is verified
    /// with; the roots of the system when `None`.
    ca: Option<String>,
    /// External account binding: the key id and its key.
    eab: Option<(String, Vec<u8>)>,
    /// The contacts of the account, as `mailto:` urls.
    contact: Vec<String>,
    /// An RSA key for the certificate, and not the ECDSA one that is
    /// made otherwise.
    rsa: bool,
}

// Without the key of the binding: the parameters of an order are logged.
impl std::fmt::Debug for AcmeServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcmeServer")
            .field("directory", &self.url())
            .field("ca", &self.ca)
            .field("eab", &self.eab.as_ref().map(|(kid, _)| kid))
            .field("contact", &self.contact)
            .field("rsa", &self.rsa)
            .finish()
    }
}

impl AcmeServer {
    fn new(certificate: &CertificateConf) -> Self {
        let text = |value: &Option<String>| {
            value
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        };
        Self {
            directory: text(&certificate.acme_directory),
            ca: text(&certificate.acme_ca),
            // Validated with the entry: a key that does not decode is no
            // binding, and the CA says so.
            eab: text(&certificate.acme_eab_kid).zip(
                certificate
                    .acme_eab_hmac
                    .as_deref()
                    .and_then(decode_eab_hmac),
            ),
            contact: certificate
                .acme_contact
                .as_deref()
                .map(|contact| {
                    acme_contacts(contact)
                        .map(|address| format!("mailto:{address}"))
                        .collect()
                })
                .unwrap_or_default(),
            rsa: certificate.acme_key_type.as_deref() == Some("rsa"),
        }
    }

    fn url(&self) -> &str {
        self.directory
            .as_deref()
            .unwrap_or(LetsEncrypt::Production.url())
    }

    /// The storage entry the credentials of the account live in: one per
    /// CA, and per binding at a CA that binds accounts. Let's Encrypt's
    /// two keep the names they had.
    fn account_storage_name(&self) -> String {
        let url = self.url();
        let kid = self.eab.as_ref().map(|(kid, _)| kid.as_str());
        match (url, kid) {
            (url, None) if url == LetsEncrypt::Production.url() => {
                account_storage_name(true).to_string()
            },
            (url, None) if url == LetsEncrypt::Staging.url() => {
                account_storage_name(false).to_string()
            },
            _ => {
                let mut hasher = Sha256::new();
                hasher.update(url.as_bytes());
                hasher.update([0]);
                hasher.update(kid.unwrap_or_default().as_bytes());
                let digest = hex::encode(hasher.finalize());
                format!("acme_account_{}", &digest[..16])
            },
        }
    }

    /// What an account is made or loaded with: the roots of the system,
    /// or the one root of a CA of one's own.
    fn account_builder(&self) -> Result<AccountBuilder> {
        match &self.ca {
            Some(path) => {
                Account::builder_with_root(pingap_util::resolve_path(path))
            },
            None => Account::builder(),
        }
        .map_err(|e| Error::Instant {
            category: "create_account".to_string(),
            source: e,
        })
    }
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
    server: AcmeServer,
}

/// The orders of one certificate that failed in a row, and when the next
/// one may be tried.
#[derive(Clone, Copy, Default)]
struct Retry {
    failures: u32,
    not_before: u64,
}

const RETRY_FIRST_DELAY: u64 = 10 * 60;
const RETRY_MAX_DELAY: u64 = 6 * 3600;

/// How long to wait after `failures` failed orders in a row: ten minutes,
/// doubled each time, six hours at most.
///
/// A failed order used to be tried again at the next check, ten minutes
/// later and for ever, which is more than the five failed validations an
/// hour a CA allows a name: a domain that could not be validated locked
/// itself out, and so did every other order for it.
fn retry_delay(failures: u32) -> u64 {
    let doublings = failures.saturating_sub(1).min(16);
    (RETRY_FIRST_DELAY << doublings).min(RETRY_MAX_DELAY)
}

/// The names a certificate is ordered for, from the `domains` of its
/// entry: in lower case, which is how a CA writes them into the
/// certificate. Written as `Example.com`, the name was never one the
/// certificate that came back was for: its domains had "changed" every
/// time they were looked at, and it was ordered again every time.
fn ordered_domains(domains: &str) -> Vec<String> {
    domains
        .split(',')
        .map(|item| item.trim().to_lowercase())
        .filter(|item| !item.is_empty())
        .collect()
}

/// Whether `conf` holds a certificate that `params` can go on with: one
/// that parses, is for the same domains, and is not due for renewal.
fn is_usable(conf: &CertificateConf, params: &UpdateCertificateParams) -> bool {
    let pem = conf.tls_cert.as_deref().unwrap_or_default();
    let key = conf.tls_key.as_deref().unwrap_or_default();
    if pem.is_empty() || key.is_empty() {
        return false;
    }
    let Ok((certificate, _)) = parse_leaf_chain_certificates(pem, key) else {
        return false;
    };
    let mut wanted = params.domains.clone();
    let mut held = certificate.domains.clone();
    wanted.sort();
    held.sort();
    wanted == held && certificate.valid(params.buffer_days)
}

/// Asks the CA for a certificate and stores it. A field of the task, so
/// that a test can stand in for the CA.
type Order = Box<
    dyn Fn(
            Arc<ConfigManager>,
            UpdateCertificateParams,
        ) -> Pin<Box<dyn Future<Output = Result<()>> + Send>>
        + Send
        + Sync,
>;

struct LetsEncryptTask {
    config_manager: Arc<ConfigManager>,
    certificate_provider: Arc<dyn CertificateProvider>,
    sender: Option<Arc<NotificationSender>>,
    running: AtomicBool,
    order: Order,
    retries: Mutex<HashMap<String, Retry>>,
}

impl LetsEncryptTask {
    async fn notify(&self, data: NotificationData) {
        if let Some(sender) = &self.sender {
            sender.notify(data).await;
        }
    }

    fn retry_of(&self, name: &str) -> Option<Retry> {
        let retries = self.retries.lock().unwrap_or_else(|e| e.into_inner());
        retries.get(name).copied()
    }

    fn clear_retry(&self, name: &str) {
        let mut retries =
            self.retries.lock().unwrap_or_else(|e| e.into_inner());
        retries.remove(name);
    }

    /// Periodically checks and updates certificates that need renewal.
    /// A certificate needs renewal if:
    /// - It is invalid or expired
    /// - The configured domains have changed
    /// - The certificate cannot be loaded
    ///
    /// The check runs every UPDATE_INTERVAL iterations to avoid excessive checks.
    async fn update_certificates(
        &self,
        count: u32,
        params: &[UpdateCertificateParams],
    ) -> Result<bool, ServiceError> {
        if params.is_empty() {
            return Ok(false);
        }
        const UPDATE_INTERVAL: u32 = 10;
        if !count.is_multiple_of(UPDATE_INTERVAL) {
            return Ok(false);
        }
        let config = self.config_manager.get_current_config();
        for item in params.iter() {
            let name = &item.name;
            let domains = &item.domains;
            let is_manual = item.dns_provider == DNS_PROVIDER_MANUAL;
            // manual dns challenge is only run once
            if item.dns_challenge && is_manual && count > 0 {
                continue;
            }

            let should_renew = match get_lets_encrypt_certificate(&config, name)
            {
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
                debug!(
                    target: LOG_TARGET,
                    domains = domains.join(","),
                    name,
                    "certificate still valid"
                );
                continue;
            }

            // The storage first: an instance that shares it may have this
            // certificate already. The check above goes by the running
            // configuration, which only learns of a certificate here, so
            // every instance used to order its own and half a dozen of
            // them ran into the CA's limit on duplicates.
            match self.adopt_stored_certificate(item).await {
                Ok(true) => {
                    self.clear_retry(name);
                    continue;
                },
                Ok(false) => {},
                Err(e) => {
                    warn!(
                        target: LOG_TARGET,
                        error = %e,
                        name,
                        "the certificate in the storage could not be used"
                    );
                },
            }

            let now = pingap_core::now_sec();
            if let Some(retry) = self.retry_of(name)
                && now < retry.not_before
            {
                debug!(
                    target: LOG_TARGET,
                    name,
                    failures = retry.failures,
                    "waiting before the next order"
                );
                continue;
            }

            let ordered =
                (self.order)(self.config_manager.clone(), item.clone()).await;
            let installed = match ordered {
                Ok(()) => self.install_renewed_certificate(item).await,
                Err(e) => Err(e),
            };
            match installed {
                Ok(()) => self.clear_retry(name),
                Err(e) => self.order_failed(item, &e, now).await,
            }
        }
        Ok(true)
    }

    /// Records a failed order, says so, and puts the next one off.
    async fn order_failed(
        &self,
        params: &UpdateCertificateParams,
        error: &Error,
        now: u64,
    ) {
        let failures = self
            .retry_of(&params.name)
            .map_or(1, |retry| retry.failures.saturating_add(1));
        let delay = retry_delay(failures);
        {
            let mut retries =
                self.retries.lock().unwrap_or_else(|e| e.into_inner());
            retries.insert(
                params.name.clone(),
                Retry {
                    failures,
                    not_before: now + delay,
                },
            );
        }
        // The challenge answered by hand is asked for once, when the
        // process starts.
        let manual =
            params.dns_challenge && params.dns_provider == DNS_PROVIDER_MANUAL;
        let retry_in = if manual {
            "the next start".to_string()
        } else {
            format!("{}m", delay / 60)
        };
        error!(
            target: LOG_TARGET,
            error = %error,
            domains = params.domains.join(","),
            name = params.name,
            failures,
            retry_in,
            "certificate renewal failed"
        );
        self.notify(NotificationData {
            category: "lets_encrypt".to_string(),
            level: NotificationLevel::Error,
            title: "Generate cert from let's encrypt failed".to_string(),
            message: format!(
                "Certificate: {}, domains: {:?}, error: {error}, failures: {failures}, next attempt: {retry_in}",
                params.name, params.domains
            ),
        })
        .await;
    }

    /// Takes the certificate the storage holds for this entry when it is
    /// one to go on with. `Ok(false)` when it is not.
    async fn adopt_stored_certificate(
        &self,
        params: &UpdateCertificateParams,
    ) -> Result<bool> {
        let stored: Option<CertificateConf> = self
            .config_manager
            .get(Category::Certificate, &params.name)
            .await
            .map_err(|e| Error::Fail {
                category: "load_config".to_string(),
                message: e.to_string(),
            })?;
        let Some(conf) = stored.filter(|conf| is_usable(conf, params)) else {
            return Ok(false);
        };
        self.install(&params.name, conf).await?;
        info!(
            target: LOG_TARGET,
            domains = params.domains.join(","),
            name = params.name,
            "certificate taken from the storage, no order needed"
        );
        Ok(true)
    }

    /// Installs the certificate an order just stored.
    async fn install_renewed_certificate(
        &self,
        params: &UpdateCertificateParams,
    ) -> Result<()> {
        info!(
            target: LOG_TARGET,
            domains = params.domains.join(","),
            "renew certificate success"
        );
        self.notify(NotificationData {
            category: "lets_encrypt".to_string(),
            title: "Generate new cert from let's encrypt".to_string(),
            message: format!("Domains: {:?}", params.domains),
            ..Default::default()
        })
        .await;
        let stored: Option<CertificateConf> = self
            .config_manager
            .get(Category::Certificate, &params.name)
            .await
            .map_err(|e| Error::Fail {
                category: "load_config".to_string(),
                message: e.to_string(),
            })?;
        let Some(conf) = stored else {
            return Err(Error::Fail {
                category: "load_config".to_string(),
                message: format!(
                    "certificate({}) is not in the storage",
                    params.name
                ),
            });
        };
        let usable = is_usable(&conf, params);
        self.install(&params.name, conf).await?;
        // The certificate is in use, and the next check would order
        // another all the same: `buffer_days` is not less than what a
        // certificate is good for, or `domains` is not what the CA put
        // into it (a name twice). That is a failure of
        // this entry, to be told about and to wait after, not an order to
        // repeat every ten minutes.
        if !usable {
            return Err(Error::Fail {
                category: "new_certificate".to_string(),
                message: "the new certificate is already due for renewal by this entry's buffer_days, or is not for its domains".to_string(),
            });
        }
        Ok(())
    }

    /// Puts `conf` to work as the entry `name`: its certificate into the
    /// certificate store, the entry into the running configuration.
    ///
    /// Only this entry. The whole stored configuration used to be read and
    /// made the running one, which marked as applied whatever else had
    /// changed in the storage and was not. And it was made so only when
    /// every certificate of it loaded: with one broken entry anywhere the
    /// new certificate was installed and served but never recorded, the
    /// next check found the old one still due, and ordered again - every
    /// ten minutes, until the CA refused.
    ///
    /// Of `conf`, which is the entry as the storage holds it, only the
    /// certificate and its key. The settings stay those of the running
    /// entry: the storage has them as they are written, a
    /// `dns_service_url` or `domains` that is read from the environment
    /// or a file as the reference to it, and the running configuration
    /// has what the reference stands for. With the stored entry put in
    /// whole, the next renewal asked the provider at the address
    /// `$FILE:/run/secrets/dns`, and the next reload found an entry that
    /// had changed and restarted for it. A setting that was changed in
    /// the storage is the reload's to apply, as for any other entry.
    async fn install(&self, name: &str, conf: CertificateConf) -> Result<()> {
        let mut config =
            self.config_manager.get_current_config().as_ref().clone();
        let conf = match config.certificates.get(name) {
            Some(running) => CertificateConf {
                tls_cert: conf.tls_cert,
                tls_key: conf.tls_key,
                ..running.clone()
            },
            None => conf,
        };
        config.certificates.insert(name.to_string(), conf);
        let (certificates, errors, _) = update_certificates(
            &config.certificates,
            &self.certificate_provider.list(),
        );
        self.certificate_provider.store(certificates);

        let (own, others): (Vec<_>, Vec<_>) =
            errors.into_iter().partition(|(failed, _)| failed == name);
        if !others.is_empty() {
            let message = others
                .into_iter()
                .map(|(failed, message)| format!("{message}({failed})"))
                .collect::<Vec<_>>()
                .join(";");
            error!(target: LOG_TARGET, error = message, "parse certificate fail");
            self.notify(NotificationData {
                category: "parse_certificate_fail".to_string(),
                level: NotificationLevel::Error,
                message,
                ..Default::default()
            })
            .await;
        }
        if let Some((_, message)) = own.into_iter().next() {
            return Err(Error::Fail {
                category: "install_certificate".to_string(),
                message,
            });
        }
        self.config_manager.set_current_config(config);
        Ok(())
    }
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
            let dns_service_url = dns_service_url_from_env(
                certificate.dns_service_url.as_deref().unwrap_or_default(),
            );

            params.push(UpdateCertificateParams {
                name: name.to_string(),
                buffer_days: certificate.buffer_days.unwrap_or_default(),
                domains: ordered_domains(&domains),
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
                server: AcmeServer::new(certificate),
            });
        }
        self.update_certificates(count, &params).await?;

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
/// The remark the ACME account credentials are stored with.
static ACCOUNT_REMARK: &str = "let's encrypt account credentials";
/// How old a token has to be before cleanup may touch it. Validation completes
/// within minutes of `set_ready`, whichever instance wrote the token, so a day
/// is far outside any window in which another process could still need it.
const HTTP_01_TOKEN_MAX_AGE: u64 = 24 * 3600;
/// Cleanup cadence in service cycles (one cycle per minute).
const TOKEN_CLEAR_INTERVAL: u32 = 60;

/// Removes http-01 challenge tokens, and the TXT values the manual DNS task
/// records, that no validation can still be using.
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
        if !matches!(
            conf.remark.as_deref(),
            Some(remark) if remark == HTTP_01_TOKEN_REMARK || remark == MANUAL_DNS_REMARK
        ) {
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
        order: Box::new(|config_manager, params| {
            Box::pin(update_certificate_lets_encrypt(config_manager, params))
        }),
        retries: Mutex::new(HashMap::new()),
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

    let pem = cert.tls_cert.as_deref().unwrap_or_default();
    let key = cert.tls_key.as_deref().unwrap_or_default();
    if pem.is_empty() || key.is_empty() {
        return Ok(None);
    }

    let (cert, _) =
        parse_leaf_chain_certificates(pem, key).map_err(|e| Error::Fail {
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
    let Some(token) = path.strip_prefix(WELL_KNOWN_PATH_PREFIX) else {
        return Ok(false);
    };
    {
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

        // A token of an order of this process is answered from memory.
        // Any other may be one of another instance on the same storage,
        // or of the process this one took over from: those are answered
        // from what the storage held when it was last read.
        let value = match own_token(token) {
            Some(value) => Ok(Some(value)),
            None => STORED_TOKENS.get(&config_manager, token).await,
        };
        let value = value.map_err(|e| {
            error!(
                target: LOG_TARGET,
                error = e,
                token,
                "load http-01 token fail"
            );
            pingora::Error::because(
                pingora::ErrorType::HTTPStatus(500),
                e,
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
            body: value.into(),
            ..Default::default()
        }
        .send(session)
        .await?;
        Ok(true)
    }
}

/// The tokens of the orders this process has made, with their answers and
/// when they were noted: the challenge of an order of its own is answered
/// from here, whatever else is going on at the storage.
static OWN_TOKENS: LazyLock<Mutex<HashMap<String, (String, u64)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn remember_own_token(token: &str, key_authorization: &str) {
    let now = pingap_core::now_sec();
    let mut tokens = OWN_TOKENS.lock().unwrap_or_else(|e| e.into_inner());
    // An order is over within minutes, one way or the other.
    tokens.retain(|_, (_, at)| now.saturating_sub(*at) < HTTP_01_TOKEN_MAX_AGE);
    tokens.insert(token.to_string(), (key_authorization.to_string(), now));
}

fn own_token(token: &str) -> Option<String> {
    let tokens = OWN_TOKENS.lock().unwrap_or_else(|e| e.into_inner());
    tokens.get(token).map(|(value, _)| value.clone())
}

/// How long the tokens read from the storage are answered from.
///
/// The challenge path is open to everyone on port 80, ahead of every
/// plugin, and each request to it read the storage: the whole
/// configuration file parsed again, or a request to etcd. The storage is
/// now read once for everyone who asks within this time, however many they
/// are, so what a flood of made-up tokens costs is one read a second - and
/// the token of another instance is still found among them, which a cap on
/// the number of lookups could not promise.
const STORED_TOKENS_TTL: Duration = Duration::from_secs(1);

/// How long a read that failed stands for: the storage is not asked again
/// by every request of a flood while it is down, and the requests of one
/// validation, which come moments apart, are not all told of a failure
/// that was over with the next read.
const STORED_TOKENS_FAILURE_TTL: Duration = Duration::from_millis(100);

/// How long an order waits between storing a token and telling the CA to
/// come for it: longer than [`STORED_TOKENS_TTL`], so that whatever another
/// instance read before the token was there is too old to answer from by
/// the time the validation request arrives.
const TOKEN_SETTLE_DELAY: Duration = Duration::from_millis(1500);

/// The http-01 tokens the storage held when it was last read.
struct StoredTokens {
    state: tokio::sync::Mutex<StoredTokensState>,
    ttl: Duration,
    failure_ttl: Duration,
}

#[derive(Default)]
struct StoredTokensState {
    tokens: HashMap<String, String>,
    /// When the last read of the storage began.
    loaded_at: Option<Instant>,
    /// What the last read failed with, when it did. `tokens` are then
    /// those of the read before.
    failure: Option<String>,
}

impl StoredTokensState {
    /// Whether a request that arrived at `asked_at` is answered from what
    /// is held: the read is no older than `ttl`, or began after the request
    /// arrived - then it holds whatever the request may be after, however
    /// long it took. A storage that takes seconds to answer is so read
    /// once for all the requests that were waiting, not once for each.
    fn answers(&self, asked_at: Instant, ttl: Duration) -> bool {
        self.loaded_at
            .is_some_and(|at| at >= asked_at || at.elapsed() < ttl)
    }
}

static STORED_TOKENS: LazyLock<StoredTokens> = LazyLock::new(|| {
    StoredTokens::new(STORED_TOKENS_TTL, STORED_TOKENS_FAILURE_TTL)
});

impl StoredTokens {
    fn new(ttl: Duration, failure_ttl: Duration) -> Self {
        Self {
            state: Default::default(),
            ttl,
            failure_ttl,
        }
    }
    /// The key authorization stored for an http-01 `token`, `None` when
    /// there is no such token.
    ///
    /// The lock is held while the storage is read: the requests that arrive
    /// meanwhile wait for that one read instead of starting their own.
    async fn get(
        &self,
        config_manager: &ConfigManager,
        token: &str,
    ) -> Result<Option<String>, String> {
        let asked_at = Instant::now();
        let mut state = self.state.lock().await;
        let ttl = if state.failure.is_some() {
            self.failure_ttl
        } else {
            self.ttl
        };
        if !state.answers(asked_at, ttl) {
            // When the read began is what counts, what it returns is no
            // newer; and it is noted once the read is over, so that one
            // that was given up half way leaves nothing behind.
            let began = Instant::now();
            match load_http_01_tokens(config_manager).await {
                Ok(tokens) => {
                    state.tokens = tokens;
                    state.failure = None;
                },
                Err(e) => state.failure = Some(e.to_string()),
            }
            state.loaded_at = Some(began);
        }
        match (state.tokens.get(token), &state.failure) {
            // After a failure too: what was read before may hold the token.
            (Some(value), _) => Ok(Some(value.clone())),
            (None, None) => Ok(None),
            // Not "no such token": nobody knows.
            (None, Some(failure)) => Err(failure.clone()),
        }
    }
}

/// The http-01 tokens in the storage, with their key authorizations.
///
/// The request path only picks a name, and the storage holds more than
/// tokens: the ACME account credentials, the includes, whatever was added
/// through the admin. Only an entry stored as a token is answered, going by
/// the remark every token carries. Without that check
/// `/.well-known/acme-challenge/lets_encrypt_account` handed out the
/// account key on port 80.
///
/// Only the storage category is read, as a lookup of one token did: a
/// server or a plugin that does not parse is no reason to fail a
/// validation.
async fn load_http_01_tokens(
    config_manager: &ConfigManager,
) -> Result<HashMap<String, String>, pingap_config::Error> {
    let config = config_manager.load_category(Category::Storage).await?;
    let mut tokens = HashMap::new();
    for (name, value) in config.storages.iter().flatten() {
        let Ok(conf) = value.clone().try_into::<StorageConf>() else {
            continue;
        };
        if conf.remark.as_deref() == Some(HTTP_01_TOKEN_REMARK) {
            tokens.insert(name.clone(), conf.value);
        }
    }
    Ok(tokens)
}

/// The storage entry the ACME account credentials live in, one per CA
/// environment.
fn account_storage_name(production: bool) -> &'static str {
    if production {
        "lets_encrypt_account"
    } else {
        "lets_encrypt_staging_account"
    }
}

/// The ACME account: the one stored from an earlier order when it still
/// works, otherwise a new one, stored for the next time. Every order used to
/// register a new account, which Let's Encrypt rate-limits per IP and which
/// left a trail of one-shot accounts behind.
async fn load_or_create_account(
    config_manager: &Arc<ConfigManager>,
    server: &AcmeServer,
) -> Result<Account> {
    let name = server.account_storage_name();
    let name = name.as_str();
    let stored: Option<StorageConf> = config_manager
        .get(Category::Storage, name)
        .await
        .unwrap_or_else(|e| {
            warn!(
                target: LOG_TARGET,
                error = %e,
                "load let's encrypt account fail, create a new one"
            );
            None
        });
    if let Some(stored) = stored {
        let account = match serde_json::from_str::<AccountCredentials>(
            &stored.value,
        ) {
            Ok(credentials) => {
                server
                    .account_builder()?
                    .from_credentials(credentials)
                    .await
            },
            Err(e) => {
                warn!(
                    target: LOG_TARGET,
                    error = %e,
                    "stored let's encrypt account is invalid, create a new one"
                );
                return create_account(config_manager, server, name).await;
            },
        };
        match account {
            Ok(account) => return Ok(account),
            Err(e) => warn!(
                target: LOG_TARGET,
                error = %e,
                "stored let's encrypt account is not usable, create a new one"
            ),
        }
    }
    create_account(config_manager, server, name).await
}

async fn create_account(
    config_manager: &Arc<ConfigManager>,
    server: &AcmeServer,
    name: &str,
) -> Result<Account> {
    let contact: Vec<&str> =
        server.contact.iter().map(String::as_str).collect();
    let external_account = server
        .eab
        .as_ref()
        .map(|(kid, key)| ExternalAccountKey::new(kid.clone(), key));
    let (account, credentials) = server
        .account_builder()?
        .create(
            &NewAccount {
                contact: &contact,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            server.url().to_string(),
            external_account.as_ref(),
        )
        .await
        .map_err(|e| Error::Instant {
            category: "create_account".to_string(),
            source: e,
        })?;
    info!(target: LOG_TARGET, "create let's encrypt account success");
    // Best effort: an order can proceed with an account that could not be
    // stored; the next one registers again.
    let value = match serde_json::to_string(&credentials) {
        Ok(value) => value,
        Err(e) => {
            warn!(
                target: LOG_TARGET,
                error = %e,
                "serialize let's encrypt account fail"
            );
            return Ok(account);
        },
    };
    let conf = StorageConf {
        category: "config".to_string(),
        value,
        secret: None,
        remark: Some(ACCOUNT_REMARK.to_string()),
        created_at: Some(pingap_core::now_sec()),
    };
    if let Err(e) = config_manager.update(Category::Storage, name, &conf).await
    {
        warn!(
            target: LOG_TARGET,
            error = %e,
            "save let's encrypt account fail"
        );
    }
    Ok(account)
}

/// A resolver on the system's DNS configuration for confirming that a TXT
/// record has propagated. No caching: the first lookup runs before the
/// record exists, and a cached NXDOMAIN (negative TTL is the SOA minimum -
/// often 600s, longer than the whole wait) would be replayed for every
/// remaining attempt, so the check could never see the record appear.
fn new_txt_resolver() -> Result<Resolver<TokioRuntimeProvider>> {
    // The system resolver, like everything else on this host uses; the
    // previous hardcoded default (Google public DNS) is only the fallback
    // when the system configuration is unreadable.
    let (resolver_config, mut resolver_options) = read_system_conf()
        .unwrap_or_else(|e| {
            warn!(
                target: LOG_TARGET,
                error = %e,
                "read system dns conf fail, use default resolver"
            );
            (ResolverConfig::default(), ResolverOpts::default())
        });
    resolver_options.cache_size = 0;
    let mut resolver_builder = Resolver::builder_with_config(
        resolver_config,
        TokioRuntimeProvider::default(),
    );
    *resolver_builder.options_mut() = resolver_options;
    resolver_builder.build().map_err(|e| Error::Fail {
        category: "build_resolver".to_string(),
        message: e.to_string(),
    })
}

/// ACME HTTP-01 tokens are base64url strings; anything else is rejected so the
/// token cannot be abused as a storage lookup key for path traversal.
fn is_valid_challenge_token(token: &str) -> bool {
    !token.is_empty()
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// How long one exchange with the CA, or with a dns provider, may take.
const ACME_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// The share of one domain in the time an order's authorizations may take:
/// the wait for its dns record (ten lookups, ten seconds apart) and the
/// requests around it.
const ACME_AUTHORIZATION_TIMEOUT: Duration = Duration::from_secs(150);

/// Runs `future` for at most `limit`.
///
/// Nothing in the client sets a timeout of its own, and a connection that
/// simply goes quiet never fails. The certificate task shares a background
/// service with others (log flush, log compression, certificate expiry),
/// which waits for every task before its next round: one request that
/// hung kept all of them from ever running again.
async fn bounded<T>(
    category: &str,
    limit: Duration,
    future: impl Future<Output = T>,
) -> Result<T> {
    tokio::time::timeout(limit, future)
        .await
        .map_err(|_| Error::Fail {
            category: category.to_string(),
            message: format!("no answer within {}s", limit.as_secs()),
        })
}

/// A certificate request for `names` with a new RSA key of 2048 bits: the
/// request in DER, the key in PEM.
fn rsa_request(names: Vec<String>) -> Result<(Vec<u8>, String)> {
    use pingap_certificate::rcgen;
    let fail = |e: rcgen::Error| Error::Fail {
        category: "finalize".to_string(),
        message: e.to_string(),
    };
    let key = rcgen::KeyPair::generate_rsa_for(
        &rcgen::PKCS_RSA_SHA256,
        rcgen::RsaKeySize::_2048,
    )
    .map_err(fail)?;
    let mut params = rcgen::CertificateParams::new(names).map_err(fail)?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let request = params.serialize_request(&key).map_err(fail)?;
    Ok((request.der().to_vec(), key.serialize_pem()))
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
    params: UpdateCertificateParams,
) -> Result<(String, String)> {
    let mut domains: Vec<String> = params.domains.to_vec();
    // sort domain for comparing later
    domains.sort();
    info!(
        target: LOG_TARGET,
        domains = domains.join(","),
        directory = params.server.url(),
        "order a certificate by acme"
    );
    ensure_crypto_provider();

    let account = bounded(
        "create_account",
        ACME_REQUEST_TIMEOUT,
        load_or_create_account(&config_manager, &params.server),
    )
    .await??;

    let identifiers = domains
        .iter()
        .map(|item| Identifier::Dns(item.to_owned()))
        .collect::<Vec<Identifier>>();
    let mut order = bounded(
        "new_order",
        ACME_REQUEST_TIMEOUT,
        account.new_order(&NewOrder::new(&identifiers)),
    )
    .await?
    .map_err(|e| Error::Instant {
        category: "new_order".to_string(),
        source: e,
    })?;

    // `Ready` is an order whose authorizations are all valid already: the
    // CA keeps a validation for a while and reuses it. There is nothing
    // left to prove, the loop below finds every authorization valid and the
    // order goes straight on to be finalized. Only `Pending` used to be
    // accepted, so for as long as the CA remembered the validation every
    // attempt failed here, ten minutes apart.
    let state = order.state();
    if !matches!(state.status, OrderStatus::Pending | OrderStatus::Ready) {
        return Err(Error::Fail {
            message: format!(
                "order is neither pending nor ready, status: {:?}",
                state.status
            ),
            category: "order_status".to_string(),
        });
    }

    let mut dns_tasks = vec![];
    // Built on the first DNS-01 challenge and shared by the order's others.
    let mut resolver = None;

    // Every authorization may wait for its dns record to show up, on top of
    // the CA's own validation.
    let authorize_timeout = ACME_REQUEST_TIMEOUT * 3
        + ACME_AUTHORIZATION_TIMEOUT * domains.len() as u32;
    let result = bounded("authorize", authorize_timeout, async {
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
                let identifier = challenge.identifier().to_string();
                let identifier =
                    identifier.strip_prefix("*.").unwrap_or(&identifier);
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
                let resolver = match &resolver {
                    Some(resolver) => resolver,
                    None => resolver.insert(new_txt_resolver()?),
                };
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
                remember_own_token(&challenge.token, key_auth.as_str());
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
                // Another instance may be the one the CA reaches, and it
                // answers from what it last read from the storage.
                tokio::time::sleep(TOKEN_SETTLE_DELAY).await;
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
    .await
    .and_then(|result| result);

    // After a timeout as well: the records that were added are still there.
    for task in dns_tasks.iter() {
        // ignore done error
        let done = bounded("dns_done", ACME_REQUEST_TIMEOUT, task.done())
            .await
            .and_then(|result| result);
        if let Err(err) = done {
            error!(
                target: LOG_TARGET,
                error = err.to_string(),
                "remove acme dns text record fail"
            );
        }
    }
    result?;

    let private_key_pem = if params.server.rsa {
        // The order makes an ECDSA key itself and nothing else: for an
        // RSA one the request is made here. Off the threads that serve
        // requests, a key of this kind takes its time.
        let names = domains.clone();
        let (csr, key) =
            tokio::task::spawn_blocking(move || rsa_request(names))
                .await
                .map_err(|e| Error::Fail {
                    category: "finalize".to_string(),
                    message: e.to_string(),
                })??;
        bounded("finalize", ACME_REQUEST_TIMEOUT, order.finalize_csr(&csr))
            .await?
            .map_err(|e| Error::Instant {
                category: "finalize".to_string(),
                source: e,
            })?;
        key
    } else {
        bounded("finalize", ACME_REQUEST_TIMEOUT, order.finalize())
            .await?
            .map_err(|e| Error::Instant {
                category: "finalize".to_string(),
                source: e,
            })?
    };
    let cert_chain_pem = bounded(
        "poll_certificate",
        ACME_REQUEST_TIMEOUT * 2,
        order.poll_certificate(
            &RetryPolicy::default().timeout(Duration::from_secs(60)),
        ),
    )
    .await?
    .map_err(|e| Error::Instant {
        category: "poll_certificate".to_string(),
        source: e,
    })?;

    Ok((cert_chain_pem, private_key_pem))
}

#[cfg(test)]
mod tests {
    use super::is_valid_challenge_token;
    use super::{
        LetsEncryptTask, Order, UpdateCertificateParams, retry_delay,
        update_certificate_lets_encrypt,
    };
    use pingap_certificate::{
        CertificateProvider, DynamicCertificates, TlsCertificate, rcgen,
    };
    use pingap_config::{
        Category, CertificateConf, ConfigManager, new_file_config_manager,
    };
    use pingap_core::{
        BackgroundTask, Notification, NotificationData, NotificationLevel,
        NotificationSender,
    };
    use pretty_assertions::assert_eq;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Store(Mutex<Arc<DynamicCertificates>>);
    impl CertificateProvider for Store {
        fn get(&self, sni: &str) -> Option<Arc<TlsCertificate>> {
            self.list().get(sni).cloned()
        }
        fn list(&self) -> Arc<DynamicCertificates> {
            self.0.lock().unwrap().clone()
        }
        fn store(&self, data: DynamicCertificates) {
            *self.0.lock().unwrap() = Arc::new(data);
        }
    }

    struct Recorder(Arc<Mutex<Vec<NotificationData>>>);
    #[async_trait::async_trait]
    impl Notification for Recorder {
        async fn notify(&self, data: NotificationData) {
            self.0.lock().unwrap().push(data);
        }
    }

    /// A certificate for `example.com` as the CA would give it, good for
    /// years or over since 2020.
    fn certificate(expired: bool) -> (String, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params =
            rcgen::CertificateParams::new(vec!["example.com".to_string()])
                .unwrap();
        if expired {
            params.not_before = rcgen::date_time_ymd(2019, 10, 1);
            params.not_after = rcgen::date_time_ymd(2020, 1, 1);
        }
        (params.self_signed(&key).unwrap().pem(), key.serialize_pem())
    }

    fn params() -> UpdateCertificateParams {
        UpdateCertificateParams {
            name: "site".to_string(),
            domains: vec!["example.com".to_string()],
            buffer_days: 30,
            dns_challenge: false,
            dns_provider: "".to_string(),
            dns_service_url: "".to_string(),
            server: Default::default(),
        }
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        manager: Arc<ConfigManager>,
        store: Arc<Store>,
        orders: Arc<AtomicU32>,
        notifications: Arc<Mutex<Vec<NotificationData>>>,
        task: LetsEncryptTask,
    }

    /// A task on a config directory of its own holding `certificates`, the
    /// running configuration being what is stored. An order is `order`,
    /// counted.
    async fn fixture(certificates: &str, order: Order) -> Fixture {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("certificates.toml"), certificates)
            .unwrap();
        let manager = Arc::new(
            new_file_config_manager(dir.path().to_string_lossy().as_ref())
                .unwrap(),
        );
        let config = manager.load_all().await.unwrap();
        manager.set_current_config(config.to_pingap_config(true).unwrap());
        let store = Arc::new(Store::default());
        let orders = Arc::new(AtomicU32::new(0));
        let notifications = Arc::new(Mutex::new(vec![]));
        let sender: NotificationSender =
            Box::new(Recorder(notifications.clone()));
        let counter = orders.clone();
        let task = LetsEncryptTask {
            config_manager: manager.clone(),
            certificate_provider: store.clone(),
            sender: Some(Arc::new(sender)),
            running: AtomicBool::new(false),
            order: Box::new(move |manager, params| {
                counter.fetch_add(1, Ordering::Relaxed);
                order(manager, params)
            }),
            retries: Mutex::new(HashMap::new()),
        };
        Fixture {
            _dir: dir,
            manager,
            store,
            orders,
            notifications,
            task,
        }
    }

    /// An order that works: a new certificate, stored where the real one
    /// stores it.
    fn issuing() -> Order {
        Box::new(|manager, params| {
            Box::pin(async move {
                let mut conf: CertificateConf = manager
                    .get(Category::Certificate, &params.name)
                    .await
                    .unwrap()
                    .unwrap();
                let (pem, key) = certificate(false);
                conf.tls_cert = Some(pem);
                conf.tls_key = Some(key);
                manager
                    .update(Category::Certificate, &params.name, &conf)
                    .await
                    .unwrap();
                Ok(())
            })
        })
    }

    const SITE: &str = "[certificates.site]\ndomains = \"example.com\"\nacme = \"lets_encrypt\"\n";

    /// Regression: the entry a new certificate was installed with was the
    /// stored one, whole. A setting written as a reference is the
    /// reference there, and became the setting of the running entry: the
    /// next renewal went to the provider at `$FILE:...`, and the next
    /// reload saw a changed entry.
    #[tokio::test]
    async fn test_install_keeps_the_settings_that_are_running() {
        use std::io::Write;
        let mut secret = tempfile::NamedTempFile::new().unwrap();
        secret
            .write_all(b"https://api.cloudflare.com?token=abc")
            .unwrap();
        let reference = format!("$FILE:{}", secret.path().to_string_lossy());
        let fixture = fixture(
            &format!("{SITE}dns_challenge = true\ndns_provider = \"cf\"\ndns_service_url = \"{reference}\"\n"),
            issuing(),
        )
        .await;
        // What a process runs with.
        let document = fixture.manager.load_all().await.unwrap();
        let running = document
            .to_running_config(pingap_config::MissingReference::Refuse)
            .unwrap();
        let before = running.certificates["site"].clone();
        assert_eq!(
            Some("https://api.cloudflare.com?token=abc".to_string()),
            before.dns_service_url
        );
        fixture.manager.set_current_config(running);

        fixture
            .task
            .update_certificates(0, &[params()])
            .await
            .unwrap();
        assert_eq!(1, fixture.orders.load(Ordering::Relaxed));
        let after =
            fixture.manager.get_current_config().certificates["site"].clone();
        // The certificate is the new one, the settings are what they were.
        assert_eq!(true, after.tls_cert.is_some());
        assert_eq!(
            before,
            CertificateConf {
                tls_cert: None,
                tls_key: None,
                ..after
            }
        );
        // The storage still has the reference.
        let stored: CertificateConf = fixture
            .manager
            .get(Category::Certificate, "site")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(Some(reference), stored.dns_service_url);
        assert_eq!(true, stored.tls_cert.is_some());
    }

    /// Regression: a new certificate was recorded as the running one only
    /// when every certificate of the configuration loaded. With a broken
    /// entry anywhere it was installed and served but the next check still
    /// found the old one, and ordered again: every ten minutes.
    #[tokio::test]
    async fn test_renewal_does_not_depend_on_the_other_certificates() {
        // spellchecker:off
        let broken = "[certificates.broken]\ndomains = \"broken.test\"\ntls_cert = \"bm90IGEgY2VydGlmaWNhdGU=\"\ntls_key = \"bm90IGEga2V5\"\n";
        // spellchecker:on
        let fixture = fixture(&format!("{SITE}\n{broken}"), issuing()).await;

        fixture
            .task
            .update_certificates(0, &[params()])
            .await
            .unwrap();
        assert_eq!(1, fixture.orders.load(Ordering::Relaxed));
        assert_eq!(true, fixture.store.get("example.com").is_some());
        let running = fixture.manager.get_current_config();
        assert_eq!(
            true,
            running.certificates["site"].tls_cert.is_some(),
            "the new certificate is not in the running configuration"
        );
        // The broken one is reported, and is nobody's reason to order.
        assert_eq!(
            true,
            fixture
                .notifications
                .lock()
                .unwrap()
                .iter()
                .any(|data| data.category == "parse_certificate_fail"
                    && data.message.contains("broken"))
        );

        fixture
            .task
            .update_certificates(0, &[params()])
            .await
            .unwrap();
        assert_eq!(1, fixture.orders.load(Ordering::Relaxed));
    }

    /// Regression: `domains = "Example.com"` was never the name of the
    /// certificate the CA gave for it, which has it in lower case. The
    /// domains had changed at every check, and every check ordered again.
    #[tokio::test]
    async fn test_domains_in_capitals_are_not_ordered_again() {
        assert_eq!(
            vec!["example.com".to_string(), "www.example.com".to_string()],
            super::ordered_domains(" Example.com ,, WWW.Example.COM")
        );

        let site = SITE.replace("example.com", "Example.com");
        let fixture = fixture(&site, issuing()).await;
        fixture.task.execute(0).await.unwrap();
        assert_eq!(1, fixture.orders.load(Ordering::Relaxed));
        assert_eq!(true, fixture.store.get("example.com").is_some());
        // The certificate that came back is the entry's: nothing is
        // reported about it, and no order is put off for later. (That
        // is what the count of orders alone does not show - an order
        // that failed this way is not repeated for ten minutes.)
        assert_eq!(
            false,
            fixture
                .notifications
                .lock()
                .unwrap()
                .iter()
                .any(|data| data.level != NotificationLevel::Info),
        );
        assert_eq!(true, fixture.task.retries.lock().unwrap().is_empty());
        // The next time the certificates are looked at.
        fixture.task.execute(10).await.unwrap();
        assert_eq!(1, fixture.orders.load(Ordering::Relaxed));
    }

    /// Regression: whether to order went by the running configuration
    /// alone, which only learns of a certificate from an order of its own.
    /// Of two instances on one storage each ordered its certificate.
    #[tokio::test]
    async fn test_certificate_in_the_storage_is_taken_instead_of_ordered() {
        let (pem, key) = certificate(true);
        let stored = |pem: &str, key: &str| {
            format!(
                "{SITE}tls_cert = \"\"\"\n{pem}\"\"\"\ntls_key = \"\"\"\n{key}\"\"\"\n"
            )
        };
        let fixture = fixture(&stored(&pem, &key), issuing()).await;
        // What is stored is as old as what is running: nothing to take.
        assert_eq!(
            false,
            fixture
                .task
                .adopt_stored_certificate(&params())
                .await
                .unwrap()
        );

        // Another instance renews it.
        let (pem, key) = certificate(false);
        let mut conf: CertificateConf = fixture
            .manager
            .get(Category::Certificate, "site")
            .await
            .unwrap()
            .unwrap();
        conf.tls_cert = Some(pem.clone());
        conf.tls_key = Some(key);
        fixture
            .manager
            .update(Category::Certificate, "site", &conf)
            .await
            .unwrap();

        fixture
            .task
            .update_certificates(0, &[params()])
            .await
            .unwrap();
        assert_eq!(0, fixture.orders.load(Ordering::Relaxed));
        assert_eq!(true, fixture.store.get("example.com").is_some());
        assert_eq!(
            Some(pem),
            fixture.manager.get_current_config().certificates["site"]
                .tls_cert
                .clone()
        );

        // One for other domains is not this entry's certificate.
        let other = UpdateCertificateParams {
            domains: vec![
                "example.com".to_string(),
                "www.example.com".to_string(),
            ],
            ..params()
        };
        assert_eq!(
            false,
            fixture.task.adopt_stored_certificate(&other).await.unwrap()
        );
    }

    /// Regression: a failed order was logged and tried again at the next
    /// check, ten minutes later, without end and without a word to
    /// whoever could do something about it.
    #[tokio::test]
    async fn test_failed_order_is_reported_and_put_off() {
        let failing: Order = Box::new(|_, _| {
            Box::pin(async {
                Err(super::Error::Fail {
                    category: "order".to_string(),
                    message: "the CA says no".to_string(),
                })
            })
        });
        let fixture = fixture(SITE, failing).await;

        fixture
            .task
            .update_certificates(0, &[params()])
            .await
            .unwrap();
        assert_eq!(1, fixture.orders.load(Ordering::Relaxed));
        {
            let notifications = fixture.notifications.lock().unwrap();
            assert_eq!(1, notifications.len());
            assert_eq!("lets_encrypt", notifications[0].category);
            assert_eq!(NotificationLevel::Error, notifications[0].level);
            assert_eq!(
                true,
                notifications[0].message.contains("the CA says no"),
                "{}",
                notifications[0].message
            );
        }
        // The next check comes too soon for another order.
        fixture
            .task
            .update_certificates(0, &[params()])
            .await
            .unwrap();
        assert_eq!(1, fixture.orders.load(Ordering::Relaxed));

        // Once the wait is over it is tried again, and waits longer.
        let wait_over = |fixture: &Fixture| {
            let mut retries = fixture.task.retries.lock().unwrap();
            let retry = retries.get_mut("site").unwrap();
            let waited = retry.not_before - pingap_core::now_sec();
            retry.not_before = 0;
            (retry.failures, waited)
        };
        let (failures, waited) = wait_over(&fixture);
        assert_eq!(1, failures);
        assert_eq!(true, (590..=600).contains(&waited), "{waited}");
        fixture
            .task
            .update_certificates(0, &[params()])
            .await
            .unwrap();
        assert_eq!(2, fixture.orders.load(Ordering::Relaxed));
        let (failures, waited) = wait_over(&fixture);
        assert_eq!(2, failures);
        assert_eq!(true, (1190..=1200).contains(&waited), "{waited}");
    }

    /// An order that works and gives a certificate the entry takes for due
    /// at once - `buffer_days` longer than the certificate lasts - was
    /// made again at every check.
    #[tokio::test]
    async fn test_certificate_that_is_due_at_once_is_not_ordered_again() {
        // Good for ninety days, with a margin of a hundred.
        let short: Order = Box::new(|manager, params| {
            Box::pin(async move {
                let key = rcgen::KeyPair::generate().unwrap();
                let mut cert =
                    rcgen::CertificateParams::new(params.domains.clone())
                        .unwrap();
                let now = std::time::SystemTime::now();
                let day = std::time::Duration::from_secs(24 * 3600);
                cert.not_before = (now - day).into();
                cert.not_after = (now + 90 * day).into();
                let mut conf: CertificateConf = manager
                    .get(Category::Certificate, &params.name)
                    .await
                    .unwrap()
                    .unwrap();
                conf.tls_cert = Some(cert.self_signed(&key).unwrap().pem());
                conf.tls_key = Some(key.serialize_pem());
                manager
                    .update(Category::Certificate, &params.name, &conf)
                    .await
                    .unwrap();
                Ok(())
            })
        });
        let fixture = fixture(SITE, short).await;
        let params = UpdateCertificateParams {
            buffer_days: 100,
            ..params()
        };
        for _ in 0..3 {
            fixture
                .task
                .update_certificates(0, std::slice::from_ref(&params))
                .await
                .unwrap();
        }
        // Ordered once, installed, and reported as something to look at.
        assert_eq!(1, fixture.orders.load(Ordering::Relaxed));
        assert_eq!(true, fixture.store.get("example.com").is_some());
        let notifications = fixture.notifications.lock().unwrap();
        assert_eq!(
            true,
            notifications
                .iter()
                .any(|data| data.level == NotificationLevel::Error
                    && data.message.contains("already due")),
            "{notifications:?}"
        );
    }

    /// The challenge path asked the storage on every request. It is read
    /// once for everyone who asks within a second, a token of another
    /// instance is still found there, and a token of an order of this
    /// process does not need the storage at all.
    #[tokio::test]
    async fn test_stored_tokens_are_read_once_for_everyone() {
        use super::{
            HTTP_01_TOKEN_REMARK, StoredTokens, StoredTokensState, own_token,
            remember_own_token,
        };
        use pingap_config::{Category, StorageConf};
        use std::time::{Duration, Instant};

        let dir = tempfile::TempDir::new().unwrap();
        let manager = new_file_config_manager(&format!(
            "{}?separation=true",
            dir.path().to_string_lossy()
        ))
        .unwrap();
        let store = async |name: &str| {
            manager
                .update(
                    Category::Storage,
                    name,
                    &StorageConf {
                        category: "config".to_string(),
                        value: format!("{name}.thumbprint"),
                        secret: None,
                        remark: Some(HTTP_01_TOKEN_REMARK.to_string()),
                        created_at: None,
                    },
                )
                .await
                .unwrap();
        };
        // What was read is too old to answer from. The test sets that
        // itself, with lifetimes no run of it outlasts, instead of waiting.
        let expire = async |tokens: &StoredTokens| {
            tokens.state.lock().await.loaded_at = None;
        };
        let hour = Duration::from_secs(3600);
        store("first").await;

        let tokens = StoredTokens::new(hour, hour);
        // A token of another instance, among any number of made-up ones.
        for index in 0..1000 {
            let name = format!("made-up-{index}");
            assert_eq!(None, tokens.get(&manager, &name).await.unwrap());
        }
        assert_eq!(
            Some("first.thumbprint".to_string()),
            tokens.get(&manager, "first").await.unwrap()
        );

        // The storage was read for the first of them only: a token added
        // since is not seen until that read is too old.
        store("second").await;
        assert_eq!(None, tokens.get(&manager, "second").await.unwrap());
        expire(&tokens).await;
        assert_eq!(
            Some("second.thumbprint".to_string()),
            tokens.get(&manager, "second").await.unwrap()
        );

        // An entry of another category that does not parse is not in the
        // way: only the storage category is read.
        let upstreams = dir.path().join("upstreams");
        std::fs::create_dir_all(&upstreams).unwrap();
        std::fs::write(upstreams.join("broken.toml"), "not toml [").unwrap();
        store("third").await;
        expire(&tokens).await;
        assert_eq!(
            Some("third.thumbprint".to_string()),
            tokens.get(&manager, "third").await.unwrap()
        );

        // A storage that cannot be read: what was read before is still
        // answered, and for anything else the answer is the failure, not
        // "no such token" - for the requests that did not read as well.
        let storages = dir.path().join("storages");
        std::fs::write(storages.join("broken.toml"), "not toml [").unwrap();
        expire(&tokens).await;
        for _ in 0..3 {
            let failure = tokens.get(&manager, "made-up").await.unwrap_err();
            assert_eq!(true, failure.contains("broken.toml"), "{failure}");
            assert_eq!(
                Some("first.thumbprint".to_string()),
                tokens.get(&manager, "first").await.unwrap()
            );
        }
        // Readable again: the failure is over with the next read.
        std::fs::remove_file(storages.join("broken.toml")).unwrap();
        expire(&tokens).await;
        assert_eq!(None, tokens.get(&manager, "made-up").await.unwrap());

        // A read that failed stands for less long than one that did not.
        let impatient = StoredTokens::new(hour, Duration::ZERO);
        std::fs::write(storages.join("broken.toml"), "not toml [").unwrap();
        assert_eq!(true, impatient.get(&manager, "first").await.is_err());
        std::fs::remove_file(storages.join("broken.toml")).unwrap();
        assert_eq!(
            Some("first.thumbprint".to_string()),
            impatient.get(&manager, "first").await.unwrap()
        );

        // A read that took longer than it is good for: the requests that
        // were waiting for it are answered from it, a later one is not.
        let now = Instant::now();
        let second = Duration::from_secs(1);
        if let (Some(before), Some(began)) =
            (now.checked_sub(second * 3), now.checked_sub(second * 2))
        {
            let slow = StoredTokensState {
                loaded_at: Some(began),
                ..Default::default()
            };
            assert_eq!(true, slow.answers(before, second));
            assert_eq!(false, slow.answers(now, second));
            assert_eq!(true, slow.answers(now, hour));
        }
        assert_eq!(false, StoredTokensState::default().answers(now, hour));

        assert_eq!(None, own_token("token-of-nobody"));
        remember_own_token("token-of-this-process", "token.thumbprint");
        assert_eq!(
            Some("token.thumbprint".to_string()),
            own_token("token-of-this-process")
        );
    }

    #[test]
    fn test_retry_delay() {
        assert_eq!(600, retry_delay(1));
        assert_eq!(1200, retry_delay(2));
        assert_eq!(4800, retry_delay(4));
        assert_eq!(6 * 3600, retry_delay(7));
        assert_eq!(6 * 3600, retry_delay(u32::MAX));
        // Never asked with none, and no shorter than the first if it is.
        assert_eq!(600, retry_delay(0));
    }

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
                server: Default::default(),
            },
        )
        .await
        .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("panel"), "{message}");
        assert!(message.contains("could not be persisted"), "{message}");
    }

    /// A directory of hcl files is read-only, and the certificate could
    /// not be saved: said so, before anything is asked of the CA.
    #[tokio::test]
    async fn test_renewal_refuses_a_read_only_storage() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("main.hcl"),
            "certificate \"panel\" {\n  domains = \"example.com\"\n  acme = \"lets_encrypt\"\n}\n",
        )
        .unwrap();
        let manager = Arc::new(
            new_file_config_manager(dir.path().to_string_lossy().as_ref())
                .unwrap(),
        );
        let message = update_certificate_lets_encrypt(
            manager,
            UpdateCertificateParams {
                name: "panel".to_string(),
                domains: vec!["example.com".to_string()],
                buffer_days: 30,
                dns_challenge: false,
                dns_provider: "".to_string(),
                dns_service_url: "".to_string(),
                server: Default::default(),
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(message.contains("read but not written"), "{message}");
    }

    /// An exchange that gets no answer ends, with an error that says so.
    #[tokio::test]
    async fn test_bounded() {
        use super::bounded;
        use std::time::Duration;

        let result = bounded("new_order", Duration::from_millis(20), async {
            tokio::time::sleep(Duration::from_secs(30)).await;
        })
        .await;
        assert_eq!(
            "Let's Encrypt operation failed: no answer within 0s, category: new_order",
            result.unwrap_err().to_string()
        );
        let result =
            bounded("new_order", Duration::from_secs(5), async { 7 }).await;
        assert_eq!(7, result.unwrap());
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
        // The manual DNS task's TXT value: swept by age like a token.
        manager
            .update(
                Category::Storage,
                "manual-txt",
                &token(
                    Some(now - 25 * 3600),
                    crate::dns_manual::MANUAL_DNS_REMARK,
                ),
            )
            .await
            .unwrap();

        let removed = clear_stale_http_tokens(&manager, now).await.unwrap();
        assert_eq!(3, removed);

        let left = manager.load_all().await.unwrap();
        let left = left.storages.unwrap();
        assert!(left.contains_key("fresh"));
        assert!(left.contains_key("user-data"));
        assert!(!left.contains_key("stale"));
        assert!(!left.contains_key("legacy"));
        assert!(!left.contains_key("manual-txt"));

        // Nothing left to do on the next run.
        assert_eq!(0, clear_stale_http_tokens(&manager, now).await.unwrap());
    }

    /// Regression: the challenge endpoint answered with any storage entry
    /// the token happened to name, the ACME account credentials included.
    #[tokio::test]
    async fn test_load_http_01_token_only_serves_tokens() {
        use super::{
            ACCOUNT_REMARK, HTTP_01_TOKEN_REMARK, account_storage_name,
            load_http_01_tokens,
        };
        use pingap_config::{Category, StorageConf};

        let dir = tempfile::TempDir::new().unwrap();
        let manager = new_file_config_manager(&format!(
            "{}?separation=true",
            dir.path().to_string_lossy()
        ))
        .unwrap();
        let entry = |value: &str, remark: Option<&str>| StorageConf {
            category: "config".to_string(),
            value: value.to_string(),
            secret: None,
            remark: remark.map(|remark| remark.to_string()),
            created_at: None,
        };
        for (name, conf) in [
            ("token", entry("key-auth", Some(HTTP_01_TOKEN_REMARK))),
            (
                account_storage_name(true),
                entry("account-key", Some(ACCOUNT_REMARK)),
            ),
            ("include", entry("secret", None)),
            ("user-data", entry("secret", Some("my secret"))),
        ] {
            manager
                .update(Category::Storage, name, &conf)
                .await
                .unwrap();
        }

        let tokens = load_http_01_tokens(&manager).await.unwrap();
        assert_eq!(Some("key-auth"), tokens.get("token").map(|v| v.as_str()));
        assert_eq!(1, tokens.len(), "{tokens:?}");
    }

    #[test]
    fn test_account_storage_name() {
        use super::account_storage_name;
        assert_eq!("lets_encrypt_account", account_storage_name(true));
        assert_eq!("lets_encrypt_staging_account", account_storage_name(false));
    }

    /// What a certificate's entry says of the CA, as an order uses it.
    #[test]
    fn test_acme_server() {
        use super::AcmeServer;
        use instant_acme::LetsEncrypt;
        use pingap_config::CertificateConf;
        let server = |conf: &str| {
            AcmeServer::new(&toml::from_str::<CertificateConf>(conf).unwrap())
        };

        // Nothing said: Let's Encrypt, under the name the account has
        // always been stored by.
        let default = server("domains = \"example.com\"");
        assert_eq!(AcmeServer::default(), default);
        assert_eq!(LetsEncrypt::Production.url(), default.url());
        assert_eq!("lets_encrypt_account", default.account_storage_name());
        assert_eq!(
            "lets_encrypt_staging_account",
            server(&format!(
                "acme_directory = \"{}\"",
                LetsEncrypt::Staging.url()
            ))
            .account_storage_name()
        );

        let zero = server(
            "acme_directory = \"https://acme.zerossl.com/v2/DV90\"\nacme_eab_kid = \"kid-1\"\nacme_eab_hmac = \"c2VjcmV0LWtleQ\"\nacme_contact = \"ops@example.com, mailto:sec@example.com\"\nacme_key_type = \"rsa\"\nacme_ca = \" /etc/ssl/ca.pem \"",
        );
        assert_eq!("https://acme.zerossl.com/v2/DV90", zero.url());
        assert_eq!(
            Some(("kid-1".to_string(), b"secret-key".to_vec())),
            zero.eab
        );
        assert_eq!(
            vec!["mailto:ops@example.com", "mailto:sec@example.com"],
            zero.contact
        );
        assert_eq!(true, zero.rsa);
        assert_eq!(Some("/etc/ssl/ca.pem".to_string()), zero.ca);
        // The key of the binding is not in what gets logged.
        let debug = format!("{zero:?}");
        assert_eq!(true, debug.contains("kid-1"), "{debug}");
        assert_eq!(false, debug.contains("115, 101"), "{debug}");

        // One account per CA, and per binding at one CA.
        let name = zero.account_storage_name();
        assert_eq!(true, name.starts_with("acme_account_"), "{name}");
        assert_eq!(29, name.len());
        let other_kid = server(
            "acme_directory = \"https://acme.zerossl.com/v2/DV90\"\nacme_eab_kid = \"kid-2\"\nacme_eab_hmac = \"c2VjcmV0LWtleQ\"",
        );
        let other_ca = server("acme_directory = \"https://ca.internal/acme\"");
        assert_eq!(true, name != other_kid.account_storage_name());
        assert_eq!(true, name != other_ca.account_storage_name());
        assert_eq!(
            true,
            other_kid.account_storage_name() != other_ca.account_storage_name()
        );
        // Let's Encrypt with a binding is not the account without one.
        let bound = server(
            "acme_eab_kid = \"kid-1\"\nacme_eab_hmac = \"c2VjcmV0LWtleQ\"",
        );
        assert_eq!(true, bound.account_storage_name().starts_with("acme_"));
    }

    /// An RSA key and a request for it that names the domains.
    #[test]
    fn test_rsa_request() {
        use pingap_certificate::rcgen;
        let (csr, key) = super::rsa_request(vec![
            "example.com".to_string(),
            "*.example.com".to_string(),
        ])
        .unwrap();
        assert_eq!(true, key.starts_with("-----BEGIN PRIVATE KEY-----"));
        let key = rcgen::KeyPair::from_pem(&key).unwrap();
        assert_eq!(true, key.is_compatible(&rcgen::PKCS_RSA_SHA256));
        let request = rcgen::CertificateSigningRequestParams::from_der(
            &csr.as_slice().into(),
        )
        .unwrap();
        assert_eq!(
            vec![
                rcgen::SanType::DnsName("example.com".try_into().unwrap()),
                rcgen::SanType::DnsName("*.example.com".try_into().unwrap()),
            ],
            request.params.subject_alt_names
        );
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
