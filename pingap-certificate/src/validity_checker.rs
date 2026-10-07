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

use super::LOG_TARGET;
use crate::CertificateProvider;
use ahash::AHashSet;
use async_trait::async_trait;
use pingap_core::Error as ServiceError;
use pingap_core::{
    BackgroundTask, NotificationData, NotificationLevel, NotificationSender,
};
use std::sync::Arc;
use tracing::error;

/// Number of seconds in a day
const SECONDS_PER_DAY: i64 = 24 * 3600;
/// Default certificate expiration warning threshold (7 days)
const DEFAULT_EXPIRATION_WARNING_DAYS: u16 = 7;
/// Check interval in minutes
const CHECK_INTERVAL_MINUTES: u32 = 24 * 60;

/// Performs periodic certificate validity checks and sends notifications for issues
///
/// # Arguments
///
/// * `count` - Counter for determining check intervals
///
/// # Returns
///
/// * `Ok(true)` if check was performed
/// * `Ok(false)` if check was skipped due to interval
/// * `Err(ServiceError)` if an error occurred during the check
async fn do_validity_check(
    count: u32,
    provider: Arc<dyn CertificateProvider>,
    sender: Option<Arc<NotificationSender>>,
) -> Result<bool, ServiceError> {
    if !count.is_multiple_of(CHECK_INTERVAL_MINUTES) {
        return Ok(false);
    }

    let now = pingap_core::now_sec() as i64;
    let mut name_list = vec![];
    // The store maps every domain to its certificate: check each
    // certificate once and report it by its configured name, not once per
    // domain.
    let mut checked = AHashSet::new();
    for cert in provider.list().values() {
        if !checked.insert(cert.hash_key.clone()) {
            continue;
        }
        let Some(info) = &cert.info else {
            continue;
        };
        let name = cert.name.clone().unwrap_or_default();
        let domains = cert.domains.join(",");
        let mut buffer_days = cert.buffer_days;
        if buffer_days == 0 {
            buffer_days = DEFAULT_EXPIRATION_WARNING_DAYS;
        }
        let mut time_offset = (buffer_days as i64) * SECONDS_PER_DAY;
        // A certificate of ACME is renewed for whoever runs it, and
        // `buffer_days` is when: until then there is nothing to warn of.
        // It is warned of once half of that margin is gone as well, a week
        // before the end at the latest - by then the renewal has failed
        // for a while, or was never going to happen: the ACME task is
        // switched off, or the challenge is one that is answered by hand.
        if info.acme.is_some() {
            time_offset = (info.renewal_margin(cert.buffer_days) / 2)
                .min(DEFAULT_EXPIRATION_WARNING_DAYS as i64 * SECONDS_PER_DAY);
        }

        if now > info.not_after - time_offset {
            error!(
                target: LOG_TARGET,
                expired_date = info.not_after.to_string(),
                name,
                domains,
                "certificate will be expired",
            );
            name_list.push(name);
            continue;
        }

        if now < info.not_before {
            error!(
                target: LOG_TARGET,
                valid_date = info.not_before.to_string(),
                name,
                domains,
                "certificate is not valid",
            );
            name_list.push(name);
            continue;
        }
    }
    name_list.sort();

    if !name_list.is_empty()
        && let Some(sender) = &sender
    {
        sender
            .notify(NotificationData {
                level: NotificationLevel::Warn,
                category: "tls_validity".to_string(),
                message: format!(
                    "certificate {} will be expired",
                    name_list.join(",")
                ),
                ..Default::default()
            })
            .await;
    }
    Ok(true)
}

struct CertificateValidityTask {
    provider: Arc<dyn CertificateProvider>,
    sender: Option<Arc<NotificationSender>>,
}

#[async_trait]
impl BackgroundTask for CertificateValidityTask {
    async fn execute(&self, count: u32) -> Result<bool, ServiceError> {
        do_validity_check(count, self.provider.clone(), self.sender.clone())
            .await?;
        Ok(true)
    }
}

/// Creates a new background service for certificate validity checking
///
/// # Returns
///
/// A tuple containing:
/// * Service name as String
/// * Service task future for executing validity checks
pub fn new_certificate_validity_service(
    provider: Arc<dyn CertificateProvider>,
    sender: Option<Arc<NotificationSender>>,
) -> Box<dyn BackgroundTask> {
    Box::new(CertificateValidityTask { provider, sender })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DynamicCertificates, TlsCertificate, update_certificates};
    use pingap_config::CertificateConf;
    use pretty_assertions::assert_eq;
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct Store(DynamicCertificates);
    impl CertificateProvider for Store {
        fn get(&self, sni: &str) -> Option<Arc<TlsCertificate>> {
            self.0.get(sni).cloned()
        }
        fn list(&self) -> Arc<DynamicCertificates> {
            Arc::new(self.0.clone())
        }
        fn store(&self, _data: DynamicCertificates) {}
    }

    struct Recorder(Arc<Mutex<Vec<String>>>);
    #[async_trait]
    impl pingap_core::Notification for Recorder {
        async fn notify(&self, data: NotificationData) {
            self.0.lock().unwrap().push(data.message);
        }
    }

    /// A certificate for `domain`, issued sixty days ago, that is over in
    /// `days`.
    fn expiring(domain: &str, acme: bool, days: u64) -> CertificateConf {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params =
            rcgen::CertificateParams::new(vec![domain.to_string()]).unwrap();
        let now = std::time::SystemTime::now();
        let day = std::time::Duration::from_secs(24 * 3600);
        params.not_before = (now - 60 * day).into();
        params.not_after = (now + days as u32 * day).into();
        let cert = params.self_signed(&key).unwrap();
        CertificateConf {
            domains: Some(domain.to_string()),
            tls_cert: Some(cert.pem()),
            tls_key: Some(key.serialize_pem()),
            acme: acme.then(|| "lets_encrypt".to_string()),
            ..Default::default()
        }
    }

    /// Regression: nothing marked a certificate as one of ACME, so the
    /// check that is for certificates somebody has to replace by hand
    /// warned about those as well, every day from a week before the end,
    /// while their renewal was not even due. One that is still not
    /// renewed a week before its end is another matter.
    #[tokio::test]
    async fn test_validity_check_leaves_acme_certificates_to_acme() {
        let configs = HashMap::from([
            // Due for renewal (20 of 80 days left), which is its task's.
            ("renewing".to_string(), expiring("renewing.test", true, 20)),
            // Should have been renewed long ago.
            ("stuck".to_string(), expiring("stuck.test", true, 3)),
            ("manual".to_string(), expiring("manual.test", false, 3)),
            ("fine".to_string(), expiring("fine.test", false, 20)),
        ]);
        let (certificates, errors, _) =
            update_certificates(&configs, &DynamicCertificates::default());
        assert_eq!(true, errors.is_empty(), "{errors:?}");
        let messages = Arc::new(Mutex::new(vec![]));
        let sender: NotificationSender = Box::new(Recorder(messages.clone()));

        let checked = do_validity_check(
            0,
            Arc::new(Store(certificates)),
            Some(Arc::new(sender)),
        )
        .await
        .unwrap();
        assert_eq!(true, checked);
        assert_eq!(
            vec!["certificate manual,stuck will be expired".to_string()],
            *messages.lock().unwrap()
        );
    }
}
