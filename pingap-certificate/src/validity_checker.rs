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

use super::{get_certificate_info_list, Certificate, LOG_CATEGORY};
use pingap_core::Error as ServiceError;
use pingap_core::SimpleServiceTaskFuture;
use snafu::Snafu;
use tracing::error;

/// Number of seconds in a day
const SECONDS_PER_DAY: i64 = 24 * 3600;
/// Default certificate expiration warning threshold (7 days)
const DEFAULT_EXPIRATION_WARNING_DAYS: i64 = 7;
/// Check interval in minutes
const CHECK_INTERVAL_MINUTES: u32 = 24 * 60;

/// Certificate validity error types
#[derive(Debug, Snafu)]
pub enum ValidityError {
    #[snafu(display("{name} cert will expire on {date}, issuer: {issuer}"))]
    WillExpire {
        name: String,
        issuer: String,
        date: i64,
    },
    #[snafu(display("{name} cert not valid until {date}, issuer: {issuer}"))]
    NotYetValid {
        name: String,
        issuer: String,
        date: i64,
    },
}

/// Checks the validity of certificates against current time and expiration threshold
///
/// # Arguments
///
/// * `validity_list` - List of tuples containing certificate name and certificate data
/// * `time_offset` - Time offset in seconds to check for upcoming expiration
///
/// # Returns
///
/// * `Ok(())` if all certificates are valid
/// * `Err(ValidityError)` if any certificate is invalid or about to expire
fn validity_check(
    validity_list: &[(String, Certificate)],
    time_offset: i64,
) -> Result<(), ValidityError> {
    let now = pingap_util::now_sec() as i64;
    for (name, cert) in validity_list.iter() {
        // Skip ACME certificates as they auto-update
        if cert.acme.is_some() {
            continue;
        }

        if now > cert.not_after - time_offset {
            return Err(ValidityError::WillExpire {
                name: name.clone(),
                issuer: cert.issuer.clone(),
                date: cert.not_after,
            });
        }

        if now < cert.not_before {
            return Err(ValidityError::NotYetValid {
                name: name.clone(),
                issuer: cert.issuer.clone(),
                date: cert.not_before,
            });
        }
    }
    Ok(())
}

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
async fn do_validity_check(count: u32) -> Result<bool, ServiceError> {
    if count % CHECK_INTERVAL_MINUTES != 0 {
        return Ok(false);
    }

    let certificate_info_list = get_certificate_info_list();
    let time_offset = DEFAULT_EXPIRATION_WARNING_DAYS * SECONDS_PER_DAY;

    if let Err(err) = validity_check(&certificate_info_list, time_offset) {
        error!(category = LOG_CATEGORY, task = "validityChecker", error = %err);
        pingap_webhook::send_notification(pingap_core::NotificationData {
            level: pingap_core::NotificationLevel::Warn,
            category: "tls_validity".to_string(),
            message: err.to_string(),
            ..Default::default()
        })
        .await;
    }
    Ok(true)
}

/// Creates a new background service for certificate validity checking
///
/// # Returns
///
/// A tuple containing:
/// * Service name as String
/// * Service task future for executing validity checks
pub fn new_certificate_validity_service() -> (String, SimpleServiceTaskFuture) {
    let task: SimpleServiceTaskFuture =
        Box::new(|count: u32| Box::pin(do_validity_check(count)));
    ("validityChecker".to_string(), task)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use x509_parser::time::ASN1Time;

    #[test]
    fn test_validity_check() {
        let result = validity_check(
            &[(
                "Pingap".to_string(),
                Certificate {
                    not_after: ASN1Time::from_timestamp(2651852800)
                        .unwrap()
                        .timestamp(),
                    not_before: ASN1Time::from_timestamp(2651852800)
                        .unwrap()
                        .timestamp(),
                    issuer: "pingap".to_string(),
                    ..Default::default()
                },
            )],
            7 * 24 * 3600,
        );

        assert_eq!(
            "Pingap cert not valid until 2651852800, issuer: pingap",
            result.unwrap_err().to_string()
        );

        let result = validity_check(
            &[(
                "Pingap".to_string(),
                Certificate {
                    not_after: ASN1Time::from_timestamp(2651852800)
                        .unwrap()
                        .timestamp(),
                    not_before: ASN1Time::from_timestamp(2651852800)
                        .unwrap()
                        .timestamp(),
                    issuer: "pingap".to_string(),
                    ..Default::default()
                },
            )],
            7 * 24 * 3600,
        );
        assert_eq!(
            "Pingap cert not valid until 2651852800, issuer: pingap",
            result.unwrap_err().to_string()
        );
    }
}
