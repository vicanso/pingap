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

use super::{Certificate, LOG_CATEGORY};
use crate::proxy::get_certificate_info_list;
use crate::service::SimpleServiceTaskFuture;
use crate::util;
use crate::webhook;
use tracing::warn;

// Verify the validity period of tls certificate,
// include not after and not before.
fn validity_check(
    validity_list: &[(String, Certificate)],
    time_offset: i64,
) -> Result<(), String> {
    let now = util::now().as_secs() as i64;
    for (name, cert) in validity_list.iter() {
        // acme certificate will auto update
        if cert.acme.is_some() {
            continue;
        }
        // will expire check
        if now > cert.not_after - time_offset {
            let message = format!(
                "{name} cert will be expired, issuer: {}, expired date: {:?}",
                cert.issuer, cert.not_after
            );
            return Err(message);
        }
        // not valid check
        if now < cert.not_before {
            let message = format!(
                "{name} cert is not valid, issuer: {}, valid date: {:?}",
                cert.issuer, cert.not_before
            );
            return Err(message);
        }
    }
    Ok(())
}

async fn do_validity_check(count: u32) -> Result<(), String> {
    // Add 1 every loop
    let offset = 24 * 60;
    if count % offset != 0 {
        return Ok(());
    }
    let certificate_info_list = get_certificate_info_list();
    let time_offset = 7 * 24 * 3600_i64;
    if let Err(message) = validity_check(&certificate_info_list, time_offset) {
        // certificate will be expired
        warn!(category = LOG_CATEGORY, message);
        webhook::send(webhook::SendNotificationParams {
            level: webhook::NotificationLevel::Warn,
            category: webhook::NotificationCategory::TlsValidity,
            msg: message,
            ..Default::default()
        });
    }
    Ok(())
}

pub fn new_certificate_validity_service() -> (String, SimpleServiceTaskFuture) {
    let task: SimpleServiceTaskFuture =
        Box::new(|count: u32| Box::pin(do_validity_check(count)));
    ("validityChecker".to_string(), task)
}

#[cfg(test)]
mod tests {
    use super::validity_check;
    use crate::acme::Certificate;
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
            "Pingap cert is not valid, issuer: pingap, valid date: 2651852800",
            result.unwrap_err()
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
            "Pingap cert is not valid, issuer: pingap, valid date: 2651852800",
            result.unwrap_err()
        );
    }
}
