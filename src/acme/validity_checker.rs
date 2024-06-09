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

use crate::service::{CommonServiceTask, ServiceTask};
use crate::util;
use crate::webhook;
use async_trait::async_trait;
use log::warn;
use std::time::Duration;
use x509_parser::certificate::Validity;

struct ValidityChecker {
    time_offset: i64,
    validity_list: Vec<(String, Validity)>,
}

fn validity_check(validity_list: &[(String, Validity)], time_offset: i64) -> Option<String> {
    let now = util::now().as_secs() as i64;
    for (name, validity) in validity_list.iter() {
        if now > validity.not_after.timestamp() - time_offset {
            let message = format!(
                "{name} cert will be expired, expired date: {:?}",
                validity.not_after
            );
            return Some(message);
        }
        if now < validity.not_before.timestamp() {
            let message = format!(
                "{name} cert is not valid, valid date: {:?}",
                validity.not_before
            );
            return Some(message);
        }
    }
    None
}

#[async_trait]
impl ServiceTask for ValidityChecker {
    async fn run(&self) -> Option<bool> {
        if let Some(message) = validity_check(&self.validity_list, self.time_offset) {
            warn!("{message}");
            webhook::send(webhook::SendNotificationParams {
                level: webhook::NotificationLevel::Warn,
                category: webhook::NotificationCategory::TlsValidity,
                msg: message,
            });
        }
        None
    }
    fn description(&self) -> String {
        let offset_human: humantime::Duration = Duration::from_secs(self.time_offset as u64).into();
        format!(
            "offset: {offset_human}, validity_list: {:?}",
            self.validity_list
        )
    }
}

pub fn new_tls_validity_service(validity_list: Vec<(String, Validity)>) -> CommonServiceTask {
    let checker = ValidityChecker {
        validity_list,
        // cert will be expired 7 days later
        time_offset: 7 * 24 * 3600_i64,
    };
    CommonServiceTask::new(
        "Tls validity checker",
        // check interval: one day
        Duration::from_secs(24 * 60 * 60),
        checker,
    )
}

#[cfg(test)]
mod tests {
    use crate::service::ServiceTask;

    use super::{new_tls_validity_service, validity_check, Validity, ValidityChecker};
    use pretty_assertions::assert_eq;
    use x509_parser::time::ASN1Time;

    #[test]
    fn test_validity_check() {
        let result = validity_check(
            &[(
                "Pingap".to_string(),
                Validity {
                    not_after: ASN1Time::from_timestamp(1651852800).unwrap(),
                    not_before: ASN1Time::now(),
                },
            )],
            7 * 24 * 3600,
        );
        assert_eq!(
            "Pingap cert will be expired, expired date: ASN1Time(2022-05-06 16:00:00.0 +00:00:00)",
            result.unwrap_or_default().to_string()
        );

        let result = validity_check(
            &[(
                "Pingap".to_string(),
                Validity {
                    not_after: ASN1Time::from_timestamp(2651852800).unwrap(),
                    not_before: ASN1Time::from_timestamp(2651852800).unwrap(),
                },
            )],
            7 * 24 * 3600,
        );
        assert_eq!(
            "Pingap cert is not valid, valid date: ASN1Time(2054-01-12 17:46:40.0 +00:00:00)",
            result.unwrap_or_default().to_string()
        );
    }
    #[tokio::test]
    async fn test_validity_service() {
        let _ = new_tls_validity_service(vec![(
            "Pingap".to_string(),
            Validity {
                not_after: ASN1Time::from_timestamp(2651852800).unwrap(),
                not_before: ASN1Time::from_timestamp(2651852800).unwrap(),
            },
        )]);
        let checker = ValidityChecker {
            validity_list: vec![(
                "Pingap".to_string(),
                Validity {
                    not_after: ASN1Time::from_timestamp(2651852800).unwrap(),
                    not_before: ASN1Time::from_timestamp(2651852800).unwrap(),
                },
            )],
            time_offset: 7 * 24 * 3600_i64,
        };
        assert_eq!(
            r#"offset: 7days, validity_list: [("Pingap", Validity { not_before: ASN1Time(2054-01-12 17:46:40.0 +00:00:00), not_after: ASN1Time(2054-01-12 17:46:40.0 +00:00:00) })]"#,
            checker.description()
        );
        let result = checker.run().await;
        assert_eq!(true, result.is_none());
    }
}
