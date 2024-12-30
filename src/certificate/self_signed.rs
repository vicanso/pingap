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

use crate::service::Error as ServiceError;
use crate::service::SimpleServiceTaskFuture;
use crate::util;
use ahash::AHashMap;
use arc_swap::ArcSwap;
use once_cell::sync::Lazy;
use pingora::tls::pkey::{PKey, Private};
use pingora::tls::x509::X509;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

const VALIDITY_CHECK_INTERVAL: u32 = 24 * 60; // 24 hours in minutes
const CERTIFICATE_EXPIRY_DAYS: u64 = 2;
const SECONDS_PER_DAY: u64 = 24 * 3600;

/// Represents a self-signed certificate with usage tracking
#[derive(Debug)]
pub struct SelfSignedCertificate {
    pub x509: X509,
    pub key: PKey<Private>,
    stale: AtomicBool,
    count: AtomicU32,
    not_after: i64,
}

type SelfSignedCertificateMap = AHashMap<String, Arc<SelfSignedCertificate>>;
static SELF_SIGNED_CERTIFICATE_MAP: Lazy<ArcSwap<SelfSignedCertificateMap>> =
    Lazy::new(|| ArcSwap::from_pointee(AHashMap::new()));

/// Checks the validity of self-signed certificates and performs cleanup.
///
/// # Arguments
///
/// * `count` - The current iteration count used to determine when to perform validity checks
///
/// # Returns
///
/// * `Ok(true)` if the validity check was performed
/// * `Ok(false)` if the check was skipped (based on count)
/// * `Err(CertificateError)` if the validation process failed
///
/// This function performs the following:
/// 1. Checks if it's time to perform validation based on the count
/// 2. Removes expired certificates
/// 3. Updates usage statistics and stale flags
/// 4. Stores the updated certificate map
async fn do_self_signed_certificate_validity(
    count: u32,
) -> Result<bool, ServiceError> {
    if count % VALIDITY_CHECK_INTERVAL != 0 {
        return Ok(false);
    }
    let mut m = AHashMap::new();
    let expired = (util::now().as_secs()
        - CERTIFICATE_EXPIRY_DAYS * SECONDS_PER_DAY) as i64;

    m.extend(
        SELF_SIGNED_CERTIFICATE_MAP
            .load()
            .iter()
            .filter(|(_, v)| v.not_after >= expired)
            .flat_map(|(k, v)| {
                let count = v.count.load(Ordering::Relaxed);
                let stale = v.stale.load(Ordering::Relaxed);

                if count == 0 {
                    if stale {
                        return None;
                    }
                    v.stale.store(true, Ordering::Relaxed);
                } else {
                    v.stale.store(false, Ordering::Relaxed);
                    v.count.store(0, Ordering::Relaxed);
                }
                Some((k.to_string(), v.clone()))
            }),
    );

    SELF_SIGNED_CERTIFICATE_MAP.store(Arc::new(m));
    Ok(true)
}

/// Creates a new service task for certificate validity checking.
///
/// # Returns
///
/// A tuple containing:
/// * The service name as a String
/// * The service task future that performs periodic certificate validation
///
/// This service is responsible for maintaining the health of the certificate pool
/// by regularly checking and cleaning up expired or unused certificates.
pub fn new_self_signed_certificate_validity_service(
) -> (String, SimpleServiceTaskFuture) {
    let task: SimpleServiceTaskFuture = Box::new(|count: u32| {
        Box::pin(do_self_signed_certificate_validity(count))
    });

    ("selfSignedCertificateStale".to_string(), task)
}

/// Retrieves a self-signed certificate from the global certificate map.
///
/// # Arguments
///
/// * `name` - The name/identifier of the certificate to retrieve
///
/// # Returns
///
/// * `Some(Arc<SelfSignedCertificate>)` if the certificate exists
/// * `None` if no certificate is found with the given name
///
/// This function automatically increments the usage counter of the retrieved certificate.
#[must_use]
pub fn get_self_signed_certificate(
    name: &str,
) -> Option<Arc<SelfSignedCertificate>> {
    SELF_SIGNED_CERTIFICATE_MAP.load().get(name).map(|v| {
        v.count.fetch_add(1, Ordering::Relaxed);
        v.clone()
    })
}

/// Adds a new self-signed certificate to the global certificate map.
///
/// # Arguments
///
/// * `name` - The name/identifier for the certificate
/// * `x509` - The X509 certificate
/// * `key` - The private key associated with the certificate
/// * `not_after` - The expiration timestamp of the certificate
///
/// # Returns
///
/// An `Arc<SelfSignedCertificate>` containing the newly added certificate
///
/// This function creates a new certificate entry with initial usage counters
/// and adds it to the global certificate map.
pub fn add_self_signed_certificate(
    name: &str,
    x509: X509,
    key: PKey<Private>,
    not_after: i64,
) -> Arc<SelfSignedCertificate> {
    let mut m = SELF_SIGNED_CERTIFICATE_MAP.load().as_ref().clone();
    let v = Arc::new(SelfSignedCertificate {
        x509,
        key,
        not_after,
        stale: AtomicBool::new(false),
        count: AtomicU32::new(0),
    });
    m.insert(name.to_string(), v.clone());
    SELF_SIGNED_CERTIFICATE_MAP.store(Arc::new(m));
    v
}
