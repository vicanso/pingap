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

use crate::service::SimpleServiceTaskFuture;
use crate::util;
use ahash::AHashMap;
use arc_swap::ArcSwap;
use once_cell::sync::Lazy;
use pingora::tls::pkey::{PKey, Private};
use pingora::tls::x509::X509;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

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

async fn do_self_signed_certificate_validity(count: u32) -> Result<(), String> {
    // Add 1 every loop
    let offset = 24 * 60;
    if count % offset != 0 {
        return Ok(());
    }
    let mut m = AHashMap::new();

    // two days
    let expired = (util::now().as_secs() - 2 * 24 * 3600) as i64;

    for (k, v) in SELF_SIGNED_CERTIFICATE_MAP.load().iter() {
        // certificate is expired
        if v.not_after < expired {
            continue;
        }
        let count = v.count.load(Ordering::Relaxed);
        let stale = v.stale.load(Ordering::Relaxed);
        // certificate is stale and use count is 0
        if stale && count == 0 {
            continue;
        }
        if count == 0 {
            // set stale
            v.stale.store(true, Ordering::Relaxed);
        } else {
            // reset
            v.stale.store(false, Ordering::Relaxed);
            v.count.store(0, Ordering::Relaxed);
        }
        m.insert(k.to_string(), v.clone());
    }
    SELF_SIGNED_CERTIFICATE_MAP.store(Arc::new(m));
    Ok(())
}

pub fn new_self_signed_certificate_validity_service(
) -> (String, SimpleServiceTaskFuture) {
    let task: SimpleServiceTaskFuture = Box::new(|count: u32| {
        Box::pin(do_self_signed_certificate_validity(count))
    });

    ("selfSignedCertificateStale".to_string(), task)
}

pub fn get_self_signed_certificate(
    name: &str,
) -> Option<Arc<SelfSignedCertificate>> {
    if let Some(v) = SELF_SIGNED_CERTIFICATE_MAP.load().get(name) {
        v.count.fetch_add(1, Ordering::Relaxed);
        return Some(v.clone());
    }
    None
}

// Add self signed certificate to global map
pub fn add_self_signed_certificate(
    name: &str,
    x509: X509,
    key: PKey<Private>,
    not_after: i64,
) -> Arc<SelfSignedCertificate> {
    let mut m = AHashMap::new();
    for (k, v) in SELF_SIGNED_CERTIFICATE_MAP.load().iter() {
        m.insert(k.to_string(), v.clone());
    }
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
