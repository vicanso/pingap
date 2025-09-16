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

use ahash::AHashMap;
use arc_swap::ArcSwap;
use once_cell::sync::Lazy;
use pingap_certificate::{
    CertificateProvider, DynamicCertificates, DEFAULT_SERVER_NAME,
};
use std::sync::Arc;

struct Provider {
    certificates: ArcSwap<DynamicCertificates>,
}

impl CertificateProvider for Provider {
    fn store(&self, data: DynamicCertificates) {
        self.certificates.store(Arc::new(data));
    }
    fn get(
        &self,
        sni: &str,
    ) -> Option<Arc<pingap_certificate::TlsCertificate>> {
        let certs = self.certificates.load();
        certs
            .get(sni)
            .or_else(|| {
                // If exact match fails, try wildcard match without new string allocation.
                sni.split_once('.')
                    .and_then(|(_, domain)| certs.get(&format!("*.{}", domain)))
            })
            .or_else(|| {
                // Fallback to the default certificate.
                certs.get(DEFAULT_SERVER_NAME)
            })
            .cloned()
    }
    fn list(&self) -> Arc<DynamicCertificates> {
        self.certificates.load().clone()
    }
}

static CERTIFICATE_PROVIDER: Lazy<Arc<Provider>> = Lazy::new(|| {
    Arc::new(Provider {
        certificates: ArcSwap::from_pointee(AHashMap::new()),
    })
});

pub fn new_certificate_provider() -> Arc<dyn CertificateProvider> {
    CERTIFICATE_PROVIDER.clone()
}
