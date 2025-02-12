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
use pingap_core::Error as ServiceError;
use pingap_core::SimpleServiceTaskFuture;
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
    /// The X509 certificate
    pub x509: X509,
    /// The private key associated with the certificate
    pub key: PKey<Private>,
    /// Indicates whether the certificate is stale (unused for a period)
    stale: AtomicBool,
    /// Tracks the number of times this certificate has been used
    count: AtomicU32,
    /// Unix timestamp indicating when the certificate expires
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
    let expired = (pingap_util::now_sec()
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
                    // certificate is not used and stale, remove it
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
    name: String,
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
    m.insert(name, v.clone());
    SELF_SIGNED_CERTIFICATE_MAP.store(Arc::new(m));
    v
}

#[cfg(test)]
mod tests {
    use super::{
        add_self_signed_certificate, do_self_signed_certificate_validity,
        get_self_signed_certificate,
    };
    use pingora::tls::pkey::PKey;
    use pingora::tls::x509::X509;
    use pretty_assertions::assert_eq;

    #[tokio::test]
    async fn test_add_self_signed_certificate() {
        // spellchecker:off
        let pem = r#"-----BEGIN CERTIFICATE-----
MIIENzCCAp+gAwIBAgIRALESVNFwfk4BBxPnZLHdLaMwDQYJKoZIhvcNAQELBQAw
bTEeMBwGA1UEChMVbWtjZXJ0IGRldmVsb3BtZW50IENBMSEwHwYDVQQLDBh0cmVl
QGFub255bW91cyAoVHJlZVhpZSkxKDAmBgNVBAMMH21rY2VydCB0cmVlQGFub255
bW91cyAoVHJlZVhpZSkwHhcNMjUwMTI4MDczODE4WhcNMjcwNDI4MDczODE4WjBd
MScwJQYDVQQKEx5ta2NlcnQgZGV2ZWxvcG1lbnQgY2VydGlmaWNhdGUxMjAwBgNV
BAsMKXRyZWVAVHJlZVhpZXMtTWFjQm9vay1Qcm8ubG9jYWwgKFRyZWVYaWUpMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv/Wt6HfiFrIOnW3eZx7A+iF7
tywiyqRYX0CoecStk4n0H2s0V2nk6zmPwEvF1Qxd4OjUkwrVtIWCNyC3SXzoG+62
dYMMCRmDZGqiUPaZjKcpObsxIcWIt1lO6mqZaf7hPNPtAb3gO4lLOgy4Ipv7q0Oy
BY2myg7X9xOTzXmI6va8XSdGHsoilpic/mF95BE3D7FINx3j12HAwnMGY5/xPAFp
QTa/3zoE22TCUpZHb1v9X3N2olPCUWRNbgCFWl5vKpfvqLlP19th1jhr2DkUVeWs
RXYaB2ULwkNKkdhO0ka3hZipu6C3qDmfssfkm+lVhUvgUYWElaKDZG88ia26rQID
AQABo2IwYDAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwHwYD
VR0jBBgwFoAU210uBCmUnt7NVBOP3t3kjNq6XlEwGAYDVR0RBBEwD4INKi5leGFt
cGxlLmNvbTANBgkqhkiG9w0BAQsFAAOCAYEATOEErFNYpxuxFkO/fDoUvuD9c9n3
UetdrQ3u1E5EeYy+LaCWjEtDLf8t2NYKfuqQGxWgkdQYU6GIF4pbuZeARrReoind
4SRSaA4Zwc8BvmA+UeCgm0uGAY2B3FQ6oUK7sY+wtIr0ob6nGLUtstZVesvA3elG
xVcUM5tmBlm2rjLjvumIsfNK7VdKUY6yV2Z50nXNDkpT+achL1sJVMUIRokUezNB
Pn1UjgblgpjuIA0A+e1XIm0Co/1JtJv8FOfUWGFE0oYJNSqp0sX51ZZ+5flV/3nS
inJvDyFSfTsSNlgEeFb0Ek8XmFpQqFXd8O20owgkcO/XFCkovFzuPdJwQ0hxTAzU
yOFUVc2HLxISKWJmyZ2XCoSrZgHjnOxdqY187J9Xv2T7P59H4JYvSB90iwqKLKTW
GEVKsWU+0lbeWGwpAe46HfSg3xl/zoL62SCNsC0ruoJofprLDF0e6vxJQy9s4Dp6
DiHunXjaGjAc2C1GAdLdkLDokENUTFp9nZJv
-----END CERTIFICATE-----"#;
        let key = r#"-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC/9a3od+IWsg6d
bd5nHsD6IXu3LCLKpFhfQKh5xK2TifQfazRXaeTrOY/AS8XVDF3g6NSTCtW0hYI3
ILdJfOgb7rZ1gwwJGYNkaqJQ9pmMpyk5uzEhxYi3WU7qaplp/uE80+0BveA7iUs6
DLgim/urQ7IFjabKDtf3E5PNeYjq9rxdJ0YeyiKWmJz+YX3kETcPsUg3HePXYcDC
cwZjn/E8AWlBNr/fOgTbZMJSlkdvW/1fc3aiU8JRZE1uAIVaXm8ql++ouU/X22HW
OGvYORRV5axFdhoHZQvCQ0qR2E7SRreFmKm7oLeoOZ+yx+Sb6VWFS+BRhYSVooNk
bzyJrbqtAgMBAAECggEBAJIME8KY43UtB52TZ/DBH0Wvj/bvJ5FRtMLT6NqsXvuv
rALzh6EyOi8VXl+JxvyvKgXiX0l4pttv8ICM7aaF1/rYhg2mJNQPiz4tO02qMW0o
CV+ZImp1Ze1Jj5cef5Z7i1bCTsJSenYRoSCLaNU8JCBLovhCq7Fz1bBwPrXIT/mj
aoDF68eWuxefM0EiUh0xqNSF/eglyXOIt6Fz6p3gMvTKwYsSM02CXaui6rNbU5aN
YJ5M6Sem/FqtwIyb48UHMvI26ajVwtMSiNwR2XXV6gxg8xWFpjU+Uh3u1Qxacj2K
aW5jBFiLQegcZetGvL+z65VYV/cKHkYl4PhULep3CmkCgYEA45BpCntOVP/2ThUP
oXTDJnRJ8YfiYgP41zPAfK8daeOCuJRNhGXUr8fI/PiAmLIRbs8hJ8TeZTa8nzSE
0zBJ7CEbjSXbKR6UDCvm85QPGnog7fDpkjk2qcFRbXFZbolerMzHuQfUvFH/t48Q
SScn64aSq/Ymjkz9O0jPJ4xrK7sCgYEA1/JQEkUdbFsOO/mRA+YEtS1C359UD5Au
n413sI/D/C8dbTveQ4lNnd5s/JLZEvBCIX6+mczvm7ZAKLv4k9uYHw6mzdEQbUNR
uf6BNbAeRUxoN90qWzSVqkK9S4vs8x3zWkREqSJeSwW7Kh2DAz8HM4u36gxQhz2V
+eHz0a1Q6LcCgYEAoQOV/y+eDjCJ81edlq0KQ9Q2Waq++IE8+fAJO2+gTUMIRFfS
vWJb6gBfavbd7qzX/uKZ4AzBGzZuoetELDXXqDcIyodFmcOkFzSdFi3lveM6F4HF
kove7J/3YIu6LqcOERBYJMiwsosGd7fHWytUaKbwcrIZN8iryN3MjXwifG8CgYEA
qt0oq/wR1t2JOr0yF+KVUQGaCzSXH6VWrpoR3Rsz2EMzRm37ZHasekA2/fX3WjvO
J5CQoUL9R7iBtXldqygyikhehTVpiPqeHMuaUu+iU/Sr9Z/CVt4ZmdkqzC7P8mF9
Xqvro+P0tem3+Q/WzOe++/MON1s9EHUTSN+Wuw4mmasCgYBqzSZro05J6U+74g5X
1QRl97OzlCgzaIWLHlv9nZzHivIrQxPtK1QStFiJOeQTq5XqdLywkGHWHsgBYQhl
iama6sNZgokeRWVL1QJBaC2q0312AG8xeOZ7oWqfAtfxGpjhvNpgPJfZi8NA7+WE
kknq2XUsBMCyIW1BqgLVEyeNxg==
-----END PRIVATE KEY-----"#;
        // spellchecker:on

        let cert = X509::from_pem(pem.as_bytes()).unwrap();
        let key = PKey::private_key_from_pem(key.as_bytes()).unwrap();

        let name = nanoid::nanoid!(10);
        add_self_signed_certificate(
            name.clone(),
            cert,
            key,
            (pingap_util::now_sec() + 1000000000) as i64,
        );

        let cert = get_self_signed_certificate(&name).unwrap();
        assert_eq!(
            r#"[organizationName = "mkcert development certificate", organizationalUnitName = "tree@TreeXies-MacBook-Pro.local (TreeXie)"]"#,
            format!("{:?}", cert.x509.subject_name())
        );

        do_self_signed_certificate_validity(0).await.unwrap();

        let cert = get_self_signed_certificate(&name).unwrap();
        assert_eq!(
            r#"[organizationName = "mkcert development certificate", organizationalUnitName = "tree@TreeXies-MacBook-Pro.local (TreeXie)"]"#,
            format!("{:?}", cert.x509.subject_name())
        );
    }
}
