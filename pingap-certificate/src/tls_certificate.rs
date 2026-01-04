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

use super::chain::get_lets_encrypt_chain_certificate;
use super::self_signed::{
    SelfSignedCertificate, add_self_signed_certificate,
    get_self_signed_certificate,
};
use super::{
    Certificate, Error, LOG_TARGET, Result, parse_leaf_chain_certificates,
};
use pingap_config::CertificateConf;
use pingap_config::Hashable;
use pingora::tls::pkey::{PKey, Private};
use pingora::tls::x509::X509;
use std::sync::Arc;
use tracing::info;

// Constants for categorizing different types of certificates and errors
const LETS_ENCRYPT: &str = "lets_encrypt";
const ERROR_CERTIFICATE: &str = "certificate";
const ERROR_X509: &str = "x509_from_pem";
const ERROR_PRIVATE_KEY: &str = "private_key_from_pem";
const ERROR_CA: &str = "ca";

/// Represents a TLS certificate with its associated data
#[derive(Debug, Clone, Default)]
pub struct TlsCertificate {
    // Optional name identifier for the certificate
    pub name: Option<String>,
    // Optional chain certificate (intermediate CA)
    pub chain_certificates: Option<Vec<X509>>,
    // Optional tuple containing the certificate and its private key
    pub certificate: Option<(X509, PKey<Private>)>,
    // List of domain names this certificate is valid for
    pub domains: Vec<String>,
    // Additional certificate information
    pub info: Option<Certificate>,
    // Unique hash key for identifying the certificate
    pub hash_key: String,
    // Indicates if this certificate is a Certificate Authority
    pub is_ca: bool,
    // Buffer days for certificate renewal
    pub buffer_days: u16,
}

impl TryFrom<&CertificateConf> for TlsCertificate {
    type Error = Error;
    fn try_from(value: &CertificateConf) -> Result<Self, Self::Error> {
        // parse certificate
        let (info, x509_certificates) = parse_leaf_chain_certificates(
            value.tls_cert.clone().unwrap_or_default().as_str(),
            value.tls_key.clone().unwrap_or_default().as_str(),
        )
        .map_err(|e| Error::Invalid {
            message: e.to_string(),
            category: ERROR_CERTIFICATE.to_string(),
        })?;
        let category = if value.acme.is_some() {
            LETS_ENCRYPT
        } else {
            ""
        };
        let hash_key = value.hash_key();
        if x509_certificates.is_empty() {
            return Err(Error::Invalid {
                message: "x509 certificates is empty".to_string(),
                category: ERROR_CERTIFICATE.to_string(),
            });
        }
        let cert = x509_certificates[0].clone();
        let mut chain_certificates = None;
        if x509_certificates.len() > 1 {
            chain_certificates = Some(x509_certificates[1..].to_vec());
        } else if category == LETS_ENCRYPT {
            if let Some(chain_certificate) = get_lets_encrypt_chain_certificate(
                info.get_issuer_common_name().as_str(),
            ) {
                chain_certificates = Some(vec![chain_certificate]);
            }
        }

        let key = PKey::private_key_from_pem(&info.get_key()).map_err(|e| {
            Error::Invalid {
                category: ERROR_PRIVATE_KEY.to_string(),
                message: e.to_string(),
            }
        })?;
        Ok(TlsCertificate {
            hash_key,
            chain_certificates,
            domains: info.domains.clone(),
            certificate: Some((cert, key)),
            info: Some(info),
            is_ca: value.is_ca.unwrap_or_default(),
            buffer_days: value.buffer_days.unwrap_or_default(),
            ..Default::default()
        })
    }
}

/// Creates a new certificate signed by the given CA certificate
///
/// # Arguments
/// * `root_ca` - The CA certificate to sign with
/// * `cn` - The common name for the new certificate
///
/// # Returns
/// A tuple containing the new certificate, private key, and expiration timestamp
fn new_certificate_with_ca(
    root_ca: &TlsCertificate,
    cn: &str,
) -> Result<(X509, PKey<Private>, i64)> {
    let Some(info) = &root_ca.info else {
        return Err(Error::Invalid {
            message: "root ca is invalid".to_string(),
            category: ERROR_CA.to_string(),
        });
    };
    let binding = info.get_cert();
    let ca_pem = std::string::String::from_utf8_lossy(&binding);

    let ca_params = rcgen::CertificateParams::from_ca_cert_pem(&ca_pem)
        .map_err(|e| Error::Invalid {
            message: e.to_string(),
            category: ERROR_CA.to_string(),
        })?;

    let binding = info.get_key();
    let ca_key = std::string::String::from_utf8_lossy(&binding);

    let ca_kp =
        rcgen::KeyPair::from_pem(&ca_key).map_err(|e| Error::Invalid {
            message: e.to_string(),
            category: ERROR_CA.to_string(),
        })?;
    let not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    let two_years_from_now =
        time::OffsetDateTime::now_utc() + time::Duration::days(365 * 2);
    let not_after = ca_params.not_after.min(two_years_from_now);
    let ca_cert =
        ca_params.self_signed(&ca_kp).map_err(|e| Error::Invalid {
            message: e.to_string(),
            category: ERROR_CA.to_string(),
        })?;

    let mut params = rcgen::CertificateParams::new(vec![cn.to_string()])
        .map_err(|e| Error::Invalid {
            message: e.to_string(),
            category: ERROR_CA.to_string(),
        })?;
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, cn.to_string());
    if let Some(organ) = ca_cert
        .params()
        .distinguished_name
        .get(&rcgen::DnType::OrganizationName)
    {
        dn.push(rcgen::DnType::OrganizationName, organ.clone());
    };
    if let Some(unit) = ca_cert
        .params()
        .distinguished_name
        .get(&rcgen::DnType::OrganizationalUnitName)
    {
        dn.push(rcgen::DnType::OrganizationalUnitName, unit.clone());
    };

    params.distinguished_name = dn;
    params.not_before = not_before;
    params.not_after = not_after;

    let cert_key = rcgen::KeyPair::generate().map_err(|e| Error::Invalid {
        message: e.to_string(),
        category: ERROR_CA.to_string(),
    })?;

    let cert = params.signed_by(&cert_key, &ca_cert, &ca_kp).map_err(|e| {
        Error::Invalid {
            message: e.to_string(),
            category: ERROR_CA.to_string(),
        }
    })?;

    let cert =
        X509::from_pem(cert.pem().as_bytes()).map_err(|e| Error::Invalid {
            category: ERROR_X509.to_string(),
            message: e.to_string(),
        })?;

    let key = PKey::private_key_from_pem(cert_key.serialize_pem().as_bytes())
        .map_err(|e| Error::Invalid {
        category: ERROR_PRIVATE_KEY.to_string(),
        message: e.to_string(),
    })?;

    Ok((cert, key, not_after.unix_timestamp()))
}

impl TlsCertificate {
    /// Gets or creates a self-signed certificate for the given server name.
    /// If a cached certificate exists for the server name, returns that.
    /// Otherwise creates a new certificate signed by this CA.
    ///
    /// # Arguments
    /// * `server_name` - The server name to create the certificate for
    ///
    /// # Returns
    /// An Arc containing the self-signed certificate
    pub fn get_self_signed_certificate(
        &self,
        server_name: &str,
    ) -> Result<Arc<SelfSignedCertificate>> {
        // Format the common name (converts subdomain.example.com to *.example.com)
        let cn = Self::format_common_name(server_name);
        // Create a unique cache key using the certificate name and common name
        let cache_key = format!("{:?}:{}", self.name, cn);

        // Try to get existing certificate from cache
        if let Some(cert) = get_self_signed_certificate(&cache_key) {
            return Ok(cert);
        }

        // Generate new certificate if not found in cache
        let (cert, key, not_after) = new_certificate_with_ca(self, &cn)?;
        info!(
            target: LOG_TARGET,
            ca_common_name = self.name,
            common_name = cn,
            "create new self signed certificate"
        );
        Ok(add_self_signed_certificate(cache_key, cert, key, not_after))
    }

    /// Formats a server name into a common name by converting subdomain patterns
    /// For example, converts "subdomain.example.com" into "*.example.com"
    ///
    /// # Arguments
    /// * `server_name` - The server name to format
    ///
    /// # Returns
    /// The formatted common name as a String
    fn format_common_name(server_name: &str) -> String {
        let parts: Vec<&str> = server_name.split('.').collect();
        // If there are more than 2 parts (e.g., sub.example.com),
        // convert to wildcard format (*.example.com)
        if parts.len() > 2 {
            format!("*.{}", parts[1..].join("."))
        } else {
            server_name.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TlsCertificate;
    use pingap_config::CertificateConf;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_format_common_name() {
        assert_eq!(
            "*.example.com",
            TlsCertificate::format_common_name("subdomain.example.com")
        );
        assert_eq!(
            "example.com",
            TlsCertificate::format_common_name("example.com")
        );
    }

    #[test]
    fn test_get_self_signed_certificate() {
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
        let cert = TlsCertificate::try_from(&CertificateConf {
            tls_cert: Some(pem.to_string()),
            tls_key: Some(key.to_string()),
            ..Default::default()
        })
        .unwrap();

        let server_name = format!("{}.test.example.com", nanoid::nanoid!(10));
        let cert = cert.get_self_signed_certificate(&server_name).unwrap();
        assert_eq!(
            r#"[commonName = "*.test.example.com", organizationName = "mkcert development certificate", organizationalUnitName = "tree@TreeXies-MacBook-Pro.local (TreeXie)"]"#,
            format!("{:?}", cert.x509.subject_name())
        );
    }
}
