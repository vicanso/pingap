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

use super::{Error, Result};
use crate::PingapTomlConfig;
use crate::secrets::{masked_entry, masked_fragment};
use bytesize::ByteSize;
use pingap_core::ACCESS_LOG_PRESETS;
use pingap_discovery::{
    DNS_DISCOVERY, DOCKER_DISCOVERY, STATIC_DISCOVERY, TRANSPARENT_DISCOVERY,
    is_static_discovery,
};
use pingap_util::{is_pem, resolve_path};
use regex::Regex;
use rustls_pki_types::pem::PemObject;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize, Serializer};
use std::collections::HashSet;
use std::fs::File;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::{BufReader, Read};
use std::net::{IpAddr, ToSocketAddrs};
use std::time::Duration;
use std::{collections::HashMap, str::FromStr};
use strum::EnumString;
use tempfile::tempfile_in;
use toml::Table;
use toml::{Value, map::Map};
use url::Url;

pub const CATEGORY_BASIC: &str = "basic";
pub const CATEGORY_SERVER: &str = "server";
pub const CATEGORY_LOCATION: &str = "location";
pub const CATEGORY_UPSTREAM: &str = "upstream";
pub const CATEGORY_PLUGIN: &str = "plugin";
pub const CATEGORY_CERTIFICATE: &str = "certificate";
pub const CATEGORY_STORAGE: &str = "storage";

pub trait Validate {
    fn validate(&self) -> Result<()>;
}

#[derive(PartialEq, Debug, Default, Clone, EnumString, strum::Display)]
#[strum(serialize_all = "snake_case")]
pub enum PluginCategory {
    /// Statistics and metrics collection
    #[default]
    Stats,
    /// Rate limiting and throttling
    Limit,
    /// Response compression (gzip, deflate, etc)
    Compression,
    /// Administrative interface and controls
    Admin,
    /// Static file serving and directory listing
    Directory,
    /// Mock/stub responses for testing
    Mock,
    /// Request ID generation and tracking
    RequestId,
    /// IP-based access control
    IpRestriction,
    /// API key authentication
    KeyAuth,
    /// HTTP Basic authentication
    BasicAuth,
    /// Combined authentication methods
    CombinedAuth,
    /// JSON Web Token (JWT) authentication
    Jwt,
    /// Response caching
    Cache,
    /// URL redirection rules
    Redirect,
    /// Health check endpoint
    Ping,
    /// Custom response header manipulation
    ResponseHeaders,
    /// Substring filter
    SubFilter,
    /// Referer-based access control
    RefererRestriction,
    /// User-Agent based access control
    UaRestriction,
    /// Cross-Site Request Forgery protection
    Csrf,
    /// Cross-Origin Resource Sharing
    Cors,
    /// Accept-Encoding header processing
    AcceptEncoding,
    /// Traffic splitting
    TrafficSplitting,
}
impl Serialize for PluginCategory {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().as_ref())
    }
}

impl<'de> Deserialize<'de> for PluginCategory {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value: String = serde::Deserialize::deserialize(deserializer)?;
        PluginCategory::from_str(&value).map_err(|_| {
            serde::de::Error::custom(format!(
                "invalid plugin category: {value}"
            ))
        })
    }
}

/// The dns provider used when no api credentials are configured: the TXT record
/// is logged and the operator adds it by hand.
pub const DNS_PROVIDER_MANUAL: &str = "manual";

/// Maps a configured `dns_provider` to the canonical name the acme code matches
/// on, or `None` when it is not a provider Pingap knows about.
///
/// `aliyun` and `cloudflare` are accepted as aliases because earlier
/// documentation used those spellings.
pub fn normalize_dns_provider(value: &str) -> Option<&'static str> {
    match value.trim().to_lowercase().as_str() {
        "" | "manual" => Some(DNS_PROVIDER_MANUAL),
        "ali" | "aliyun" => Some("ali"),
        "cf" | "cloudflare" => Some("cf"),
        "tencent" => Some("tencent"),
        "huawei" => Some("huawei"),
        _ => None,
    }
}

/// Configuration struct for TLS/SSL certificates
#[derive(Debug, Default, Deserialize, Clone, Serialize, Hash)]
pub struct CertificateConf {
    /// Domain names this certificate is valid for (comma separated)
    pub domains: Option<String>,
    /// TLS certificate in PEM format or base64 encoded
    pub tls_cert: Option<String>,
    /// Private key in PEM format or base64 encoded
    pub tls_key: Option<String>,
    /// Whether this is the default certificate for the server
    pub is_default: Option<bool>,
    /// Whether this certificate is a Certificate Authority (CA)
    pub is_ca: Option<bool>,
    /// ACME configuration for automated certificate management
    pub acme: Option<String>,
    /// Whether to use DNS challenge for ACME certificate management
    pub dns_challenge: Option<bool>,
    /// DNS provider for ACME certificate management
    pub dns_provider: Option<String>,
    /// DNS service url for ACME certificate management
    pub dns_service_url: Option<String>,
    /// Buffer days for certificate renewal
    pub buffer_days: Option<u16>,
    /// Optional description/notes about this certificate
    pub remark: Option<String>,
}

/// Validates a certificate in PEM format or base64 encoded
fn validate_cert(value: &str) -> Result<()> {
    // Convert from PEM/base64 to binary
    let buf_list =
        pingap_util::convert_pem(value).map_err(|e| Error::Invalid {
            message: e.to_string(),
        })?;
    for buf in buf_list {
        // Parse all certificates in the buffer
        let certs = rustls_pki_types::CertificateDer::pem_slice_iter(&buf)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| Error::Invalid {
                message: "Failed to parse certificate".to_string(),
            })?;

        // Ensure at least one valid certificate was found
        if certs.is_empty() {
            return Err(Error::Invalid {
                message: "No valid certificates found in input".to_string(),
            });
        }
    }

    Ok(())
}

impl CertificateConf {
    /// The files the certificate and its key are read from, when they are
    /// given as paths and not as their content.
    fn files(&self) -> impl Iterator<Item = std::path::PathBuf> + '_ {
        [&self.tls_cert, &self.tls_key]
            .into_iter()
            .flatten()
            .filter(|value| !is_pem(value))
            .map(|value| std::path::PathBuf::from(resolve_path(value)))
            .filter(|path| path.is_file())
    }
    /// Whether the certificate or its key comes from a file. Its
    /// [`Hashable::hash_key`] then changes with the content of the file,
    /// which the configuration document does not show: whoever watches
    /// the document for changes has to look at these separately.
    pub fn reads_files(&self) -> bool {
        self.files().next().is_some()
    }
}

// Generate hash key for certificate configuration
// Add the content of the certificate and key files to the hash key
impl Hashable for CertificateConf {
    fn hash_key(&self) -> String {
        let mut hasher = DefaultHasher::new();

        // 1. Hash the struct's own fields first.
        // This includes the paths themselves, so changes to paths affect the hash.
        self.hash(&mut hasher);

        // 2. Iterate through the optional certificate and key file paths.
        for path in self.files() {
            match File::open(&path) {
                Ok(file) => {
                    let mut reader = BufReader::new(file);
                    let mut buffer = [0; 8192];

                    loop {
                        match reader.read(&mut buffer) {
                            Ok(0) => break, // End of file reached successfully.
                            Ok(bytes_read) => {
                                // Hash the chunk that was read.
                                hasher.write(&buffer[..bytes_read]);
                            },
                            Err(e) => {
                                hasher.write(b"Error reading file content:");
                                hasher.write(e.to_string().as_bytes());
                                break;
                            },
                        }
                    }
                },
                Err(e) => {
                    hasher.write(b"Error opening file:");
                    hasher.write(e.to_string().as_bytes());
                },
            }
        }

        format!("{:x}", hasher.finish())
    }
}

impl Validate for CertificateConf {
    /// Validates the certificate configuration:
    /// - Validates private key can be parsed if present
    /// - Validates certificate can be parsed if present  
    /// - Validates certificate chain can be parsed if present
    fn validate(&self) -> Result<()> {
        // Validate private key
        if let Some(tls_key) =
            self.tls_key.as_deref().filter(|key| !key.is_empty())
        {
            let buf_list = pingap_util::convert_pem(tls_key).map_err(|e| {
                Error::Invalid {
                    message: e.to_string(),
                }
            })?;
            let buf = buf_list.first().ok_or_else(|| Error::Invalid {
                message: "private key is empty".to_string(),
            })?;
            let _ = rustls_pki_types::PrivateKeyDer::from_pem_slice(buf)
                .map_err(|_| Error::Invalid {
                    message: "Failed to parse private key".to_string(),
                })?;
        }

        // Validate main certificate
        if let Some(tls_cert) =
            self.tls_cert.as_deref().filter(|cert| !cert.is_empty())
        {
            validate_cert(tls_cert)?;
        }

        // An unrecognised dns provider used to fall through to the manual task,
        // which just waits for a TXT record nobody is going to add. Reject it
        // here so `pingap -t` reports the typo instead.
        if let Some(dns_provider) = &self.dns_provider
            && normalize_dns_provider(dns_provider).is_none()
        {
            return Err(Error::Invalid {
                message: format!(
                    "Invalid dns_provider({dns_provider}), expect one of: ali, cf, tencent, huawei, manual"
                ),
            });
        }

        Ok(())
    }
}

/// Accepted values of `UpstreamConf::discovery`, as `guess_discovery`
/// gives them: empty for static addresses that name none.
const KNOWN_DISCOVERIES: [&str; 5] = [
    "",
    STATIC_DISCOVERY,
    DNS_DISCOVERY,
    DOCKER_DISCOVERY,
    TRANSPARENT_DISCOVERY,
];

/// Accepted values of `UpstreamConf::h1_upgrade`, matched case-insensitively.
/// They mirror pingora's `H1UpgradePolicy` variants; the upstream crate maps
/// them, this crate only validates them.
pub const H1_UPGRADE_POLICIES: [&str; 3] =
    ["websocket_only", "preserve", "deny"];

/// Configuration for an upstream service that handles proxied requests
#[derive(Debug, Default, Deserialize, Clone, Serialize, Hash)]
pub struct UpstreamConf {
    /// List of upstream server addresses in format "host:port" or "host:port weight"
    pub addrs: Vec<String>,

    /// Service discovery mechanism to use (e.g. "dns", "static")
    pub discovery: Option<String>,

    /// DNS server for DNS discovery
    pub dns_server: Option<String>,

    /// DNS domain for DNS discovery
    pub dns_domain: Option<String>,

    /// DNS search for DNS discovery
    pub dns_search: Option<String>,

    /// How frequently to update the upstream server list
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub update_frequency: Option<Duration>,

    /// Load balancing algorithm (e.g. "round_robin", "hash:cookie")
    pub algo: Option<String>,

    /// Server Name Indication for TLS connections
    pub sni: Option<String>,

    /// Whether to verify upstream TLS certificates
    pub verify_cert: Option<bool>,

    /// Health check URL to verify upstream server status
    pub health_check: Option<String>,

    /// Whether to only use IPv4 addresses
    pub ipv4_only: Option<bool>,

    /// Enable request tracing
    pub enable_tracer: Option<bool>,

    /// Enable backend stats
    pub enable_backend_stats: Option<bool>,

    /// Failure status codes for backend stats
    /// Format: "400,500,502,503,504"
    pub backend_failure_status_code: Option<String>,

    /// Maximum number of consecutive failures required to trip the circuit breaker
    pub circuit_break_max_consecutive_failures: Option<u32>,

    /// Maximum failure rate (percentage, 0 to 100) required to trip the circuit breaker
    pub circuit_break_max_failure_percent: Option<u16>,

    /// Minimum total number of requests (within the statistics window) required
    /// before the failure rate is considered significant for circuit breaking.
    /// Prevents tripping the breaker when traffic is very low.
    pub circuit_break_min_requests_threshold: Option<u64>,

    /// The number of consecutive successes required to reset the circuit breaker to closed.
    pub circuit_break_half_open_consecutive_success_threshold: Option<u32>,

    /// The duration of the open state of the circuit breaker.
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub circuit_break_open_duration: Option<Duration>,

    /// Interval for backend stats, default is 60 seconds
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub backend_stats_interval: Option<Duration>,

    /// Application Layer Protocol Negotiation for TLS
    pub alpn: Option<String>,

    /// Maximum number of concurrent HTTP/2 streams per upstream connection.
    /// Only takes effect when the upstream negotiates HTTP/2 (`alpn = "H2"` or
    /// `"H2H1"`, including cleartext h2c). Must be greater than zero. When unset,
    /// Pingora's default of 1 stream per connection is used.
    pub max_h2_streams: Option<usize>,

    /// Strip the standard hop-by-hop request headers (`Connection`,
    /// `Keep-Alive`, `Proxy-Connection`, `Proxy-Authenticate`,
    /// `Proxy-Authorization`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`,
    /// `HTTP2-Settings`) before the request reaches the upstream. Default
    /// `true`, which is what RFC 9110 asks of a proxy.
    pub strip_hop_by_hop: Option<bool>,

    /// Strip the extension headers named in the downstream `Connection`
    /// header. While on, a request whose `Connection` nominates `Host`, an
    /// `X-Forwarded-*` header or a pseudo-header is rejected rather than
    /// forwarded with that metadata removed. Default `true`.
    pub strip_connection_nominated: Option<bool>,

    /// Reject `Connection` nominations that are not a valid HTTP token, such
    /// as a quoted name. Only has an effect while `strip_connection_nominated`
    /// is on. Default `true`.
    pub reject_malformed_connection_nominations: Option<bool>,

    /// What to do with an HTTP/1 `Upgrade` handshake: `websocket_only`
    /// (default) forwards a valid WebSocket upgrade in normalized form and
    /// drops every other one, `preserve` forwards any upgrade request with
    /// its headers untouched (Docker attach/exec, h2c and other non-WebSocket
    /// protocols need this), `deny` forwards none.
    pub h1_upgrade: Option<String>,

    /// CA certificate(s) used to verify this upstream's server certificate
    /// instead of the system trust store: a PEM file path, base64-encoded
    /// PEM, or raw PEM, holding one or more certificates. Lets a private
    /// or self-signed backend keep `verify_cert` enabled.
    pub ca: Option<String>,

    /// HTTP/2 flow-control window advertised per stream to this upstream
    /// (RFC 9113 §6.9.2), between 1 and 2 GiB - 1; pingora defaults to
    /// 8 MiB. Larger windows help big responses on high-latency links.
    #[serde(default, serialize_with = "serialize_byte_size")]
    pub h2_stream_window_size: Option<ByteSize>,

    /// HTTP/2 connection-level flow-control window advertised to this
    /// upstream, shared by every stream on the connection, between 1 and
    /// 2 GiB - 1; pingora defaults to 8 MiB.
    #[serde(default, serialize_with = "serialize_byte_size")]
    pub h2_connection_window_size: Option<ByteSize>,

    /// Timeout for establishing new connections
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub connection_timeout: Option<Duration>,

    /// Total timeout for the entire request/response cycle
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub total_connection_timeout: Option<Duration>,

    /// Timeout for reading response data
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub read_timeout: Option<Duration>,

    /// Timeout for idle connections in the pool
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub idle_timeout: Option<Duration>,

    /// Timeout for writing request data
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub write_timeout: Option<Duration>,

    /// TCP keepalive idle time
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub tcp_idle: Option<Duration>,

    /// TCP keepalive probe interval
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub tcp_interval: Option<Duration>,

    /// TCP keepalive user timeout
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub tcp_user_timeout: Option<Duration>,

    /// Number of TCP keepalive probes before connection is dropped
    pub tcp_probe_count: Option<usize>,

    /// TCP receive buffer size
    #[serde(default, serialize_with = "serialize_byte_size")]
    pub tcp_recv_buf: Option<ByteSize>,

    /// Enable TCP Fast Open
    pub tcp_fast_open: Option<bool>,

    /// List of included configuration files
    pub includes: Option<Vec<String>>,

    /// Optional description/notes about this upstream
    pub remark: Option<String>,
}

fn is_valid_upstream_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            !ipv4.is_unspecified()
                && !ipv4.is_broadcast()
                && !ipv4.is_multicast()
                && !ipv4.is_link_local()
        },
        IpAddr::V6(ipv6) => {
            !ipv6.is_unspecified()
                && !ipv6.is_multicast()
                && (ipv6.segments()[0] & 0xffc0) != 0xfe80
        },
    }
}

impl Validate for UpstreamConf {
    /// Validates the upstream configuration:
    /// 1. The address list can't be empty
    /// 2. For static discovery, addresses must be valid socket addresses
    /// 3. Health check URL must be valid if specified
    /// 4. TCP probe count must not exceed maximum (16)
    /// 5. `h1_upgrade` must be one of the known policies
    fn validate(&self) -> Result<()> {
        // Validate address list
        self.validate_addresses()?;

        // Validate health check URL if specified
        self.validate_health_check()?;

        // Validate TCP probe count
        self.validate_tcp_probe_count()?;

        // Validate max h2 streams
        self.validate_max_h2_streams()?;

        // Validate the HTTP/1 upgrade policy name
        self.validate_h1_upgrade()?;

        // Validate the custom CA bundle and the HTTP/2 flow-control windows
        self.validate_ca()?;
        self.validate_h2_window()?;

        Ok(())
    }
}

impl UpstreamConf {
    /// Determines the appropriate service discovery mechanism:
    /// - Returns configured discovery if set
    /// - Returns DNS discovery if any address contains a hostname
    /// - Returns empty string (static discovery) otherwise
    pub fn guess_discovery(&self) -> String {
        // Return explicitly configured discovery if set. In lower case,
        // which is how every reader of it compares: `DNS` was no discovery
        // any of them knew, and the upstream was built as a static one.
        if let Some(discovery) = &self.discovery {
            return discovery.trim().to_ascii_lowercase();
        }

        // Check if any address contains a hostname (non-IP)
        let has_hostname = self.addrs.iter().any(|addr| {
            // `host[:port] [weight]`; an IPv6 literal with a port is
            // bracketed, a bare one has more than one colon and no port.
            let host_port = addr.split_whitespace().next().unwrap_or(addr);
            let host = if let Some(rest) = host_port.strip_prefix('[') {
                rest.split_once(']').map_or(rest, |(host, _)| host)
            } else if host_port.matches(':').count() > 1 {
                host_port
            } else {
                host_port
                    .split_once(':')
                    .map_or(host_port, |(host, _)| host)
            };

            // If host can't be parsed as IP, it's a hostname
            host.parse::<std::net::IpAddr>().is_err()
        });

        if has_hostname {
            DNS_DISCOVERY.to_string()
        } else {
            String::new()
        }
    }

    /// The discovery has to be one this build knows. Anything else was
    /// taken for static addresses when the upstream was built, so a typo
    /// (`dsn`) resolved its hosts once at startup and never again.
    fn validate_discovery(&self) -> Result<()> {
        let discovery = self.guess_discovery();
        if !KNOWN_DISCOVERIES.contains(&discovery.as_str()) {
            return Err(Error::Invalid {
                message: format!(
                    "upstream discovery should be one of {}, got {:?}",
                    KNOWN_DISCOVERIES[1..].join(", "),
                    self.discovery.as_deref().unwrap_or_default()
                ),
            });
        }
        // The refresh of a discovery runs every `update_frequency`; with
        // zero it never ran after the first lookup.
        if self.update_frequency.is_some_and(|value| value.is_zero())
            && matches!(discovery.as_str(), DNS_DISCOVERY | DOCKER_DISCOVERY)
        {
            return Err(Error::Invalid {
                message: format!(
                    "upstream update_frequency should be greater than 0 for {discovery} discovery"
                ),
            });
        }
        Ok(())
    }

    fn validate_addresses(&self) -> Result<()> {
        self.validate_discovery()?;
        // A transparent upstream sends each request where the request
        // itself points, and has no addresses to list.
        if self.addrs.is_empty()
            && self.guess_discovery() != TRANSPARENT_DISCOVERY
        {
            return Err(Error::Invalid {
                message: "upstream addrs is empty".to_string(),
            });
        }

        // The weight applies to every discovery: a zero weight is a backend
        // that is never selected, and anything else after it is a typo.
        for addr in &self.addrs {
            let mut parts = addr.split_whitespace();
            if parts.next().is_none() {
                return Err(Error::Invalid {
                    message: "upstream addr is empty".to_string(),
                });
            }
            if let Some(weight) = parts.next()
                && weight
                    .parse::<usize>()
                    .ok()
                    .filter(|weight| *weight > 0)
                    .is_none()
            {
                return Err(Error::Invalid {
                    message: format!(
                        "upstream addr({addr}) weight must be a positive integer"
                    ),
                });
            }
            if parts.next().is_some() {
                return Err(Error::Invalid {
                    message: format!(
                        "upstream addr({addr}) has more than a weight after the address"
                    ),
                });
            }
        }

        // Only validate addresses for static discovery
        if !is_static_discovery(&self.guess_discovery()) {
            return Ok(());
        }

        for addr in &self.addrs {
            let parts: Vec<_> = addr.split_whitespace().collect();
            let host_port = parts[0].to_string();

            // `[v6]`, `[v6]:port`, a bare `v6` (more than one colon, no
            // port), `host` or `host:port`.
            let (host, has_port) =
                if let Some(rest) = host_port.strip_prefix('[') {
                    rest.split_once(']').map_or((rest, false), |(h, after)| {
                        (h, after.starts_with(':'))
                    })
                } else if host_port.matches(':').count() > 1 {
                    (host_port.as_str(), false)
                } else {
                    host_port
                        .split_once(':')
                        .map_or((host_port.as_str(), false), |(h, _)| (h, true))
                };

            if let Ok(ip) = host.parse::<IpAddr>()
                && !is_valid_upstream_ip(ip)
            {
                return Err(Error::Invalid {
                    message: format!(
                        "upstream addr({host}) is an invalid IP \
                             (unspecified, broadcast, multicast, or link-local)"
                    ),
                });
            }

            // Add default port 80 if not specified. An IPv6 literal
            // without one used to be taken as having it, for its colons,
            // and failed with `invalid port value`.
            let addr_to_check = if has_port {
                host_port.clone()
            } else if host.contains(':') {
                format!("[{host}]:80")
            } else {
                format!("{host}:80")
            };

            // Validate socket address
            addr_to_check.to_socket_addrs().map_err(|e| Error::Invalid {
                message: format!(
                    "upstream addr({addr}) is invalid: {e}, expect host, host:port or [ipv6]:port"
                ),
            })?;
        }

        Ok(())
    }

    fn validate_health_check(&self) -> Result<()> {
        let health_check = match &self.health_check {
            Some(url) if !url.is_empty() => url,
            _ => return Ok(()),
        };

        Url::parse(health_check).map_err(|e| Error::UrlParse {
            source: e,
            url: health_check.to_string(),
        })?;

        Ok(())
    }

    fn validate_tcp_probe_count(&self) -> Result<()> {
        const MAX_TCP_PROBE_COUNT: usize = 16;

        if let Some(count) = self.tcp_probe_count
            && count > MAX_TCP_PROBE_COUNT
        {
            return Err(Error::Invalid {
                message: format!(
                    "tcp probe count should be <= {MAX_TCP_PROBE_COUNT}"
                ),
            });
        }

        validate_tcp_keepalive(
            self.tcp_idle,
            self.tcp_interval,
            self.tcp_probe_count,
        )
    }

    fn validate_max_h2_streams(&self) -> Result<()> {
        if let Some(max_h2_streams) = self.max_h2_streams
            && max_h2_streams == 0
        {
            return Err(Error::Invalid {
                message: "max h2 streams should be greater than 0".to_string(),
            });
        }

        Ok(())
    }

    fn validate_h1_upgrade(&self) -> Result<()> {
        if let Some(policy) = &self.h1_upgrade
            && !H1_UPGRADE_POLICIES.contains(&policy.to_lowercase().as_str())
        {
            return Err(Error::Invalid {
                message: format!(
                    "h1 upgrade should be one of {}, got {policy:?}",
                    H1_UPGRADE_POLICIES.join(", ")
                ),
            });
        }

        Ok(())
    }

    fn validate_ca(&self) -> Result<()> {
        if let Some(ca) = &self.ca {
            validate_cert(ca).map_err(|e| Error::Invalid {
                message: format!("upstream ca is invalid: {e}"),
            })?;
        }
        Ok(())
    }

    fn validate_h2_window(&self) -> Result<()> {
        // RFC 9113 §6.9.2: a flow-control window cannot exceed 2^31 - 1.
        for (name, value) in [
            ("h2 stream window size", self.h2_stream_window_size),
            ("h2 connection window size", self.h2_connection_window_size),
        ] {
            if let Some(size) = value
                && !(1..=H2_MAX_WINDOW_SIZE).contains(&size.as_u64())
            {
                return Err(Error::Invalid {
                    message: format!("{name} should be between 1 and 2GiB - 1"),
                });
            }
        }
        Ok(())
    }
}

impl Validate for LocationConf {
    fn validate(&self) -> Result<()> {
        self.validate_with_upstream(None)?;
        Ok(())
    }
}

/// Configuration for a location/route that handles incoming requests
#[derive(Debug, Default, Deserialize, Clone, Serialize, Hash)]
pub struct LocationConf {
    /// Name of the upstream service to proxy requests to
    pub upstream: Option<String>,

    /// URL path pattern to match requests against
    /// Can start with:
    /// - "=" for exact match
    /// - "~" for regex match
    /// - No prefix for prefix match
    pub path: Option<String>,

    /// Host/domain name to match requests against
    pub host: Option<String>,

    /// Optional request match conditions ("name:value" for an exact value, or
    /// "name" for presence) on headers / query params / cookies respectively.
    /// The location matches only when path/host match AND every listed
    /// condition holds.
    pub match_headers: Option<Vec<String>>,
    pub match_query: Option<Vec<String>>,
    pub match_cookies: Option<Vec<String>>,

    /// Headers to set on proxied requests (overwrites existing)
    pub proxy_set_headers: Option<Vec<String>>,

    /// Headers to add to proxied requests (appends to existing)
    pub proxy_add_headers: Option<Vec<String>>,

    /// URL rewrite rule in format "pattern replacement"
    pub rewrite: Option<String>,

    /// Manual weight for location matching priority
    /// Higher weight = higher priority
    pub weight: Option<u16>,

    /// List of plugins to apply to requests matching this location
    pub plugins: Option<Vec<String>>,

    /// Maximum allowed size of request body
    #[serde(default, serialize_with = "serialize_byte_size")]
    pub client_max_body_size: Option<ByteSize>,

    /// Maximum number of concurrent requests being processed
    pub max_processing: Option<i32>,

    /// List of included configuration files
    pub includes: Option<Vec<String>>,

    /// Whether to enable gRPC-Web protocol support
    pub grpc_web: Option<bool>,

    /// Whether to enable reverse proxy headers
    pub enable_reverse_proxy_headers: Option<bool>,

    /// Maximum number of retries for failed connections
    pub max_retries: Option<u8>,

    /// Maximum window for retries
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub max_retry_window: Option<Duration>,

    /// Optional description/notes about this location
    pub remark: Option<String>,
}

impl LocationConf {
    /// Validates the location configuration:
    /// 1. Validates that headers are properly formatted as "name: value"
    /// 2. Validates header names and values are valid HTTP headers
    /// 3. Validates upstream exists if specified
    /// 4. Validates rewrite pattern is valid regex if specified
    fn validate_with_upstream(
        &self,
        upstream_names: Option<&[String]>,
    ) -> Result<()> {
        // The same parse the proxy applies when it builds the location, so
        // what validates here is what loads there.
        let validate = |headers: &Option<Vec<String>>| -> Result<()> {
            for header in headers.iter().flatten() {
                match pingap_core::convert_header(header) {
                    Ok(Some(_)) => {},
                    Ok(None) => {
                        return Err(Error::Invalid {
                            message: format!("header {header} is invalid"),
                        });
                    },
                    Err(err) => {
                        return Err(Error::Invalid {
                            message: format!(
                                "header {header} is invalid: {err}"
                            ),
                        });
                    },
                }
            }
            Ok(())
        };

        // Validate upstream exists if specified
        if let Some(upstream_names) = upstream_names {
            let upstream = self.upstream.clone().unwrap_or_default();
            if !upstream.is_empty()
                && !upstream.starts_with("$")
                && !upstream_names.contains(&upstream)
            {
                return Err(Error::Invalid {
                    message: format!("upstream({upstream}) is not found"),
                });
            }
        }

        // Validate headers
        validate(&self.proxy_add_headers)?;
        validate(&self.proxy_set_headers)?;

        // Validate rewrite pattern is valid regex
        if let Some(value) = &self.rewrite {
            let arr: Vec<&str> = value.split(' ').collect();
            let _ =
                Regex::new(arr[0]).map_err(|e| Error::Regex { source: e })?;
        }

        Ok(())
    }

    /// Calculates the matching priority weight for this location
    /// Higher weight = higher priority
    /// Weight is based on:
    /// - Path match type (exact=1024, prefix=512, regex=256)
    /// - Path length (up to 64)
    /// - Host presence (+128)
    ///
    /// Returns either the manual weight if set, or calculated weight
    pub fn get_weight(&self) -> u16 {
        // Return manual weight if set
        if let Some(weight) = self.weight {
            return weight;
        }

        let mut weight: u16 = 0;
        let path = self.path.as_deref().unwrap_or_default();

        // Add weight based on path match type and length
        if path.len() > 1 {
            if path.starts_with('=') {
                weight += 1024; // Exact match
            } else if path.starts_with('~') {
                weight += 256; // Regex match
            } else {
                weight += 512; // Prefix match
            }
            weight += path.len().min(64) as u16;
        };
        // Add weight if host is specified
        if let Some(host) = &self.host {
            let exist_regex = host.split(',').any(|item| item.starts_with("~"));
            // exact host weight is 128
            // regexp host weight is host length
            if !exist_regex && !host.is_empty() {
                weight += 128;
            } else {
                weight += host.len() as u16;
            }
        }

        weight
    }
}

/// Configuration for a server instance that handles incoming HTTP/HTTPS requests
#[derive(Debug, Default, Deserialize, Clone, Serialize)]
pub struct ServerConf {
    /// Address to listen on in format "host:port" or multiple addresses separated by commas
    pub addr: String,

    /// Access log format string for request logging
    pub access_log: Option<String>,

    /// List of location names that this server handles
    pub locations: Option<Vec<String>>,

    /// Number of worker threads for this server instance
    pub threads: Option<usize>,

    /// OpenSSL cipher list for protocols before TLS 1.3.
    /// Rejected at config validation under the rustls backend.
    pub tls_cipher_list: Option<String>,

    /// TLS 1.3 ciphersuites string (OpenSSL).
    /// Rejected at config validation under the rustls backend.
    pub tls_ciphersuites: Option<String>,

    /// Minimum TLS version to accept (e.g. "tlsv1.2").
    /// Rejected at config validation under the rustls backend.
    pub tls_min_version: Option<String>,

    /// Maximum TLS version to use (e.g. "tlsv1.3").
    /// Rejected at config validation under the rustls backend.
    pub tls_max_version: Option<String>,

    /// Whether to use global certificates instead of per-server certs
    pub global_certificates: Option<bool>,

    /// Compute the JA4 fingerprint of every TLS client from its
    /// ClientHello, for `$ja4` in headers and `{:ja4}` in the access log.
    /// Needs a TLS listener (`global_certificates`).
    pub ja4: Option<bool>,

    /// Whether to enable HTTP/2 protocol support
    pub enabled_h2: Option<bool>,

    /// Cap on concurrent HTTP/2 streams per downstream connection. Unset
    /// keeps pingora's bounded default of 100.
    pub h2_max_concurrent_streams: Option<u32>,

    /// Largest decoded HTTP/2 request header list a client may send. Unset
    /// keeps pingora's bounded default of 64 KiB. A client whose cookies or
    /// tokens exceed it is refused at the h2 layer, so raise this
    /// deliberately rather than removing the bound.
    #[serde(default, serialize_with = "serialize_byte_size")]
    pub h2_max_header_list_size: Option<ByteSize>,

    /// Initial HTTP/2 flow-control window per stream (RFC 9113 §6.9.2),
    /// between 1 and 2 GiB - 1. Larger windows help big uploads on
    /// high-latency links.
    #[serde(default, serialize_with = "serialize_byte_size")]
    pub h2_initial_window_size: Option<ByteSize>,

    /// Initial HTTP/2 flow-control window for the whole connection, between
    /// 1 and 2 GiB - 1.
    #[serde(default, serialize_with = "serialize_byte_size")]
    pub h2_initial_connection_window_size: Option<ByteSize>,

    /// Close a downstream HTTP/2 connection that has been idle this long.
    /// Unset leaves it open, which is pingora's default.
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub h2_idle_timeout: Option<Duration>,

    /// Serve HTTP/1.1 pipelined requests sequentially on one keep-alive
    /// connection (RFC 9112 §9.3.2). Off by default: pingora then answers
    /// the first request, closes the connection and drops the rest.
    pub h1_pipelining: Option<bool>,

    /// TCP keepalive idle timeout
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub tcp_idle: Option<Duration>,

    /// TCP keepalive probe interval
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub tcp_interval: Option<Duration>,

    /// TCP keepalive user timeout
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub tcp_user_timeout: Option<Duration>,

    // downstream read timeout
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub downstream_read_timeout: Option<Duration>,

    // downstream write timeout
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub downstream_write_timeout: Option<Duration>,

    /// Number of TCP keepalive probes before connection is dropped
    pub tcp_probe_count: Option<usize>,

    /// TCP Fast Open queue length (0 to disable)
    pub tcp_fastopen: Option<usize>,

    /// Enable SO_REUSEPORT to allow multiple sockets to bind to the same address and port.
    /// This is useful for load balancing across multiple worker processes.
    /// See the [man page](https://man7.org/linux/man-pages/man7/socket.7.html) for more information.
    pub reuse_port: Option<bool>,

    /// Path to expose Prometheus metrics on
    pub prometheus_metrics: Option<String>,

    /// OpenTelemetry exporter configuration
    pub otlp_exporter: Option<String>,

    /// List of configuration files to include
    pub includes: Option<Vec<String>>,

    /// List of modules to enable for this server
    pub modules: Option<Vec<String>>,

    /// Whether to enable server-timing header
    pub enable_server_timing: Option<bool>,

    /// Optional description/notes about this server
    pub remark: Option<String>,
}

/// Checks that an `access_log` is a format, a preset, or a file followed
/// by one of the two - the forms `parse_access_log_directive` of
/// `pingap-logger` reads.
///
/// Anything else is taken for a format as well, one with no placeholder in
/// it: `access_log = "stdout"`, or a file path on its own, printed that
/// very word once per request and logged nothing.
fn validate_access_log(access_log: &str) -> Result<()> {
    let is_preset = |value: &str| ACCESS_LOG_PRESETS.contains(&value);
    let format = match access_log.split_once(' ') {
        Some((_, format))
            if !access_log.starts_with('{')
                && (is_preset(format) || format.starts_with('{')) =>
        {
            format
        },
        _ => access_log,
    };
    if format.is_empty() || is_preset(format) || format.contains('{') {
        return Ok(());
    }
    Err(Error::Invalid {
        message: format!(
            "access_log {access_log:?} logs nothing of the request: expected a format such as \"{{method}} {{uri}} {{status}}\", one of {}, or a file path followed by either",
            ACCESS_LOG_PRESETS.join(", ")
        ),
    })
}

impl Validate for ServerConf {
    fn validate(&self) -> Result<()> {
        self.validate_with_locations(&[])?;
        Ok(())
    }
}

impl ServerConf {
    /// Validate the options of server config.
    /// 1. Parse listen addr to socket addr.
    /// 2. Check the locations are exists.
    /// 3. Parse access log layout success.
    fn validate_with_locations(&self, location_names: &[String]) -> Result<()> {
        for addr in self.addr.split(',') {
            let _ = addr.to_socket_addrs().map_err(|e| Error::Io {
                source: e,
                file: self.addr.clone(),
            })?;
        }
        if !location_names.is_empty()
            && let Some(locations) = &self.locations
        {
            for item in locations {
                if !location_names.contains(item) {
                    return Err(Error::Invalid {
                        message: format!("location({item}) is not found"),
                    });
                }
            }
        }
        validate_access_log(self.access_log.as_deref().unwrap_or_default())?;

        self.validate_h2()?;
        validate_tcp_keepalive(
            self.tcp_idle,
            self.tcp_interval,
            self.tcp_probe_count,
        )?;

        // The fingerprint comes from the ClientHello, which only a TLS
        // listener receives; on a plain one the option would do nothing.
        if self.ja4.unwrap_or_default()
            && !self.global_certificates.unwrap_or_default()
        {
            return Err(Error::Invalid {
                message:
                    "ja4 needs a TLS listener (global_certificates = true)"
                        .to_string(),
            });
        }

        Ok(())
    }

    /// The HTTP/2 knobs are forwarded to the h2 crate as SETTINGS, which
    /// does not check them itself: a zero or an oversized value would only
    /// surface as a protocol error on the first client connection.
    fn validate_h2(&self) -> Result<()> {
        if self.h2_max_concurrent_streams == Some(0) {
            return Err(Error::Invalid {
                message: "h2 max concurrent streams should be greater than 0"
                    .to_string(),
            });
        }
        if let Some(size) = self.h2_max_header_list_size
            && !(1..=u64::from(u32::MAX)).contains(&size.as_u64())
        {
            return Err(Error::Invalid {
                message:
                    "h2 max header list size should be between 1 and 4GiB - 1"
                        .to_string(),
            });
        }
        // RFC 9113 §6.9.2: a flow-control window cannot exceed 2^31 - 1.
        for (name, value) in [
            ("h2 initial window size", self.h2_initial_window_size),
            (
                "h2 initial connection window size",
                self.h2_initial_connection_window_size,
            ),
        ] {
            if let Some(size) = value
                && !(1..=H2_MAX_WINDOW_SIZE).contains(&size.as_u64())
            {
                return Err(Error::Invalid {
                    message: format!("{name} should be between 1 and 2GiB - 1"),
                });
            }
        }
        Ok(())
    }
}

/// Largest HTTP/2 flow-control window the protocol allows (RFC 9113 §6.9.2).
const H2_MAX_WINDOW_SIZE: u64 = (1 << 31) - 1;

/// Basic configuration options for the application
#[derive(Debug, Default, Deserialize, Clone, Serialize)]
pub struct BasicConf {
    /// Application name
    pub name: Option<String>,
    /// Error page template
    pub error_template: Option<String>,
    /// Path to PID file (default: /run/pingap.pid)
    pub pid_file: Option<String>,
    /// File the daemon redirects its stderr to. Only used with `--daemon`:
    /// without it the daemonized process keeps whatever stderr it inherited,
    /// which is the spawning terminal for a manual start and `/dev/null` for a
    /// process spawned by an auto restart. Set this to keep the panics and the
    /// early startup errors that happen before the logger is initialized.
    pub error_log: Option<String>,
    /// Unix domain socket path for graceful upgrades(default: /tmp/pingap_upgrade.sock)
    pub upgrade_sock: Option<String>,
    /// Working directory the daemon switches to right after forking, only
    /// used together with `--daemon`. Unset keeps pingora's default.
    pub working_directory: Option<String>,
    /// How long `--autorestart` waits for the replacement process to report
    /// that it is ready for the listening sockets before abandoning the
    /// restart and keeping the current process(default: 1m)
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub restart_ready_timeout: Option<Duration>,
    /// User for daemon
    pub user: Option<String>,
    /// Group for daemon
    pub group: Option<String>,
    /// Number of worker threads(default: 1)
    pub threads: Option<usize>,
    /// Upper bound of each worker runtime's blocking thread pool, which
    /// serves `spawn_blocking` work such as file cache I/O. Unset keeps
    /// tokio's default of 512.
    pub max_blocking_threads: Option<usize>,
    /// Enable work stealing between worker threads(default: true)
    pub work_stealing: Option<bool>,
    /// Number of listener tasks to use per fd. This allows for parallel accepts.
    pub listener_tasks_per_fd: Option<usize>,
    /// Number of dedicated thread pools that run downstream TLS handshakes
    /// off the worker threads, sharded by connection. Only takes effect
    /// together with `downstream_tls_offload_thread_per_pool`; both unset
    /// keeps handshakes on the workers, which is pingora's default.
    pub downstream_tls_offload_threadpools: Option<usize>,
    /// Threads in each of those pools. Only takes effect together with
    /// `downstream_tls_offload_threadpools`.
    pub downstream_tls_offload_thread_per_pool: Option<usize>,
    /// Number of dedicated thread pools that establish upstream connections
    /// (TCP connect and TLS handshake) off the worker threads. Only takes
    /// effect together with `upstream_connect_offload_thread_per_pool`; both
    /// unset keeps connecting on the workers, which is pingora's default.
    pub upstream_connect_offload_threadpools: Option<usize>,
    /// Threads in each of those pools. Only takes effect together with
    /// `upstream_connect_offload_threadpools`.
    pub upstream_connect_offload_thread_per_pool: Option<usize>,
    /// Grace period before forcefully terminating during shutdown(default: 5m)
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub grace_period: Option<Duration>,
    /// Maximum time to wait for graceful shutdown
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub graceful_shutdown_timeout: Option<Duration>,
    /// Maximum number of idle connections to keep in upstream connection pool
    pub upstream_keepalive_pool_size: Option<usize>,
    /// Trusted downstream proxy IPs/CIDRs. When set, `X-Forwarded-For` /
    /// `X-Real-IP` are only honoured for connections coming directly from one
    /// of these addresses; otherwise the direct peer address is used as the
    /// client IP. Leave unset to trust forwarded headers unconditionally.
    pub trusted_proxies: Option<Vec<String>>,
    /// Webhook URL for notifications
    pub webhook: Option<String>,
    /// Type of webhook (e.g. "wecom", "dingtalk")
    pub webhook_type: Option<String>,
    /// List of events to send webhook notifications for
    pub webhook_notifications: Option<Vec<String>>,
    /// Notifications no more than this far apart are merged into one webhook
    /// post; each one extends the wait (default: 10s, 0s posts every
    /// notification on its own)
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub webhook_batch_window: Option<Duration>,
    /// A batch is posted as soon as it holds this many notifications
    /// (default: 5, 1 posts every notification on its own)
    pub webhook_batch_max_events: Option<usize>,
    /// Log level (debug, info, warn, error)
    pub log_level: Option<String>,
    /// Size of log buffer before flushing
    #[serde(default, serialize_with = "serialize_byte_size")]
    pub log_buffered_size: Option<ByteSize>,
    /// Whether to format logs as JSON
    pub log_format_json: Option<bool>,
    /// Sentry DSN for error reporting
    pub sentry: Option<String>,
    /// Pyroscope server URL for continuous profiling
    pub pyroscope: Option<String>,
    /// How often to check for configuration changes that require restart
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub auto_restart_check_interval: Option<Duration>,

    // log compress algorithm: gzip, zstd
    pub log_compress_algorithm: Option<String>,
    /// Log compress level
    pub log_compress_level: Option<u8>,
    /// Log compress days ago
    pub log_compress_days_ago: Option<u16>,
    /// Log compress time point hour
    pub log_compress_time_point_hour: Option<u8>,
}

impl Validate for BasicConf {
    fn validate(&self) -> Result<()> {
        // Anything shorter than the restart's own polling would abandon
        // every restart before the replacement can even fork.
        if let Some(value) = self.restart_ready_timeout
            && value < Duration::from_secs(1)
        {
            return Err(Error::Invalid {
                message: "restart ready timeout should be at least 1s"
                    .to_string(),
            });
        }
        // pingora rejects a zero-sized blocking pool at startup; fail the
        // config check instead.
        if self.max_blocking_threads == Some(0) {
            return Err(Error::Invalid {
                message: "max blocking threads should be greater than 0"
                    .to_string(),
            });
        }
        // The interval is the period of a timer, and a timer with a period
        // of zero panics the moment it is created: the config check passed
        // and the background service died at startup.
        if let Some(value) = self.auto_restart_check_interval
            && value < Duration::from_secs(1)
        {
            return Err(Error::Invalid {
                message: "auto restart check interval should be at least 1s"
                    .to_string(),
            });
        }
        // The number of accept loops per listening socket. With none the
        // socket is bound and nothing ever accepts on it.
        if self.listener_tasks_per_fd == Some(0) {
            return Err(Error::Invalid {
                message: "listener tasks per fd should be greater than 0"
                    .to_string(),
            });
        }
        // Anything else was taken for zstd without a word.
        if let Some(value) = &self.log_compress_algorithm
            && !["", "gzip", "zstd"].contains(&value.as_str())
        {
            return Err(Error::Invalid {
                message: format!(
                    "log compress algorithm {value} is invalid, expected gzip or zstd"
                ),
            });
        }
        // An hour of the day; past 23 the compression never ran.
        if self
            .log_compress_time_point_hour
            .is_some_and(|hour| hour > 23)
        {
            return Err(Error::Invalid {
                message: "log compress time point hour should be 0 to 23"
                    .to_string(),
            });
        }
        // pingora only offloads when both values of a pair are set and
        // non-zero, and says nothing otherwise; refuse the half-configured
        // states instead.
        validate_offload_pair(
            "downstream tls offload",
            self.downstream_tls_offload_threadpools,
            self.downstream_tls_offload_thread_per_pool,
        )?;
        validate_offload_pair(
            "upstream connect offload",
            self.upstream_connect_offload_threadpools,
            self.upstream_connect_offload_thread_per_pool,
        )?;
        Ok(())
    }
}

/// The keepalive timings go to the kernel in whole seconds, and it refuses
/// a zero for any of the three (`EINVAL`). An idle time or interval under
/// one second, or a probe count of zero, passed the config check and then
/// failed every connection the option was applied to.
fn validate_tcp_keepalive(
    idle: Option<Duration>,
    interval: Option<Duration>,
    probe_count: Option<usize>,
) -> Result<()> {
    for (name, value) in [("tcp idle", idle), ("tcp interval", interval)] {
        if value.is_some_and(|value| value < Duration::from_secs(1)) {
            return Err(Error::Invalid {
                message: format!("{name} should be at least 1s"),
            });
        }
    }
    if probe_count == Some(0) {
        return Err(Error::Invalid {
            message: "tcp probe count should be greater than 0".to_string(),
        });
    }
    Ok(())
}

/// A size as text that reads back to the same number of bytes.
///
/// The size type writes itself rounded to one decimal of the nearest binary
/// unit, so `10MB` was saved as `9.5 MiB`, which is 38528 bytes less: a
/// size changed the first time its entry was saved through the admin.
///
/// The largest unit that divides the size is used (`10 MB`, `64 KiB`), and
/// kilobytes with up to three decimals for the sizes that have none.
fn format_byte_size(size: ByteSize) -> String {
    const UNITS: [(u64, &str); 6] = [
        (1 << 30, "GiB"),
        (1_000_000_000, "GB"),
        (1 << 20, "MiB"),
        (1_000_000, "MB"),
        (1 << 10, "KiB"),
        (1_000, "KB"),
    ];
    let bytes = size.as_u64();
    if bytes == 0 {
        return "0 KB".to_string();
    }
    for (unit, name) in UNITS {
        if bytes.is_multiple_of(unit) {
            return format!("{} {name}", bytes / unit);
        }
    }
    let decimals = format!("{:03}", bytes % 1000);
    let text =
        format!("{}.{} KB", bytes / 1000, decimals.trim_end_matches('0'));
    // The parser goes through a float; fall back to plain bytes should
    // that ever land on another number.
    if text.parse::<ByteSize>().is_ok_and(|parsed| parsed == size) {
        text
    } else {
        bytes.to_string()
    }
}

fn serialize_byte_size<S: serde::Serializer>(
    value: &Option<ByteSize>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    match value {
        Some(size) => serializer.serialize_some(&format_byte_size(*size)),
        None => serializer.serialize_none(),
    }
}

/// An offload pool is described by two numbers that only mean something
/// together: how many pools, and how many threads in each.
fn validate_offload_pair(
    name: &str,
    pools: Option<usize>,
    threads: Option<usize>,
) -> Result<()> {
    match (pools, threads) {
        (None, None) => Ok(()),
        (Some(pools), Some(threads)) if pools > 0 && threads > 0 => Ok(()),
        (Some(_), Some(_)) => Err(Error::Invalid {
            message: format!(
                "{name} threadpools and thread per pool should be greater than 0"
            ),
        }),
        _ => Err(Error::Invalid {
            message: format!(
                "{name} threadpools and thread per pool should be set together"
            ),
        }),
    }
}

impl BasicConf {
    /// Returns the path to the PID file
    /// - If pid_file is explicitly configured, uses that value
    /// - Otherwise tries to use /run/pingap.pid or /var/run/pingap.pid if writable
    /// - Falls back to /tmp/pingap.pid if neither system directories are writable
    pub fn get_pid_file(&self) -> String {
        if let Some(pid_file) = &self.pid_file {
            return pid_file.clone();
        }
        for dir in ["/run", "/var/run"] {
            if tempfile_in(dir).is_ok() {
                return format!("{dir}/pingap.pid");
            }
        }
        "/tmp/pingap.pid".to_string()
    }
}

#[derive(Debug, Default, Deserialize, Clone, Serialize)]
pub struct StorageConf {
    pub category: String,
    pub value: String,
    pub secret: Option<String>,
    pub remark: Option<String>,
    /// Unix timestamp (seconds) of when the entry was written. Optional so
    /// entries from before the field existed still deserialize; short-lived
    /// entries (ACME http-01 tokens) rely on it for age based cleanup.
    pub created_at: Option<u64>,
}

impl Validate for StorageConf {
    fn validate(&self) -> Result<()> {
        Ok(())
    }
}

pub trait Hashable: Hash {
    fn hash_key(&self) -> String {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
}
impl Hashable for UpstreamConf {}
impl Hashable for LocationConf {}

pub type PluginConf = Map<String, Value>;

impl Validate for PluginConf {
    fn validate(&self) -> Result<()> {
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct PingapConfig {
    pub basic: BasicConf,
    pub upstreams: HashMap<String, UpstreamConf>,
    pub locations: HashMap<String, LocationConf>,
    pub servers: HashMap<String, ServerConf>,
    pub plugins: HashMap<String, PluginConf>,
    pub certificates: HashMap<String, CertificateConf>,
    pub storages: HashMap<String, StorageConf>,
}

impl PingapConfig {
    // 需要一个辅助函数来避免重复
    fn get_value_for_category<T: Serialize>(
        &self,
        map: &HashMap<String, T>,
        name: Option<&str>,
    ) -> Result<toml::Value> {
        match name {
            // 如果指定了名称，只序列化那一个项
            Some(name) => {
                if let Some(item) = map.get(name) {
                    let mut table = Map::new();
                    table.insert(
                        name.to_string(),
                        toml::Value::try_from(item)
                            .map_err(|e| Error::Ser { source: e })?,
                    );
                    Ok(toml::Value::Table(table))
                } else {
                    Ok(toml::Value::Table(Map::new())) // 未找到，返回空表
                }
            },
            // 否则，序列化整个类别
            None => Ok(toml::Value::try_from(map)
                .map_err(|e| Error::Ser { source: e })?),
        }
    }
    pub fn get_toml(
        &self,
        category: &str,
        name: Option<&str>,
    ) -> Result<(String, String)> {
        let (key, value_to_serialize) = match category {
            CATEGORY_SERVER => {
                ("servers", self.get_value_for_category(&self.servers, name)?)
            },
            CATEGORY_LOCATION => (
                "locations",
                self.get_value_for_category(&self.locations, name)?,
            ),
            CATEGORY_UPSTREAM => (
                "upstreams",
                self.get_value_for_category(&self.upstreams, name)?,
            ),
            CATEGORY_PLUGIN => {
                ("plugins", self.get_value_for_category(&self.plugins, name)?)
            },
            CATEGORY_CERTIFICATE => (
                "certificates",
                self.get_value_for_category(&self.certificates, name)?,
            ),
            CATEGORY_STORAGE => (
                "storages",
                self.get_value_for_category(&self.storages, name)?,
            ),
            _ => (
                CATEGORY_BASIC,
                toml::Value::try_from(&self.basic)
                    .map_err(|e| Error::Ser { source: e })?,
            ),
        };

        let path = {
            let name = name.unwrap_or_default();
            if key == CATEGORY_BASIC || name.is_empty() {
                format!("/{key}.toml")
            } else {
                format!("/{key}/{name}.toml")
            }
        };

        if let Some(table) = value_to_serialize.as_table()
            && table.is_empty()
        {
            return Ok((path, "".to_string()));
        }

        let mut wrapper = Map::new();
        wrapper.insert(key.to_string(), value_to_serialize);

        let toml_string = toml::to_string_pretty(&wrapper)
            .map_err(|e| Error::Ser { source: e })?;

        Ok((path, toml_string))
    }
    pub fn get_storage_value(&self, name: &str) -> Result<String> {
        let Some(item) = self.storages.get(name) else {
            return Ok(String::new());
        };
        match &item.secret {
            Some(key) => {
                pingap_util::aes_decrypt(key, &item.value).map_err(|e| {
                    Error::Invalid {
                        message: e.to_string(),
                    }
                })
            },
            None => Ok(item.value.clone()),
        }
    }
}

/// Deserializes one entry straight from its `toml::Value`, naming the
/// entry in the error.
fn parse_entry<T: DeserializeOwned>(
    kind: &str,
    name: &str,
    value: Value,
) -> Result<T> {
    value.try_into().map_err(|e| Error::Invalid {
        message: if name.is_empty() {
            format!("{kind}: {e}")
        } else {
            format!("{kind}({name}): {e}")
        },
    })
}

/// Expands an entry's `includes`. Each named storage holds a TOML fragment
/// whose keys are merged into the entry; a fragment overrides the entry's
/// own keys and a later fragment overrides an earlier one, as before. An
/// include that names no storage, or a storage whose value is not TOML,
/// is a configuration error: it used to be dropped without a word, leaving
/// the entry without the settings it was meant to share.
pub(crate) fn expand_includes(
    storages: &HashMap<String, StorageConf>,
    kind: &str,
    name: &str,
    value: &mut Value,
) -> Result<()> {
    let Some(table) = value.as_table_mut() else {
        return Ok(());
    };
    let Some(includes) = table.remove("includes") else {
        return Ok(());
    };
    let invalid = |message: String| Error::Invalid {
        message: format!("{kind}({name}): {message}"),
    };
    let Some(includes) = includes.as_array() else {
        return Err(invalid("includes must be an array".to_string()));
    };
    for include in includes {
        let Some(include_name) = include.as_str() else {
            return Err(invalid("includes must be storage names".to_string()));
        };
        let Some(storage) = storages.get(include_name) else {
            return Err(invalid(format!(
                "include({include_name}) is not found"
            )));
        };
        let fragment: Table = toml::from_str(&storage.value).map_err(|e| {
            invalid(format!("include({include_name}) is not valid toml: {e}"))
        })?;
        table.extend(fragment);
    }
    Ok(())
}

pub(crate) fn convert_pingap_config(
    data: &[u8],
    replace_include: bool,
) -> Result<PingapConfig, Error> {
    let config = PingapTomlConfig::from_toml(&String::from_utf8_lossy(data))?;
    convert_toml_config(&config, replace_include)
}

/// Resolves the loose document into typed configuration. Every entry is
/// deserialized from its `toml::Value`, not printed back to text and
/// parsed a second time.
pub(crate) fn convert_toml_config(
    data: &PingapTomlConfig,
    replace_include: bool,
) -> Result<PingapConfig> {
    fn entries<T: DeserializeOwned>(
        section: &Option<Map<String, Value>>,
        kind: &str,
        storages: &HashMap<String, StorageConf>,
        replace_include: bool,
    ) -> Result<HashMap<String, T>> {
        let mut out = HashMap::new();
        for (name, value) in section.iter().flatten() {
            let mut value = value.clone();
            if replace_include {
                expand_includes(storages, kind, name, &mut value)?;
            }
            out.insert(name.clone(), parse_entry(kind, name, value)?);
        }
        Ok(out)
    }

    let basic = match &data.basic {
        Some(value) => parse_entry("basic", "", value.clone())?,
        None => BasicConf::default(),
    };
    let storages = entries(&data.storages, "storage", &HashMap::new(), false)?;
    Ok(PingapConfig {
        basic,
        upstreams: entries(
            &data.upstreams,
            "upstream",
            &storages,
            replace_include,
        )?,
        locations: entries(
            &data.locations,
            "location",
            &storages,
            replace_include,
        )?,
        servers: entries(&data.servers, "server", &storages, replace_include)?,
        plugins: entries(&data.plugins, "plugin", &storages, false)?,
        certificates: entries(
            &data.certificates,
            "certificate",
            &storages,
            false,
        )?,
        storages,
    })
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
struct Description {
    category: String,
    name: String,
    data: String,
}

impl PingapConfig {
    pub fn new(data: &[u8], replace_includes: bool) -> Result<Self> {
        convert_pingap_config(data, replace_includes)
    }
    /// Validate the options of pinggap config.
    pub fn validate(&self) -> Result<()> {
        // `basic` carries the restart hand-over timeout; a bad one used to
        // slip through because nothing ever called this.
        self.basic.validate()?;
        let mut upstream_names = vec![];
        for (name, upstream) in self.upstreams.iter() {
            // With the name of the upstream: `upstream addrs is empty`
            // does not say which of them.
            upstream.validate().map_err(|e| Error::Invalid {
                message: match e {
                    Error::Invalid { message } => {
                        format!("upstream({name}): {message}")
                    },
                    other => format!("upstream({name}): {other}"),
                },
            })?;
            upstream_names.push(name.to_string());
        }
        let mut location_names = vec![];
        for (name, location) in self.locations.iter() {
            location.validate_with_upstream(Some(&upstream_names))?;
            location_names.push(name.to_string());
        }
        let mut listen_addr_list = vec![];
        for server in self.servers.values() {
            for addr in server.addr.split(',') {
                if listen_addr_list.contains(&addr.to_string()) {
                    return Err(Error::Invalid {
                        message: format!("{addr} is inused by other server"),
                    });
                }
                listen_addr_list.push(addr.to_string());
            }
            server.validate_with_locations(&location_names)?;
        }
        // Plugin configs are validated by the binary (`src/main.rs`) through
        // the plugin factory: that factory lives in a higher layer than this
        // crate, so it cannot be reached from here without a dependency cycle.
        // What a plugin names of the other entries is checked here, with
        // the other references: a `traffic_splitting` plugin sending its
        // share of the requests to an upstream that does not exist used to
        // pass, and those requests then failed.
        for (name, upstream) in self.plugin_upstreams() {
            if !upstream_names.iter().any(|item| item == upstream) {
                return Err(Error::Invalid {
                    message: format!(
                        "plugin({name}): upstream({upstream}) is not found"
                    ),
                });
            }
        }
        for certificate in self.certificates.values() {
            certificate.validate()?;
        }
        // Round trip through the loose form with includes expanded: proves
        // the config serializes and that every include resolves.
        convert_toml_config(
            &PingapTomlConfig::from_pingap_config(self)?,
            true,
        )?;
        Ok(())
    }
    /// The upstreams that plugins send requests to, with the name of the
    /// plugin: the `upstream` of each `traffic_splitting` plugin.
    fn plugin_upstreams(&self) -> impl Iterator<Item = (&str, &str)> {
        self.plugins.iter().filter_map(|(name, plugin)| {
            let text =
                |key: &str| plugin.get(key).and_then(|value| value.as_str());
            if text("category") != Some("traffic_splitting") {
                return None;
            }
            let upstream = text("upstream").filter(|item| !item.is_empty())?;
            Some((name.as_str(), upstream))
        })
    }
    /// Generate the content hash of config.
    pub fn hash(&self) -> Result<String> {
        let mut lines = vec![];
        for desc in self.descriptions() {
            lines.push(desc.category);
            lines.push(desc.name);
            lines.push(desc.data);
        }
        let hash = crc32fast::hash(lines.join("\n").as_bytes());
        Ok(format!("{hash:X}"))
    }
    /// Whether `name` in `category` can be removed: an upstream, location,
    /// plugin or storage still referenced by another entry cannot. The
    /// `includes` that refer to a storage are only there in a config
    /// loaded without replacing them.
    pub fn check_removable(&self, category: &str, name: &str) -> Result<()> {
        let in_use = |kind: &str, by: &str, by_name: &str| Error::Invalid {
            message: format!("{kind}({name}) is in used by {by}({by_name})"),
        };
        match category {
            CATEGORY_UPSTREAM => {
                if let Some((location_name, _)) =
                    self.locations.iter().find(|(_, location)| {
                        location.upstream.as_deref() == Some(name)
                    })
                {
                    return Err(in_use("upstream", "location", location_name));
                }
                if let Some((plugin_name, _)) = self
                    .plugin_upstreams()
                    .find(|(_, upstream)| *upstream == name)
                {
                    return Err(in_use("upstream", "plugin", plugin_name));
                }
            },
            CATEGORY_LOCATION => {
                if let Some((server_name, _)) =
                    self.servers.iter().find(|(_, server)| {
                        server.locations.as_ref().is_some_and(|locations| {
                            locations.iter().any(|l| l == name)
                        })
                    })
                {
                    return Err(in_use("location", "server", server_name));
                }
            },
            CATEGORY_PLUGIN => {
                if let Some((location_name, _)) =
                    self.locations.iter().find(|(_, location)| {
                        location.plugins.as_ref().is_some_and(|plugins| {
                            plugins.iter().any(|p| p == name)
                        })
                    })
                {
                    return Err(in_use(
                        "proxy plugin",
                        "location",
                        location_name,
                    ));
                }
            },
            CATEGORY_STORAGE => {
                let includes = |list: &Option<Vec<String>>| {
                    list.iter().flatten().any(|item| item == name)
                };
                let upstreams = self
                    .upstreams
                    .iter()
                    .filter(|(_, conf)| includes(&conf.includes))
                    .map(|(by, _)| ("upstream", by));
                let locations = self
                    .locations
                    .iter()
                    .filter(|(_, conf)| includes(&conf.includes))
                    .map(|(by, _)| ("location", by));
                let servers = self
                    .servers
                    .iter()
                    .filter(|(_, conf)| includes(&conf.includes))
                    .map(|(by, _)| ("server", by));
                if let Some((by, by_name)) =
                    upstreams.chain(locations).chain(servers).next()
                {
                    return Err(in_use("storage", by, by_name));
                }
            },
            _ => {},
        }
        Ok(())
    }
    /// Remove the config by name.
    pub fn remove(&mut self, category: &str, name: &str) -> Result<()> {
        self.check_removable(category, name)?;
        match category {
            CATEGORY_UPSTREAM => {
                self.upstreams.remove(name);
            },
            CATEGORY_LOCATION => {
                self.locations.remove(name);
            },
            CATEGORY_SERVER => {
                self.servers.remove(name);
            },
            CATEGORY_PLUGIN => {
                self.plugins.remove(name);
            },
            CATEGORY_CERTIFICATE => {
                self.certificates.remove(name);
            },
            _ => {},
        };
        Ok(())
    }
    fn descriptions(&self) -> Vec<Description> {
        /// `[basic]` on its own, so the whole config need not be cloned and
        /// emptied to print that one table.
        #[derive(Serialize)]
        struct BasicOnly<'a> {
            basic: &'a BasicConf,
        }
        let value = self;
        let mut descriptions = vec![];
        // Every entry is printed with its credentials replaced by their
        // checksums (see `secrets`): what is made here ends up in the log
        // and in the webhook as the difference of a reload. A checksum
        // changes with the value, so a changed secret still shows as a
        // change, here and to whoever goes by `diff` to decide what to
        // reload.
        for (name, data) in value.servers.iter() {
            descriptions.push(Description {
                category: CATEGORY_SERVER.to_string(),
                name: format!("server:{name}"),
                data: masked_entry(data),
            });
        }
        for (name, data) in value.locations.iter() {
            descriptions.push(Description {
                category: CATEGORY_LOCATION.to_string(),
                name: format!("location:{name}"),
                data: masked_entry(data),
            });
        }
        for (name, data) in value.upstreams.iter() {
            descriptions.push(Description {
                category: CATEGORY_UPSTREAM.to_string(),
                name: format!("upstream:{name}"),
                data: masked_entry(data),
            });
        }
        for (name, data) in value.plugins.iter() {
            descriptions.push(Description {
                category: CATEGORY_PLUGIN.to_string(),
                name: format!("plugin:{name}"),
                data: masked_entry(data),
            });
        }
        for (name, data) in value.certificates.iter() {
            descriptions.push(Description {
                category: CATEGORY_CERTIFICATE.to_string(),
                name: format!("certificate:{name}"),
                data: masked_entry(data),
            });
        }
        for (name, data) in value.storages.iter() {
            // What a storage holds is a fragment of configuration or a
            // secret, and either may carry credentials.
            let mut clone_data = data.clone();
            clone_data.value = masked_fragment(&clone_data.value);
            descriptions.push(Description {
                category: CATEGORY_STORAGE.to_string(),
                name: format!("storage:{name}"),
                data: masked_entry(&clone_data),
            });
        }
        descriptions.push(Description {
            category: CATEGORY_BASIC.to_string(),
            name: CATEGORY_BASIC.to_string(),
            data: masked_entry(&BasicOnly {
                basic: &value.basic,
            }),
        });
        descriptions.sort_by_key(|d| d.name.clone());
        descriptions
    }
    /// Get the different content of two config.
    pub fn diff(&self, other: &PingapConfig) -> (Vec<String>, Vec<String>) {
        // 1. 将描述列表转换为 HashMap，以便进行高效的键查找。
        let current_map: HashMap<_, _> = self
            .descriptions()
            .into_iter()
            .map(|d| (d.name.clone(), d))
            .collect();
        let new_map: HashMap<_, _> = other
            .descriptions()
            .into_iter()
            .map(|d| (d.name.clone(), d))
            .collect();

        // 使用 HashSet 存储受影响的类别，以自动处理重复。
        let mut affected_categories = HashSet::new();

        // 分别存储新增、删除和修改的项，以便最后格式化输出。
        let mut added_items = vec![];
        let mut removed_items = vec![];
        let mut modified_items = vec![];

        // 2. 遍历当前配置，查找被删除或被修改的项。
        for (name, current_item) in &current_map {
            match new_map.get(name) {
                Some(new_item) => {
                    // 键存在于两个配置中，检查内容是否发生变化。
                    if current_item.data != new_item.data {
                        affected_categories
                            .insert(current_item.category.clone());

                        // 使用 diff::lines 生成逐行差异
                        let mut item_diff_result = vec![];
                        for diff in
                            diff::lines(&current_item.data, &new_item.data)
                        {
                            match diff {
                                diff::Result::Left(l) => {
                                    item_diff_result.push(format!("- {l}"))
                                },
                                diff::Result::Right(r) => {
                                    item_diff_result.push(format!("+ {r}"))
                                },
                                _ => (),
                            }
                        }

                        if !item_diff_result.is_empty() {
                            modified_items.push(format!("[MODIFIED] {name}"));
                            modified_items.extend(item_diff_result);
                            modified_items.push("".to_string()); // 添加空行分隔
                        }
                    }
                },
                None => {
                    // 在新配置中不存在，说明该项已被删除。
                    removed_items.push(format!("-- [REMOVED] {name}"));
                    affected_categories.insert(current_item.category.clone());
                },
            }
        }

        // 3. 遍历新配置，查找新增的项。
        for (name, new_item) in &new_map {
            if !current_map.contains_key(name) {
                added_items.push(format!("++ [ADDED] {name}"));
                affected_categories.insert(new_item.category.clone());
            }
        }

        // 4. 组合所有差异，生成最终的可读输出。
        let mut final_diff = Vec::new();
        if !added_items.is_empty() {
            final_diff.extend(added_items);
            final_diff.push("".to_string()); // 添加空行分隔
        }
        if !removed_items.is_empty() {
            final_diff.extend(removed_items);
            final_diff.push("".to_string());
        }
        if !modified_items.is_empty() {
            final_diff.extend(modified_items);
        }

        // 将 HashSet 转换为 Vec 并返回结果
        (affected_categories.into_iter().collect(), final_diff)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BasicConf, LocationConf, PluginCategory, ServerConf, UpstreamConf,
    };
    use super::{
        CATEGORY_BASIC, CATEGORY_STORAGE, CATEGORY_UPSTREAM,
        convert_pingap_config,
    };
    use super::{
        CertificateConf, Hashable, PingapConfig, Validate, validate_cert,
    };
    use bytesize::ByteSize;
    use pingap_core::PluginStep;
    use pingap_util::base64_encode;
    use pretty_assertions::assert_eq;
    use serde::{Deserialize, Serialize};
    use std::str::FromStr;
    use std::time::Duration;

    #[test]
    fn test_plugin_step() {
        let step = PluginStep::from_str("early_request").unwrap();
        assert_eq!(step, PluginStep::EarlyRequest);

        assert_eq!("early_request", step.to_string());
    }

    #[test]
    fn test_config_diff() {
        let base = convert_pingap_config(
            br#"
[upstreams.charts]
addrs = ["127.0.0.1:5000"]

[upstreams.api]
addrs = ["127.0.0.1:6000"]
"#,
            false,
        )
        .unwrap();

        // No change: identical config -> nothing affected, empty diff.
        let (categories, detail) = base.diff(&base.clone());
        assert_eq!(true, categories.is_empty());
        assert_eq!(true, detail.is_empty());

        // Modify one upstream -> only the upstream category is affected.
        let mut modified = base.clone();
        modified.upstreams.get_mut("charts").unwrap().addrs =
            vec!["127.0.0.1:5001".to_string()];
        let (categories, detail) = base.diff(&modified);
        assert_eq!(vec![CATEGORY_UPSTREAM.to_string()], categories);
        assert_eq!(
            true,
            detail
                .iter()
                .any(|l| l.contains("[MODIFIED]") && l.contains("charts"))
        );

        // Add an upstream -> upstream category affected, ADDED marker.
        let mut added = base.clone();
        added
            .upstreams
            .insert("new".to_string(), base.upstreams["api"].clone());
        let (categories, detail) = base.diff(&added);
        assert_eq!(vec![CATEGORY_UPSTREAM.to_string()], categories);
        assert_eq!(true, detail.iter().any(|l| l.contains("[ADDED]")));

        // Remove an upstream -> upstream category affected, REMOVED marker.
        let mut removed = base.clone();
        removed.upstreams.remove("api");
        let (categories, detail) = base.diff(&removed);
        assert_eq!(vec![CATEGORY_UPSTREAM.to_string()], categories);
        assert_eq!(true, detail.iter().any(|l| l.contains("[REMOVED]")));

        // Change basic -> only the basic category is affected.
        let mut basic_changed = base.clone();
        basic_changed.basic.name = Some("renamed".to_string());
        let (categories, _) = base.diff(&basic_changed);
        assert_eq!(vec![CATEGORY_BASIC.to_string()], categories);
    }

    /// Regression: the difference of a reload goes to the log and to the
    /// webhook, and carried the credentials of whatever had changed - the
    /// old value and the new - as they are written in the config.
    #[test]
    fn test_config_diff_has_no_credentials() {
        let config = |secret: &str| {
            convert_pingap_config(
                format!(
                    r#"
[basic]
webhook = "https://hook.test/send?key={secret}"

[plugins.auth]
category = "basic_auth"
authorizations = ["{secret}"]

[plugins.token]
category = "jwt"
secret = "{secret}"
header = "Authorization"

[plugins.api]
category = "key_auth"
query = "apikey"
keys = ["{secret}", "other"]

[plugins.limiter]
category = "limit"
tag = "header"
key = "X-Client"
max = 10

[locations.app]
proxy_set_headers = ["Authorization: Bearer {secret}", "X-Mode: {secret}"]

[servers.web]
addr = "127.0.0.1:80"
prometheus_metrics = "http://user:{secret}@push.test/metrics"

[storages.shared]
category = "config"
value = 'proxy_add_headers = ["X-Api-Key: {secret}"]'
"#
                )
                .as_bytes(),
                false,
            )
            .unwrap()
        };
        let old = config("0ld-s3cret");
        let new = config("n3w-s3cret");

        let (mut categories, detail) = old.diff(&new);
        categories.sort();
        // Every one of them is still seen to have changed.
        assert_eq!(
            vec!["basic", "location", "plugin", "server", "storage"],
            categories
        );
        let text = detail.join("\n");
        for name in ["plugin:auth", "plugin:token", "plugin:api", "basic"] {
            assert_eq!(
                true,
                text.contains(&format!("[MODIFIED] {name}")),
                "{name}: {text}"
            );
        }
        // The one header that is no credential is the only place either
        // value may show.
        let leaked: Vec<&str> = text
            .lines()
            .filter(|line| line.contains("s3cret"))
            .collect();
        assert_eq!(2, leaked.len(), "{leaked:?}");
        assert_eq!(
            true,
            leaked.iter().all(|line| line.contains("X-Mode")),
            "{leaked:?}"
        );
        // What is not a credential reads as before.
        let (_, detail) = old.diff(&{
            let mut renamed = old.clone();
            renamed
                .plugins
                .get_mut("limiter")
                .unwrap()
                .insert("key".to_string(), "X-User".into());
            renamed
        });
        let text = detail.join("\n");
        assert_eq!(true, text.contains(r#"- key = "X-Client""#), "{text}");
        assert_eq!(true, text.contains(r#"+ key = "X-User""#), "{text}");

        // The hash goes by the same text and still tells the two apart.
        assert_ne!(old.hash().unwrap(), new.hash().unwrap());
    }

    #[test]
    fn test_validate_cert() {
        // spellchecker:off
        let pem = r#"-----BEGIN CERTIFICATE-----
MIIEljCCAv6gAwIBAgIQeYUdeFj3gpzhQes3aGaMZTANBgkqhkiG9w0BAQsFADCB
pTEeMBwGA1UEChMVbWtjZXJ0IGRldmVsb3BtZW50IENBMT0wOwYDVQQLDDR4aWVz
aHV6aG91QHhpZXNodXpob3VzLU1hY0Jvb2stQWlyLmxvY2FsICjosKLmoJHmtLIp
MUQwQgYDVQQDDDtta2NlcnQgeGllc2h1emhvdUB4aWVzaHV6aG91cy1NYWNCb29r
LUFpci5sb2NhbCAo6LCi5qCR5rSyKTAeFw0yMzA5MjQxMzA1MjdaFw0yNTEyMjQx
MzA1MjdaMGgxJzAlBgNVBAoTHm1rY2VydCBkZXZlbG9wbWVudCBjZXJ0aWZpY2F0
ZTE9MDsGA1UECww0eGllc2h1emhvdUB4aWVzaHV6aG91cy1NYWNCb29rLUFpci5s
b2NhbCAo6LCi5qCR5rSyKTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
ALuJ8lYEj9uf4iE9hguASq7re87Np+zJc2x/eqr1cR/SgXRStBsjxqI7i3xwMRqX
AuhAnM6ktlGuqidl7D9y6AN/UchqgX8AetslRJTpCcEDfL/q24zy0MqOS0FlYEgh
s4PIjWsSNoglBDeaIdUpN9cM/64IkAAtHndNt2p2vPfjrPeixLjese096SKEnZM/
xBdWF491hx06IyzjtWKqLm9OUmYZB9d/gDGnDsKpqClw8m95opKD4TBHAoE//WvI
m1mZnjNTNR27vVbmnc57d2Lx2Ib2eqJG5zMsP2hPBoqS8CKEwMRFLHAcclNkI67U
kcSEGaWgr15QGHJPN/FtjDsCAwEAAaN+MHwwDgYDVR0PAQH/BAQDAgWgMBMGA1Ud
JQQMMAoGCCsGAQUFBwMBMB8GA1UdIwQYMBaAFJo0y9bYUM/OuenDjsJ1RyHJfL3n
MDQGA1UdEQQtMCuCBm1lLmRldoIJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAA
AAAAAAABMA0GCSqGSIb3DQEBCwUAA4IBgQAlQbow3+4UyQx+E+J0RwmHBltU6i+K
soFfza6FWRfAbTyv+4KEWl2mx51IfHhJHYZvsZqPqGWxm5UvBecskegDExFMNFVm
O5QixydQzHHY2krmBwmDZ6Ao88oW/qw4xmMUhzKAZbsqeQyE/uiUdyI4pfDcduLB
rol31g9OFsgwZrZr0d1ZiezeYEhemnSlh9xRZW3veKx9axgFttzCMmWdpGTCvnav
ZVc3rB+KBMjdCwsS37zmrNm9syCjW1O5a1qphwuMpqSnDHBgKWNpbsgqyZM0oyOc
9Bkja+BV5wFO+4zH5WtestcrNMeoQ83a5lI0m42u/bUEJ/T/5BQBSFidNuvS7Ylw
IZpXa00xvlnm1BOHOfRI4Ehlfa5jmfcdnrGkQLGjiyygQtKcc7rOXGK+mSeyxwhs
sIARwslSQd4q0dbYTPKvvUHxTYiCv78vQBAsE15T2GGS80pAFDBW9vOf3upANvOf
EHjKf0Dweb4ppL4ddgeAKU5V0qn76K2fFaE=
-----END CERTIFICATE-----"#;
        // spellchecker:on
        let result = validate_cert(pem);
        assert_eq!(true, result.is_ok());

        let value = base64_encode(pem);
        let result = validate_cert(&value);
        assert_eq!(true, result.is_ok());
    }

    #[test]
    fn test_plugin_category_serde() {
        #[derive(Deserialize, Serialize)]
        struct TmpPluginCategory {
            category: PluginCategory,
        }
        let tmp = TmpPluginCategory {
            category: PluginCategory::RequestId,
        };
        let data = serde_json::to_string(&tmp).unwrap();
        assert_eq!(r#"{"category":"request_id"}"#, data);

        let tmp: TmpPluginCategory = serde_json::from_str(&data).unwrap();
        assert_eq!(PluginCategory::RequestId, tmp.category);
    }

    #[test]
    fn test_upstream_conf_guess_discovery() {
        let guess = |addrs: &[&str]| {
            UpstreamConf {
                addrs: addrs.iter().map(|addr| addr.to_string()).collect(),
                ..Default::default()
            }
            .guess_discovery()
        };
        // IP literals, with or without port and weight, are static.
        assert_eq!("", guess(&["127.0.0.1:8080", "127.0.0.1 10"]));
        assert_eq!("", guess(&["[::1]:8080 2", "[::1]", "2001:db8::1"]));
        // A name anywhere means DNS.
        assert_eq!("dns", guess(&["127.0.0.1:8080", "api:8080"]));
        assert_eq!("dns", guess(&["api"]));
        // An explicit choice always wins.
        let conf = UpstreamConf {
            addrs: vec!["api:8080".to_string()],
            discovery: Some("static".to_string()),
            ..Default::default()
        };
        assert_eq!("static", conf.guess_discovery());
    }

    #[test]
    fn test_upstream_conf_addr_weight() {
        for (addr, message) in [
            ("127.0.0.1:8080 0", "weight must be a positive integer"),
            ("127.0.0.1:8080 x", "weight must be a positive integer"),
            (
                "127.0.0.1:8080 1 2",
                "has more than a weight after the address",
            ),
        ] {
            let conf = UpstreamConf {
                addrs: vec![addr.to_string()],
                ..Default::default()
            };
            let err = conf.validate().expect_err(addr).to_string();
            assert_eq!(true, err.contains(message), "{addr}: {err}");
        }
        // The weight is checked for every discovery, not only static.
        let conf = UpstreamConf {
            addrs: vec!["api:8080 0".to_string()],
            discovery: Some("dns".to_string()),
            ..Default::default()
        };
        assert_eq!(true, conf.validate().is_err());
        let conf = UpstreamConf {
            addrs: vec![
                "[::1]:8080 3".to_string(),
                "127.0.0.1:8080".to_string(),
            ],
            ..Default::default()
        };
        assert_eq!(true, conf.validate().is_ok());
    }

    #[test]
    fn test_upstream_conf() {
        let mut conf = UpstreamConf::default();

        let result = conf.validate();
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Invalid error upstream addrs is empty",
            result.expect_err("").to_string()
        );

        conf.addrs = vec!["127.0.0.1".to_string(), "github".to_string()];
        conf.discovery = Some("static".to_string());
        let result = conf.validate();
        assert_eq!(true, result.is_err());
        let message = result.expect_err("").to_string();
        assert_eq!(
            true,
            message.starts_with("Invalid error upstream addr(github) is invalid: failed to lookup address information"),
            "{message}"
        );

        conf.addrs = vec!["127.0.0.1".to_string(), "github.com".to_string()];
        conf.health_check = Some("http:///".to_string());
        let result = conf.validate();
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Url parse error empty host, http:///",
            result.expect_err("").to_string()
        );

        conf.health_check = Some("http://github.com/".to_string());
        let result = conf.validate();
        assert_eq!(true, result.is_ok());
    }

    /// Regression: the validation let through what the upstream is not
    /// built as - an unknown discovery, a refresh interval of zero - and
    /// refused what it is built from. (The building itself is tested in
    /// `pingap-upstream`.)
    #[test]
    fn test_upstream_discovery_is_validated() {
        let conf = |discovery: Option<&str>, addrs: &[&str]| UpstreamConf {
            addrs: addrs.iter().map(|addr| addr.to_string()).collect(),
            discovery: discovery.map(|value| value.to_string()),
            ..Default::default()
        };
        let error = |conf: &UpstreamConf| {
            conf.validate()
                .err()
                .map(|e| e.to_string())
                .unwrap_or_default()
        };

        // A discovery nothing knows was built as static addresses.
        assert_eq!(
            "Invalid error upstream discovery should be one of static, dns, docker, transparent, got \"dsn\"",
            error(&conf(Some("dsn"), &["example.com:80"]))
        );
        // Case is not what tells them apart.
        let upper = conf(Some("DNS"), &["example.com:80"]);
        assert_eq!("", error(&upper));
        assert_eq!("dns", upper.guess_discovery());
        for discovery in ["static", "dns", "docker", "transparent", ""] {
            assert_eq!(
                "",
                error(&conf(Some(discovery), &["127.0.0.1:80"])),
                "{discovery}"
            );
        }

        // A refresh interval of zero never refreshed.
        let mut never = conf(Some("dns"), &["example.com:80"]);
        never.update_frequency = Some(Duration::ZERO);
        assert_eq!(
            "Invalid error upstream update_frequency should be greater than 0 for dns discovery",
            error(&never)
        );
        never.update_frequency = Some(Duration::from_secs(30));
        assert_eq!("", error(&never));
        // Static addresses are not refreshed, whatever it says.
        let mut fixed = conf(None, &["127.0.0.1:80"]);
        fixed.update_frequency = Some(Duration::ZERO);
        assert_eq!("", error(&fixed));

        // A transparent upstream has no addresses to give.
        assert_eq!("", error(&conf(Some("transparent"), &[])));
        assert_eq!(
            "Invalid error upstream addrs is empty",
            error(&conf(None, &[]))
        );

        // An IPv6 address without a port gets the default one like any
        // other host, and a bad address is named.
        for addr in ["[::1]", "::1", "[::1]:8080", "127.0.0.1", "127.0.0.1:80"]
        {
            assert_eq!("", error(&conf(Some("static"), &[addr])), "{addr}");
        }
        let message = error(&conf(Some("static"), &["127.0.0.1:port"]));
        assert_eq!(
            true,
            message.starts_with(
                "Invalid error upstream addr(127.0.0.1:port) is invalid: "
            ),
            "{message}"
        );
    }

    /// The upstream an error is about is named.
    #[test]
    fn test_validate_names_the_upstream() {
        let config = PingapConfig::new(
            b"[upstreams.api]\naddrs = []\n\n[upstreams.web]\naddrs = [\"127.0.0.1:80\"]\n",
            false,
        )
        .unwrap();
        assert_eq!(
            "Invalid error upstream(api): upstream addrs is empty",
            config.validate().unwrap_err().to_string()
        );
    }

    /// A storage that an entry includes cannot be removed. The includes
    /// are there in a config loaded as it is written.
    #[test]
    fn test_storage_in_use_is_not_removable() {
        let config = PingapConfig::new(
            br#"
[servers.web]
addr = "127.0.0.1:80"
includes = ["tls"]

[upstreams.api]
addrs = ["127.0.0.1:9001"]
includes = ["timeouts"]

[storages.timeouts]
category = "config"
value = 'read_timeout = "7s"'

[storages.tls]
category = "config"
value = 'tls_min_version = "tlsv1.2"'

[storages.unused]
category = "config"
value = ''
"#,
            false,
        )
        .unwrap();
        assert_eq!(
            "Invalid error storage(timeouts) is in used by upstream(api)",
            config
                .check_removable(CATEGORY_STORAGE, "timeouts")
                .unwrap_err()
                .to_string()
        );
        assert_eq!(
            "Invalid error storage(tls) is in used by server(web)",
            config
                .check_removable(CATEGORY_STORAGE, "tls")
                .unwrap_err()
                .to_string()
        );
        assert_eq!(
            true,
            config.check_removable(CATEGORY_STORAGE, "unused").is_ok()
        );
    }

    #[test]
    fn test_upstream_max_h2_streams() {
        // Parse from TOML
        let conf: UpstreamConf = toml::from_str(
            r#"
addrs = ["127.0.0.1:8080"]
alpn = "H2"
max_h2_streams = 100
"#,
        )
        .unwrap();
        assert_eq!(Some(100), conf.max_h2_streams);
        assert_eq!(true, conf.validate().is_ok());

        // Round-trip through serialization
        let toml = toml::to_string(&conf).unwrap();
        assert_eq!(true, toml.contains("max_h2_streams = 100"));
        let restored: UpstreamConf = toml::from_str(&toml).unwrap();
        assert_eq!(Some(100), restored.max_h2_streams);

        // Absent by default
        let conf = UpstreamConf {
            addrs: vec!["127.0.0.1:8080".to_string()],
            ..Default::default()
        };
        assert_eq!(None, conf.max_h2_streams);
        assert_eq!(true, conf.validate().is_ok());

        // Zero is rejected
        let conf = UpstreamConf {
            addrs: vec!["127.0.0.1:8080".to_string()],
            max_h2_streams: Some(0),
            ..Default::default()
        };
        let result = conf.validate();
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Invalid error max h2 streams should be greater than 0",
            result.expect_err("").to_string()
        );
    }

    #[test]
    fn test_upstream_ca_and_h2_window() {
        // spellchecker:off
        let pem = r#"-----BEGIN CERTIFICATE-----
MIIEljCCAv6gAwIBAgIQeYUdeFj3gpzhQes3aGaMZTANBgkqhkiG9w0BAQsFADCB
pTEeMBwGA1UEChMVbWtjZXJ0IGRldmVsb3BtZW50IENBMT0wOwYDVQQLDDR4aWVz
aHV6aG91QHhpZXNodXpob3VzLU1hY0Jvb2stQWlyLmxvY2FsICjosKLmoJHmtLIp
MUQwQgYDVQQDDDtta2NlcnQgeGllc2h1emhvdUB4aWVzaHV6aG91cy1NYWNCb29r
LUFpci5sb2NhbCAo6LCi5qCR5rSyKTAeFw0yMzA5MjQxMzA1MjdaFw0yNTEyMjQx
MzA1MjdaMGgxJzAlBgNVBAoTHm1rY2VydCBkZXZlbG9wbWVudCBjZXJ0aWZpY2F0
ZTE9MDsGA1UECww0eGllc2h1emhvdUB4aWVzaHV6aG91cy1NYWNCb29rLUFpci5s
b2NhbCAo6LCi5qCR5rSyKTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
ALuJ8lYEj9uf4iE9hguASq7re87Np+zJc2x/eqr1cR/SgXRStBsjxqI7i3xwMRqX
AuhAnM6ktlGuqidl7D9y6AN/UchqgX8AetslRJTpCcEDfL/q24zy0MqOS0FlYEgh
s4PIjWsSNoglBDeaIdUpN9cM/64IkAAtHndNt2p2vPfjrPeixLjese096SKEnZM/
xBdWF491hx06IyzjtWKqLm9OUmYZB9d/gDGnDsKpqClw8m95opKD4TBHAoE//WvI
m1mZnjNTNR27vVbmnc57d2Lx2Ib2eqJG5zMsP2hPBoqS8CKEwMRFLHAcclNkI67U
kcSEGaWgr15QGHJPN/FtjDsCAwEAAaN+MHwwDgYDVR0PAQH/BAQDAgWgMBMGA1Ud
JQQMMAoGCCsGAQUFBwMBMB8GA1UdIwQYMBaAFJo0y9bYUM/OuenDjsJ1RyHJfL3n
MDQGA1UdEQQtMCuCBm1lLmRldoIJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAA
AAAAAAABMA0GCSqGSIb3DQEBCwUAA4IBgQAlQbow3+4UyQx+E+J0RwmHBltU6i+K
soFfza6FWRfAbTyv+4KEWl2mx51IfHhJHYZvsZqPqGWxm5UvBecskegDExFMNFVm
O5QixydQzHHY2krmBwmDZ6Ao88oW/qw4xmMUhzKAZbsqeQyE/uiUdyI4pfDcduLB
rol31g9OFsgwZrZr0d1ZiezeYEhemnSlh9xRZW3veKx9axgFttzCMmWdpGTCvnav
ZVc3rB+KBMjdCwsS37zmrNm9syCjW1O5a1qphwuMpqSnDHBgKWNpbsgqyZM0oyOc
9Bkja+BV5wFO+4zH5WtestcrNMeoQ83a5lI0m42u/bUEJ/T/5BQBSFidNuvS7Ylw
IZpXa00xvlnm1BOHOfRI4Ehlfa5jmfcdnrGkQLGjiyygQtKcc7rOXGK+mSeyxwhs
sIARwslSQd4q0dbYTPKvvUHxTYiCv78vQBAsE15T2GGS80pAFDBW9vOf3upANvOf
EHjKf0Dweb4ppL4ddgeAKU5V0qn76K2fFaE=
-----END CERTIFICATE-----"#;
        // spellchecker:on

        // A PEM bundle (raw or base64) and the two windows parse, validate
        // and round-trip through TOML.
        let conf: UpstreamConf = toml::from_str(&format!(
            r#"
addrs = ["127.0.0.1:8080"]
ca = "{}"
h2_stream_window_size = "1mib"
h2_connection_window_size = "16mib"
"#,
            base64_encode(pem)
        ))
        .unwrap();
        assert_eq!(true, conf.ca.is_some());
        assert_eq!(Some(ByteSize::mib(1)), conf.h2_stream_window_size);
        assert_eq!(Some(ByteSize::mib(16)), conf.h2_connection_window_size);
        assert_eq!(true, conf.validate().is_ok());
        let toml = toml::to_string(&conf).unwrap();
        assert_eq!(true, toml.contains("h2_stream_window_size = \"1 MiB\""));
        let restored: UpstreamConf = toml::from_str(&toml).unwrap();
        assert_eq!(conf.ca, restored.ca);
        assert_eq!(
            conf.h2_connection_window_size,
            restored.h2_connection_window_size
        );

        // Absent by default: system trust store and pingora's window sizes.
        let conf = UpstreamConf {
            addrs: vec!["127.0.0.1:8080".to_string()],
            ..Default::default()
        };
        assert_eq!(None, conf.ca);
        assert_eq!(None, conf.h2_stream_window_size);
        assert_eq!(None, conf.h2_connection_window_size);
        assert_eq!(true, conf.validate().is_ok());

        // Something that is not a certificate is rejected up front.
        let conf = UpstreamConf {
            addrs: vec!["127.0.0.1:8080".to_string()],
            ca: Some("not a certificate".to_string()),
            ..Default::default()
        };
        let err = conf.validate().unwrap_err().to_string();
        assert_eq!(true, err.contains("upstream ca is invalid"), "{err}");

        // Windows must stay within RFC 9113's 2^31 - 1 limit and be non-zero.
        let conf = UpstreamConf {
            addrs: vec!["127.0.0.1:8080".to_string()],
            h2_stream_window_size: Some(ByteSize::b(0)),
            ..Default::default()
        };
        let err = conf.validate().unwrap_err().to_string();
        assert_eq!(
            true,
            err.contains("h2 stream window size should be between"),
            "{err}"
        );
        let conf = UpstreamConf {
            addrs: vec!["127.0.0.1:8080".to_string()],
            h2_connection_window_size: Some(ByteSize::gib(2)),
            ..Default::default()
        };
        let err = conf.validate().unwrap_err().to_string();
        assert_eq!(
            true,
            err.contains("h2 connection window size should be between"),
            "{err}"
        );
    }

    #[test]
    fn test_upstream_request_header_policy() {
        // The legacy passthrough recipe parses, validates and round-trips.
        let conf: UpstreamConf = toml::from_str(
            r#"
addrs = ["127.0.0.1:8080"]
strip_hop_by_hop = false
strip_connection_nominated = false
reject_malformed_connection_nominations = false
h1_upgrade = "preserve"
"#,
        )
        .unwrap();
        assert_eq!(Some(false), conf.strip_hop_by_hop);
        assert_eq!(Some(false), conf.strip_connection_nominated);
        assert_eq!(Some(false), conf.reject_malformed_connection_nominations);
        assert_eq!(Some("preserve".to_string()), conf.h1_upgrade);
        assert_eq!(true, conf.validate().is_ok());
        let toml = toml::to_string(&conf).unwrap();
        assert_eq!(true, toml.contains("h1_upgrade = \"preserve\""));
        let restored: UpstreamConf = toml::from_str(&toml).unwrap();
        assert_eq!(Some(false), restored.strip_hop_by_hop);

        // Absent by default, so pingora's standards-oriented policy applies.
        let conf = UpstreamConf {
            addrs: vec!["127.0.0.1:8080".to_string()],
            ..Default::default()
        };
        assert_eq!(None, conf.strip_hop_by_hop);
        assert_eq!(None, conf.h1_upgrade);
        assert_eq!(true, conf.validate().is_ok());

        // Case does not matter for the policy name.
        let conf = UpstreamConf {
            addrs: vec!["127.0.0.1:8080".to_string()],
            h1_upgrade: Some("WebSocket_Only".to_string()),
            ..Default::default()
        };
        assert_eq!(true, conf.validate().is_ok());

        // An unknown policy is refused with the accepted names spelled out.
        let conf = UpstreamConf {
            addrs: vec!["127.0.0.1:8080".to_string()],
            h1_upgrade: Some("tcp".to_string()),
            ..Default::default()
        };
        let result = conf.validate();
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Invalid error h1 upgrade should be one of websocket_only, preserve, deny, got \"tcp\"",
            result.expect_err("").to_string()
        );
    }

    #[test]
    fn test_upstream_invalid_ip() {
        let invalid_addrs = vec![
            "0.0.0.0:80",
            "255.255.255.255:80",
            "224.0.0.1:80",
            "169.254.1.1:80",
            "[::]:80",
            "[ff02::1]:80",
            "[fe80::1]:80",
        ];
        for addr in invalid_addrs {
            let conf = UpstreamConf {
                addrs: vec![addr.to_string()],
                discovery: Some("static".to_string()),
                ..Default::default()
            };
            let result = conf.validate();
            assert!(
                result.is_err(),
                "{addr} should be rejected as invalid upstream IP"
            );
            assert!(
                result.unwrap_err().to_string().contains("invalid IP"),
                "{addr} error should mention invalid IP"
            );
        }

        let valid_addrs =
            vec!["127.0.0.1:80", "192.168.1.1:80", "10.0.0.1:8080"];
        for addr in valid_addrs {
            let conf = UpstreamConf {
                addrs: vec![addr.to_string()],
                discovery: Some("static".to_string()),
                ..Default::default()
            };
            let result = conf.validate();
            assert!(
                result.is_ok(),
                "{addr} should be accepted as valid upstream IP"
            );
        }
    }

    #[test]
    fn test_location_conf() {
        let mut conf = LocationConf::default();
        let upstream_names = vec!["upstream1".to_string()];

        conf.upstream = Some("upstream2".to_string());
        let result = conf.validate_with_upstream(Some(&upstream_names));
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Invalid error upstream(upstream2) is not found",
            result.expect_err("").to_string()
        );

        conf.upstream = Some("upstream1".to_string());
        conf.proxy_set_headers = Some(vec!["X-Request-Id".to_string()]);
        let result = conf.validate_with_upstream(Some(&upstream_names));
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Invalid error header X-Request-Id is invalid",
            result.expect_err("").to_string()
        );

        conf.proxy_set_headers = Some(vec!["请求:响应".to_string()]);
        let result = conf.validate_with_upstream(Some(&upstream_names));
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Invalid error header 请求:响应 is invalid: invalid header name: 请求 - invalid HTTP header name",
            result.expect_err("").to_string()
        );

        conf.proxy_set_headers = Some(vec!["X-Request-Id: abcd".to_string()]);
        let result = conf.validate_with_upstream(Some(&upstream_names));
        assert_eq!(true, result.is_ok());

        conf.rewrite = Some(r"foo(bar".to_string());
        let result = conf.validate_with_upstream(Some(&upstream_names));
        assert_eq!(true, result.is_err());
        assert_eq!(
            true,
            result
                .expect_err("")
                .to_string()
                .starts_with("Regex error regex parse error")
        );

        conf.rewrite = Some(r"^/api /".to_string());
        let result = conf.validate_with_upstream(Some(&upstream_names));
        assert_eq!(true, result.is_ok());
    }

    #[test]
    fn test_location_get_wegiht() {
        let mut conf = LocationConf {
            weight: Some(2048),
            ..Default::default()
        };

        assert_eq!(2048, conf.get_weight());

        conf.weight = None;
        conf.path = Some("=/api".to_string());
        assert_eq!(1029, conf.get_weight());

        conf.path = Some("~/api".to_string());
        assert_eq!(261, conf.get_weight());

        conf.path = Some("/api".to_string());
        assert_eq!(516, conf.get_weight());

        conf.path = None;
        conf.host = Some("github.com".to_string());
        assert_eq!(128, conf.get_weight());

        conf.host = Some("~github.com".to_string());
        assert_eq!(11, conf.get_weight());

        conf.host = Some("".to_string());
        assert_eq!(0, conf.get_weight());
    }

    #[test]
    fn test_server_conf() {
        let mut conf = ServerConf::default();
        let location_names = vec!["lo".to_string()];

        let result = conf.validate_with_locations(&location_names);
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Io error invalid socket address, ",
            result.expect_err("").to_string()
        );

        conf.addr = "127.0.0.1:3001".to_string();
        conf.locations = Some(vec!["lo1".to_string()]);
        let result = conf.validate_with_locations(&location_names);
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Invalid error location(lo1) is not found",
            result.expect_err("").to_string()
        );

        conf.locations = Some(vec!["lo".to_string()]);
        let result = conf.validate_with_locations(&location_names);
        assert_eq!(true, result.is_ok());
    }

    /// Regression: the upstream a `traffic_splitting` plugin names was not
    /// checked, and could be removed while the plugin still used it.
    #[test]
    fn test_plugin_upstream_reference() {
        let new_config = |upstream: &str| {
            PingapConfig::new(
                format!(
                    r#"
[upstreams.main]
addrs = ["127.0.0.1:5000"]

[upstreams.canary]
addrs = ["127.0.0.1:5001"]

[plugins.split]
category = "traffic_splitting"
upstream = "{upstream}"
weight = 10

[plugins.other]
category = "mock"
upstream = "not-a-reference"
"#
                )
                .as_bytes(),
                false,
            )
            .unwrap()
        };
        assert_eq!(
            "Invalid error plugin(split): upstream(canery) is not found",
            new_config("canery").validate().unwrap_err().to_string()
        );
        let config = new_config("canary");
        config.validate().unwrap();
        assert_eq!(
            "Invalid error upstream(canary) is in used by plugin(split)",
            config
                .check_removable(CATEGORY_UPSTREAM, "canary")
                .unwrap_err()
                .to_string()
        );
        config.check_removable(CATEGORY_UPSTREAM, "main").unwrap();
    }

    /// Regression: an `access_log` without a placeholder was taken for a
    /// format and printed as it is, once per request.
    #[test]
    fn test_access_log_needs_a_placeholder() {
        let validate = |access_log: &str| {
            ServerConf {
                addr: "127.0.0.1:3001".to_string(),
                access_log: Some(access_log.to_string()),
                ..Default::default()
            }
            .validate()
        };
        for access_log in [
            "",
            "combined",
            "json",
            "{method} {uri} {status}",
            "/var/log/pingap/access.log combined",
            "/var/log/pingap/access.log {method} {uri}",
            "{\"uri\":{uri}}",
        ] {
            assert_eq!(true, validate(access_log).is_ok(), "{access_log}");
        }
        for access_log in [
            "stdout",
            "/var/log/pingap/access.log",
            "combinedd",
            "stdout combinedd",
        ] {
            let err = validate(access_log).unwrap_err().to_string();
            assert_eq!(
                true,
                err.contains("logs nothing of the request"),
                "{access_log}: {err}"
            );
        }
    }

    #[test]
    fn test_server_ja4_conf() {
        let conf: ServerConf = toml::from_str(
            "addr = \"127.0.0.1:3001\"\nglobal_certificates = true\nja4 = true\n",
        )
        .unwrap();
        assert_eq!(Some(true), conf.ja4);
        assert_eq!(true, conf.validate().is_ok());

        let conf: ServerConf =
            toml::from_str("addr = \"127.0.0.1:3001\"\nja4 = true\n").unwrap();
        assert_eq!(
            "Invalid error ja4 needs a TLS listener (global_certificates = true)",
            conf.validate().unwrap_err().to_string()
        );
    }

    #[test]
    fn test_server_h2_conf() {
        // All five knobs parse and round-trip.
        let conf: ServerConf = toml::from_str(
            r#"
addr = "127.0.0.1:3001"
h2_max_concurrent_streams = 256
h2_max_header_list_size = "128kb"
h2_initial_window_size = "1mb"
h2_initial_connection_window_size = "4mb"
h2_idle_timeout = "2m"
h1_pipelining = true
"#,
        )
        .unwrap();
        assert_eq!(Some(256), conf.h2_max_concurrent_streams);
        assert_eq!(Some(ByteSize::kb(128)), conf.h2_max_header_list_size);
        assert_eq!(Some(ByteSize::mb(1)), conf.h2_initial_window_size);
        assert_eq!(
            Some(ByteSize::mb(4)),
            conf.h2_initial_connection_window_size
        );
        assert_eq!(Some(Duration::from_secs(120)), conf.h2_idle_timeout);
        assert_eq!(Some(true), conf.h1_pipelining);
        assert_eq!(true, conf.validate().is_ok());
        let restored: ServerConf =
            toml::from_str(&toml::to_string(&conf).unwrap()).unwrap();
        assert_eq!(Some(256), restored.h2_max_concurrent_streams);
        assert_eq!(Some(ByteSize::kb(128)), restored.h2_max_header_list_size);

        // Unset is the default and validates.
        let base = ServerConf {
            addr: "127.0.0.1:3001".to_string(),
            ..Default::default()
        };
        assert_eq!(None, base.h2_max_concurrent_streams);
        assert_eq!(true, base.validate().is_ok());

        // Out-of-range values are refused up front.
        let cases: [(ServerConf, &str); 3] = [
            (
                ServerConf {
                    h2_max_concurrent_streams: Some(0),
                    ..base.clone()
                },
                "Invalid error h2 max concurrent streams should be greater than 0",
            ),
            (
                ServerConf {
                    h2_max_header_list_size: Some(ByteSize::b(0)),
                    ..base.clone()
                },
                "Invalid error h2 max header list size should be between 1 and 4GiB - 1",
            ),
            (
                ServerConf {
                    h2_initial_window_size: Some(ByteSize::gib(2)),
                    ..base.clone()
                },
                "Invalid error h2 initial window size should be between 1 and 2GiB - 1",
            ),
        ];
        for (conf, message) in cases {
            let result = conf.validate();
            assert_eq!(true, result.is_err());
            assert_eq!(message, result.expect_err("").to_string());
        }
    }

    #[test]
    fn test_basic_daemon_conf() {
        let conf: BasicConf = toml::from_str(
            r#"
working_directory = "/var/lib/pingap"
restart_ready_timeout = "2m"
"#,
        )
        .unwrap();
        assert_eq!(Some("/var/lib/pingap".to_string()), conf.working_directory);
        assert_eq!(Some(Duration::from_secs(120)), conf.restart_ready_timeout);
        assert_eq!(true, conf.validate().is_ok());

        // Unset everywhere is the default and validates.
        assert_eq!(true, BasicConf::default().validate().is_ok());

        // A sub-second wait is refused up front.
        let conf = BasicConf {
            restart_ready_timeout: Some(Duration::from_millis(500)),
            ..Default::default()
        };
        let result = conf.validate();
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Invalid error restart ready timeout should be at least 1s",
            result.expect_err("").to_string()
        );
    }

    /// Regression: a size was written rounded to one decimal of a binary
    /// unit, so the first save of an entry changed it.
    #[test]
    fn test_byte_size_is_saved_exactly() {
        for (text, bytes) in [
            ("10 MB", 10_000_000),
            ("1 MB", 1_000_000),
            ("100 KB", 100_000),
            ("1 MiB", 1 << 20),
            ("64 KiB", 64 << 10),
            ("2 GiB", 2 << 30),
            ("3 GB", 3_000_000_000),
            ("1000 KiB", 1_024_000),
            ("1.5 KB", 1_500),
            ("1.234 KB", 1_234),
            ("0.001 KB", 1),
            ("12345.678 KB", 12_345_678),
            ("0 KB", 0),
        ] {
            let size = ByteSize(bytes);
            assert_eq!(text, super::format_byte_size(size), "{bytes}");
            assert_eq!(size, text.parse::<ByteSize>().unwrap(), "{text}");
        }

        // Through a config entry and back, as the admin saves one.
        let conf: LocationConf =
            toml::from_str("client_max_body_size = \"10MB\"").unwrap();
        let saved = toml::to_string(&conf).unwrap();
        assert_eq!(
            true,
            saved.contains("client_max_body_size = \"10 MB\""),
            "{saved}"
        );
        let restored: LocationConf = toml::from_str(&saved).unwrap();
        assert_eq!(Some(ByteSize(10_000_000)), restored.client_max_body_size);
        // What an earlier version wrote still loads.
        let conf: LocationConf =
            toml::from_str("client_max_body_size = \"9.5 MiB\"").unwrap();
        assert_eq!(Some(ByteSize(9_961_472)), conf.client_max_body_size);
        // Unset stays unset.
        assert_eq!(
            false,
            toml::to_string(&LocationConf::default())
                .unwrap()
                .contains("client_max_body_size")
        );
    }

    /// Values that used to pass the check and only fail, or silently do
    /// nothing, in the running process.
    #[test]
    fn test_basic_values_that_fail_at_runtime() {
        let invalid = |conf: &str| {
            toml::from_str::<BasicConf>(conf)
                .unwrap()
                .validate()
                .unwrap_err()
                .to_string()
        };
        // A timer with a period of zero panics when it is created.
        for value in ["0s", "500ms"] {
            assert_eq!(
                "Invalid error auto restart check interval should be at least 1s",
                invalid(&format!("auto_restart_check_interval = \"{value}\""))
            );
        }
        // No accept loop: the listener is bound and never answers.
        assert_eq!(
            "Invalid error listener tasks per fd should be greater than 0",
            invalid("listener_tasks_per_fd = 0")
        );
        assert_eq!(
            "Invalid error log compress algorithm brotli is invalid, expected gzip or zstd",
            invalid("log_compress_algorithm = \"brotli\"")
        );
        assert_eq!(
            "Invalid error log compress time point hour should be 0 to 23",
            invalid("log_compress_time_point_hour = 24")
        );

        for conf in [
            "auto_restart_check_interval = \"1s\"",
            "listener_tasks_per_fd = 1",
            "log_compress_algorithm = \"gzip\"",
            "log_compress_algorithm = \"zstd\"",
            "log_compress_time_point_hour = 23",
            "log_compress_time_point_hour = 0",
        ] {
            let result = toml::from_str::<BasicConf>(conf).unwrap().validate();
            assert_eq!(true, result.is_ok(), "{conf}: {result:?}");
        }
    }

    /// The kernel takes the keepalive timings in whole seconds and refuses
    /// a zero, so a value under one second failed every connection.
    #[test]
    fn test_tcp_keepalive_values() {
        let upstream = |conf: &str| {
            toml::from_str::<UpstreamConf>(&format!(
                "addrs = [\"127.0.0.1:8080\"]\n{conf}"
            ))
            .unwrap()
            .validate()
            .map_err(|e| e.to_string())
        };
        let server = |conf: &str| {
            toml::from_str::<ServerConf>(&format!(
                "addr = \"127.0.0.1:8080\"\n{conf}"
            ))
            .unwrap()
            .validate()
            .map_err(|e| e.to_string())
        };
        for (conf, expected) in [
            ("tcp_idle = \"500ms\"", "tcp idle should be at least 1s"),
            ("tcp_idle = \"0s\"", "tcp idle should be at least 1s"),
            (
                "tcp_interval = \"999ms\"",
                "tcp interval should be at least 1s",
            ),
            (
                "tcp_probe_count = 0",
                "tcp probe count should be greater than 0",
            ),
        ] {
            let expected = Err(format!("Invalid error {expected}"));
            assert_eq!(expected, upstream(conf), "upstream: {conf}");
            assert_eq!(expected, server(conf), "server: {conf}");
        }
        for conf in [
            "tcp_idle = \"1s\"\ntcp_interval = \"1s\"\ntcp_probe_count = 1",
            // on its own: the other three take the kernel's defaults
            "tcp_user_timeout = \"30s\"",
            "tcp_idle = \"2m\"",
        ] {
            assert_eq!(Ok(()), upstream(conf), "upstream: {conf}");
            assert_eq!(Ok(()), server(conf), "server: {conf}");
        }
    }

    #[test]
    fn test_basic_max_blocking_threads() {
        let conf: BasicConf =
            toml::from_str("max_blocking_threads = 64").unwrap();
        assert_eq!(Some(64), conf.max_blocking_threads);
        assert_eq!(true, conf.validate().is_ok());

        // Unset keeps tokio's default; zero is refused up front.
        let conf = BasicConf::default();
        assert_eq!(None, conf.max_blocking_threads);
        assert_eq!(true, conf.validate().is_ok());
        let conf = BasicConf {
            max_blocking_threads: Some(0),
            ..Default::default()
        };
        let err = conf.validate().unwrap_err().to_string();
        assert_eq!(true, err.contains("max blocking threads"), "{err}");
    }

    #[test]
    fn test_basic_tls_offload_conf() {
        let conf: BasicConf = toml::from_str(
            r#"
downstream_tls_offload_threadpools = 2
downstream_tls_offload_thread_per_pool = 4
"#,
        )
        .unwrap();
        assert_eq!(Some(2), conf.downstream_tls_offload_threadpools);
        assert_eq!(Some(4), conf.downstream_tls_offload_thread_per_pool);
        assert_eq!(true, conf.validate().is_ok());

        // Half a configuration would be a silent no-op in pingora.
        let conf = BasicConf {
            downstream_tls_offload_threadpools: Some(2),
            ..Default::default()
        };
        assert_eq!(
            "Invalid error downstream tls offload threadpools and thread per pool should be set together",
            conf.validate().expect_err("").to_string()
        );
        // So would a zero.
        let conf = BasicConf {
            downstream_tls_offload_threadpools: Some(2),
            downstream_tls_offload_thread_per_pool: Some(0),
            ..Default::default()
        };
        assert_eq!(
            "Invalid error downstream tls offload threadpools and thread per pool should be greater than 0",
            conf.validate().expect_err("").to_string()
        );

        // The upstream pair follows the same rule.
        let conf: BasicConf = toml::from_str(
            r#"
upstream_connect_offload_threadpools = 1
upstream_connect_offload_thread_per_pool = 8
"#,
        )
        .unwrap();
        assert_eq!(Some(1), conf.upstream_connect_offload_threadpools);
        assert_eq!(Some(8), conf.upstream_connect_offload_thread_per_pool);
        assert_eq!(true, conf.validate().is_ok());
        let conf = BasicConf {
            upstream_connect_offload_thread_per_pool: Some(8),
            ..Default::default()
        };
        assert_eq!(
            "Invalid error upstream connect offload threadpools and thread per pool should be set together",
            conf.validate().expect_err("").to_string()
        );
    }

    #[test]
    fn test_certificate_conf() {
        // spellchecker:off
        let pem = r#"-----BEGIN CERTIFICATE-----
MIIEljCCAv6gAwIBAgIQeYUdeFj3gpzhQes3aGaMZTANBgkqhkiG9w0BAQsFADCB
pTEeMBwGA1UEChMVbWtjZXJ0IGRldmVsb3BtZW50IENBMT0wOwYDVQQLDDR4aWVz
aHV6aG91QHhpZXNodXpob3VzLU1hY0Jvb2stQWlyLmxvY2FsICjosKLmoJHmtLIp
MUQwQgYDVQQDDDtta2NlcnQgeGllc2h1emhvdUB4aWVzaHV6aG91cy1NYWNCb29r
LUFpci5sb2NhbCAo6LCi5qCR5rSyKTAeFw0yMzA5MjQxMzA1MjdaFw0yNTEyMjQx
MzA1MjdaMGgxJzAlBgNVBAoTHm1rY2VydCBkZXZlbG9wbWVudCBjZXJ0aWZpY2F0
ZTE9MDsGA1UECww0eGllc2h1emhvdUB4aWVzaHV6aG91cy1NYWNCb29rLUFpci5s
b2NhbCAo6LCi5qCR5rSyKTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
ALuJ8lYEj9uf4iE9hguASq7re87Np+zJc2x/eqr1cR/SgXRStBsjxqI7i3xwMRqX
AuhAnM6ktlGuqidl7D9y6AN/UchqgX8AetslRJTpCcEDfL/q24zy0MqOS0FlYEgh
s4PIjWsSNoglBDeaIdUpN9cM/64IkAAtHndNt2p2vPfjrPeixLjese096SKEnZM/
xBdWF491hx06IyzjtWKqLm9OUmYZB9d/gDGnDsKpqClw8m95opKD4TBHAoE//WvI
m1mZnjNTNR27vVbmnc57d2Lx2Ib2eqJG5zMsP2hPBoqS8CKEwMRFLHAcclNkI67U
kcSEGaWgr15QGHJPN/FtjDsCAwEAAaN+MHwwDgYDVR0PAQH/BAQDAgWgMBMGA1Ud
JQQMMAoGCCsGAQUFBwMBMB8GA1UdIwQYMBaAFJo0y9bYUM/OuenDjsJ1RyHJfL3n
MDQGA1UdEQQtMCuCBm1lLmRldoIJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAA
AAAAAAABMA0GCSqGSIb3DQEBCwUAA4IBgQAlQbow3+4UyQx+E+J0RwmHBltU6i+K
soFfza6FWRfAbTyv+4KEWl2mx51IfHhJHYZvsZqPqGWxm5UvBecskegDExFMNFVm
O5QixydQzHHY2krmBwmDZ6Ao88oW/qw4xmMUhzKAZbsqeQyE/uiUdyI4pfDcduLB
rol31g9OFsgwZrZr0d1ZiezeYEhemnSlh9xRZW3veKx9axgFttzCMmWdpGTCvnav
ZVc3rB+KBMjdCwsS37zmrNm9syCjW1O5a1qphwuMpqSnDHBgKWNpbsgqyZM0oyOc
9Bkja+BV5wFO+4zH5WtestcrNMeoQ83a5lI0m42u/bUEJ/T/5BQBSFidNuvS7Ylw
IZpXa00xvlnm1BOHOfRI4Ehlfa5jmfcdnrGkQLGjiyygQtKcc7rOXGK+mSeyxwhs
sIARwslSQd4q0dbYTPKvvUHxTYiCv78vQBAsE15T2GGS80pAFDBW9vOf3upANvOf
EHjKf0Dweb4ppL4ddgeAKU5V0qn76K2fFaE=
-----END CERTIFICATE-----"#;
        let key = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7ifJWBI/bn+Ih
PYYLgEqu63vOzafsyXNsf3qq9XEf0oF0UrQbI8aiO4t8cDEalwLoQJzOpLZRrqon
Zew/cugDf1HIaoF/AHrbJUSU6QnBA3y/6tuM8tDKjktBZWBIIbODyI1rEjaIJQQ3
miHVKTfXDP+uCJAALR53Tbdqdrz346z3osS43rHtPekihJ2TP8QXVhePdYcdOiMs
47Viqi5vTlJmGQfXf4Axpw7CqagpcPJveaKSg+EwRwKBP/1ryJtZmZ4zUzUdu71W
5p3Oe3di8diG9nqiRuczLD9oTwaKkvAihMDERSxwHHJTZCOu1JHEhBmloK9eUBhy
TzfxbYw7AgMBAAECggEALjed0FMJfO+XE+gMm9L/FMKV3W5TXwh6eJemDHG2ckg3
fQpQtouHjT2tb3par5ndro0V19tBzzmDV3hH048m3I3JAuI0ja75l/5EO4p+y+Fn
IgjoGIFSsUiGBVTNeJlNm0GWkHeJlt3Af09t3RFuYIIklKgpjNGRu4ccl5ExmslF
WHv7/1dwzeJCi8iOY2gJZz6N7qHD95VkgVyDj/EtLltONAtIGVdorgq70CYmtwSM
9XgXszqOTtSJxle+UBmeQTL4ZkUR0W+h6JSpcTn0P9c3fiNDrHSKFZbbpAhO/wHd
Ab4IK8IksVyg+tem3m5W9QiXn3WbgcvjJTi83Y3syQKBgQD5IsaSbqwEG3ruttQe
yfMeq9NUGVfmj7qkj2JiF4niqXwTpvoaSq/5gM/p7lAtSMzhCKtlekP8VLuwx8ih
n4hJAr8pGfyu/9IUghXsvP2DXsCKyypbhzY/F2m4WNIjtyLmed62Nt1PwWWUlo9Q
igHI6pieT45vJTBICsRyqC/a/wKBgQDAtLXUsCABQDTPHdy/M/dHZA/QQ/xU8NOs
ul5UMJCkSfFNk7b2etQG/iLlMSNup3bY3OPvaCGwwEy/gZ31tTSymgooXQMFxJ7G
1S/DF45yKD6xJEmAUhwz/Hzor1cM95g78UpZFCEVMnEmkBNb9pmrXRLDuWb0vLE6
B6YgiEP6xQKBgBOXuooVjg2co6RWWIQ7WZVV6f65J4KIVyNN62zPcRaUQZ/CB/U9
Xm1+xdsd1Mxa51HjPqdyYBpeB4y1iX+8bhlfz+zJkGeq0riuKk895aoJL5c6txAP
qCJ6EuReh9grNOFvQCaQVgNJsFVpKcgpsk48tNfuZcMz54Ii5qQlue29AoGAA2Sr
Nv2K8rqws1zxQCSoHAe1B5PK46wB7i6x7oWUZnAu4ZDSTfDHvv/GmYaN+yrTuunY
0aRhw3z/XPfpUiRIs0RnHWLV5MobiaDDYIoPpg7zW6cp7CqF+JxfjrFXtRC/C38q
MftawcbLm0Q6MwpallvjMrMXDwQrkrwDvtrnZ4kCgYEA0oSvmSK5ADD0nqYFdaro
K+hM90AVD1xmU7mxy3EDPwzjK1wZTj7u0fvcAtZJztIfL+lmVpkvK8KDLQ9wCWE7
SGToOzVHYX7VazxioA9nhNne9kaixvnIUg3iowAz07J7o6EU8tfYsnHxsvjlIkBU
ai02RHnemmqJaNepfmCdyec=
-----END PRIVATE KEY-----"#;
        // spellchecker:on
        let conf = CertificateConf {
            tls_cert: Some(pem.to_string()),
            tls_key: Some(key.to_string()),
            ..Default::default()
        };
        let result = conf.validate();
        assert_eq!(true, result.is_ok());

        // spellchecker:off
        assert_eq!("15ba921aee80abc3", conf.hash_key());
        // spellchecker:on
    }
    #[test]
    fn test_includes() {
        let base = r#"
[storages.timeouts]
category = "config"
value = """
connection_timeout = "5s"
read_timeout = "30s"
"""

[storages.longer]
category = "config"
value = """
read_timeout = "60s"
"""

[storages.broken]
category = "config"
value = "read_timeout = "

[upstreams.api]
addrs = ["127.0.0.1:8080"]
read_timeout = "1s"
"#;
        let load = |includes: &str, replace: bool| {
            PingapConfig::new(
                format!("{base}includes = {includes}").as_bytes(),
                replace,
            )
        };

        // A fragment overrides the entry, a later fragment an earlier one.
        let config = load(r#"["timeouts", "longer"]"#, true).unwrap();
        let api = &config.upstreams["api"];
        assert_eq!(Some(Duration::from_secs(5)), api.connection_timeout);
        assert_eq!(Some(Duration::from_secs(60)), api.read_timeout);
        assert_eq!(None, api.includes);

        // Left as written when includes are not expanded.
        let config = load(r#"["timeouts", "longer"]"#, false).unwrap();
        let api = &config.upstreams["api"];
        assert_eq!(None, api.connection_timeout);
        assert_eq!(Some(Duration::from_secs(1)), api.read_timeout);
        assert_eq!(
            Some(vec!["timeouts".to_string(), "longer".to_string()]),
            api.includes
        );

        // A broken include is an error, not a silently missing setting.
        let err =
            |includes: &str| load(includes, true).unwrap_err().to_string();
        assert_eq!(
            "Invalid error upstream(api): include(missing) is not found",
            err(r#"["missing"]"#)
        );
        assert!(err(r#"["broken"]"#).starts_with(
            "Invalid error upstream(api): include(broken) is not valid toml: "
        ));
        assert_eq!(
            "Invalid error upstream(api): includes must be an array",
            err(r#""timeouts""#)
        );
        assert_eq!(
            "Invalid error upstream(api): includes must be storage names",
            err("[1]")
        );
    }
}
