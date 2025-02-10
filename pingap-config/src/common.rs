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
// use crate::plugin::parse_plugins;
// use crate::proxy::Parser;
use arc_swap::ArcSwap;
use bytesize::ByteSize;
use http::{HeaderName, HeaderValue};
use once_cell::sync::Lazy;
use pingap_discovery::{is_static_discovery, DNS_DISCOVERY};
use regex::Regex;
use serde::{Deserialize, Serialize, Serializer};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::Cursor;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Duration;
use std::{collections::HashMap, str::FromStr};
use strum::EnumString;
use toml::Table;
use toml::{map::Map, Value};
use url::Url;

pub const CATEGORY_BASIC: &str = "basic";
pub const CATEGORY_SERVER: &str = "server";
pub const CATEGORY_LOCATION: &str = "location";
pub const CATEGORY_UPSTREAM: &str = "upstream";
pub const CATEGORY_PLUGIN: &str = "plugin";
pub const CATEGORY_CERTIFICATE: &str = "certificate";
pub const CATEGORY_STORAGE: &str = "storage";

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
                "invalid plugin category: {}",
                value
            ))
        })
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
    /// Certificate chain in PEM format or base64 encoded
    pub tls_chain: Option<String>,
    /// Whether this is the default certificate for the server
    pub is_default: Option<bool>,
    /// Whether this certificate is a Certificate Authority (CA)
    pub is_ca: Option<bool>,
    /// ACME configuration for automated certificate management
    pub acme: Option<String>,
    /// Optional description/notes about this certificate
    pub remark: Option<String>,
}

/// Validates a certificate in PEM format or base64 encoded
fn validate_cert(value: &str) -> Result<()> {
    // Convert from PEM/base64 to binary
    let buf = pingap_util::convert_pem(value).map_err(|e| Error::Invalid {
        message: e.to_string(),
    })?;
    let mut cursor = Cursor::new(&buf);

    // Parse all certificates in the buffer
    let certs = rustls_pemfile::certs(&mut cursor)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::Invalid {
            message: format!("Failed to parse certificate: {}", e),
        })?;

    // Ensure at least one valid certificate was found
    if certs.is_empty() {
        return Err(Error::Invalid {
            message: "No valid certificates found in input".to_string(),
        });
    }

    Ok(())
}

impl CertificateConf {
    /// Generates a unique hash key for this certificate configuration
    /// Used for caching and comparison purposes
    pub fn hash_key(&self) -> String {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }

    /// Validates the certificate configuration:
    /// - Validates private key can be parsed if present
    /// - Validates certificate can be parsed if present  
    /// - Validates certificate chain can be parsed if present
    pub fn validate(&self) -> Result<()> {
        // Validate private key
        let tls_key = self.tls_key.clone().unwrap_or_default();
        if !tls_key.is_empty() {
            let buf = pingap_util::convert_pem(&tls_key).map_err(|e| {
                Error::Invalid {
                    message: e.to_string(),
                }
            })?;
            let mut key = Cursor::new(buf);
            let _ = rustls_pemfile::private_key(&mut key).map_err(|e| {
                Error::Invalid {
                    message: e.to_string(),
                }
            })?;
        }

        // Validate main certificate
        let tls_cert = self.tls_cert.clone().unwrap_or_default();
        if !tls_cert.is_empty() {
            validate_cert(&tls_cert)?;
        }

        // Validate certificate chain
        let tls_chain = self.tls_chain.clone().unwrap_or_default();
        if !tls_chain.is_empty() {
            validate_cert(&tls_chain)?;
        }
        Ok(())
    }
}

/// Configuration for an upstream service that handles proxied requests
#[derive(Debug, Default, Deserialize, Clone, Serialize, Hash)]
pub struct UpstreamConf {
    /// List of upstream server addresses in format "host:port" or "host:port weight"
    pub addrs: Vec<String>,

    /// Service discovery mechanism to use (e.g. "dns", "static")
    pub discovery: Option<String>,

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

    /// Application Layer Protocol Negotiation for TLS
    pub alpn: Option<String>,

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

    /// Number of TCP keepalive probes before connection is dropped
    pub tcp_probe_count: Option<usize>,

    /// TCP receive buffer size
    pub tcp_recv_buf: Option<ByteSize>,

    /// Enable TCP Fast Open
    pub tcp_fast_open: Option<bool>,

    /// List of included configuration files
    pub includes: Option<Vec<String>>,

    /// Optional description/notes about this upstream
    pub remark: Option<String>,
}

impl UpstreamConf {
    /// Generates a unique hash key for this upstream configuration
    /// Used for caching and comparison purposes
    pub fn hash_key(&self) -> String {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }

    /// Determines the appropriate service discovery mechanism:
    /// - Returns configured discovery if set
    /// - Returns DNS discovery if any address contains a hostname
    /// - Returns empty string (static discovery) otherwise
    pub fn guess_discovery(&self) -> String {
        // Return explicitly configured discovery if set
        if let Some(discovery) = &self.discovery {
            return discovery.clone();
        }

        // Check if any address contains a hostname (non-IP)
        let has_hostname = self.addrs.iter().any(|addr| {
            // Extract host portion before port
            let host =
                addr.split_once(':').map_or(addr.as_str(), |(host, _)| host);

            // If host can't be parsed as IP, it's a hostname
            host.parse::<std::net::IpAddr>().is_err()
        });

        if has_hostname {
            DNS_DISCOVERY.to_string()
        } else {
            String::new()
        }
    }

    /// Validates the upstream configuration:
    /// 1. The address list can't be empty
    /// 2. For static discovery, addresses must be valid socket addresses
    /// 3. Health check URL must be valid if specified
    /// 4. TCP probe count must not exceed maximum (16)
    pub fn validate(&self, name: &str) -> Result<()> {
        // Validate address list
        self.validate_addresses(name)?;

        // Validate health check URL if specified
        self.validate_health_check()?;

        // Validate TCP probe count
        self.validate_tcp_probe_count()?;

        Ok(())
    }

    fn validate_addresses(&self, name: &str) -> Result<()> {
        if self.addrs.is_empty() {
            return Err(Error::Invalid {
                message: "upstream addrs is empty".to_string(),
            });
        }

        // Only validate addresses for static discovery
        if !is_static_discovery(&self.guess_discovery()) {
            return Ok(());
        }

        for addr in &self.addrs {
            let parts: Vec<_> = addr.split_whitespace().collect();
            let host_port = parts[0].to_string();

            // Add default port 80 if not specified
            let addr_to_check = if !host_port.contains(':') {
                format!("{host_port}:80")
            } else {
                host_port
            };

            // Validate socket address
            addr_to_check.to_socket_addrs().map_err(|e| Error::Io {
                source: e,
                file: format!("{}(upstream:{name})", parts[0]),
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

        if let Some(count) = self.tcp_probe_count {
            if count > MAX_TCP_PROBE_COUNT {
                return Err(Error::Invalid {
                    message: format!(
                        "tcp probe count should be <= {MAX_TCP_PROBE_COUNT}"
                    ),
                });
            }
        }

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
    pub client_max_body_size: Option<ByteSize>,

    /// Maximum number of concurrent requests being processed
    pub max_processing: Option<i32>,

    /// List of included configuration files
    pub includes: Option<Vec<String>>,

    /// Whether to enable gRPC-Web protocol support
    pub grpc_web: Option<bool>,

    /// Whether to enable reverse proxy headers
    pub enable_reverse_proxy_headers: Option<bool>,

    /// Optional description/notes about this location
    pub remark: Option<String>,
}

impl LocationConf {
    /// Generates a unique hash key for this location configuration
    /// Used for caching and comparison purposes
    pub fn hash_key(&self) -> String {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }

    /// Validates the location configuration:
    /// 1. Validates that headers are properly formatted as "name: value"
    /// 2. Validates header names and values are valid HTTP headers
    /// 3. Validates upstream exists if specified
    /// 4. Validates rewrite pattern is valid regex if specified
    fn validate(&self, name: &str, upstream_names: &[String]) -> Result<()> {
        // Helper function to validate HTTP headers
        let validate = |headers: &Option<Vec<String>>| -> Result<()> {
            if let Some(headers) = headers {
                for header in headers.iter() {
                    // Split header into name and value parts
                    let arr = header
                        .split_once(':')
                        .map(|(k, v)| (k.trim(), v.trim()));
                    if arr.is_none() {
                        return Err(Error::Invalid {
                            message: format!(
                                "header {header} is invalid(location:{name})"
                            ),
                        });
                    }
                    let (header_name, header_value) = arr.unwrap();

                    // Validate header name is valid
                    HeaderName::from_bytes(header_name.as_bytes()).map_err(|err| Error::Invalid {
                        message: format!("header name({header_name}) is invalid, error: {err}(location:{name})"),
                    })?;

                    // Validate header value is valid
                    HeaderValue::from_str(header_value).map_err(|err| Error::Invalid {
                        message: format!("header value({header_value}) is invalid, error: {err}(location:{name})"),
                    })?;
                }
            }
            Ok(())
        };

        // Validate upstream exists if specified
        let upstream = self.upstream.clone().unwrap_or_default();
        if !upstream.is_empty() && !upstream_names.contains(&upstream) {
            return Err(Error::Invalid {
                message: format!(
                    "upstream({upstream}) is not found(location:{name})"
                ),
            });
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
        let path = self.path.clone().unwrap_or("".to_string());

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
        if !self.host.clone().unwrap_or_default().is_empty() {
            weight += 128;
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

    /// OpenSSL cipher list string for TLS connections
    pub tls_cipher_list: Option<String>,

    /// TLS 1.3 ciphersuites string
    pub tls_ciphersuites: Option<String>,

    /// Minimum TLS version to accept (e.g. "TLSv1.2")
    pub tls_min_version: Option<String>,

    /// Maximum TLS version to use (e.g. "TLSv1.3")
    pub tls_max_version: Option<String>,

    /// Whether to use global certificates instead of per-server certs
    pub global_certificates: Option<bool>,

    /// Whether to enable HTTP/2 protocol support
    pub enabled_h2: Option<bool>,

    /// TCP keepalive idle timeout
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub tcp_idle: Option<Duration>,

    /// TCP keepalive probe interval
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub tcp_interval: Option<Duration>,

    /// Number of TCP keepalive probes before connection is dropped
    pub tcp_probe_count: Option<usize>,

    /// TCP Fast Open queue length (0 to disable)
    pub tcp_fastopen: Option<usize>,

    /// Path to expose Prometheus metrics on
    pub prometheus_metrics: Option<String>,

    /// OpenTelemetry exporter configuration
    pub otlp_exporter: Option<String>,

    /// List of configuration files to include
    pub includes: Option<Vec<String>>,

    /// List of modules to enable for this server
    pub modules: Option<Vec<String>>,

    /// Optional description/notes about this server
    pub remark: Option<String>,
}

impl ServerConf {
    /// Validate the options of server config.
    /// 1. Parse listen addr to socket addr.
    /// 2. Check the locations are exists.
    /// 3. Parse access log layout success.
    fn validate(&self, name: &str, location_names: &[String]) -> Result<()> {
        for addr in self.addr.split(',') {
            let _ = addr.to_socket_addrs().map_err(|e| Error::Io {
                source: e,
                file: self.addr.clone(),
            })?;
        }
        if let Some(locations) = &self.locations {
            for item in locations {
                if !location_names.contains(item) {
                    return Err(Error::Invalid {
                        message: format!(
                            "location({item}) is not found(server:{name})"
                        ),
                    });
                }
            }
        }
        let access_log = self.access_log.clone().unwrap_or_default();
        if !access_log.is_empty() {
            // TODO: validate access log format
            // let logger = Parser::from(access_log.as_str());
            // if logger.tags.is_empty() {
            //     return Err(Error::Invalid {
            //         message: "access log format is invalid".to_string(),
            //     });
            // }
        }

        Ok(())
    }
}

/// Basic configuration options for the application
#[derive(Debug, Default, Deserialize, Clone, Serialize)]
pub struct BasicConf {
    /// Application name
    pub name: Option<String>,
    /// Error page template
    pub error_template: Option<String>,
    /// Path to PID file (default: /run/pingap.pid)
    pub pid_file: Option<String>,
    /// Unix domain socket path for graceful upgrades(default: /tmp/pingap_upgrade.sock)
    pub upgrade_sock: Option<String>,
    /// User for daemon
    pub user: Option<String>,
    /// Group for daemon
    pub group: Option<String>,
    /// Number of worker threads(default: 1)
    pub threads: Option<usize>,
    /// Enable work stealing between worker threads(default: true)
    pub work_stealing: Option<bool>,
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
    /// Webhook URL for notifications
    pub webhook: Option<String>,
    /// Type of webhook (e.g. "wecom", "dingtalk")
    pub webhook_type: Option<String>,
    /// List of events to send webhook notifications for
    pub webhook_notifications: Option<Vec<String>>,
    /// Log level (debug, info, warn, error)
    pub log_level: Option<String>,
    /// Size of log buffer before flushing
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
    /// Directory to store cache files
    pub cache_directory: Option<String>,
    /// Maximum size of cache storage
    pub cache_max_size: Option<ByteSize>,
}

impl BasicConf {
    /// Returns the path to the PID file
    /// If pid_file is configured, returns that value
    /// Otherwise returns /run/{pkg_name}.pid
    pub fn get_pid_file(&self) -> String {
        if let Some(pid_file) = &self.pid_file {
            pid_file.clone()
        } else {
            "/run/pingap.pid".to_string()
        }
    }
}

#[derive(Debug, Default, Deserialize, Clone, Serialize)]
pub struct StorageConf {
    pub category: String,
    pub value: String,
    pub secret: Option<String>,
    pub remark: Option<String>,
}

#[derive(Deserialize, Debug, Serialize)]
struct TomlConfig {
    basic: Option<BasicConf>,
    servers: Option<Map<String, Value>>,
    upstreams: Option<Map<String, Value>>,
    locations: Option<Map<String, Value>>,
    plugins: Option<Map<String, Value>>,
    certificates: Option<Map<String, Value>>,
    storages: Option<Map<String, Value>>,
}

fn format_toml(value: &Value) -> String {
    if let Some(value) = value.as_table() {
        value.to_string()
    } else {
        "".to_string()
    }
}

pub type PluginConf = Map<String, Value>;

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct PingapConf {
    pub basic: BasicConf,
    pub upstreams: HashMap<String, UpstreamConf>,
    pub locations: HashMap<String, LocationConf>,
    pub servers: HashMap<String, ServerConf>,
    pub plugins: HashMap<String, PluginConf>,
    pub certificates: HashMap<String, CertificateConf>,
    pub storages: HashMap<String, StorageConf>,
}

impl PingapConf {
    pub fn get_toml(
        &self,
        category: &str,
        name: Option<&str>,
    ) -> Result<(String, String)> {
        let ping_conf = toml::to_string_pretty(self)
            .map_err(|e| Error::Ser { source: e })?;
        let data: TomlConfig =
            toml::from_str(&ping_conf).map_err(|e| Error::De { source: e })?;

        let filter_values = |mut values: Map<String, Value>| {
            let name = name.unwrap_or_default();
            if name.is_empty() {
                return values;
            }
            let remove_keys: Vec<_> = values
                .keys()
                .filter(|key| *key != name)
                .map(|key| key.to_string())
                .collect();
            for key in remove_keys {
                values.remove(&key);
            }
            values
        };
        let get_path = |key: &str| {
            let name = name.unwrap_or_default();
            if key == CATEGORY_BASIC || name.is_empty() {
                return format!("/{key}.toml");
            }
            format!("/{key}/{name}.toml")
        };

        let (key, value) = match category {
            CATEGORY_SERVER => {
                ("servers", filter_values(data.servers.unwrap_or_default()))
            },
            CATEGORY_LOCATION => (
                "locations",
                filter_values(data.locations.unwrap_or_default()),
            ),
            CATEGORY_UPSTREAM => (
                "upstreams",
                filter_values(data.upstreams.unwrap_or_default()),
            ),
            CATEGORY_PLUGIN => {
                ("plugins", filter_values(data.plugins.unwrap_or_default()))
            },
            CATEGORY_CERTIFICATE => (
                "certificates",
                filter_values(data.certificates.unwrap_or_default()),
            ),
            CATEGORY_STORAGE => {
                ("storages", filter_values(data.storages.unwrap_or_default()))
            },
            _ => {
                let value = toml::to_string(&data.basic.unwrap_or_default())
                    .map_err(|e| Error::Ser { source: e })?;
                let m: Map<String, Value> = toml::from_str(&value)
                    .map_err(|e| Error::De { source: e })?;
                ("basic", m)
            },
        };
        let path = get_path(key);
        if value.is_empty() {
            return Ok((path, "".to_string()));
        }

        let mut m = Map::new();
        let _ = m.insert(key.to_string(), toml::Value::Table(value));
        let value =
            toml::to_string_pretty(&m).map_err(|e| Error::Ser { source: e })?;
        Ok((path, value))
    }
    pub fn get_storage_value(&self, name: &str) -> Result<String> {
        for (key, item) in self.storages.iter() {
            if key != name {
                continue;
            }

            if let Some(key) = &item.secret {
                return pingap_util::aes_decrypt(key, &item.value).map_err(
                    |e| Error::Invalid {
                        message: e.to_string(),
                    },
                );
            }
            return Ok(item.value.clone());
        }
        Ok("".to_string())
    }
}

fn convert_include_toml(
    data: &HashMap<String, String>,
    replace_includes: bool,
    mut value: Value,
) -> String {
    let Some(m) = value.as_table_mut() else {
        return "".to_string();
    };
    if !replace_includes {
        return m.to_string();
    }
    if let Some(includes) = m.remove("includes") {
        if let Some(includes) = get_include_toml(data, includes) {
            if let Ok(includes) = toml::from_str::<Table>(&includes) {
                for (key, value) in includes.iter() {
                    m.insert(key.to_string(), value.clone());
                }
            }
        }
    }
    m.to_string()
}

fn get_include_toml(
    data: &HashMap<String, String>,
    includes: Value,
) -> Option<String> {
    let values = includes.as_array()?;
    let arr: Vec<String> = values
        .iter()
        .map(|item| {
            let key = item.as_str().unwrap_or_default();
            if let Some(value) = data.get(key) {
                value.clone()
            } else {
                "".to_string()
            }
        })
        .collect();
    Some(arr.join("\n"))
}

fn convert_pingap_config(
    data: &[u8],
    replace_includes: bool,
) -> Result<PingapConf, Error> {
    let data: TomlConfig = toml::from_str(
        std::string::String::from_utf8_lossy(data)
            .to_string()
            .as_str(),
    )
    .map_err(|e| Error::De { source: e })?;

    let mut conf = PingapConf {
        basic: data.basic.unwrap_or_default(),
        ..Default::default()
    };
    let mut includes = HashMap::new();
    for (name, value) in data.storages.unwrap_or_default() {
        let toml = format_toml(&value);
        let storage: StorageConf = toml::from_str(toml.as_str())
            .map_err(|e| Error::De { source: e })?;
        includes.insert(name.clone(), storage.value.clone());
        conf.storages.insert(name, storage);
    }

    for (name, value) in data.upstreams.unwrap_or_default() {
        let toml = convert_include_toml(&includes, replace_includes, value);

        let upstream: UpstreamConf = toml::from_str(toml.as_str())
            .map_err(|e| Error::De { source: e })?;
        conf.upstreams.insert(name, upstream);
    }
    for (name, value) in data.locations.unwrap_or_default() {
        let toml = convert_include_toml(&includes, replace_includes, value);

        let location: LocationConf = toml::from_str(toml.as_str())
            .map_err(|e| Error::De { source: e })?;
        conf.locations.insert(name, location);
    }
    for (name, value) in data.servers.unwrap_or_default() {
        let toml = convert_include_toml(&includes, replace_includes, value);

        let server: ServerConf = toml::from_str(toml.as_str())
            .map_err(|e| Error::De { source: e })?;
        conf.servers.insert(name, server);
    }
    for (name, value) in data.plugins.unwrap_or_default() {
        let plugin: PluginConf = toml::from_str(format_toml(&value).as_str())
            .map_err(|e| Error::De { source: e })?;
        conf.plugins.insert(name, plugin);
    }

    for (name, value) in data.certificates.unwrap_or_default() {
        let certificate: CertificateConf =
            toml::from_str(format_toml(&value).as_str())
                .map_err(|e| Error::De { source: e })?;
        conf.certificates.insert(name, certificate);
    }

    Ok(conf)
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
struct Description {
    category: String,
    name: String,
    data: String,
}

impl PingapConf {
    pub fn new(data: &[u8], replace_includes: bool) -> Result<Self> {
        convert_pingap_config(data, replace_includes)
    }
    /// Validate the options of pinggap config.
    pub fn validate(&self) -> Result<()> {
        let mut upstream_names = vec![];
        for (name, upstream) in self.upstreams.iter() {
            upstream.validate(name)?;
            upstream_names.push(name.to_string());
        }
        let mut location_names = vec![];
        for (name, location) in self.locations.iter() {
            location.validate(name, &upstream_names)?;
            location_names.push(name.to_string());
        }
        let mut listen_addr_list = vec![];
        for (name, server) in self.servers.iter() {
            for addr in server.addr.split(',') {
                if listen_addr_list.contains(&addr.to_string()) {
                    return Err(Error::Invalid {
                        message: format!("{addr} is inused by other server"),
                    });
                }
                listen_addr_list.push(addr.to_string());
            }
            server.validate(name, &location_names)?;
        }
        // TODO: validate plugins
        // for (name, plugin) in self.plugins.iter() {
        //     parse_plugins(vec![(name.to_string(), plugin.clone())]).map_err(
        //         |e| Error::Invalid {
        //             message: e.to_string(),
        //         },
        //     )?;
        // }
        for (_, certificate) in self.certificates.iter() {
            certificate.validate()?;
        }
        let ping_conf = toml::to_string_pretty(self)
            .map_err(|e| Error::Ser { source: e })?;
        convert_pingap_config(ping_conf.as_bytes(), true)?;
        Ok(())
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
        Ok(format!("{:X}", hash))
    }
    /// Remove the config by name.
    pub fn remove(&mut self, category: &str, name: &str) -> Result<()> {
        match category {
            CATEGORY_UPSTREAM => {
                for (location_name, location) in self.locations.iter() {
                    if let Some(upstream) = &location.upstream {
                        if upstream == name {
                            return Err(Error::Invalid {
                                message: format!(
                                    "upstream({name}) is in used by location({location_name})",
                                ),
                            });
                        }
                    }
                }
                self.upstreams.remove(name);
            },
            CATEGORY_LOCATION => {
                for (server_name, server) in self.servers.iter() {
                    if let Some(locations) = &server.locations {
                        if locations.contains(&name.to_string()) {
                            return Err(Error::Invalid {
                               message: format!("location({name}) is in used by server({server_name})"),
                           });
                        }
                    }
                }
                self.locations.remove(name);
            },
            CATEGORY_SERVER => {
                self.servers.remove(name);
            },
            CATEGORY_PLUGIN => {
                for (location_name, location) in self.locations.iter() {
                    if let Some(plugins) = &location.plugins {
                        if plugins.contains(&name.to_string()) {
                            return Err(Error::Invalid {
                                message: format!(
                                    "proxy plugin({name}) is in used by location({location_name})"
                                ),
                            });
                        }
                    }
                }
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
        let mut value = self.clone();
        let mut descriptions = vec![];
        for (name, data) in value.servers.iter() {
            descriptions.push(Description {
                category: CATEGORY_SERVER.to_string(),
                name: format!("server:{name}"),
                data: toml::to_string_pretty(data).unwrap_or_default(),
            });
        }
        for (name, data) in value.locations.iter() {
            descriptions.push(Description {
                category: CATEGORY_LOCATION.to_string(),
                name: format!("location:{name}"),
                data: toml::to_string_pretty(data).unwrap_or_default(),
            });
        }
        for (name, data) in value.upstreams.iter() {
            descriptions.push(Description {
                category: CATEGORY_UPSTREAM.to_string(),
                name: format!("upstream:{name}"),
                data: toml::to_string_pretty(data).unwrap_or_default(),
            });
        }
        for (name, data) in value.plugins.iter() {
            descriptions.push(Description {
                category: CATEGORY_PLUGIN.to_string(),
                name: format!("plugin:{name}"),
                data: toml::to_string_pretty(data).unwrap_or_default(),
            });
        }
        for (name, data) in value.certificates.iter() {
            let mut clone_data = data.clone();
            if let Some(cert) = &clone_data.tls_cert {
                clone_data.tls_cert = Some(format!(
                    "crc32:{:X}",
                    crc32fast::hash(cert.as_bytes())
                ));
            }
            if let Some(key) = &clone_data.tls_key {
                clone_data.tls_key = Some(format!(
                    "crc32:{:X}",
                    crc32fast::hash(key.as_bytes())
                ));
            }
            descriptions.push(Description {
                category: CATEGORY_CERTIFICATE.to_string(),
                name: format!("certificate:{name}"),
                data: toml::to_string_pretty(&clone_data).unwrap_or_default(),
            });
        }
        for (name, data) in value.storages.iter() {
            let mut clone_data = data.clone();
            if let Some(secret) = &clone_data.secret {
                clone_data.secret = Some(format!(
                    "crc32:{:X}",
                    crc32fast::hash(secret.as_bytes())
                ));
            }
            descriptions.push(Description {
                category: CATEGORY_STORAGE.to_string(),
                name: format!("storage:{name}"),
                data: toml::to_string_pretty(&clone_data).unwrap_or_default(),
            });
        }
        value.servers = HashMap::new();
        value.locations = HashMap::new();
        value.upstreams = HashMap::new();
        value.plugins = HashMap::new();
        value.certificates = HashMap::new();
        value.storages = HashMap::new();
        descriptions.push(Description {
            category: CATEGORY_BASIC.to_string(),
            name: CATEGORY_BASIC.to_string(),
            data: toml::to_string_pretty(&value).unwrap_or_default(),
        });
        descriptions.sort_by_key(|d| d.name.clone());
        descriptions
    }
    /// Get the different content of two config.
    pub fn diff(&self, other: &PingapConf) -> (Vec<String>, Vec<String>) {
        let mut category_list = vec![];

        let current_descriptions = self.descriptions();
        let new_descriptions = other.descriptions();
        let mut diff_result = vec![];

        // remove item
        let mut exists_remove = false;
        for item in current_descriptions.iter() {
            let mut found = false;
            for new_item in new_descriptions.iter() {
                if item.name == new_item.name {
                    found = true;
                }
            }
            if !found {
                exists_remove = true;
                diff_result.push(format!("--{}", item.name));
                category_list.push(item.category.clone());
            }
        }
        if exists_remove {
            diff_result.push("".to_string());
        }

        // add item
        let mut exists_add = false;
        for new_item in new_descriptions.iter() {
            let mut found = false;
            for item in current_descriptions.iter() {
                if item.name == new_item.name {
                    found = true;
                }
            }
            if !found {
                exists_add = true;
                diff_result.push(format!("++{}", new_item.name));
                category_list.push(new_item.category.clone());
            }
        }
        if exists_add {
            diff_result.push("".to_string());
        }

        for item in current_descriptions.iter() {
            for new_item in new_descriptions.iter() {
                if item.name != new_item.name {
                    continue;
                }
                let mut item_diff_result = vec![];
                for diff in diff::lines(&item.data, &new_item.data) {
                    match diff {
                        diff::Result::Left(l) => {
                            item_diff_result.push(format!("-{}", l))
                        },
                        diff::Result::Right(r) => {
                            item_diff_result.push(format!("+{}", r))
                        },
                        _ => {},
                    };
                }
                if !item_diff_result.is_empty() {
                    diff_result.push(item.name.clone());
                    diff_result.extend(item_diff_result);
                    diff_result.push("\n".to_string());
                    category_list.push(item.category.clone());
                }
            }
        }

        (category_list, diff_result)
    }
}

static CURRENT_CONFIG: Lazy<ArcSwap<PingapConf>> =
    Lazy::new(|| ArcSwap::from_pointee(PingapConf::default()));
/// Set current config of pingap.
pub fn set_current_config(value: &PingapConf) {
    CURRENT_CONFIG.store(Arc::new(value.clone()));
}

/// Get the running pingap config.
pub fn get_current_config() -> Arc<PingapConf> {
    CURRENT_CONFIG.load().clone()
}

/// Get current running pingap's config crc hash
pub fn get_config_hash() -> String {
    get_current_config().hash().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{
        get_config_hash, set_current_config, validate_cert, BasicConf,
        CertificateConf,
    };
    use super::{
        LocationConf, PingapConf, PluginCategory, ServerConf, UpstreamConf,
    };
    use pingap_core::PluginStep;
    use pingap_util::base64_encode;
    use pretty_assertions::assert_eq;
    use serde::{Deserialize, Serialize};
    use std::str::FromStr;

    #[test]
    fn test_plugin_step() {
        let step = PluginStep::from_str("early_request").unwrap();
        assert_eq!(step, PluginStep::EarlyRequest);

        assert_eq!("early_request", step.to_string());
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
    fn test_current_config() {
        let conf = PingapConf {
            basic: BasicConf {
                name: Some("Pingap-X".to_string()),
                threads: Some(5),
                ..Default::default()
            },
            ..Default::default()
        };
        set_current_config(&conf);
        assert_eq!("B7B8046B", get_config_hash());
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
    fn test_upstream_conf() {
        let mut conf = UpstreamConf::default();

        let result = conf.validate("test");
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Invalid error upstream addrs is empty",
            result.expect_err("").to_string()
        );

        conf.addrs = vec!["127.0.0.1".to_string(), "github".to_string()];
        conf.discovery = Some("static".to_string());
        let result = conf.validate("test");
        assert_eq!(true, result.is_err());
        assert_eq!(
            true,
            result
                .expect_err("")
                .to_string()
                .contains("Io error failed to lookup address information")
        );

        conf.addrs = vec!["127.0.0.1".to_string(), "github.com".to_string()];
        conf.health_check = Some("http:///".to_string());
        let result = conf.validate("test");
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Url parse error empty host, http:///",
            result.expect_err("").to_string()
        );

        conf.health_check = Some("http://github.com/".to_string());
        let result = conf.validate("test");
        assert_eq!(true, result.is_ok());
    }

    #[test]
    fn test_location_conf() {
        let mut conf = LocationConf::default();
        let upstream_names = vec!["upstream1".to_string()];

        conf.upstream = Some("upstream2".to_string());
        let result = conf.validate("lo", &upstream_names);
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Invalid error upstream(upstream2) is not found(location:lo)",
            result.expect_err("").to_string()
        );

        conf.upstream = Some("upstream1".to_string());
        conf.proxy_set_headers = Some(vec!["X-Request-Id".to_string()]);
        let result = conf.validate("lo", &upstream_names);
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Invalid error header X-Request-Id is invalid(location:lo)",
            result.expect_err("").to_string()
        );

        conf.proxy_set_headers = Some(vec!["请求:响应".to_string()]);
        let result = conf.validate("lo", &upstream_names);
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Invalid error header name(请求) is invalid, error: invalid HTTP header name(location:lo)",
            result.expect_err("").to_string()
        );

        conf.proxy_set_headers = Some(vec!["X-Request-Id: abcd".to_string()]);
        let result = conf.validate("lo", &upstream_names);
        assert_eq!(true, result.is_ok());

        conf.rewrite = Some(r"foo(bar".to_string());
        let result = conf.validate("lo", &upstream_names);
        assert_eq!(true, result.is_err());
        assert_eq!(
            true,
            result
                .expect_err("")
                .to_string()
                .starts_with("Regex error regex parse error")
        );

        conf.rewrite = Some(r"^/api /".to_string());
        let result = conf.validate("lo", &upstream_names);
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

        conf.host = Some("".to_string());
        assert_eq!(0, conf.get_weight());
    }

    #[test]
    fn test_server_conf() {
        let mut conf = ServerConf::default();
        let location_names = vec!["lo".to_string()];

        let result = conf.validate("test", &location_names);
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Io error invalid socket address, ",
            result.expect_err("").to_string()
        );

        conf.addr = "127.0.0.1:3001".to_string();
        conf.locations = Some(vec!["lo1".to_string()]);
        let result = conf.validate("test", &location_names);
        assert_eq!(true, result.is_err());
        assert_eq!(
            "Invalid error location(lo1) is not found(server:test)",
            result.expect_err("").to_string()
        );

        conf.locations = Some(vec!["lo".to_string()]);
        let result = conf.validate("test", &location_names);
        assert_eq!(true, result.is_ok());
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

        assert_eq!("df7255ff75e0f40c", conf.hash_key());
    }
}
