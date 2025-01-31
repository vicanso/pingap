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

use crate::config::PingapConf;
use pingora::protocols::l4::ext::TcpKeepalive;
use std::fmt;

static ERROR_TEMPLATE: &str = include_str!("../../error.html");

// ServerConf struct represents the configuration for a server instance
#[derive(Debug, Default)]
pub struct ServerConf {
    // Whether this server instance handles admin-related functionality
    pub admin: bool,

    // Unique identifier for this server instance
    pub name: String,

    // Comma-separated list of IP:port combinations where the server will listen
    // Example: "127.0.0.1:3000,127.0.0.1:3001"
    pub addr: String,

    // Access log configuration string. Supports formats like "combined", "tiny", etc.
    // None means access logging is disabled
    pub access_log: Option<String>,

    // List of location route identifiers that this server will handle
    // These correspond to the location configurations defined elsewhere
    pub locations: Vec<String>,

    // OpenSSL cipher list string for TLS versions below 1.3
    // Example: "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
    pub tls_cipher_list: Option<String>,

    // TLS 1.3 specific cipher suite configuration
    // Example: "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384"
    pub tls_ciphersuites: Option<String>,

    // Minimum TLS version the server will accept
    // Common values: "TLSv1.2", "TLSv1.3"
    pub tls_min_version: Option<String>,

    // Maximum TLS version the server will support
    // Common values: "TLSv1.2", "TLSv1.3"
    pub tls_max_version: Option<String>,

    // Number of worker threads for handling connections
    // None means use system default
    pub threads: Option<usize>,

    // HTML template used for displaying error pages to clients
    // Will use default template if not specified
    pub error_template: String,

    // TCP keepalive configuration for maintaining persistent connections
    // Includes idle time, probe count, and interval settings
    pub tcp_keepalive: Option<TcpKeepalive>,

    // TCP Fast Open queue size for improved connection establishment
    // None means TCP Fast Open is disabled
    pub tcp_fastopen: Option<usize>,

    // Whether to use globally configured TLS certificates
    // False means server-specific certificates will be used
    pub global_certificates: bool,

    // Whether HTTP/2 protocol support is enabled for this server
    pub enabled_h2: bool,

    // Endpoint path for exposing Prometheus metrics
    // None means metrics collection is disabled
    pub prometheus_metrics: Option<String>,

    // OpenTelemetry exporter configuration string
    // Used for distributed tracing support
    pub otlp_exporter: Option<String>,

    // List of enabled module names for this server instance
    // Allows for dynamic functionality extension
    pub modules: Option<Vec<String>>,
}

impl fmt::Display for ServerConf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ServerConf {{")?;
        write!(f, " name: {}, ", self.name)?;
        write!(f, "admin: {}, ", self.admin)?;
        write!(f, "addr: {}, ", self.addr)?;
        write!(f, "access_log: {:?}, ", self.access_log)?;
        write!(f, "locations: {:?}, ", self.locations)?;
        if let Some(ref ciphers) = self.tls_cipher_list {
            write!(f, "tls_cipher_list: {}, ", ciphers)?;
        }
        if let Some(ref suites) = self.tls_ciphersuites {
            write!(f, "tls_ciphersuites: {}, ", suites)?;
        }
        if let Some(ref min_ver) = self.tls_min_version {
            write!(f, "tls_min_version: {}, ", min_ver)?;
        }
        if let Some(ref max_ver) = self.tls_max_version {
            write!(f, "tls_max_version: {}, ", max_ver)?;
        }
        write!(f, "threads: {:?}, ", self.threads)?;
        write!(f, "global_certificates: {}, ", self.global_certificates)?;
        write!(f, "enabled_h2: {}, ", self.enabled_h2)?;
        write!(f, "tcp_keepalive: {:?}, ", self.tcp_keepalive)?;
        write!(f, "tcp_fastopen: {:?}, ", self.tcp_fastopen)?;
        if let Some(ref metrics) = self.prometheus_metrics {
            write!(f, "prometheus_metrics: {}, ", metrics)?;
        }
        if let Some(ref exporter) = self.otlp_exporter {
            write!(f, "otlp_exporter: {}, ", exporter)?;
        }
        if let Some(ref modules) = self.modules {
            write!(f, "modules: {:?}, ", modules)?;
        }
        write!(f, "error_template: {} }}", self.error_template)?;
        Ok(())
    }
}

// Conversion implementation from PingapConf to Vec<ServerConf>
impl From<PingapConf> for Vec<ServerConf> {
    fn from(conf: PingapConf) -> Self {
        let mut upstreams = vec![];
        for (name, item) in conf.upstreams {
            upstreams.push((name, item));
        }
        let mut locations = vec![];
        for (name, item) in conf.locations {
            locations.push((name, item));
        }
        // Sort locations by weight in descending order for priority routing
        locations.sort_by_key(|b| std::cmp::Reverse(b.1.get_weight()));
        let mut servers = vec![];
        for (name, item) in conf.servers {
            // Set up error template, using default if none specified
            let mut error_template =
                conf.basic.error_template.clone().unwrap_or_default();
            if error_template.is_empty() {
                error_template = ERROR_TEMPLATE.to_string();
            }

            // Configure TCP keepalive only if all required parameters are present
            let tcp_keepalive = if item.tcp_idle.is_some()
                && item.tcp_probe_count.is_some()
                && item.tcp_interval.is_some()
            {
                Some(TcpKeepalive {
                    idle: item.tcp_idle.unwrap_or_default(),
                    count: item.tcp_probe_count.unwrap_or_default(),
                    interval: item.tcp_interval.unwrap_or_default(),
                })
            } else {
                None
            };

            // Create server configuration with all settings
            servers.push(ServerConf {
                name,
                admin: false,
                tls_cipher_list: item.tls_cipher_list.clone(),
                tls_ciphersuites: item.tls_ciphersuites.clone(),
                tls_min_version: item.tls_min_version.clone(),
                tls_max_version: item.tls_max_version.clone(),
                addr: item.addr,
                access_log: item.access_log,
                locations: item.locations.unwrap_or_default(),
                threads: item.threads,
                global_certificates: item
                    .global_certificates
                    .unwrap_or_default(),
                enabled_h2: item.enabled_h2.unwrap_or_default(),
                tcp_keepalive,
                tcp_fastopen: item.tcp_fastopen,
                prometheus_metrics: item.prometheus_metrics,
                otlp_exporter: item.otlp_exporter.clone(),
                modules: item.modules.clone(),
                error_template,
            });
        }

        servers
    }
}

#[cfg(test)]
mod tests {
    use super::ServerConf;
    use pingora::protocols::l4::ext::TcpKeepalive;
    use pretty_assertions::assert_eq;
    use std::time::Duration;

    #[test]
    fn test_server_conf() {
        let conf = ServerConf {
            name: "pingap".to_string(),
            addr: "127.0.0.1:3000,127.0.0.1:3001".to_string(),
            access_log: Some("combined".to_string()),

            locations: vec!["charts-location".to_string()],
            threads: Some(4),
            error_template: "<html></html>".to_string(),
            tcp_keepalive: Some(TcpKeepalive {
                idle: Duration::from_secs(10),
                interval: Duration::from_secs(5),
                count: 10,
            }),
            tcp_fastopen: Some(10),
            enabled_h2: true,
            ..Default::default()
        };

        assert_eq!(
            r#"ServerConf { name: pingap, admin: false, addr: 127.0.0.1:3000,127.0.0.1:3001, access_log: Some("combined"), locations: ["charts-location"], threads: Some(4), global_certificates: false, enabled_h2: true, tcp_keepalive: Some(TcpKeepalive { idle: 10s, interval: 5s, count: 10 }), tcp_fastopen: Some(10), error_template: <html></html> }"#,
            conf.to_string()
        );
    }
}
