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

use pingap_config::PingapConfig;
use pingora::protocols::l4::ext::TcpKeepalive;
use std::fmt;
use std::time::Duration;

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

    /// Enable SO_REUSEPORT to allow multiple sockets to bind to the same address and port.
    /// This is useful for load balancing across multiple worker processes.
    /// See the [man page](https://man7.org/linux/man-pages/man7/socket.7.html) for more information.
    pub reuse_port: Option<bool>,

    // Whether to use globally configured TLS certificates
    // False means the server is using http protocol
    pub global_certificates: bool,

    // Whether HTTP/2 protocol support is enabled for this server
    // The http protocol is using h2c
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

    // Whether to enable server-timing header
    pub enable_server_timing: bool,

    // downstream read timeout
    pub downstream_read_timeout: Option<Duration>,

    // downstream write timeout
    pub downstream_write_timeout: Option<Duration>,
}

impl fmt::Display for ServerConf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Helper closure to format optional values consistently
        let format_opt_usize = |opt: &Option<usize>| {
            opt.map_or("default".to_string(), |v| v.to_string())
        };
        let format_opt_duration = |opt: &Option<Duration>| {
            opt.map_or("default".to_string(), |v| format!("{v:?}"))
        };

        // Main Server Identity
        writeln!(f, "Server Configuration: '{}'", self.name)?;
        writeln!(f, "  Listen Addresses: {}", self.addr)?;

        // --- General ---
        writeln!(f, "  - General Settings:")?;
        writeln!(f, "    Admin Role: {}", self.admin)?;
        writeln!(
            f,
            "    Access Log: {}",
            self.access_log.as_deref().unwrap_or("disabled")
        )?;
        if !self.locations.is_empty() {
            writeln!(f, "    Locations: {}", self.locations.join(", "))?;
        }
        writeln!(f, "    Worker Threads: {}", format_opt_usize(&self.threads))?;

        // --- Protocols & Timeouts ---
        writeln!(f, "  - Protocols & Timeouts:")?;
        writeln!(f, "    HTTP/2 Enabled: {}", self.enabled_h2)?;
        writeln!(
            f,
            "    Downstream Read Timeout: {}",
            format_opt_duration(&self.downstream_read_timeout)
        )?;
        writeln!(
            f,
            "    Downstream Write Timeout: {}",
            format_opt_duration(&self.downstream_write_timeout)
        )?;

        // --- TLS ---
        writeln!(f, "  - TLS Settings:")?;
        writeln!(f, "    Global Certificates: {}", self.global_certificates)?;
        writeln!(
            f,
            "    Min Version: {}",
            self.tls_min_version.clone().unwrap_or_default()
        )?;
        writeln!(
            f,
            "    Max Version: {}",
            self.tls_max_version.clone().unwrap_or_default()
        )?;
        writeln!(
            f,
            "    Cipher List (TLS <1.3): {}",
            self.tls_cipher_list.clone().unwrap_or_default()
        )?;
        writeln!(
            f,
            "    Ciphersuites (TLS 1.3): {}",
            self.tls_ciphersuites.clone().unwrap_or_default()
        )?;

        // --- TCP ---
        writeln!(f, "  - TCP Settings:")?;
        if let Some(keepalive) = &self.tcp_keepalive {
            // Assuming TcpKeepalive has a readable Debug format
            writeln!(
                f,
                "    Keepalive: idle={:?}, interval={:?}, count={:?}",
                keepalive.idle, keepalive.interval, keepalive.count
            )?;
        } else {
            writeln!(f, "    Keepalive: disabled")?;
        }
        writeln!(f, "    Fast Open: {}", format_opt_usize(&self.tcp_fastopen))?;
        writeln!(f, "    Reuse Port: {}", self.reuse_port.unwrap_or(false))?;

        // --- Observability ---
        writeln!(f, "  - Observability:")?;
        writeln!(
            f,
            "    Prometheus Endpoint: {}",
            self.prometheus_metrics.as_deref().unwrap_or("disabled")
        )?;
        writeln!(
            f,
            "    OTLP Exporter: {}",
            self.otlp_exporter.as_deref().unwrap_or("disabled")
        )?;
        writeln!(f, "    Server-Timing Header: {}", self.enable_server_timing)?;

        // --- Extensibility ---
        if let Some(modules) = &self.modules {
            if !modules.is_empty() {
                writeln!(f, "  - Enabled Modules:")?;
                writeln!(f, "    {}", modules.join(", "))?;
            }
        }

        Ok(())
    }
}
// Conversion implementation from PingapConfig to Vec<ServerConf>
pub fn parse_from_conf(conf: PingapConfig) -> Vec<ServerConf> {
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
        let tcp_keepalive = if (item.tcp_idle.is_some()
            && item.tcp_probe_count.is_some()
            && item.tcp_interval.is_some())
            || item.tcp_user_timeout.is_some()
        {
            Some(TcpKeepalive {
                idle: item.tcp_idle.unwrap_or_default(),
                count: item.tcp_probe_count.unwrap_or_default(),
                interval: item.tcp_interval.unwrap_or_default(),
                #[cfg(target_os = "linux")]
                user_timeout: item.tcp_user_timeout.unwrap_or_default(),
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
            global_certificates: item.global_certificates.unwrap_or_default(),
            enabled_h2: item.enabled_h2.unwrap_or_default(),
            tcp_keepalive,
            tcp_fastopen: item.tcp_fastopen,
            reuse_port: item.reuse_port,
            prometheus_metrics: item.prometheus_metrics,
            otlp_exporter: item.otlp_exporter.clone(),
            modules: item.modules.clone(),
            enable_server_timing: item.enable_server_timing.unwrap_or_default(),
            error_template,
            downstream_read_timeout: item.downstream_read_timeout,
            downstream_write_timeout: item.downstream_write_timeout,
        });
    }

    servers
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
                #[cfg(target_os = "linux")]
                user_timeout: Duration::from_secs(0),
            }),
            tcp_fastopen: Some(10),
            enabled_h2: true,
            ..Default::default()
        };

        #[cfg(target_os = "linux")]
        assert_eq!(
            r#"Server Configuration: 'pingap'
  Listen Addresses: 127.0.0.1:3000,127.0.0.1:3001
  - General Settings:
    Admin Role: false
    Access Log: combined
    Locations: charts-location
    Worker Threads: 4
  - Protocols & Timeouts:
    HTTP/2 Enabled: true
    Downstream Read Timeout: default
    Downstream Write Timeout: default
  - TLS Settings:
    Global Certificates: false
    Min Version: 
    Max Version: 
    Cipher List (TLS <1.3): 
    Ciphersuites (TLS 1.3): 
  - TCP Settings:
    Keepalive: idle=10s, interval=5s, count=10
    Fast Open: 10
    Reuse Port: false
  - Observability:
    Prometheus Endpoint: disabled
    OTLP Exporter: disabled
    Server-Timing Header: false
"#,
            conf.to_string()
        );
        #[cfg(not(target_os = "linux"))]
        assert_eq!(
            r#"Server Configuration: 'pingap'
  Listen Addresses: 127.0.0.1:3000,127.0.0.1:3001
  - General Settings:
    Admin Role: false
    Access Log: combined
    Locations: charts-location
    Worker Threads: 4
  - Protocols & Timeouts:
    HTTP/2 Enabled: true
    Downstream Read Timeout: default
    Downstream Write Timeout: default
  - TLS Settings:
    Global Certificates: false
    Min Version: 
    Max Version: 
    Cipher List (TLS <1.3): 
    Ciphersuites (TLS 1.3): 
  - TCP Settings:
    Keepalive: idle=10s, interval=5s, count=10
    Fast Open: 10
    Reuse Port: false
  - Observability:
    Prometheus Endpoint: disabled
    OTLP Exporter: disabled
    Server-Timing Header: false
"#,
            conf.to_string()
        );
    }
}
