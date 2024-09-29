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

use crate::config::PingapConf;
use pingora::protocols::l4::ext::TcpKeepalive;
use std::fmt;

static ERROR_TEMPLATE: &str = include_str!("../../error.html");

#[derive(Debug, Default)]
pub struct ServerConf {
    pub admin: bool,
    pub name: String,
    pub addr: String,
    pub access_log: Option<String>,
    pub locations: Vec<String>,
    pub tls_cipher_list: Option<String>,
    pub tls_ciphersuites: Option<String>,
    pub tls_min_version: Option<String>,
    pub tls_max_version: Option<String>,
    pub threads: Option<usize>,
    pub error_template: String,
    pub tcp_keepalive: Option<TcpKeepalive>,
    pub tcp_fastopen: Option<usize>,
    pub global_certificates: bool,
    pub enabled_h2: bool,
    pub prometheus_metrics: Option<String>,
    pub otlp_exporter: Option<String>,
}

impl fmt::Display for ServerConf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "name:{} ", self.name)?;
        write!(f, "addr:{} ", self.addr)?;
        write!(f, "locations:{:?} ", self.locations)?;
        write!(f, "threads:{:?} ", self.threads)?;
        write!(f, "{} ", self.global_certificates)?;
        write!(f, "tcp_keepalive:{:?} ", self.tcp_keepalive)?;
        write!(f, "tcp_fastopen:{:?} ", self.tcp_fastopen)?;
        write!(f, "http2:{}", self.enabled_h2)
    }
}

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
        // sort location by weight
        locations.sort_by_key(|b| std::cmp::Reverse(b.1.get_weight()));
        let mut servers = vec![];
        for (name, item) in conf.servers {
            // load config validate base64
            // so ignore error

            let mut error_template =
                conf.basic.error_template.clone().unwrap_or_default();
            if error_template.is_empty() {
                error_template = ERROR_TEMPLATE.to_string();
            }

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
                error_template,
            });
        }

        servers
    }
}

#[cfg(test)]
mod tests {
    use super::ServerConf;
    use crate::config::PingapConf;
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
            r#"name:pingap addr:127.0.0.1:3000,127.0.0.1:3001 locations:["charts-location"] threads:Some(4) false tcp_keepalive:Some(TcpKeepalive { idle: 10s, interval: 5s, count: 10 }) tcp_fastopen:Some(10) http2:true"#,
            conf.to_string()
        );
    }
    #[test]
    fn test_server_conf_from() {
        let toml_data = include_bytes!("../../conf/pingap.toml");
        let pingap_conf = PingapConf::try_from(toml_data.as_ref()).unwrap();
        let confs: Vec<ServerConf> = pingap_conf.into();

        assert_eq!(1, confs.len());
        let server = &confs[0];
        assert_eq!("test", server.name);
        assert_eq!("0.0.0.0:6188", server.addr);
        assert_eq!("tiny", server.access_log.clone().unwrap_or_default());
        assert_eq!(1, server.locations.len());
        assert_eq!(1, server.threads.unwrap_or_default());
    }
}
