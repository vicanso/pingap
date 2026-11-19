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

use super::{Error, LOG_TARGET, Result};
use bollard::query_parameters::{EventsOptionsBuilder, ListContainersOptions};
use futures::StreamExt;
use pingap_core::{NotificationData, NotificationLevel, NotificationSender};
use pingora::server::ShutdownWatch;
use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tracing::{debug, error, info, warn};

const LABEL_ENABLE: &str = "pingap.enable";
const LABEL_NAME: &str = "pingap.name";
const LABEL_HOST: &str = "pingap.host";
const LABEL_PATH: &str = "pingap.path";
const LABEL_PORT: &str = "pingap.port";
const LABEL_TLS: &str = "pingap.tls";
const LABEL_PLUGINS: &str = "pingap.plugins";
const LABEL_SERVER: &str = "pingap.server";
const LABEL_WEIGHT: &str = "pingap.weight";

const CONTAINER_EVENTS: &[&str] = &[
    "start",
    "stop",
    "die",
    "kill",
    "pause",
    "unpause",
    "destroy",
    "update",
    "health_status",
];

const EVENT_DEBOUNCE: Duration = Duration::from_millis(500);
const EVENT_RECONNECT_DELAY: Duration = Duration::from_secs(5);

/// A route specification extracted from container `pingap.*` labels.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DockerLabelRoute {
    /// Logical service/route name shared across replicas of the same service.
    pub name: String,
    /// Resolved upstream backend `ip:port` addresses.
    pub addrs: Vec<String>,
    /// Virtual hostnames declared via `pingap.host`.
    pub hosts: Vec<String>,
    /// Optional location path matcher from `pingap.path`.
    pub path: Option<String>,
    /// Optional TLS mode from `pingap.tls` (`"acme"`, `"true"`, `"false"`).
    pub tls: Option<String>,
    /// Plugin names declared via `pingap.plugins`.
    pub plugins: Vec<String>,
    /// Optional target server name from `pingap.server`.
    pub server: Option<String>,
    /// Optional location priority weight from `pingap.weight`.
    pub weight: Option<u16>,
}

/// Network endpoint attached to a container summary.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ContainerEndpoint {
    /// Container IP address inside a Docker network.
    pub ip: Option<IpAddr>,
    /// Network gateway IP address used when a port is published on the host.
    pub gateway: Option<IpAddr>,
    /// Container private port.
    pub private_port: u16,
    /// Published host port (`0` when unpublished).
    pub public_port: u16,
}

/// Normalized container metadata used to derive [`DockerLabelRoute`] entries.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ContainerLabelInput {
    /// Container ID.
    pub id: String,
    /// Container names (usually prefixed with `/`).
    pub names: Vec<String>,
    /// Container labels map.
    pub labels: HashMap<String, String>,
    /// Attached network endpoints.
    pub endpoints: Vec<ContainerEndpoint>,
}

impl ContainerLabelInput {
    /// Builds a normalized input from a Bollard container summary.
    pub fn from_summary(summary: &bollard::models::ContainerSummary) -> Self {
        let (private_port, public_port) = summary
            .ports
            .as_deref()
            .and_then(|ports| ports.iter().find(|p| p.private_port > 0))
            .map(|p| (p.private_port, p.public_port.unwrap_or(0)))
            .unwrap_or((0, 0));

        let mut endpoints = Vec::new();
        if let Some(networks) = summary
            .network_settings
            .as_ref()
            .and_then(|s| s.networks.as_ref())
        {
            for network in networks.values() {
                let ip = network
                    .ip_address
                    .as_deref()
                    .and_then(|s| s.parse::<IpAddr>().ok());
                let gateway = network
                    .gateway
                    .as_deref()
                    .and_then(|s| s.parse::<IpAddr>().ok());
                endpoints.push(ContainerEndpoint {
                    ip,
                    gateway,
                    private_port,
                    public_port,
                });
            }
        }

        Self {
            id: summary.id.clone().unwrap_or_default(),
            names: summary.names.clone().unwrap_or_default(),
            labels: summary.labels.clone().unwrap_or_default(),
            endpoints,
        }
    }
}

fn is_label_enabled(labels: &HashMap<String, String>) -> bool {
    labels.get(LABEL_ENABLE).is_some_and(|v| {
        let trimmed = v.trim();
        trimmed.eq_ignore_ascii_case("true") || trimmed == "1"
    })
}

fn non_empty_label(
    labels: &HashMap<String, String>,
    key: &str,
) -> Option<String> {
    labels
        .get(key)
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn parse_csv_label(labels: &HashMap<String, String>, key: &str) -> Vec<String> {
    labels
        .get(key)
        .map(|v| {
            v.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn sanitize_route_name(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut prev_underscore = false;
    for ch in raw.chars() {
        let mapped = match ch {
            'a'..='z' | '0'..='9' | '_' | '-' => Some(ch),
            'A'..='Z' => Some(ch.to_ascii_lowercase()),
            _ => Some('_'),
        };
        if let Some(c) = mapped {
            if c == '_' {
                if !prev_underscore && !out.is_empty() {
                    out.push('_');
                }
                prev_underscore = true;
            } else {
                out.push(c);
                prev_underscore = false;
            }
        }
    }
    let trimmed = out.trim_matches('_').to_string();
    if trimmed.is_empty() {
        "container".to_string()
    } else {
        trimmed
    }
}

fn resolve_route_name(
    container: &ContainerLabelInput,
    hosts: &[String],
) -> String {
    if let Some(name) = non_empty_label(&container.labels, LABEL_NAME) {
        return sanitize_route_name(&name);
    }
    if let Some(host) = hosts.first() {
        return sanitize_route_name(host);
    }
    if let Some(cname) = container
        .names
        .iter()
        .map(|n| n.trim().trim_start_matches('/'))
        .find(|n| !n.is_empty())
    {
        return sanitize_route_name(cname);
    }
    let short_id = container.id.chars().take(12).collect::<String>();
    sanitize_route_name(&short_id)
}

fn resolve_container_addrs(
    container: &ContainerLabelInput,
    override_port: Option<u16>,
) -> Vec<String> {
    let mut addrs = Vec::new();
    for ep in &container.endpoints {
        let resolved = if let Some(port) = override_port.filter(|p| *p > 0) {
            ep.ip.map(|ip| SocketAddr::new(ip, port))
        } else if ep.public_port > 0 {
            ep.gateway.map(|gw| SocketAddr::new(gw, ep.public_port))
        } else if ep.private_port > 0 {
            ep.ip.map(|ip| SocketAddr::new(ip, ep.private_port))
        } else {
            None
        };
        if let Some(sock) = resolved {
            addrs.push(sock.to_string());
        }
    }
    addrs.sort();
    addrs.dedup();
    addrs
}

fn parse_u16_label(labels: &HashMap<String, String>, key: &str) -> Option<u16> {
    let raw = non_empty_label(labels, key)?;
    match raw.parse::<u16>() {
        Ok(val) if val > 0 => Some(val),
        _ => {
            warn!(
                target: LOG_TARGET,
                label = key,
                value = raw,
                "invalid numeric docker label value, ignoring"
            );
            None
        },
    }
}

fn normalize_tls_label(labels: &HashMap<String, String>) -> Option<String> {
    let raw = non_empty_label(labels, LABEL_TLS)?;
    let lower = raw.to_ascii_lowercase();
    if matches!(lower.as_str(), "acme" | "true" | "false") {
        Some(lower)
    } else if lower == "1" {
        Some("true".to_string())
    } else if lower == "0" {
        Some("false".to_string())
    } else {
        warn!(
            target: LOG_TARGET,
            value = raw,
            "invalid pingap.tls label value, ignoring"
        );
        None
    }
}

fn build_container_route(
    container: &ContainerLabelInput,
) -> Option<DockerLabelRoute> {
    if !is_label_enabled(&container.labels) {
        return None;
    }
    let port = parse_u16_label(&container.labels, LABEL_PORT);
    let addrs = resolve_container_addrs(container, port);
    if addrs.is_empty() {
        return None;
    }
    let hosts = parse_csv_label(&container.labels, LABEL_HOST);
    let name = resolve_route_name(container, &hosts);
    let path = non_empty_label(&container.labels, LABEL_PATH);
    let tls = normalize_tls_label(&container.labels);
    let plugins = parse_csv_label(&container.labels, LABEL_PLUGINS);
    let server = non_empty_label(&container.labels, LABEL_SERVER);
    let weight = parse_u16_label(&container.labels, LABEL_WEIGHT);

    Some(DockerLabelRoute {
        name,
        addrs,
        hosts,
        path,
        tls,
        plugins,
        server,
        weight,
    })
}

fn merge_route_into(
    existing: &mut DockerLabelRoute,
    incoming: DockerLabelRoute,
) {
    existing.addrs.extend(incoming.addrs);
    existing.addrs.sort();
    existing.addrs.dedup();
    if existing.hosts.is_empty() {
        existing.hosts = incoming.hosts;
    }
    if existing.path.is_none() {
        existing.path = incoming.path;
    }
    if existing.tls.is_none() {
        existing.tls = incoming.tls;
    }
    if existing.plugins.is_empty() {
        existing.plugins = incoming.plugins;
    }
    if existing.server.is_none() {
        existing.server = incoming.server;
    }
    if existing.weight.is_none() {
        existing.weight = incoming.weight;
    }
}

/// Extracts and groups enabled [`DockerLabelRoute`] definitions from container metadata.
///
/// Multiple replicas resolving to the same route `name` have their backend addresses
/// merged and sorted deterministically.
pub fn extract_routes_from_containers(
    containers: &[ContainerLabelInput],
) -> Vec<DockerLabelRoute> {
    let mut grouped: BTreeMap<String, DockerLabelRoute> = BTreeMap::new();
    for container in containers {
        let Some(route) = build_container_route(container) else {
            continue;
        };
        if let Some(existing) = grouped.get_mut(&route.name) {
            merge_route_into(existing, route);
        } else {
            grouped.insert(route.name.clone(), route);
        }
    }
    grouped.into_values().collect()
}

/// Watches Docker containers bearing `pingap.enable` labels and emits updated route sets.
pub struct DockerLabelWatcher {
    docker: bollard::Docker,
    sender: Option<Arc<NotificationSender>>,
    failing: AtomicBool,
}

impl DockerLabelWatcher {
    /// Connects to the local Docker socket / `DOCKER_HOST`.
    pub fn connect(sender: Option<Arc<NotificationSender>>) -> Result<Self> {
        let docker = bollard::Docker::connect_with_local_defaults()
            .map_err(|e| Error::Docker { source: e })?;
        Ok(Self {
            docker,
            sender,
            failing: AtomicBool::new(false),
        })
    }

    async fn report_failure(&self, error: &str) {
        if self.failing.swap(true, Ordering::Relaxed) {
            debug!(
                target: LOG_TARGET,
                error,
                "docker label watcher still failing"
            );
            return;
        }
        error!(target: LOG_TARGET, error, "docker label watcher failed");
        if let Some(sender) = &self.sender {
            sender
                .notify(NotificationData {
                    category: "service_discover_fail".to_string(),
                    level: NotificationLevel::Warn,
                    message: format!("docker label discovery failed: {error}"),
                    ..Default::default()
                })
                .await;
        }
    }

    fn report_working(&self) {
        if self.failing.swap(false, Ordering::Relaxed) {
            info!(
                target: LOG_TARGET,
                "docker label watcher recovered"
            );
        }
    }

    /// Queries currently running containers with `pingap.enable` and extracts routes.
    pub async fn list_routes(&self) -> Result<Vec<DockerLabelRoute>> {
        let mut filters = HashMap::new();
        filters.insert("label".to_string(), vec![LABEL_ENABLE.to_string()]);
        let summaries = self
            .docker
            .list_containers(Some(ListContainersOptions {
                filters: Some(filters),
                ..Default::default()
            }))
            .await
            .map_err(|e| Error::Docker { source: e })?;
        let inputs: Vec<ContainerLabelInput> = summaries
            .iter()
            .map(ContainerLabelInput::from_summary)
            .collect();
        Ok(extract_routes_from_containers(&inputs))
    }

    async fn refresh_if_changed<F, Fut>(
        &self,
        last_routes: &mut Option<Vec<DockerLabelRoute>>,
        on_routes: &mut F,
    ) where
        F: FnMut(Vec<DockerLabelRoute>) -> Fut,
        Fut: Future<Output = ()>,
    {
        match self.list_routes().await {
            Ok(routes) => {
                self.report_working();
                if last_routes.as_ref() != Some(&routes) {
                    *last_routes = Some(routes.clone());
                    on_routes(routes).await;
                }
            },
            Err(e) => {
                let msg = e.to_string();
                self.report_failure(&msg).await;
            },
        }
    }

    /// Watches Docker container events until `shutdown` changes, invoking `on_routes`
    /// initially and whenever the extracted route list changes.
    pub async fn watch<F, Fut>(
        &self,
        mut shutdown: ShutdownWatch,
        mut on_routes: F,
    ) where
        F: FnMut(Vec<DockerLabelRoute>) -> Fut,
        Fut: Future<Output = ()>,
    {
        let mut last_routes: Option<Vec<DockerLabelRoute>> = None;
        loop {
            self.refresh_if_changed(&mut last_routes, &mut on_routes)
                .await;

            if self
                .wait_event_stream(
                    &mut shutdown,
                    &mut last_routes,
                    &mut on_routes,
                )
                .await
            {
                return;
            }

            tokio::select! {
                _ = shutdown.changed() => return,
                _ = tokio::time::sleep(EVENT_RECONNECT_DELAY) => {}
            }
        }
    }

    async fn wait_event_stream<F, Fut>(
        &self,
        shutdown: &mut ShutdownWatch,
        last_routes: &mut Option<Vec<DockerLabelRoute>>,
        on_routes: &mut F,
    ) -> bool
    where
        F: FnMut(Vec<DockerLabelRoute>) -> Fut,
        Fut: Future<Output = ()>,
    {
        let mut filters = HashMap::new();
        filters.insert("type".to_string(), vec!["container".to_string()]);
        filters.insert(
            "event".to_string(),
            CONTAINER_EVENTS.iter().map(|s| s.to_string()).collect(),
        );
        let options = EventsOptionsBuilder::default().filters(&filters).build();
        let mut stream = self.docker.events(Some(options));

        loop {
            let next = tokio::select! {
                _ = shutdown.changed() => return true,
                ev = stream.next() => ev,
            };
            let Some(result) = next else {
                return false;
            };
            let Ok(event) = result else {
                if let Err(err) = result {
                    self.report_failure(&err.to_string()).await;
                }
                return false;
            };
            debug!(
                target: LOG_TARGET,
                action = ?event.action,
                "docker label event received"
            );
            let ended = drain_debounce(shutdown, &mut stream).await;
            if matches!(ended, DebounceOutcome::Shutdown) {
                return true;
            }
            self.refresh_if_changed(last_routes, on_routes).await;
            if matches!(ended, DebounceOutcome::StreamEnded) {
                return false;
            }
        }
    }
}

enum DebounceOutcome {
    Elapsed,
    StreamEnded,
    Shutdown,
}

async fn drain_debounce<S, E>(
    shutdown: &mut ShutdownWatch,
    stream: &mut (impl StreamExt<Item = std::result::Result<S, E>> + Unpin),
) -> DebounceOutcome {
    let deadline = tokio::time::Instant::now() + EVENT_DEBOUNCE;
    loop {
        tokio::select! {
            _ = shutdown.changed() => return DebounceOutcome::Shutdown,
            res = tokio::time::timeout_at(deadline, stream.next()) => match res {
                Err(_) => return DebounceOutcome::Elapsed,
                Ok(Some(Ok(_))) => continue,
                Ok(_) => return DebounceOutcome::StreamEnded,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::net::Ipv4Addr;

    fn make_container(
        id: &str,
        names: &[&str],
        labels: &[(&str, &str)],
        ip: [u8; 4],
        private_port: u16,
        public_port: u16,
        gateway: Option<[u8; 4]>,
    ) -> ContainerLabelInput {
        ContainerLabelInput {
            id: id.to_string(),
            names: names.iter().map(|s| s.to_string()).collect(),
            labels: labels
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            endpoints: vec![ContainerEndpoint {
                ip: Some(IpAddr::V4(Ipv4Addr::from(ip))),
                gateway: gateway.map(|g| IpAddr::V4(Ipv4Addr::from(g))),
                private_port,
                public_port,
            }],
        }
    }

    #[test]
    fn test_extract_routes_filters_disabled_and_parses_labels() {
        let containers = vec![
            make_container(
                "111",
                &["/ignored"],
                &[("pingap.enable", "false"), ("pingap.host", "ignored.local")],
                [172, 17, 0, 2],
                8080,
                0,
                None,
            ),
            make_container(
                "222",
                &["/no-label"],
                &[("pingap.host", "nolabel.local")],
                [172, 17, 0, 3],
                8080,
                0,
                None,
            ),
            make_container(
                "333",
                &["/api-1"],
                &[
                    ("pingap.enable", "true"),
                    ("pingap.name", "User.API"),
                    ("pingap.host", "api.example.com, v2.example.com "),
                    ("pingap.path", "/v1"),
                    ("pingap.port", "9090"),
                    ("pingap.tls", "acme"),
                    ("pingap.plugins", "auth, rate_limit"),
                    ("pingap.server", "https_edge"),
                    ("pingap.weight", "1024"),
                ],
                [172, 17, 0, 4],
                80,
                30080,
                Some([172, 17, 0, 1]),
            ),
        ];

        let routes = extract_routes_from_containers(&containers);
        assert_eq!(1, routes.len());
        assert_eq!(
            DockerLabelRoute {
                name: "user_api".to_string(),
                addrs: vec!["172.17.0.4:9090".to_string()],
                hosts: vec![
                    "api.example.com".to_string(),
                    "v2.example.com".to_string(),
                ],
                path: Some("/v1".to_string()),
                tls: Some("acme".to_string()),
                plugins: vec!["auth".to_string(), "rate_limit".to_string()],
                server: Some("https_edge".to_string()),
                weight: Some(1024),
            },
            routes[0]
        );
    }

    #[test]
    fn test_extract_routes_merges_replicas_and_sorts_by_name() {
        let containers = vec![
            make_container(
                "b2",
                &["/web-2"],
                &[
                    ("pingap.enable", "1"),
                    ("pingap.name", "web"),
                    ("pingap.host", "web.example.com"),
                ],
                [172, 18, 0, 3],
                8000,
                0,
                None,
            ),
            make_container(
                "a1",
                &["/alpha-svc"],
                &[("pingap.enable", "TRUE"), ("pingap.host", "alpha.local")],
                [172, 18, 0, 5],
                80,
                18080,
                Some([172, 18, 0, 1]),
            ),
            make_container(
                "b1",
                &["/web-1"],
                &[
                    ("pingap.enable", "true"),
                    ("pingap.name", "web"),
                    ("pingap.host", "web.example.com"),
                ],
                [172, 18, 0, 2],
                8000,
                0,
                None,
            ),
        ];

        let routes = extract_routes_from_containers(&containers);
        assert_eq!(2, routes.len());
        assert_eq!("alpha_local", routes[0].name);
        assert_eq!(vec!["172.18.0.1:18080".to_string()], routes[0].addrs);
        assert_eq!("web", routes[1].name);
        assert_eq!(
            vec!["172.18.0.2:8000".to_string(), "172.18.0.3:8000".to_string(),],
            routes[1].addrs
        );
    }

    #[test]
    fn test_container_summary_conversion_and_invalid_labels() {
        use bollard::models::{
            ContainerSummary, ContainerSummaryNetworkSettings,
            EndpointSettings, PortSummary,
        };
        let mut networks = HashMap::new();
        networks.insert(
            "bridge".to_string(),
            EndpointSettings {
                ip_address: Some("10.0.0.12".to_string()),
                gateway: Some("10.0.0.1".to_string()),
                ..Default::default()
            },
        );
        let mut labels = HashMap::new();
        labels.insert("pingap.enable".to_string(), "true".to_string());
        labels.insert("pingap.port".to_string(), "invalid".to_string());
        labels.insert("pingap.tls".to_string(), "bogus".to_string());

        let summary = ContainerSummary {
            id: Some("abcdef1234567890".to_string()),
            names: Some(vec!["/my-app".to_string()]),
            labels: Some(labels),
            ports: Some(vec![PortSummary {
                private_port: 3000,
                public_port: None,
                ..Default::default()
            }]),
            network_settings: Some(ContainerSummaryNetworkSettings {
                networks: Some(networks),
            }),
            ..Default::default()
        };

        let input = ContainerLabelInput::from_summary(&summary);
        let routes = extract_routes_from_containers(&[input]);
        assert_eq!(1, routes.len());
        assert_eq!("my-app", routes[0].name);
        assert_eq!(vec!["10.0.0.12:3000".to_string()], routes[0].addrs);
        assert_eq!(None, routes[0].tls);
        assert_eq!(None, routes[0].weight);
    }
}
