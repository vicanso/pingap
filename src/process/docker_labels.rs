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

use arc_swap::{ArcSwap, ArcSwapOption};
use async_trait::async_trait;
use pingap_config::{
    CertificateConf, ConfigManager, LocationConf, PingapConfig, UpstreamConf,
};
use pingap_discovery::{DockerLabelRoute, DockerLabelWatcher};
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock};
use tracing::{error, info, warn};

static LOG_TARGET: &str = "main::process";

const DOCKER_ROUTE_PREFIX: &str = "docker_";

static STATIC_BASE_CONFIG: LazyLock<ArcSwapOption<PingapConfig>> =
    LazyLock::new(ArcSwapOption::empty);

static DOCKER_ROUTES: LazyLock<ArcSwap<Vec<DockerLabelRoute>>> =
    LazyLock::new(|| ArcSwap::from_pointee(Vec::new()));

/// Records the latest validated static configuration so Docker label updates
/// always overlay on top of the clean static baseline without persisting
/// ephemeral container routes back to config storage.
pub fn set_static_base_config(config: &PingapConfig) {
    STATIC_BASE_CONFIG.store(Some(Arc::new(config.clone())));
}

/// Records `base` as the clean static configuration and overlays active Docker
/// label routes when `basic.docker_labels_enabled` is true.
pub fn overlay_docker_routes(base: &PingapConfig) -> PingapConfig {
    set_static_base_config(base);
    if base.basic.docker_labels_enabled.unwrap_or_default() {
        merge_docker_routes(base, &DOCKER_ROUTES.load_full())
    } else {
        base.clone()
    }
}

fn sorted_server_names(base: &PingapConfig) -> Vec<&String> {
    let mut names: Vec<&String> = base.servers.keys().collect();
    names.sort();
    names
}

fn resolve_target_server(
    base: &PingapConfig,
    route: &DockerLabelRoute,
) -> Option<String> {
    if let Some(explicit) = route.server.as_deref() {
        if base.servers.contains_key(explicit) {
            return Some(explicit.to_string());
        }
        warn!(
            target: LOG_TARGET,
            route = route.name,
            server = explicit,
            "docker label target server does not exist, skipping route"
        );
        return None;
    }

    let wants_tls = matches!(route.tls.as_deref(), Some("acme" | "true"));
    if wants_tls
        && let Some(tls_srv) = base.basic.docker_labels_tls_server.as_deref()
        && base.servers.contains_key(tls_srv)
    {
        return Some(tls_srv.to_string());
    }
    if let Some(default_srv) = base.basic.docker_labels_server.as_deref()
        && base.servers.contains_key(default_srv)
    {
        return Some(default_srv.to_string());
    }

    let names = sorted_server_names(base);
    if wants_tls {
        if let Some(srv) = names.iter().find(|n| {
            base.servers
                .get(**n)
                .and_then(|s| s.global_certificates)
                .unwrap_or(false)
        }) {
            return Some((*srv).clone());
        }
    } else if let Some(srv) = names.iter().find(|n| {
        !base
            .servers
            .get(**n)
            .and_then(|s| s.global_certificates)
            .unwrap_or(false)
    }) {
        return Some((*srv).clone());
    }
    names.first().map(|n| (*n).clone())
}

fn filter_valid_plugins(
    base: &PingapConfig,
    route: &DockerLabelRoute,
) -> Vec<String> {
    let mut plugins = Vec::new();
    for plugin in &route.plugins {
        if base.plugins.contains_key(plugin) {
            plugins.push(plugin.clone());
        } else {
            warn!(
                target: LOG_TARGET,
                route = route.name,
                plugin,
                "docker label references unknown plugin, ignoring plugin"
            );
        }
    }
    plugins
}

fn cert_covers_hosts(
    certs: &HashMap<String, CertificateConf>,
    hosts: &[String],
) -> bool {
    let existing: HashSet<&str> = certs
        .values()
        .filter_map(|c| c.domains.as_deref())
        .flat_map(|d| d.split(',').map(str::trim))
        .filter(|d| !d.is_empty())
        .collect();
    hosts.iter().all(|h| existing.contains(h.as_str()))
}

fn attach_route(
    base: &PingapConfig,
    merged: &mut PingapConfig,
    route: &DockerLabelRoute,
) {
    let key = format!("{DOCKER_ROUTE_PREFIX}{}", route.name);
    if merged.upstreams.contains_key(&key)
        || merged.locations.contains_key(&key)
    {
        warn!(
            target: LOG_TARGET,
            route = key,
            "docker label route conflicts with existing entry, skipping"
        );
        return;
    }
    let Some(server_name) = resolve_target_server(base, route) else {
        return;
    };
    let plugins = filter_valid_plugins(base, route);

    merged.upstreams.insert(
        key.clone(),
        UpstreamConf {
            addrs: route.addrs.clone(),
            ..Default::default()
        },
    );
    merged.locations.insert(
        key.clone(),
        LocationConf {
            upstream: Some(key.clone()),
            host: (!route.hosts.is_empty()).then(|| route.hosts.join(",")),
            path: Some(route.path.clone().unwrap_or_else(|| "/".to_string())),
            plugins: (!plugins.is_empty()).then_some(plugins),
            weight: route.weight,
            enable_reverse_proxy_headers: Some(true),
            ..Default::default()
        },
    );
    if let Some(server) = merged.servers.get_mut(&server_name) {
        let locations = server.locations.get_or_insert_with(Vec::new);
        if !locations.contains(&key) {
            locations.push(key.clone());
        }
    }
    if route.tls.as_deref() == Some("acme")
        && !route.hosts.is_empty()
        && !merged.certificates.contains_key(&key)
        && !cert_covers_hosts(&merged.certificates, &route.hosts)
    {
        merged.certificates.insert(
            key,
            CertificateConf {
                domains: Some(route.hosts.join(",")),
                acme: Some("lets_encrypt".to_string()),
                ..Default::default()
            },
        );
    }
}

/// Overlays Docker-label-discovered routes onto a static [`PingapConfig`] baseline
/// without mutating or overwriting static entries.
pub fn merge_docker_routes(
    base: &PingapConfig,
    routes: &[DockerLabelRoute],
) -> PingapConfig {
    let mut merged = base.clone();
    for route in routes {
        if route.addrs.is_empty() {
            continue;
        }
        attach_route(base, &mut merged, route);
    }
    merged
}

/// Background service that watches Docker container labels and hot-reloads
/// merged runtime routes.
pub struct DockerLabelService {
    config_manager: Arc<ConfigManager>,
}

/// Creates a new [`DockerLabelService`] bound to `config_manager`.
pub fn new_docker_label_service(
    config_manager: Arc<ConfigManager>,
) -> DockerLabelService {
    DockerLabelService { config_manager }
}

#[async_trait]
impl BackgroundService for DockerLabelService {
    async fn start(&self, shutdown: ShutdownWatch) {
        let watcher = match DockerLabelWatcher::connect(
            crate::webhook::get_webhook_sender(),
        ) {
            Ok(w) => w,
            Err(e) => {
                error!(
                    target: LOG_TARGET,
                    error = e.to_string(),
                    "connect docker for label discovery fail"
                );
                return;
            },
        };
        info!(target: LOG_TARGET, "docker label discovery service started");
        watcher
            .watch(shutdown, |routes| async move {
                DOCKER_ROUTES.store(Arc::new(routes.clone()));
                let base = STATIC_BASE_CONFIG
                    .load_full()
                    .unwrap_or_else(|| self.config_manager.get_current_config());
                if !base.basic.docker_labels_enabled.unwrap_or_default() {
                    return;
                }
                let merged = merge_docker_routes(&base, &routes);
                if let Err(e) = super::apply_runtime_config(
                    self.config_manager.clone(),
                    &merged,
                )
                .await
                {
                    let msg = format!("apply docker label routes fail: {e}");
                    error!(target: LOG_TARGET, error = msg, "docker label apply fail");
                    pingap_core::record_recent_event(pingap_core::RecentEvent {
                        kind: pingap_core::RecentEventKind::ReloadFail,
                        category: Some("docker_labels".to_string()),
                        message: msg,
                        ..Default::default()
                    });
                }
            })
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingap_config::{PluginConf, ServerConf};
    use pretty_assertions::assert_eq;

    fn sample_base_config() -> PingapConfig {
        let mut conf = PingapConfig::default();
        conf.basic.docker_labels_enabled = Some(true);
        conf.basic.docker_labels_server = Some("http_srv".to_string());
        conf.basic.docker_labels_tls_server = Some("https_srv".to_string());
        conf.servers.insert(
            "http_srv".to_string(),
            ServerConf {
                addr: "0.0.0.0:80".to_string(),
                locations: Some(vec!["static_loc".to_string()]),
                ..Default::default()
            },
        );
        conf.servers.insert(
            "https_srv".to_string(),
            ServerConf {
                addr: "0.0.0.0:443".to_string(),
                global_certificates: Some(true),
                ..Default::default()
            },
        );
        conf.upstreams.insert(
            "static_up".to_string(),
            UpstreamConf {
                addrs: vec!["127.0.0.1:9000".to_string()],
                ..Default::default()
            },
        );
        conf.locations.insert(
            "static_loc".to_string(),
            LocationConf {
                upstream: Some("static_up".to_string()),
                path: Some("/static".to_string()),
                ..Default::default()
            },
        );
        conf.plugins
            .insert("gzip".to_string(), PluginConf::default());
        conf
    }

    #[test]
    fn test_merge_docker_routes_selects_servers_filters_plugins_and_creates_acme()
     {
        let base = sample_base_config();
        let routes = vec![
            DockerLabelRoute {
                name: "web".to_string(),
                addrs: vec!["172.17.0.2:8080".to_string()],
                hosts: vec!["app.example.com".to_string()],
                path: Some("/api".to_string()),
                tls: Some("acme".to_string()),
                plugins: vec!["gzip".to_string(), "missing_plugin".to_string()],
                server: None,
                weight: Some(500),
            },
            DockerLabelRoute {
                name: "internal".to_string(),
                addrs: vec!["172.17.0.3:3000".to_string()],
                hosts: vec!["internal.local".to_string()],
                path: None,
                tls: None,
                plugins: vec![],
                server: None,
                weight: None,
            },
        ];

        let merged = merge_docker_routes(&base, &routes);
        assert_eq!(true, merged.upstreams.contains_key("static_up"));
        assert_eq!(true, merged.locations.contains_key("static_loc"));

        let web_loc = merged.locations.get("docker_web").unwrap();
        assert_eq!(Some("docker_web"), web_loc.upstream.as_deref());
        assert_eq!(Some("/api"), web_loc.path.as_deref());
        assert_eq!(Some("app.example.com"), web_loc.host.as_deref());
        assert_eq!(Some(vec!["gzip".to_string()]), web_loc.plugins);
        assert_eq!(Some(500), web_loc.weight);

        let web_cert = merged.certificates.get("docker_web").unwrap();
        assert_eq!(Some("app.example.com"), web_cert.domains.as_deref());
        assert_eq!(Some("lets_encrypt"), web_cert.acme.as_deref());

        let https_locs = merged
            .servers
            .get("https_srv")
            .unwrap()
            .locations
            .as_ref()
            .unwrap();
        assert_eq!(true, https_locs.contains(&"docker_web".to_string()));

        let http_locs = merged
            .servers
            .get("http_srv")
            .unwrap()
            .locations
            .as_ref()
            .unwrap();
        assert_eq!(
            vec!["static_loc".to_string(), "docker_internal".to_string()],
            *http_locs
        );
    }

    #[test]
    fn test_merge_docker_routes_does_not_overwrite_static_entries() {
        let mut base = sample_base_config();
        base.locations.insert(
            "docker_dup".to_string(),
            LocationConf {
                upstream: Some("static_up".to_string()),
                path: Some("/keep".to_string()),
                ..Default::default()
            },
        );
        let routes = vec![DockerLabelRoute {
            name: "dup".to_string(),
            addrs: vec!["172.17.0.9:80".to_string()],
            hosts: vec![],
            path: Some("/override".to_string()),
            tls: None,
            plugins: vec![],
            server: None,
            weight: None,
        }];

        let merged = merge_docker_routes(&base, &routes);
        assert_eq!(
            Some("/keep"),
            merged.locations.get("docker_dup").unwrap().path.as_deref()
        );
        assert_eq!(false, merged.upstreams.contains_key("docker_dup"));
    }
}
