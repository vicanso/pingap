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

use super::{
    Plugin, get_hash_key, get_int_conf, get_str_conf, get_str_slice_conf,
};
use crate::upstreams::new_upstream_provider;
use async_trait::async_trait;
use ctor::ctor;
use http::StatusCode;
use pingap_config::PluginConf;
use pingap_core::{Ctx, HttpResponse, PluginStep, RequestPluginResult};
use pingap_plugin::{Error, get_plugin_factory};
use pingap_upstream::UpstreamProvider;
use pingora::proxy::Session;
use serde::Serialize;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::Arc;
use tracing::debug;

static LOG_TARGET: &str = "main::health";

const CATEGORY: &str = "health";

type Result<T> = std::result::Result<T, Error>;

/// Answers a path with whether the upstreams behind this instance can
/// take requests: `200` when each of them has enough healthy backends,
/// `503` and which of them does not when one has too few.
///
/// The `ping` plugin answers `pong` for as long as the process runs,
/// which tells a load balancer or a Kubernetes probe that the proxy is
/// up and nothing of what is behind it.
pub struct Health {
    /// The path that is answered, compared as it is.
    path: String,
    /// The upstreams to look at; every one of them when empty.
    upstreams: Vec<String>,
    /// How many healthy backends an upstream needs.
    min_healthy: u32,
    hash_value: String,
}

/// What is known of one upstream.
#[derive(Serialize, Debug, PartialEq)]
struct UpstreamReadiness {
    /// Backends that are healthy and enabled.
    healthy: u32,
    total: u32,
    /// Whether that is enough.
    ready: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    unhealthy_backends: Vec<String>,
    /// Why it is not ready, where the numbers do not say.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
}

#[derive(Serialize, Debug, PartialEq)]
struct Readiness {
    ready: bool,
    upstreams: BTreeMap<String, UpstreamReadiness>,
}

/// Whether the upstreams named in `names` - or all of them, when none is
/// named - each have `min_healthy` backends that can take a request.
///
/// A transparent upstream has no backends of its own to look at, and is
/// left out unless it was named. An upstream that was named and does not
/// exist is not ready: a probe that reads `200` for it would be vouching
/// for something that is not there.
fn readiness(
    provider: &dyn UpstreamProvider,
    names: &[String],
    min_healthy: u32,
) -> Readiness {
    let mut upstreams = BTreeMap::new();
    let mut look_at = |name: &str, named: bool| {
        let Some(upstream) = provider.get(name) else {
            upstreams.insert(
                name.to_string(),
                UpstreamReadiness {
                    healthy: 0,
                    total: 0,
                    ready: false,
                    unhealthy_backends: vec![],
                    reason: Some("no such upstream"),
                },
            );
            return;
        };
        let Some(backends) = upstream.get_backends() else {
            if named {
                upstreams.insert(
                    name.to_string(),
                    UpstreamReadiness {
                        healthy: 0,
                        total: 0,
                        ready: true,
                        unhealthy_backends: vec![],
                        reason: Some("no backends of its own to check"),
                    },
                );
            }
            return;
        };
        let backend_set = backends.get_backend();
        let mut healthy = 0;
        let mut unhealthy_backends = vec![];
        for backend in backend_set.iter() {
            if backends.ready(backend) {
                healthy += 1;
            } else {
                unhealthy_backends.push(backend.to_string());
            }
        }
        unhealthy_backends.sort();
        upstreams.insert(
            name.to_string(),
            UpstreamReadiness {
                healthy,
                total: backend_set.len() as u32,
                ready: healthy >= min_healthy,
                unhealthy_backends,
                reason: None,
            },
        );
    };
    if names.is_empty() {
        for (name, _) in provider.list() {
            look_at(&name, false);
        }
    } else {
        for name in names {
            look_at(name, true);
        }
    }
    Readiness {
        ready: upstreams.values().all(|upstream| upstream.ready),
        upstreams,
    }
}

impl Health {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(
            target: LOG_TARGET,
            params = pingap_config::masked_toml(params),
            "new health plugin"
        );
        let invalid = |message: &str| Error::Invalid {
            category: CATEGORY.to_string(),
            message: message.to_string(),
        };
        let path = get_str_conf(params, "path");
        // No request path is empty, so without one the plugin could never
        // answer.
        if !path.starts_with('/') {
            return Err(invalid("path is required, and starts with /"));
        }
        let min_healthy = if params.contains_key("min_healthy") {
            u32::try_from(get_int_conf(params, "min_healthy"))
                .ok()
                .filter(|min_healthy| *min_healthy > 0)
                .ok_or_else(|| invalid("min_healthy must be at least 1"))?
        } else {
            1
        };
        Ok(Self {
            hash_value: get_hash_key(params),
            path,
            upstreams: get_str_slice_conf(params, "upstreams")
                .into_iter()
                .map(|name| name.trim().to_string())
                .filter(|name| !name.is_empty())
                .collect(),
            min_healthy,
        })
    }
}

#[async_trait]
impl Plugin for Health {
    #[inline]
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    #[inline]
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        _ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        if step != PluginStep::Request {
            return Ok(RequestPluginResult::Skipped);
        }
        if session.req_header().uri.path() != self.path {
            return Ok(RequestPluginResult::Skipped);
        }
        let provider = new_upstream_provider();
        let readiness =
            readiness(provider.as_ref(), &self.upstreams, self.min_healthy);
        let mut resp = HttpResponse::try_from_json(&readiness)
            .unwrap_or_else(|e| HttpResponse::unknown_error(e.to_string()));
        if !readiness.ready {
            resp.status = StatusCode::SERVICE_UNAVAILABLE;
        }
        Ok(RequestPluginResult::Respond(resp))
    }
}

#[ctor(unsafe)]
fn init() {
    get_plugin_factory()
        .register("health", |params| Ok(Arc::new(Health::new(params)?)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingap_config::UpstreamConf;
    use pingap_upstream::Upstream;
    use pretty_assertions::assert_eq;

    struct Upstreams(Vec<(String, Arc<Upstream>)>);

    impl UpstreamProvider for Upstreams {
        fn get(&self, name: &str) -> Option<Arc<Upstream>> {
            self.0
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, upstream)| upstream.clone())
        }
        fn list(&self) -> Vec<(String, Arc<Upstream>)> {
            self.0.clone()
        }
    }

    fn upstream(name: &str, conf: UpstreamConf) -> (String, Arc<Upstream>) {
        (
            name.to_string(),
            Arc::new(Upstream::new(name, &conf, None).unwrap()),
        )
    }

    /// Takes the backend at `addr` of the upstream out of service, as a
    /// failed health check does.
    fn take_down(upstream: &Upstream, addr: &str) {
        let backends = upstream.get_backends().unwrap();
        for backend in backends.get_backend().iter() {
            if backend.to_string().contains(addr) {
                backends.set_enable(backend, false);
            }
        }
    }

    #[test]
    fn test_readiness() {
        let two = |ports: [u16; 2]| UpstreamConf {
            addrs: ports
                .iter()
                .map(|port| format!("127.0.0.1:{port}"))
                .collect(),
            ..Default::default()
        };
        let provider = Upstreams(vec![
            upstream("api", two([5001, 5002])),
            upstream("web", two([5003, 5004])),
            upstream(
                "any",
                UpstreamConf {
                    addrs: vec![],
                    discovery: Some("transparent".to_string()),
                    ..Default::default()
                },
            ),
        ]);
        let all: Vec<String> = vec![];
        let named = |names: &[&str]| -> Vec<String> {
            names.iter().map(|name| name.to_string()).collect()
        };

        // Everything is up. The transparent upstream has nothing to look
        // at and is left out.
        let ready = readiness(&provider, &all, 1);
        assert_eq!(true, ready.ready);
        assert_eq!(
            vec!["api", "web"],
            ready
                .upstreams
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>()
        );
        assert_eq!((2, 2), (ready.upstreams["api"].healthy, 2));

        // One backend of `api` goes: still enough of them for one, not
        // for two.
        take_down(&provider.get("api").unwrap(), "5001");
        let ready = readiness(&provider, &all, 1);
        assert_eq!(true, ready.ready);
        assert_eq!(1, ready.upstreams["api"].healthy);
        assert_eq!(
            vec!["127.0.0.1:5001".to_string()],
            ready.upstreams["api"].unhealthy_backends
        );
        let ready = readiness(&provider, &all, 2);
        assert_eq!(false, ready.ready);
        assert_eq!(
            (false, true),
            (ready.upstreams["api"].ready, ready.upstreams["web"].ready)
        );
        // Only the ones that were asked about count.
        assert_eq!(true, readiness(&provider, &named(&["web"]), 2).ready);
        assert_eq!(false, readiness(&provider, &named(&["api"]), 2).ready);

        // The other goes too: nothing left to send a request to.
        take_down(&provider.get("api").unwrap(), "5002");
        let ready = readiness(&provider, &all, 1);
        assert_eq!(false, ready.ready);
        assert_eq!(0, ready.upstreams["api"].healthy);

        // An upstream that was named and is not there is not ready, a
        // transparent one that was named has nothing that could be down.
        let ready = readiness(&provider, &named(&["web", "gone"]), 1);
        assert_eq!(false, ready.ready);
        assert_eq!(Some("no such upstream"), ready.upstreams["gone"].reason);
        let ready = readiness(&provider, &named(&["web", "any"]), 1);
        assert_eq!(true, ready.ready);

        // What a probe reads.
        let ready = readiness(&provider, &named(&["api"]), 1);
        assert_eq!(
            r#"{"ready":false,"upstreams":{"api":{"healthy":0,"total":2,"ready":false,"unhealthy_backends":["127.0.0.1:5001","127.0.0.1:5002"]}}}"#,
            serde_json::to_string(&ready).unwrap()
        );
    }

    #[test]
    fn test_health_params() {
        let new = |conf: &str| {
            Health::new(&toml::from_str::<PluginConf>(conf).unwrap())
        };
        let health = new(
            "path = \"/ready\"\nupstreams = [\"api\", \" web \", \"\"]\nmin_healthy = 2",
        )
        .unwrap();
        assert_eq!("/ready", health.path);
        assert_eq!(vec!["api", "web"], health.upstreams);
        assert_eq!(2, health.min_healthy);
        assert_eq!(1, new("path = \"/ready\"").unwrap().min_healthy);

        let error = |conf: &str| new(conf).err().unwrap().to_string();
        let prefix = "Plugin health invalid, message: ";
        for conf in ["", "path = \"ready\""] {
            assert_eq!(
                format!("{prefix}path is required, and starts with /"),
                error(conf)
            );
        }
        for min_healthy in [0, -1] {
            assert_eq!(
                format!("{prefix}min_healthy must be at least 1"),
                error(&format!(
                    "path = \"/ready\"\nmin_healthy = {min_healthy}"
                ))
            );
        }
    }
}
