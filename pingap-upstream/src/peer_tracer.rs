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

use crate::LOG_CATEGORY;
use pingora::upstreams::peer::Tracing;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use tracing::debug;

// UpstreamPeerTracer tracks active connections to upstream servers
#[derive(Clone, Debug)]
pub(crate) struct UpstreamPeerTracer {
    name: String,
    connected: Arc<AtomicI32>, // Number of active connections
}

impl UpstreamPeerTracer {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            connected: Arc::new(AtomicI32::new(0)),
        }
    }
    #[inline]
    pub fn connected(&self) -> i32 {
        self.connected.load(Ordering::Relaxed)
    }
}

impl Tracing for UpstreamPeerTracer {
    fn on_connected(&self) {
        debug!(
            category = LOG_CATEGORY,
            name = self.name,
            "upstream peer connected"
        );
        self.connected.fetch_add(1, Ordering::Relaxed);
    }
    fn on_disconnected(&self) {
        debug!(
            category = LOG_CATEGORY,
            name = self.name,
            "upstream peer disconnected"
        );
        self.connected.fetch_sub(1, Ordering::Relaxed);
    }
    fn boxed_clone(&self) -> Box<dyn Tracing> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::UpstreamPeerTracer;
    use pingora::upstreams::peer::Tracing;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_upstream_peer_tracer() {
        let tracer = UpstreamPeerTracer::new("upstreamname");
        tracer.on_connected();
        assert_eq!(1, tracer.connected());
        tracer.on_disconnected();
        assert_eq!(0, tracer.connected());
    }
}
