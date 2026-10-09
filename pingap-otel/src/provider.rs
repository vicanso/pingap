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

use ahash::AHashMap;
use arc_swap::ArcSwap;
use opentelemetry::global::{BoxedTracer, ObjectSafeTracerProvider};
use opentelemetry::{InstrumentationScope, trace};
use std::sync::Arc;
use std::sync::LazyLock;

/// A wrapper around a TracerProvider that implements the ObjectSafeTracerProvider trait.
/// This allows for dynamic dispatch and storage of different tracer provider implementations.
#[derive(Clone)]
pub struct InstanceTracerProvider {
    provider: Arc<dyn ObjectSafeTracerProvider + Send + Sync>,
}

impl InstanceTracerProvider {
    /// Creates a new InstanceTracerProvider by wrapping the provided TracerProvider implementation.
    ///
    /// # Type Parameters
    /// * `P` - The concrete TracerProvider type
    /// * `T` - The Tracer type produced by the provider
    /// * `S` - The Span type produced by the tracer
    ///
    /// # Arguments
    /// * `provider` - The TracerProvider implementation to wrap
    fn new<P, T, S>(provider: P) -> Self
    where
        S: trace::Span + Send + Sync + 'static,
        T: trace::Tracer<Span = S> + Send + Sync + 'static,
        P: trace::TracerProvider<Tracer = T> + Send + Sync + 'static,
    {
        InstanceTracerProvider {
            provider: Arc::new(provider),
        }
    }
}

impl trace::TracerProvider for InstanceTracerProvider {
    type Tracer = BoxedTracer;

    fn tracer_with_scope(&self, scope: InstrumentationScope) -> Self::Tracer {
        BoxedTracer::new(self.provider.boxed_tracer(scope))
    }
}

/// Global storage for tracer providers, mapping names to provider instances.
/// Uses ArcSwap for atomic updates and AHashMap for efficient lookups.
type TracerProviders = AHashMap<String, InstanceTracerProvider>;

static TRACER_PROVIDER_MAP: LazyLock<ArcSwap<TracerProviders>> =
    LazyLock::new(|| ArcSwap::from_pointee(AHashMap::new()));

/// Adds or updates a named tracer provider in the global provider map.
///
/// # Arguments
/// * `name` - The unique identifier for the provider
/// * `provider` - The TracerProvider instance to add
///
/// The servers of a process start their exporters at the same moment,
/// each from a runtime of its own. The map used to be read, copied and
/// stored back: two that read it together each stored a map with
/// themselves and without the other, and of several servers with an
/// exporter only the last to store was traced - which one, by chance.
/// The update is now made over whatever map is current when it lands.
pub fn add_provider(
    name: &str,
    provider: opentelemetry_sdk::trace::SdkTracerProvider,
) {
    let provider = InstanceTracerProvider::new(provider);
    TRACER_PROVIDER_MAP.rcu(|current| {
        let mut providers: TracerProviders = current.as_ref().clone();
        providers.insert(name.to_string(), provider.clone());
        providers
    });
}

/// Retrieves a tracer provider by name from the global provider map.
///
/// # Arguments
/// * `name` - The identifier of the provider to retrieve
///
/// # Returns
/// * `Option<InstanceTracerProvider>` - The provider if found, None otherwise
#[inline]
pub fn get_provider(name: &str) -> Option<InstanceTracerProvider> {
    TRACER_PROVIDER_MAP.load().get(name).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: providers that are added at the same moment are all
    /// there afterwards. Each used to store a copy of the map as it had
    /// read it, without the ones that were being added beside it.
    #[test]
    fn test_providers_added_together_are_all_kept() {
        let names: Vec<String> =
            (0..16).map(|index| format!("together-{index}")).collect();
        for _ in 0..50 {
            let barrier =
                std::sync::Arc::new(std::sync::Barrier::new(names.len()));
            let threads: Vec<_> = names
                .iter()
                .cloned()
                .map(|name| {
                    let barrier = barrier.clone();
                    std::thread::spawn(move || {
                        let provider =
                            opentelemetry_sdk::trace::SdkTracerProvider::builder()
                                .build();
                        barrier.wait();
                        add_provider(&name, provider);
                    })
                })
                .collect();
            for thread in threads {
                thread.join().expect("thread");
            }
            for name in names.iter() {
                assert!(get_provider(name).is_some(), "{name}");
            }
            // Start over: without them, for the next round.
            TRACER_PROVIDER_MAP.rcu(|current| {
                let mut providers: TracerProviders = current.as_ref().clone();
                providers.retain(|name, _| !name.starts_with("together-"));
                providers
            });
        }
        assert!(get_provider("together-0").is_none());
    }
}
