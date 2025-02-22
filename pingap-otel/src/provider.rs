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
use once_cell::sync::Lazy;
use opentelemetry::global::{BoxedTracer, ObjectSafeTracerProvider};
use opentelemetry::{trace, InstrumentationScope};
use std::sync::Arc;

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

static TRACER_PROVIDER_MAP: Lazy<ArcSwap<TracerProviders>> =
    Lazy::new(|| ArcSwap::from_pointee(AHashMap::new()));

/// Adds or updates a named tracer provider in the global provider map.
///
/// # Arguments
/// * `name` - The unique identifier for the provider
/// * `provider` - The TracerProvider instance to add
///
/// # Note
/// This operation creates a new copy of the provider map to ensure thread safety
pub fn add_provider(
    name: &str,
    provider: opentelemetry_sdk::trace::SdkTracerProvider,
) {
    let mut m: TracerProviders = AHashMap::new();
    for (name, provider) in TRACER_PROVIDER_MAP.load().iter() {
        m.insert(name.to_string(), provider.clone());
    }
    m.insert(name.to_string(), InstanceTracerProvider::new(provider));
    TRACER_PROVIDER_MAP.store(Arc::new(m));
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
