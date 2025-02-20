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

use async_trait::async_trait;
use humantime::parse_duration;
use opentelemetry::{
    global::{self, BoxedTracer},
    propagation::{TextMapCompositePropagator, TextMapPropagator},
    trace::TracerProvider,
    KeyValue,
};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    propagation::{BaggagePropagator, TraceContextPropagator},
    trace::{BatchConfigBuilder, RandomIdGenerator, Sampler},
    Resource,
};
use pingora::{server::ShutdownWatch, services::background::BackgroundService};
use std::time::Duration;
use tracing::{error, info};
use url::Url;

const LOG_CATEGORY: &str = "otel";
/// Default configuration values
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);
const DEFAULT_MAX_ATTRIBUTES: u32 = 16;
const DEFAULT_MAX_EVENTS: u32 = 16;
const DEFAULT_MAX_QUEUE_SIZE: usize = 2048;
const DEFAULT_SCHEDULED_DELAY: Duration = Duration::from_secs(5);
const DEFAULT_MAX_EXPORT_BATCH_SIZE: usize = 512;
const DEFAULT_MAX_EXPORT_TIMEOUT: Duration = Duration::from_secs(30);

/// Configuration for the tracer service
#[derive(Debug, Clone)]
pub struct TracerConfig {
    /// Timeout duration for exporting spans
    timeout: Duration,
    /// Maximum number of attributes allowed per span
    max_attributes: u32,
    /// Maximum number of events allowed per span
    max_events: u32,
    /// Maximum size of the span queue before dropping
    max_queue_size: usize,
    /// Delay between scheduled exports of spans
    scheduled_delay: Duration,
    /// Maximum number of spans to export in a single batch
    max_export_batch_size: usize,
    /// Maximum timeout duration for exporting a batch
    max_export_timeout: Duration,
    /// Enable Jaeger propagation format support
    support_jaeger_propagator: bool,
    /// Enable W3C Baggage propagation format support
    support_baggage_propagator: bool,
}

impl Default for TracerConfig {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            max_attributes: DEFAULT_MAX_ATTRIBUTES,
            max_events: DEFAULT_MAX_EVENTS,
            max_queue_size: DEFAULT_MAX_QUEUE_SIZE,
            scheduled_delay: DEFAULT_SCHEDULED_DELAY,
            max_export_batch_size: DEFAULT_MAX_EXPORT_BATCH_SIZE,
            max_export_timeout: DEFAULT_MAX_EXPORT_TIMEOUT,
            support_jaeger_propagator: false,
            support_baggage_propagator: false,
        }
    }
}

/// Service for managing OpenTelemetry tracing
///
/// This service handles the configuration and lifecycle of OpenTelemetry tracing,
/// including span export to a collector endpoint.
///
/// # Fields
/// * `name` - The service name used for identifying traces
/// * `endpoint` - The OpenTelemetry collector endpoint URL
/// * `config` - Configuration options for the tracer
#[derive(Debug)]
pub struct TracerService {
    name: String,
    endpoint: String,
    config: TracerConfig,
}

impl TracerService {
    /// Creates a new TracerService builder
    pub fn builder() -> TracerServiceBuilder {
        TracerServiceBuilder::default()
    }

    /// Creates a new TracerService with default configuration
    pub fn new(name: &str, endpoint: &str) -> Self {
        Self::builder().name(name).endpoint(endpoint).build()
    }
}

/// Builder for TracerService
#[derive(Default)]
pub struct TracerServiceBuilder {
    name: Option<String>,
    endpoint: Option<String>,
    config: TracerConfig,
}

impl TracerServiceBuilder {
    /// Sets the service name for the tracer
    ///
    /// # Arguments
    /// * `name` - The name of the service
    pub fn name(mut self, name: &str) -> Self {
        self.name = Some(name.to_string());
        self
    }

    /// Sets the endpoint URL for the tracer and parses any configuration from query parameters
    ///
    /// # Arguments
    /// * `endpoint` - The endpoint URL string
    pub fn endpoint(mut self, endpoint: &str) -> Self {
        self.endpoint = Some(endpoint.to_string());
        if let Ok(info) = Url::parse(endpoint) {
            self.parse_query_params(&info);
        }
        self
    }

    /// Parses configuration options from URL query parameters
    ///
    /// # Arguments
    /// * `url` - The parsed URL containing query parameters
    fn parse_query_params(&mut self, url: &Url) {
        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "timeout" => {
                    if let Ok(v) = parse_duration(&value) {
                        self.config.timeout = v;
                    }
                },
                "max_queue_size" => {
                    if let Ok(v) = value.parse::<usize>() {
                        self.config.max_queue_size = v;
                    }
                },
                "scheduled_delay" => {
                    if let Ok(v) = parse_duration(&value) {
                        self.config.scheduled_delay = v;
                    }
                },
                "max_export_batch_size" => {
                    if let Ok(v) = value.parse::<usize>() {
                        self.config.max_export_batch_size = v;
                    }
                },
                "max_export_timeout" => {
                    if let Ok(v) = parse_duration(&value) {
                        self.config.max_export_timeout = v;
                    }
                },
                "max_attributes" => {
                    if let Ok(v) = value.parse::<u32>() {
                        self.config.max_attributes = v;
                    }
                },
                "max_events" => {
                    if let Ok(v) = value.parse::<u32>() {
                        self.config.max_events = v;
                    }
                },
                "jaeger" => {
                    self.config.support_jaeger_propagator = true;
                },
                "baggage" => {
                    self.config.support_baggage_propagator = true;
                },
                _ => {},
            }
        }
    }

    /// Builds and returns a new TracerService with the configured options
    pub fn build(self) -> TracerService {
        TracerService {
            name: self.name.unwrap_or_else(|| "default".to_string()),
            endpoint: self
                .endpoint
                .unwrap_or_else(|| "http://localhost:4317".to_string()),
            config: self.config,
        }
    }
}

/// Gets the full service name by adding the 'pingap-' prefix
///
/// # Arguments
/// * `name` - Base service name
#[inline]
fn get_service_name(name: &str) -> String {
    format!("pingap-{name}")
}

/// Creates a new BoxedTracer for the given service name
///
/// # Arguments
/// * `name` - The service name to create a tracer for
///
/// # Returns
/// * `Option<BoxedTracer>` - The created tracer if successful, None otherwise
#[inline]
pub fn new_tracer(name: &str) -> Option<BoxedTracer> {
    if let Some(provider) = provider::get_provider(name) {
        return Some(provider.tracer(get_service_name(name)));
    }
    None
}

#[async_trait]
impl BackgroundService for TracerService {
    /// Open telemetry background service, it will schedule export data to server.
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let result = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(&self.endpoint)
            .with_timeout(self.config.timeout)
            .build()
            .map(|exporter| {
                let batch =
                    opentelemetry_sdk::trace::BatchSpanProcessor::builder(
                        exporter,
                        opentelemetry_sdk::runtime::Tokio,
                    )
                    .with_batch_config(
                        BatchConfigBuilder::default()
                            .with_max_queue_size(self.config.max_queue_size)
                            .with_scheduled_delay(self.config.scheduled_delay)
                            .with_max_export_batch_size(
                                self.config.max_export_batch_size,
                            )
                            .with_max_export_timeout(
                                self.config.max_export_timeout,
                            )
                            .build(),
                    )
                    .build();
                opentelemetry_sdk::trace::TracerProvider::builder()
                    .with_span_processor(batch)
                    .with_sampler(Sampler::AlwaysOn)
                    .with_id_generator(RandomIdGenerator::default())
                    .with_max_attributes_per_span(self.config.max_attributes)
                    .with_max_events_per_span(self.config.max_events)
                    .with_resource(Resource::new(vec![KeyValue::new(
                        "service.name",
                        get_service_name(&self.name),
                    )]))
                    .build()
            });

        match result {
            Ok(tracer_provider) => {
                info!(
                    category = LOG_CATEGORY,
                    name = self.name,
                    endpoint = self.endpoint,
                    "opentelemetry init success"
                );
                let mut propagators: Vec<
                    Box<dyn TextMapPropagator + Send + Sync>,
                > = vec![Box::new(TraceContextPropagator::new())];
                if self.config.support_jaeger_propagator {
                    propagators.push(Box::new(
                        opentelemetry_jaeger_propagator::Propagator::new(),
                    ));
                }
                if self.config.support_baggage_propagator {
                    propagators.push(Box::new(BaggagePropagator::new()));
                }
                global::set_text_map_propagator(
                    TextMapCompositePropagator::new(propagators),
                );

                // set tracer provider
                provider::add_provider(&self.name, tracer_provider.clone());

                let _ = shutdown.changed().await;
                if let Err(e) = tracer_provider.shutdown() {
                    error!(
                        category = LOG_CATEGORY,
                        name = self.name,
                        error = %e,
                        "opentelemetry shutdown fail"
                    );
                } else {
                    info!(
                        category = LOG_CATEGORY,
                        name = self.name,
                        "opentelemetry shutdown success"
                    );
                }
            },
            Err(e) => {
                error!(
                    category = LOG_CATEGORY,
                    name = self.name,
                    error = %e,
                    "opentelemetry init fail"
                );
            },
        }
    }
}

mod provider;
