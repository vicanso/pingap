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

use super::provider;
use async_trait::async_trait;
use humantime::parse_duration;
use opentelemetry::{
    global::{self, BoxedTracer},
    propagation::{TextMapCompositePropagator, TextMapPropagator},
    trace::TracerProvider,
};
use opentelemetry_otlp::tonic_types::metadata::MetadataMap;
use opentelemetry_otlp::{
    Compression, WithExportConfig, WithHttpConfig, WithTonicConfig,
};
use opentelemetry_sdk::{
    Resource,
    propagation::{BaggagePropagator, TraceContextPropagator},
    trace::{BatchConfigBuilder, RandomIdGenerator, Sampler},
};

use pingora::{server::ShutdownWatch, services::background::BackgroundService};
use std::collections::HashMap;
use std::time::Duration;
use tracing::{error, info, warn};
use url::Url;

const LOG_TARGET: &str = "pingap::otel";
/// Default configuration values
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);
const DEFAULT_MAX_ATTRIBUTES: u32 = 16;
const DEFAULT_MAX_EVENTS: u32 = 16;
const DEFAULT_MAX_QUEUE_SIZE: usize = 2048;
const DEFAULT_SCHEDULED_DELAY: Duration = Duration::from_secs(5);
const DEFAULT_MAX_EXPORT_BATCH_SIZE: usize = 512;
const DEFAULT_MAX_EXPORT_TIMEOUT: Duration = Duration::from_secs(30);

/// Which requests are traced.
#[derive(Debug, Clone, Copy, PartialEq)]
enum SamplerKind {
    AlwaysOn,
    AlwaysOff,
    /// A share of the traces, by their id.
    TraceIdRatio,
    /// As the caller decided, where it sent a trace of its own, and by
    /// the sampler named after it otherwise.
    ParentBasedAlwaysOn,
    ParentBasedAlwaysOff,
    ParentBasedTraceIdRatio,
}

impl SamplerKind {
    fn parse(value: &str) -> Option<Self> {
        Some(match value.trim().to_ascii_lowercase().as_str() {
            "always_on" => Self::AlwaysOn,
            "always_off" => Self::AlwaysOff,
            "traceidratio" => Self::TraceIdRatio,
            "parentbased_always_on" => Self::ParentBasedAlwaysOn,
            "parentbased_always_off" => Self::ParentBasedAlwaysOff,
            "parentbased_traceidratio" => Self::ParentBasedTraceIdRatio,
            _ => return None,
        })
    }

    fn sampler(self, ratio: f64) -> Sampler {
        match self {
            Self::AlwaysOn => Sampler::AlwaysOn,
            Self::AlwaysOff => Sampler::AlwaysOff,
            Self::TraceIdRatio => Sampler::TraceIdRatioBased(ratio),
            Self::ParentBasedAlwaysOn => {
                Sampler::ParentBased(Box::new(Sampler::AlwaysOn))
            },
            Self::ParentBasedAlwaysOff => {
                Sampler::ParentBased(Box::new(Sampler::AlwaysOff))
            },
            Self::ParentBasedTraceIdRatio => Sampler::ParentBased(Box::new(
                Sampler::TraceIdRatioBased(ratio),
            )),
        }
    }
}

/// How the spans are sent.
#[derive(Debug, Clone, Copy, PartialEq)]
enum ExportProtocol {
    /// OTLP over gRPC, to port 4317 by convention.
    Grpc,
    /// OTLP over HTTP with a protobuf body, to `/v1/traces` on port 4318
    /// by convention: for a collector behind a proxy that does not pass
    /// gRPC, or a service that only takes this.
    Http,
}

/// `Name:Value` as its two parts, where it is a header.
fn parse_header(value: &str) -> Option<(String, String)> {
    let (name, value) = value.split_once(':')?;
    let name = http::HeaderName::from_bytes(name.trim().as_bytes()).ok()?;
    let value = http::HeaderValue::from_str(value.trim()).ok()?;
    Some((name.to_string(), value.to_str().ok()?.to_string()))
}

/// What of the parameters of an exporter url is wrong, for the ones that
/// are refused when they are: `sampler`, `sample_ratio`, `protocol` and
/// `header`. A sampler that is not known would otherwise be every
/// request traced, where one in a hundred was asked for.
///
/// The parameters that were there before these are read as they always
/// were: one that does not parse leaves its default in place.
pub fn validate_endpoint(endpoint: &str) -> Result<(), String> {
    // What is no url has none of these parameters. It is left to the
    // exporter, which reports what it makes of it when it starts, as it
    // always did: a process that started with such a value still does.
    let Ok(url) = Url::parse(endpoint) else {
        return Ok(());
    };
    let mut sampler = SamplerKind::AlwaysOn;
    let mut ratio = None;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "sampler" => {
                if let Some(kind) = SamplerKind::parse(&value) {
                    sampler = kind;
                }
            },
            "sample_ratio" => ratio = Some(value.to_string()),
            _ => {},
        }
        let valid = match key.as_ref() {
            "sampler" => SamplerKind::parse(&value).is_some(),
            "sample_ratio" => value
                .parse::<f64>()
                .is_ok_and(|ratio| (0.0..=1.0).contains(&ratio)),
            "protocol" => matches!(
                value.to_ascii_lowercase().as_str(),
                "grpc" | "http" | "http/protobuf"
            ),
            // Its value is not put into the message: a token.
            "header" => {
                if parse_header(&value).is_none() {
                    return Err("otlp exporter: header should be Name:Value"
                        .to_string());
                }
                true
            },
            _ => true,
        };
        if !valid {
            return Err(format!("otlp exporter: {key}({value}) is invalid"));
        }
    }
    // A ratio that no sampler goes by: every request would be traced,
    // where a share of them was asked for.
    if let Some(ratio) = ratio
        && !matches!(
            sampler,
            SamplerKind::TraceIdRatio | SamplerKind::ParentBasedTraceIdRatio
        )
    {
        return Err(format!(
            "otlp exporter: sample_ratio({ratio}) needs sampler=traceidratio or parentbased_traceidratio"
        ));
    }
    Ok(())
}

/// `endpoint` without its parameters, which is what may be shown of it:
/// a `header` among them is a credential.
pub fn endpoint_without_query(endpoint: &str) -> &str {
    endpoint.split(['?', '#']).next().unwrap_or_default()
}

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
    compression: Option<Compression>,
    /// Which requests are traced: all of them, where nothing is said.
    sampler: SamplerKind,
    /// The share a ratio sampler takes, from 0 to 1.
    sample_ratio: f64,
    protocol: ExportProtocol,
    /// Headers of each export: what a collector asks for to take it.
    headers: Vec<(String, String)>,
    /// `max_export_timeout` was given. The batch processor has no such
    /// setting to pass it to: said once, when the service starts.
    max_export_timeout_set: bool,
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
            compression: None,
            sampler: SamplerKind::AlwaysOn,
            sample_ratio: 1.0,
            protocol: ExportProtocol::Grpc,
            headers: vec![],
            max_export_timeout_set: false,
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
                    self.config.max_export_timeout_set = true;
                    if let Ok(v) = parse_duration(&value) {
                        self.config.max_export_timeout = v;
                    }
                },
                "sampler" => {
                    if let Some(sampler) = SamplerKind::parse(&value) {
                        self.config.sampler = sampler;
                    }
                },
                "sample_ratio" => {
                    if let Ok(ratio) = value.parse::<f64>()
                        && (0.0..=1.0).contains(&ratio)
                    {
                        self.config.sample_ratio = ratio;
                    }
                },
                "protocol" => {
                    self.config.protocol =
                        match value.to_ascii_lowercase().as_str() {
                            "http" | "http/protobuf" => ExportProtocol::Http,
                            _ => ExportProtocol::Grpc,
                        };
                },
                "header" => {
                    if let Some(header) = parse_header(&value) {
                        self.config.headers.push(header);
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
                "compression" => {
                    if value.to_lowercase() == "zstd" {
                        self.config.compression = Some(Compression::Zstd);
                    } else {
                        self.config.compression = Some(Compression::Gzip);
                    }
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

/// Writes the context of a span through `injector`, in the formats the
/// configured propagators carry: `traceparent` and `tracestate`, and the
/// Jaeger and baggage headers where those were asked for.
///
/// It is what a request to an upstream needs so that the spans the
/// upstream starts are children of the proxy's.
///
/// `client_traceparent` is the `traceparent` the request came with. Where
/// the span continues that trace, the flags of the client are passed on
/// and not the span's own. With the sampler that traces everything, which
/// is the one there is unless another is asked for, every span of the
/// proxy is sampled: told so, an upstream that samples what its parent
/// sampled would record a trace the client had decided not to. A sampler
/// that goes by the parent comes to the flags of the client by itself.
pub fn inject_span_context(
    span_context: &opentelemetry::trace::SpanContext,
    client_traceparent: Option<&str>,
    injector: &mut dyn opentelemetry::propagation::Injector,
) {
    use opentelemetry::trace::{SpanContext, TraceContextExt, TraceFlags};
    if !span_context.is_valid() {
        return;
    }
    let client_flags = client_traceparent.and_then(|traceparent| {
        let mut parts = traceparent.trim().split('-');
        let (_version, trace_id, _span_id, flags) =
            (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
        if !trace_id.eq_ignore_ascii_case(&span_context.trace_id().to_string())
        {
            return None;
        }
        u8::from_str_radix(flags, 16).ok()
    });
    // A span that is not sampled is not exported, and no parent to hang
    // anything from. Where the client has a trace of its own, the
    // upstream is left with the client's `traceparent` as it came: what
    // it records hangs from the client's span. Told the id of the span
    // that was dropped, it recorded spans whose parent was nowhere.
    if client_flags.is_some() && !span_context.is_sampled() {
        return;
    }
    let span_context = match client_flags {
        Some(flags) => SpanContext::new(
            span_context.trace_id(),
            span_context.span_id(),
            TraceFlags::new(flags),
            true,
            span_context.trace_state().clone(),
        ),
        None => span_context.clone(),
    };
    let cx =
        opentelemetry::Context::new().with_remote_span_context(span_context);
    global::get_text_map_propagator(|propagator| {
        propagator.inject_context(&cx, injector);
    });
}

/// Gets the full service name by adding the 'pingap:' prefix
///
/// # Arguments
/// * `name` - Base service name
#[inline]
fn get_service_name(name: &str) -> String {
    format!("pingap:{name}")
}

/// Creates a new BoxedTracer for the given service name
///
/// # Arguments
/// * `name` - The service name to create a tracer for
///
/// # Returns
/// * `Option<BoxedTracer>` - The created tracer if successful, None otherwise
#[inline]
pub fn new_http_proxy_tracer(name: &str) -> Option<BoxedTracer> {
    if let Some(provider) = provider::get_provider(name) {
        return Some(provider.tracer("http_proxy"));
    }
    None
}

impl TracerService {
    /// Where an export over HTTP is posted: the url as it is written,
    /// less its parameters, and `/v1/traces` where it names no path.
    fn http_endpoint(&self) -> String {
        let endpoint = endpoint_without_query(&self.endpoint);
        match Url::parse(endpoint) {
            Ok(url) if url.path().is_empty() || url.path() == "/" => {
                format!("{}/v1/traces", endpoint.trim_end_matches('/'))
            },
            _ => endpoint.to_string(),
        }
    }

    fn new_exporter(
        &self,
    ) -> Result<
        opentelemetry_otlp::SpanExporter,
        opentelemetry_otlp::ExporterBuildError,
    > {
        match self.config.protocol {
            ExportProtocol::Grpc => {
                // Without the parameters, which are for this crate and
                // not for the collector: with them, an endpoint that
                // could not be used was reported with all of them, the
                // token of a `header` included.
                let mut builder = opentelemetry_otlp::SpanExporter::builder()
                    .with_tonic()
                    .with_endpoint(endpoint_without_query(&self.endpoint))
                    .with_timeout(self.config.timeout);
                if let Some(compression) = self.config.compression {
                    builder = builder.with_compression(compression);
                }
                if !self.config.headers.is_empty() {
                    let mut headers = http::HeaderMap::new();
                    for (name, value) in self.config.headers.iter() {
                        if let (Ok(name), Ok(value)) = (
                            http::HeaderName::from_bytes(name.as_bytes()),
                            http::HeaderValue::from_str(value),
                        ) {
                            headers.append(name, value);
                        }
                    }
                    builder = builder
                        .with_metadata(MetadataMap::from_headers(headers));
                }
                builder.build()
            },
            ExportProtocol::Http => {
                let headers: HashMap<String, String> =
                    self.config.headers.iter().cloned().collect();
                opentelemetry_otlp::SpanExporter::builder()
                    .with_http()
                    .with_endpoint(self.http_endpoint())
                    .with_timeout(self.config.timeout)
                    .with_headers(headers)
                    .build()
            },
        }
    }
}

#[async_trait]
impl BackgroundService for TracerService {
    /// Open telemetry background service, it will schedule export data to server.
    async fn start(&self, mut shutdown: ShutdownWatch) {
        if self.config.max_export_timeout_set {
            warn!(
                target: LOG_TARGET,
                name = self.name,
                "max_export_timeout is not used, the time an export may take is timeout"
            );
        }
        let result = self.new_exporter().map(|exporter| {
            let batch =
                opentelemetry_sdk::trace::BatchSpanProcessor::builder(exporter)
                    .with_batch_config(
                        BatchConfigBuilder::default()
                            .with_max_queue_size(self.config.max_queue_size)
                            .with_scheduled_delay(self.config.scheduled_delay)
                            .with_max_export_batch_size(
                                self.config.max_export_batch_size,
                            )
                            // .with_max_export_timeout(
                            //     self.config.max_export_timeout,
                            // )
                            .build(),
                    )
                    .build();
            opentelemetry_sdk::trace::SdkTracerProvider::builder()
                .with_span_processor(batch)
                .with_sampler(
                    self.config.sampler.sampler(self.config.sample_ratio),
                )
                .with_id_generator(RandomIdGenerator::default())
                .with_max_attributes_per_span(self.config.max_attributes)
                .with_max_events_per_span(self.config.max_events)
                .with_resource(
                    Resource::builder()
                        .with_service_name(get_service_name(&self.name))
                        .build(),
                )
                .build()
        });

        match result {
            Ok(tracer_provider) => {
                let mut propagators: Vec<
                    Box<dyn TextMapPropagator + Send + Sync>,
                > = vec![Box::new(TraceContextPropagator::new())];
                if self.config.support_jaeger_propagator {
                    // The Jaeger propagation format is deprecated upstream in
                    // favor of W3C TraceContext, but we keep it as an opt-in
                    // for interop with existing Jaeger deployments.
                    #[allow(deprecated)]
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
                info!(
                    target: LOG_TARGET,
                    name = self.name,
                    // Without its parameters: a header among them is a
                    // credential.
                    endpoint = endpoint_without_query(&self.endpoint),
                    protocol = ?self.config.protocol,
                    sampler = ?self.config.sampler,
                    sample_ratio = self.config.sample_ratio,
                    support_jaeger_propagator =
                        self.config.support_jaeger_propagator,
                    support_baggage_propagator =
                        self.config.support_baggage_propagator,
                    "opentelemetry init success"
                );

                let _ = shutdown.changed().await;
                if let Err(e) = tracer_provider.shutdown() {
                    error!(
                        target: LOG_TARGET,
                        name = self.name,
                        error = %e,
                        "opentelemetry shutdown fail"
                    );
                } else {
                    info!(
                        target: LOG_TARGET,
                        name = self.name,
                        "opentelemetry shutdown success"
                    );
                }
            },
            Err(e) => {
                error!(
                    target: LOG_TARGET,
                    name = self.name,
                    error = %e,
                    "opentelemetry init fail"
                );
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the url of an exporter says beyond where it is.
    #[tokio::test]
    async fn test_exporter_params() {
        // Nothing said: every request, over gRPC, as it always was.
        let service = TracerService::new("s", "http://collector:4317");
        assert_eq!(SamplerKind::AlwaysOn, service.config.sampler);
        assert_eq!(1.0, service.config.sample_ratio);
        assert_eq!(ExportProtocol::Grpc, service.config.protocol);
        assert!(service.config.headers.is_empty());
        assert!(!service.config.max_export_timeout_set);

        let endpoint = "https://otel.test?protocol=http&sampler=parentbased_traceidratio&sample_ratio=0.1&header=Authorization:Bearer%20t0ken&header=X-Scope-OrgID:%2042&timeout=5s&max_export_timeout=1m";
        assert_eq!(Ok(()), validate_endpoint(endpoint));
        let service = TracerService::new("s", endpoint);
        assert_eq!(
            SamplerKind::ParentBasedTraceIdRatio,
            service.config.sampler
        );
        assert_eq!(0.1, service.config.sample_ratio);
        assert_eq!(ExportProtocol::Http, service.config.protocol);
        assert_eq!(
            vec![
                ("authorization".to_string(), "Bearer t0ken".to_string()),
                ("x-scope-orgid".to_string(), "42".to_string()),
            ],
            service.config.headers
        );
        assert_eq!(Duration::from_secs(5), service.config.timeout);
        assert!(service.config.max_export_timeout_set);
        // Over HTTP the spans go to the path of the traces, and the
        // parameters are not part of where.
        assert_eq!("https://otel.test/v1/traces", service.http_endpoint());
        assert_eq!(
            "http://c:4318/v1/traces",
            TracerService::new("s", "http://c:4318/?protocol=http")
                .http_endpoint()
        );
        assert_eq!(
            "http://c:4318/otlp/v1/traces",
            TracerService::new(
                "s",
                "http://c:4318/otlp/v1/traces?protocol=http"
            )
            .http_endpoint()
        );
        // What is shown of it is without the token.
        assert_eq!("https://otel.test", endpoint_without_query(endpoint));
        // Both ways of sending can be built with what was said.
        assert!(service.new_exporter().is_ok());
        assert!(
            TracerService::new(
                "s",
                "http://collector:4317?header=Authorization:Bearer%20t0ken"
            )
            .new_exporter()
            .is_ok()
        );

        // Each of the samplers by its name.
        for (name, expected) in [
            ("always_on", "AlwaysOn"),
            ("always_off", "AlwaysOff"),
            ("traceidratio", "TraceIdRatioBased(0.25)"),
            ("parentbased_always_on", "ParentBased(AlwaysOn)"),
            ("parentbased_always_off", "ParentBased(AlwaysOff)"),
            (
                "ParentBased_TraceIdRatio",
                "ParentBased(TraceIdRatioBased(0.25))",
            ),
        ] {
            let sampler = SamplerKind::parse(name).expect(name).sampler(0.25);
            assert_eq!(expected, format!("{sampler:?}"), "{name}");
        }
    }

    /// The parameters that are refused when they are wrong: read as if
    /// they were not there, a sampler with a typo would trace everything.
    #[test]
    fn test_validate_endpoint() {
        for endpoint in [
            "http://c:4317",
            "http://c:4317?sampler=always_off",
            "http://c:4317?sampler=traceidratio&sample_ratio=0",
            "http://c:4317?sample_ratio=1&sampler=parentbased_traceidratio",
            // what is no url is the exporter's to report, as it was
            "collector",
            "10.0.0.5:4317",
            "",
            "http://c:4317?protocol=grpc",
            "http://c:4318?protocol=http%2Fprotobuf",
            // what was there before is read as it was, typos and all
            "http://c:4317?timeout=soon&max_queue_size=many",
        ] {
            assert_eq!(Ok(()), validate_endpoint(endpoint), "{endpoint}");
        }
        for (endpoint, message) in [
            // a ratio that no sampler goes by
            (
                "http://c:4317?sample_ratio=0.1",
                "sample_ratio(0.1) needs sampler=traceidratio",
            ),
            (
                "http://c:4317?sampler=parentbased_always_on&sample_ratio=0.1",
                "sample_ratio(0.1) needs sampler=traceidratio",
            ),
            (
                "http://c:4317?sampler=sometimes",
                "sampler(sometimes) is invalid",
            ),
            (
                "http://c:4317?sampler=traceidratio&sample_ratio=10",
                "sample_ratio(10) is invalid",
            ),
            (
                "http://c:4317?sampler=traceidratio&sample_ratio=few",
                "sample_ratio(few) is invalid",
            ),
            ("http://c:4317?protocol=udp", "protocol(udp) is invalid"),
            (
                "http://c:4317?header=Authorization%20t0ken",
                "header should be Name:Value",
            ),
            (
                "http://c:4317?header=X%20Y:t0ken",
                "header should be Name:Value",
            ),
        ] {
            let error = validate_endpoint(endpoint).unwrap_err();
            assert!(error.contains(message), "{endpoint}: {error}");
            // a token is not part of what is reported
            assert!(!error.contains("t0ken"), "{error}");
        }
    }

    /// What an upstream is told of a span: its trace and its own id, so
    /// that what the upstream does hangs from it.
    #[test]
    fn test_inject_span_context() {
        use opentelemetry::trace::{Span, SpanContext, Tracer, TracerProvider};
        use std::collections::HashMap;

        opentelemetry::global::set_text_map_propagator(
            opentelemetry_sdk::propagation::TraceContextPropagator::new(),
        );
        let provider =
            opentelemetry_sdk::trace::SdkTracerProvider::builder().build();
        let tracer = provider.tracer("test");
        let span = tracer.start("request");
        let span_context = span.span_context().clone();

        let traceparent = |client: Option<&str>| {
            let mut headers: HashMap<String, String> = HashMap::new();
            super::inject_span_context(&span_context, client, &mut headers);
            headers.get("traceparent").cloned()
        };
        let own = |flags: &str| {
            Some(format!(
                "00-{}-{}-{flags}",
                span_context.trace_id(),
                span_context.span_id()
            ))
        };
        assert_eq!(own("01"), traceparent(None));
        // The trace of a client that chose not to sample it goes on
        // unsampled, under the span of the proxy.
        let unsampled =
            format!("00-{}-b7ad6b7169203331-00", span_context.trace_id());
        assert_eq!(own("00"), traceparent(Some(&unsampled)));
        let sampled =
            format!("00-{}-b7ad6b7169203331-01", span_context.trace_id());
        assert_eq!(own("01"), traceparent(Some(&sampled)));
        // What the client sent is of another trace, or of none: the
        // span's own flags.
        for client in [
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-00",
            "not a traceparent",
            "",
        ] {
            assert_eq!(own("01"), traceparent(Some(client)), "{client}");
        }

        // A span that is not sampled - the sampler dropped it - is not
        // exported and no parent for anything. A client with a trace of
        // its own keeps its `traceparent` as it sent it: nothing is
        // written over it. A request that starts its trace here is told
        // on with the decision of the sampler.
        let dropping = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_sampler(opentelemetry_sdk::trace::Sampler::AlwaysOff)
            .build();
        let dropped = dropping.tracer("test").start("request");
        let dropped_context = dropped.span_context().clone();
        assert!(dropped_context.is_valid() && !dropped_context.is_sampled());
        let written = |client: Option<&str>| {
            let mut headers: HashMap<String, String> = HashMap::new();
            super::inject_span_context(&dropped_context, client, &mut headers);
            headers.get("traceparent").cloned()
        };
        for flags in ["01", "00"] {
            let client = format!(
                "00-{}-b7ad6b7169203331-{flags}",
                dropped_context.trace_id()
            );
            assert_eq!(None, written(Some(&client)), "{flags}");
        }
        assert_eq!(
            Some(format!(
                "00-{}-{}-00",
                dropped_context.trace_id(),
                dropped_context.span_id()
            )),
            written(None)
        );

        // No span to speak of: nothing is written.
        let mut headers: HashMap<String, String> = HashMap::new();
        super::inject_span_context(
            &SpanContext::empty_context(),
            None,
            &mut headers,
        );
        assert!(headers.is_empty());
    }
}
