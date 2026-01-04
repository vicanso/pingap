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

use pingap_core::OtelTracer;
use pingap_core::{Ctx, get_client_ip};
use pingap_otel::HeaderExtractor;
use pingap_otel::{
    KeyValue, global,
    trace::{Span, SpanKind, Tracer},
};
use pingora::http::ResponseHeader;
use pingora::proxy::Session;

#[inline]
pub(crate) fn initialize_telemetry(
    name: &str,
    session: &Session,
    ctx: &mut Ctx,
) {
    let header = session.req_header();
    let host = pingap_core::get_host(header).unwrap_or_default();
    let path = header.uri.path();
    // enable open telemetry
    if let Some(tracer) = pingap_otel::new_http_proxy_tracer(name) {
        let cx = global::get_text_map_propagator(|propagator| {
            propagator.extract(&HeaderExtractor(&header.headers))
        });
        let mut span = tracer
            .span_builder(path.to_string())
            .with_kind(SpanKind::Server)
            .start_with_context(&tracer, &cx);
        span.set_attributes(vec![
            KeyValue::new("http.method", header.method.to_string()),
            KeyValue::new("http.url", header.uri.to_string()),
            KeyValue::new("http.host", host.to_string()),
        ]);

        let features = ctx.features.get_or_insert_default();
        features.otel_tracer = Some(OtelTracer {
            tracer,
            http_request_span: span,
        });
    }
}

#[inline]
pub(crate) fn update_otel_cache_attrs(
    ctx: &mut Ctx,
    cache_status: &str,
    lookup_duration: String,
    lock_duration: String,
) {
    if let Some(tracer) =
        ctx.features.as_mut().and_then(|f| f.otel_tracer.as_mut())
    {
        let attrs = vec![
            KeyValue::new("cache.status", cache_status.to_string()),
            KeyValue::new("cache.lookup", lookup_duration),
            KeyValue::new("cache.lock", lock_duration),
        ];
        tracer.http_request_span.set_attributes(attrs);
    }
}

#[inline]
pub(crate) fn inject_telemetry_headers(
    ctx: &Ctx,
    upstream_response: &mut ResponseHeader,
) {
    if let Some(tracer) =
        ctx.features.as_ref().and_then(|f| f.otel_tracer.as_ref())
    {
        let span_context = tracer.http_request_span.span_context();
        if span_context.is_valid() {
            // Add trace ID
            let _ = upstream_response.insert_header(
                "X-Trace-Id",
                span_context.trace_id().to_string(),
            );
            // Add span ID
            let _ = upstream_response
                .insert_header("X-Span-Id", span_context.span_id().to_string());
        }
    }
}

#[inline]
pub(crate) fn set_otel_upstream_attrs(ctx: &mut Ctx) {
    if let Some(mut span) =
        ctx.features.as_mut().and_then(|f| f.upstream_span.take())
    {
        let timing = &ctx.timing;
        span.set_attributes([
            KeyValue::new("upstream.addr", ctx.upstream.address.clone()),
            KeyValue::new("upstream.reused", ctx.upstream.reused),
            KeyValue::new(
                "upstream.connect_time",
                timing.upstream_connect.unwrap_or_default() as i64,
            ),
            KeyValue::new(
                "upstream.processing_time",
                timing.upstream_processing.unwrap_or_default() as i64,
            ),
            KeyValue::new(
                "upstream.response_time",
                timing.upstream_response.unwrap_or_default() as i64,
            ),
        ]);
        span.end();
    }
}

#[inline]
pub(crate) fn set_otel_request_attrs(session: &Session, ctx: &mut Ctx) {
    if let Some(features) = ctx.features.as_mut() {
        if let Some(ref mut tracer) = features.otel_tracer.as_mut() {
            let ip = ctx
                .conn
                .client_ip
                .get_or_insert_with(|| get_client_ip(session));
            let mut attrs = vec![
                KeyValue::new("http.client_ip", ip.to_string()),
                KeyValue::new(
                    "http.status_code",
                    ctx.state.status.unwrap_or_default().as_u16() as i64,
                ),
                KeyValue::new(
                    "http.response.body.size",
                    session.body_bytes_sent() as i64,
                ),
            ];
            if !ctx.upstream.location.is_empty() {
                attrs.push(KeyValue::new(
                    "http.location",
                    ctx.upstream.location.clone(),
                ));
            }

            tracer.http_request_span.set_attributes(attrs);
            tracer.http_request_span.end()
        }
    }
}
