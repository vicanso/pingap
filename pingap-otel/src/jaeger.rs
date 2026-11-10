//! Jaeger `uber-trace-id` propagation.
//!
//! OpenTelemetry 0.33 removed `opentelemetry-jaeger-propagator`. The format
//! is still what an existing Jaeger deployment sends, and `?jaeger` on an
//! endpoint asks for it. This is the default header and the `uberctx-`
//! baggage prefix of that crate's `Propagator::new()`.

use opentelemetry::Context;
use opentelemetry::propagation::{Extractor, Injector, TextMapPropagator};
use opentelemetry::trace::{
    SpanContext, SpanId, TraceContextExt, TraceFlags, TraceId, TraceState,
};
use std::borrow::Cow;
use std::str::FromStr;

const HEADER: &str = "uber-trace-id";
const BAGGAGE_PREFIX: &str = "uberctx-";
const DEBUG: TraceFlags = TraceFlags::new(0x04);

/// Reads and writes the Jaeger trace header.
#[derive(Clone, Debug)]
pub struct Propagator {
    fields: [String; 1],
}

impl Propagator {
    /// A propagator for `uber-trace-id`.
    pub fn new() -> Self {
        Self {
            fields: [HEADER.to_string()],
        }
    }

    fn span_context(&self, extractor: &dyn Extractor) -> Option<SpanContext> {
        let mut header = Cow::from(extractor.get(HEADER).unwrap_or(""));
        if !header.contains(':') {
            header = Cow::Owned(header.replace("%3A", ":"));
        }
        let parts: Vec<&str> = header.split_terminator(':').collect();
        if parts.len() != 4 {
            return None;
        }
        let trace_id = trace_id(parts[0])?;
        let span_id = span_id(parts[1])?;
        let flags = flags(parts[3])?;
        let state = trace_state(extractor)?;
        Some(SpanContext::new(trace_id, span_id, flags, true, state))
    }
}

impl Default for Propagator {
    fn default() -> Self {
        Self::new()
    }
}

fn trace_id(value: &str) -> Option<TraceId> {
    if value.len() > 32 {
        return None;
    }
    TraceId::from_hex(value).ok()
}

fn span_id(value: &str) -> Option<SpanId> {
    match value.len() {
        16 => SpanId::from_hex(value).ok(),
        17.. => None,
        _ => {
            let padded = format!("{value:0>16}");
            SpanId::from_hex(&padded).ok()
        },
    }
}

fn flags(value: &str) -> Option<TraceFlags> {
    if value.len() > 2 {
        return None;
    }
    let flag = u8::from_str(value).ok()?;
    if flag & 0x01 == 0x01 {
        if flag & 0x02 == 0x02 {
            Some(TraceFlags::SAMPLED | DEBUG)
        } else {
            Some(TraceFlags::SAMPLED)
        }
    } else {
        Some(TraceFlags::default())
    }
}

fn trace_state(extractor: &dyn Extractor) -> Option<TraceState> {
    let pairs = extractor.keys().into_iter().filter_map(|key| {
        if key.starts_with(BAGGAGE_PREFIX) {
            extractor
                .get(key)
                .map(|value| (key.to_string(), value.to_string()))
        } else {
            None
        }
    });
    TraceState::from_key_value(pairs).ok()
}

impl TextMapPropagator for Propagator {
    fn inject_context(&self, cx: &Context, injector: &mut dyn Injector) {
        let span = cx.span();
        let span_context = span.span_context();
        if !span_context.is_valid() {
            return;
        }
        let flag = if span_context.is_sampled() {
            if span_context.trace_flags() & DEBUG == DEBUG {
                0x03
            } else {
                0x01
            }
        } else {
            0x00
        };
        let header = format!(
            "{}:{}:0:{flag:01x}",
            span_context.trace_id(),
            span_context.span_id(),
        );
        injector.set(HEADER, header);
    }

    fn extract_with_context(
        &self,
        cx: &Context,
        extractor: &dyn Extractor,
    ) -> Context {
        match self.span_context(extractor) {
            Some(span_context) => cx.with_remote_span_context(span_context),
            None => cx.clone(),
        }
    }

    fn fields(
        &self,
    ) -> opentelemetry::propagation::text_map_propagator::FieldIter<'_> {
        opentelemetry::propagation::text_map_propagator::FieldIter::new(
            self.fields.as_ref(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::propagation::{Extractor, Injector};
    use std::collections::HashMap;

    #[derive(Default)]
    struct Map(HashMap<String, String>);

    impl Injector for Map {
        fn set(&mut self, key: &str, value: String) {
            self.0.insert(key.to_string(), value);
        }
    }

    impl Extractor for Map {
        fn get(&self, key: &str) -> Option<&str> {
            self.0.get(key).map(String::as_str)
        }

        fn keys(&self) -> Vec<&str> {
            self.0.keys().map(String::as_str).collect()
        }
    }

    #[test]
    fn round_trip_keeps_the_sampled_span() {
        let propagator = Propagator::new();
        let span_context = SpanContext::new(
            TraceId::from_hex("000000000000004d0000000000000016")
                .expect("trace id"),
            SpanId::from_hex("0000000000017c29").expect("span id"),
            TraceFlags::SAMPLED,
            true,
            TraceState::default(),
        );
        let context =
            Context::new().with_remote_span_context(span_context.clone());
        let mut headers = Map::default();
        propagator.inject_context(&context, &mut headers);
        assert_eq!(
            Some("000000000000004d0000000000000016:0000000000017c29:0:1"),
            headers.get(HEADER),
        );
        let extracted =
            propagator.extract_with_context(&Context::new(), &headers);
        let got = extracted.span().span_context().clone();
        assert_eq!(span_context.trace_id(), got.trace_id());
        assert_eq!(span_context.span_id(), got.span_id());
        assert!(got.is_sampled());
    }
}
