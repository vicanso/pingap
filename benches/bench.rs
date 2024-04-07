use bytes::Bytes;
use criterion::{criterion_group, criterion_main, Criterion};
use http::{HeaderName, HeaderValue, StatusCode};
use pingap::config::{LocationConf, UpstreamConf};
use pingap::http_extra::{convert_headers, get_super_ts, HttpResponse};
use pingap::proxy::{Location, Upstream};
use pingora::http::ResponseHeader;
use std::sync::Arc;

fn bench_insert_bytes_header(c: &mut Criterion) {
    c.bench_function("bytes header", |b| {
        let arr = vec![
            (
                Bytes::from("Cache-Control"),
                Bytes::from("private, no-store"),
            ),
            (
                Bytes::from("Content-Type"),
                Bytes::from("text/html; charset=utf-8"),
            ),
            (Bytes::from("Etag"), Bytes::from("\"274-24eed9fe\"")),
            (
                Bytes::from("Date"),
                Bytes::from("Fri, 22 Mar 2024 17:16:30 GMT"),
            ),
        ];
        b.iter(|| {
            let headers = arr.clone();
            let mut resp = ResponseHeader::build(200, Some(4)).unwrap();
            for (k, v) in headers {
                let _ = resp.insert_header(k, v.to_vec());
            }
        })
    });
}

fn bench_insert_header_name(c: &mut Criterion) {
    c.bench_function("header name", |b| {
        let arr = vec![
            (
                HeaderName::from_bytes(b"Cache-Control").unwrap(),
                HeaderValue::from_str("private, no-store").unwrap(),
            ),
            (
                HeaderName::from_bytes(b"Content-Type").unwrap(),
                HeaderValue::from_str("text/html; charset=utf-8").unwrap(),
            ),
            (
                HeaderName::from_bytes(b"Etag").unwrap(),
                HeaderValue::from_str("\"274-24eed9fe\"").unwrap(),
            ),
            (
                HeaderName::from_bytes(b"Date").unwrap(),
                HeaderValue::from_str("Fri, 22 Mar 2024 17:16:30 GMT").unwrap(),
            ),
        ];
        b.iter(|| {
            let headers = arr.clone();
            let mut resp = ResponseHeader::build(200, Some(4)).unwrap();
            for (k, v) in headers {
                let _ = resp.insert_header(k, v);
            }
        })
    });
}

fn bench_get_response_header(c: &mut Criterion) {
    c.bench_function("get response header for http response", |b| {
        let resp = HttpResponse {
            status: StatusCode::OK,
            body: Bytes::from("Hello world!"),
            max_age: Some(3600),
            created_at: Some(get_super_ts() - 10),
            cache_private: Some(true),
            headers: Some(
                convert_headers(&[
                    "Contont-Type: application/json".to_string(),
                    "Content-Encoding: gzip".to_string(),
                ])
                .unwrap(),
            ),
        };

        b.iter(|| {
            let value = resp.clone();
            value.get_response_header().unwrap();
        });
    });
}

fn bench_location_filter(c: &mut Criterion) {
    let mut group = c.benchmark_group("location filter");
    let upstream_name = "charts";
    let upstream = Arc::new(
        Upstream::new(
            upstream_name,
            &UpstreamConf {
                addrs: vec!["127.0.0.1:8001".to_string()],
                ..Default::default()
            },
        )
        .unwrap(),
    );

    group.bench_function("prefix", |b| {
        let lo = Location::new(
            "",
            &LocationConf {
                upstream: upstream_name.to_string(),
                path: Some("/api".to_string()),
                ..Default::default()
            },
            vec![upstream.clone()],
        )
        .unwrap();
        b.iter(|| {
            lo.matched("", "/api/users/me");
            lo.matched("", "/rest");
        });
    });

    group.bench_function("regex", |b| {
        let lo = Location::new(
            "",
            &LocationConf {
                upstream: upstream_name.to_string(),
                path: Some("~/api".to_string()),
                ..Default::default()
            },
            vec![upstream.clone()],
        )
        .unwrap();
        b.iter(|| {
            lo.matched("", "/rest/api/users/me");
            lo.matched("", "/rest");
        });
    });
    group.bench_function("equal", |b| {
        let lo = Location::new(
            "",
            &LocationConf {
                upstream: upstream_name.to_string(),
                path: Some("=/api".to_string()),
                ..Default::default()
            },
            vec![upstream.clone()],
        )
        .unwrap();
        b.iter(|| {
            lo.matched("", "/api/users/me");
            lo.matched("", "/api");
        });
    });

    group.finish();
}

fn bench_location_rewrite_path(c: &mut Criterion) {
    let upstream_name = "charts";
    let upstream = Arc::new(
        Upstream::new(
            upstream_name,
            &UpstreamConf {
                addrs: vec!["127.0.0.1:8001".to_string()],
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let lo = Location::new(
        "",
        &LocationConf {
            upstream: upstream_name.to_string(),
            rewrite: Some("^/users/(.*)$ /$1".to_string()),
            ..Default::default()
        },
        vec![upstream.clone()],
    )
    .unwrap();

    c.bench_function("rewrite path", |b| {
        b.iter(|| {
            let _ = lo.rewrite("/users/v1/me");
        })
    });
}

fn bench_get_super_ts(c: &mut Criterion) {
    c.bench_function("get super ts", |b| {
        b.iter(|| {
            _ = get_super_ts();
        })
    });
}

criterion_group!(
    benches,
    bench_insert_bytes_header,
    bench_insert_header_name,
    bench_get_response_header,
    bench_location_filter,
    bench_location_rewrite_path,
    bench_get_super_ts,
);
criterion_main!(benches);
