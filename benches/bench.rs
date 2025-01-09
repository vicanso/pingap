use ahash::AHashMap;
use arc_swap::ArcSwap;
use bytes::Bytes;
use criterion::{criterion_group, criterion_main, Criterion};
use http::{HeaderName, HeaderValue, StatusCode};
use nanoid::nanoid;
use pingap::config::LocationConf;
use pingap::http_extra::{convert_headers, HttpResponse};
use pingap::proxy::{Location, Parser};
use pingap::state::{CompressionStat, State};
use pingap::util::{self, get_super_ts};
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::proxy::Session;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio_test::io::Builder;

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

fn bench_get_header_value(c: &mut Criterion) {
    c.bench_function("get header value", |b| {
        let mut req_header =
            RequestHeader::build("GET", b"/users/v1/me", None).unwrap();
        req_header.insert_header("User-Agent", "pingap").unwrap();
        req_header
            .insert_header("Content-Type", "application/json")
            .unwrap();
        req_header
            .insert_header(http::header::CONTENT_LENGTH, "10240")
            .unwrap();

        b.iter(|| {
            if req_header
                .headers
                .get(http::header::CONTENT_LENGTH)
                .unwrap()
                .to_str()
                .unwrap()
                .is_empty()
            {
                panic!("get header value fail")
            }
        });
    });
}

fn bench_location_filter(c: &mut Criterion) {
    let mut group = c.benchmark_group("location filter");
    let upstream_name = "charts";

    group.bench_function("prefix", |b| {
        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some(upstream_name.to_string()),
                path: Some("/api".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        b.iter(|| {
            lo.matched("", "/api/users/me");
            lo.matched("", "/rest");
        });
    });

    group.bench_function("regex", |b| {
        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some(upstream_name.to_string()),
                path: Some("~/api".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        b.iter(|| {
            lo.matched("", "/rest/api/users/me");
            lo.matched("", "/rest");
        });
    });
    group.bench_function("equal", |b| {
        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some(upstream_name.to_string()),
                path: Some("=/api".to_string()),
                ..Default::default()
            },
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

    let lo = Location::new(
        "lo",
        &LocationConf {
            upstream: Some(upstream_name.to_string()),
            rewrite: Some("^/users/(.*)$ /$1".to_string()),
            ..Default::default()
        },
    )
    .unwrap();

    c.bench_function("rewrite path", |b| {
        b.iter(|| {
            let mut req_header =
                RequestHeader::build("GET", b"/users/v1/me", None).unwrap();
            let _ = lo.rewrite(&mut req_header, None);
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

fn get_logger_session(s: crossbeam_channel::Sender<Option<Session>>) {
    std::thread::spawn(move || {
        match tokio::runtime::Runtime::new() {
            Ok(rt) => {
                let send = async move {
                    let headers = [
                        "Host: github.com",
                        "Referer: https://github.com/",
                        "user-agent: pingap/0.1.1",
                        "Cookie: deviceId=abc",
                        "Accept: application/json",
                        "X-Forwarded-For: 1.1.1.1, 2.2.2.2",
                    ]
                    .join("\r\n");
                    let input_header = format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
                    let mock_io =
                        Builder::new().read(input_header.as_bytes()).build();

                    let mut session = Session::new_h1(Box::new(mock_io));
                    session.read_request().await.unwrap();
                    let _ = s.send(Some(session));
                };
                rt.block_on(send);
            },
            Err(_e) => {
                let _ = s.send(None);
            },
        };
    });
}

fn bench_map(c: &mut Criterion) {
    let mut map = HashMap::new();
    let mut amap = ahash::AHashMap::new();
    for i in 0..10 {
        let id = nanoid!(6);
        map.insert(id.clone(), i);
        amap.insert(id, i);
    }
    let id = nanoid!(6);
    map.insert(id.clone(), 100);
    amap.insert(id.clone(), 100);
    c.bench_function("normal hash map", |b| {
        let new_id = id.clone();
        b.iter(|| {
            map.get(&new_id);
        });
    });
    c.bench_function("ahash map", |b| {
        let new_id = id.clone();
        b.iter(|| {
            amap.get(&new_id);
        });
    });
}

fn bench_logger_format(c: &mut Criterion) {
    let (s, r) = crossbeam_channel::bounded(0);
    get_logger_session(s);
    let session = r.recv().unwrap().unwrap();
    c.bench_function("logger format", |b| {
        let p: Parser =
            "{host} {method} {path} {proto} {query} {remote} {client_ip} \
{scheme} {uri} {referer} {user_agent} {when} {when_utc_iso} \
{when_unix} {size} {size_human} {status} {latency} \
{payload_size} {latency_human} {payload_size} \
{payload_size_human} {request_id} \
{:upstream_reused} {:upstream_addr} {:processing} {:upstream_connect_time} \
{:upstream_connected} {:upstream_processing_time} {:upstream_response_time} \
{:location} {:established} {:tls_version} {:compression_time} \
{:compression_ratio} {:cache_lookup_time} {:cache_lock_time} \
{~deviceId} {>accept} {:reused}"
                .into();
        let ctx = State {
            payload_size: 512,
            upstream_reused: true,
            status: Some(StatusCode::OK),
            created_at: util::now().as_millis() as u64,
            request_id: Some("AMwBhEil".to_string()),
            upstream_address: "192.168.1.1:5000".to_string(),
            upstream_connect_time: Some(30),
            upstream_connected: Some(10),
            upstream_processing_time: Some(50),
            upstream_response_time: Some(5),
            location: None,
            connection_time: 300,
            tls_version: Some("tls1.2".to_string()),
            processing: 10,
            compression_stat: Some(CompressionStat {
                in_bytes: 50 * 1024,
                out_bytes: 12 * 1024,
                duration: Duration::from_millis(8),
            }),
            cache_lookup_time: Some(3),
            cache_lock_time: Some(8),
            ..Default::default()
        };
        b.iter(|| {
            let _ = p.format(&session, &ctx);
        })
    });
}

fn bench_get_location(c: &mut Criterion) {
    let mut map: AHashMap<String, Arc<Location>> = AHashMap::new();
    for _ in 0..10 {
        let id = nanoid!(6);
        map.insert(
            id.clone(),
            Arc::new(
                Location::new(id.as_str(), &LocationConf::default()).unwrap(),
            ),
        );
    }

    let locations: ArcSwap<AHashMap<String, Arc<Location>>> =
        ArcSwap::from_pointee(map);
    c.bench_function("get location", |b| {
        b.iter(|| {
            let _ = locations.load().get("1").cloned();
        })
    });
}

criterion_group!(
    benches,
    bench_get_header_value,
    bench_insert_bytes_header,
    bench_insert_header_name,
    bench_get_response_header,
    bench_location_filter,
    bench_location_rewrite_path,
    bench_get_super_ts,
    bench_logger_format,
    bench_map,
    bench_get_location,
);
criterion_main!(benches);
