use criterion::{criterion_group, criterion_main, Criterion};
use http::HeaderValue;
use pingap_core::{
    convert_header, get_host, get_super_ts, remove_query_from_header,
};
use pingora::http::RequestHeader;

fn bench_remove_query_from_header(c: &mut Criterion) {
    c.bench_function("remove_query_from_header", |b| {
        let req =
            RequestHeader::build("GET", b"/?apikey=123&name=pingap", None)
                .unwrap();
        b.iter(|| {
            let mut new_req = req.clone();
            remove_query_from_header(&mut new_req, "apikey").unwrap();
            assert_eq!("/?name=pingap", new_req.uri.to_string());
        });
    });
}

fn bench_get_host(c: &mut Criterion) {
    c.bench_function("get uri host", |b| {
        let mut req =
            RequestHeader::build("GET", b"/?apikey=123&name=pingap", None)
                .unwrap();
        req.append_header("Host", "pingap.io").unwrap();
        b.iter(|| {
            let host = get_host(&req);
            assert_eq!(host, Some("pingap.io"));
        });
    });
}

fn bench_convert_header_value(c: &mut Criterion) {
    c.bench_function("convert header value", |b| {
        let value = HeaderValue::from_static("123123");
        b.iter(|| {
            let header = convert_header("x-trace-id: 123123").unwrap().unwrap();
            assert_eq!(header.0, "x-trace-id");
            assert_eq!(header.1, value);
        });
    });
}

fn bench_get_super_ts(c: &mut Criterion) {
    c.bench_function("get super ts", |b| {
        b.iter(|| {
            let _ = get_super_ts();
        });
    });
}

criterion_group!(
    benches,
    bench_remove_query_from_header,
    bench_get_host,
    bench_convert_header_value,
    bench_get_super_ts,
);
criterion_main!(benches);
