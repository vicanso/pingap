use bytes::BytesMut;
use criterion::{criterion_group, criterion_main, Criterion};
use http::HeaderValue;
use pingap_core::{
    convert_header, get_host, get_super_ts, now_ms, real_now_ms,
    remove_query_from_header,
};
use pingap_core::{format_duration, Ctx};
use pingora::http::RequestHeader;
use std::hint::black_box;

fn bench_remove_query_from_header(c: &mut Criterion) {
    c.bench_function("remove query from header", |b| {
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
            black_box(get_super_ts());
        });
    });
}

fn bench_now_ms(c: &mut Criterion) {
    c.bench_function("now ms", |b| {
        b.iter(|| {
            black_box(now_ms());
        });
    });
}

fn bench_real_now_ms(c: &mut Criterion) {
    c.bench_function("real now ms", |b| {
        b.iter(|| {
            let _ = real_now_ms();
        });
    });
}

fn bench_format_duration(c: &mut Criterion) {
    let mut group = c.benchmark_group("format duration");

    group.bench_function("< 1s", |b| {
        b.iter(|| {
            let buf = format_duration(BytesMut::new(), 999);
            if buf.len() != 5 {
                panic!("buf: {:?}", buf);
            }
        });
    });

    group.bench_function("< 1m", |b| {
        b.iter(|| {
            let buf = format_duration(BytesMut::new(), 9999);
            if buf.len() != 4 {
                panic!("buf: {:?}", buf);
            }
        });
    });

    group.finish();
}

fn bench_get_variable(c: &mut Criterion) {
    c.bench_function("get variable", |b| {
        let mut ctx = Ctx::new();
        ctx.add_variable("test", "123");
        ctx.add_variable("test2", "456");
        ctx.add_variable("test3", "789");
        ctx.add_variable("test4", "101");
        ctx.add_variable("test5", "121");
        b.iter(|| {
            let value = black_box(ctx.get_variable("test5"));
            if value.is_none() {
                panic!("value is none");
            }
        });
    });
}
criterion_group!(
    benches,
    bench_remove_query_from_header,
    bench_get_host,
    bench_convert_header_value,
    bench_get_super_ts,
    bench_now_ms,
    bench_real_now_ms,
    bench_format_duration,
    bench_get_variable,
);
criterion_main!(benches);
