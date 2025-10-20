use criterion::{criterion_group, criterion_main, Criterion};
use pingap_config::LocationConf;
use pingap_core::LocationInstance;
use pingap_location::Location;
use pingora::http::RequestHeader;

fn bench_match_host_path(c: &mut Criterion) {
    let mut group = c.benchmark_group("match host path");

    group.bench_function("prefix", |b| {
        let lo = Location::new(
            "lo",
            &LocationConf {
                path: Some("/api".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        b.iter(|| {
            let (matched, _) = lo.match_host_path("", "/api/users");
            if !matched {
                panic!("match failed");
            }
        });
    });

    group.bench_function("regex", |b| {
        let lo = Location::new(
            "lo",
            &LocationConf {
                path: Some("~/api".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        b.iter(|| {
            let (matched, _) = lo.match_host_path("", "/api/users");
            if !matched {
                panic!("match failed");
            }
        });
    });

    group.bench_function("host and prefix", |b| {
        let lo = Location::new(
            "lo",
            &LocationConf {
                host: Some("pingap.io".to_string()),
                path: Some("/api".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        b.iter(|| {
            let (matched, _) = lo.match_host_path("pingap.io", "/api/users");
            if !matched {
                panic!("match failed");
            }
        });
    });

    group.finish();
}

fn bench_path_rewrite(c: &mut Criterion) {
    c.bench_function("rewrite", |b| {
        let lo = Location::new(
            "lo",
            &LocationConf {
                rewrite: Some("^/users/(.*)$ /$1".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        b.iter(|| {
            let mut req_header =
                RequestHeader::build("GET", b"/users/v1/me?a=1", None).unwrap();
            let _ = lo.rewrite(&mut req_header, None);
            assert_eq!(req_header.uri, "/v1/me?a=1");
        });
    });
}

criterion_group!(benches, bench_match_host_path, bench_path_rewrite);
criterion_main!(benches);
