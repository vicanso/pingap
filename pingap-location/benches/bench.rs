use criterion::{Criterion, criterion_group, criterion_main};
use pingap_config::LocationConf;
use pingap_core::LocationInstance;
use pingap_location::Location;
use pingora::http::RequestHeader;

#[allow(clippy::unwrap_used)]
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

    group.bench_function("regex host and prefix", |b| {
        let lo = Location::new(
            "lo",
            &LocationConf {
                host: Some("~^api\\.pingap\\.io$".to_string()),
                path: Some("/api".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        b.iter(|| {
            let (matched, _) =
                lo.match_host_path("api.pingap.io", "/api/users");
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

#[allow(clippy::unwrap_used)]
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
            let _ = lo.rewrite(&mut req_header, &mut None);
            assert_eq!(req_header.uri, "/v1/me?a=1");
        });
    });
}

#[allow(clippy::unwrap_used)]
fn bench_host_index(c: &mut Criterion) {
    use pingap_location::LocationHostIndex;
    use std::collections::HashMap;
    use std::sync::Arc;
    let loc = |name: &str, host: Option<&str>| {
        Arc::new(
            Location::new(
                name,
                &LocationConf {
                    host: host.map(str::to_string),
                    path: Some("/".to_string()),
                    ..Default::default()
                },
            )
            .unwrap(),
        )
    };
    let map: HashMap<String, Arc<Location>> = (0..20)
        .map(|i| {
            let name = format!("exact{i}");
            let location = loc(&name, Some(&format!("host{i}.example.com")));
            (name, location)
        })
        .chain([
            ("wild".to_string(), loc("wild", Some("*.example.com"))),
            ("re".to_string(), loc("re", Some("~^api"))),
            ("any".to_string(), loc("any", None)),
        ])
        .collect();
    let ordered: Vec<String> = map.keys().cloned().collect();
    let index = LocationHostIndex::build(&ordered, |n| map.get(n).cloned());
    c.bench_function("host index candidates", |b| {
        b.iter(|| {
            let candidates = index.candidate_indices("host7.example.com");
            assert_eq!(4, candidates.len());
        })
    });
}

#[allow(clippy::unwrap_used)]
fn bench_rewrite_with_variables(c: &mut Criterion) {
    use ahash::AHashMap;
    c.bench_function("rewrite with variables", |b| {
        let lo = Location::new(
            "lo",
            &LocationConf {
                rewrite: Some("^/users/(.*)$ /$tenant/$1".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        b.iter(|| {
            let mut req_header =
                RequestHeader::build("GET", b"/users/v1/me?a=1", None).unwrap();
            let mut variables = Some(AHashMap::from([(
                "tenant".to_string(),
                "acme".to_string(),
            )]));
            let _ = lo.rewrite(&mut req_header, &mut variables);
        });
    });
}

#[allow(clippy::unwrap_used)]
fn bench_rewrite_named_captures(c: &mut Criterion) {
    c.bench_function("rewrite with named captures", |b| {
        let lo = Location::new(
            "lo",
            &LocationConf {
                rewrite: Some(
                    "^/users/(?<version>v\\d+)/(.*)$ /$2".to_string(),
                ),
                ..Default::default()
            },
        )
        .unwrap();
        b.iter(|| {
            let mut req_header =
                RequestHeader::build("GET", b"/users/v1/me?a=1", None).unwrap();
            let mut variables = None;
            let _ = lo.rewrite(&mut req_header, &mut variables);
            assert_eq!(req_header.uri, "/me?a=1");
            assert_eq!(1, variables.map(|v| v.len()).unwrap_or_default());
        });
    });
}

criterion_group!(
    benches,
    bench_match_host_path,
    bench_path_rewrite,
    bench_host_index,
    bench_rewrite_with_variables,
    bench_rewrite_named_captures
);
criterion_main!(benches);
