use criterion::{Criterion, criterion_group, criterion_main};
use pingap_proxy::{ErrorTemplate, error_response_header};
use pingora::protocols::http::error_resp::gen_error_response;

const TEMPLATE: &str = include_str!("../src/error.html");

fn bench_error_template(c: &mut Criterion) {
    let mut group = c.benchmark_group("error page");
    let content = "Upstream ConnectRefused context: Fail to connect to addr: 127.0.0.1:5000";
    group.bench_function("replace chain", |b| {
        b.iter(|| {
            TEMPLATE
                .replace("{{version}}", "0.14.3")
                .replace("{{content}}", content)
                .replace("{{error_type}}", "ConnectRefused")
        })
    });
    let parsed = ErrorTemplate::new(TEMPLATE);
    group.bench_function("parsed template", |b| {
        b.iter(|| parsed.render("0.14.3", content, "ConnectRefused"))
    });
    group.finish();
}

fn bench_error_response_header(c: &mut Criterion) {
    let mut group = c.benchmark_group("error response header");
    group.bench_function("generated", |b| b.iter(|| gen_error_response(404)));
    group.bench_function("prebuilt", |b| b.iter(|| error_response_header(404)));
    group.finish();
}

criterion_group!(benches, bench_error_template, bench_error_response_header);
criterion_main!(benches);
