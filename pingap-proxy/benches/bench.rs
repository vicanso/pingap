use criterion::{Criterion, criterion_group, criterion_main};
use pingap_proxy::ErrorTemplate;

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

criterion_group!(benches, bench_error_template);
criterion_main!(benches);
