use criterion::{criterion_group, criterion_main, Criterion};
use pingap_util::{format_byte_size, IpRules};

fn bench_format_byte_size(c: &mut Criterion) {
    let mut g = c.benchmark_group("format byte size");
    g.bench_function("<1KB", |b| {
        b.iter(|| {
            let mut buf = String::new();
            format_byte_size(&mut buf, 999);
            if buf != "999B" {
                panic!("value is invalid");
            }
        });
    });

    g.bench_function("<1MB", |b| {
        let size = 999 * 1000 + 900;
        b.iter(|| {
            let mut buf = String::new();
            format_byte_size(&mut buf, size);
            if buf != "999.9KB" {
                panic!("value is invalid")
            }
        });
    });

    g.finish();
}

fn bench_ip_rules(c: &mut Criterion) {
    let mut g = c.benchmark_group("ip rules");
    g.bench_function("ip", |b| {
        let rules = IpRules::new(&["192.168.1.1", "192.168.1.2"]);
        let ip = "192.168.1.1";
        b.iter(|| {
            if !rules.is_match(ip).unwrap() {
                panic!("ip should be matched");
            }
        });
    });

    g.bench_function("ip net", |b| {
        let rules = IpRules::new(&["192.168.2.0/24", "192.168.1.0/24"]);
        let ip = "192.168.1.1";
        b.iter(|| {
            if !rules.is_match(ip).unwrap() {
                panic!("ip should be matched");
            }
        });
    });

    g.finish();
}

criterion_group!(benches, bench_format_byte_size, bench_ip_rules);
criterion_main!(benches);
