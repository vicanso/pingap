use criterion::{criterion_group, criterion_main, Criterion};
use pingap_core::TinyUfo;
use std::sync::Arc;

fn bench_tinyufo_get(c: &mut Criterion) {
    let mut group = c.benchmark_group("tinyufo");

    group.bench_function("tinyufo string", |b| {
        let cache = TinyUfo::new(1000, 1000);
        let key = "key";
        cache.put(key.to_string(), "value", 100);
        b.iter(|| {
            let _ = cache.get(&key.to_string());
        });
    });

    group.bench_function("tinyufo arc", |b| {
        let cache = TinyUfo::new(1000, 1000);
        let key = Arc::new("key");
        cache.put(key.clone(), "value", 100);
        b.iter(|| {
            let _ = cache.get("key");
        });
    });

    group.finish();
}

criterion_group!(benches, bench_tinyufo_get);
criterion_main!(benches);
