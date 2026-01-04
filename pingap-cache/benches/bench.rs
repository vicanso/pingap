use criterion::{Criterion, criterion_group, criterion_main};
use pingap_core::TinyUfo;

fn bench_tinyufo_get(c: &mut Criterion) {
    c.bench_function("tinyufo get", |b| {
        let cache = TinyUfo::new(1000, 1000);
        let key = "key";
        cache.put(key.to_string(), "value", 100);
        b.iter(|| {
            let _ = cache.get(&key.to_string());
        });
    });
}

criterion_group!(benches, bench_tinyufo_get);
criterion_main!(benches);
