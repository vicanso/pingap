use bytes::Bytes;
use criterion::{Criterion, criterion_group, criterion_main};
use pingap_cache::CacheObject;
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

fn bench_cache_object(c: &mut Criterion) {
    let obj = CacheObject {
        meta: (vec![b'a'; 300].into(), vec![b'b'; 100].into()),
        body: Bytes::from(vec![0u8; 64 * 1024]),
    };
    c.bench_function("cache object to bytes 64k", |b| {
        b.iter(|| {
            let buf: Bytes = obj.clone().into();
            buf
        })
    });
    let buf: Bytes = obj.clone().into();
    c.bench_function("cache object from bytes 64k", |b| {
        b.iter(|| CacheObject::try_from(buf.clone()).expect("parse"))
    });
    c.bench_function("cache object clone", |b| b.iter(|| obj.clone()));
}

criterion_group!(benches, bench_tinyufo_get, bench_cache_object);
criterion_main!(benches);
