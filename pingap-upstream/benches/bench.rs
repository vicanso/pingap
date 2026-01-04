use criterion::{Criterion, criterion_group, criterion_main};
use pingap_upstream::HashStrategy;

#[allow(clippy::unwrap_used)]
fn new_get_session(
    headers: Vec<String>,
    url: String,
) -> std::sync::mpsc::Receiver<Option<pingora::proxy::Session>> {
    let (tx, rx) = std::sync::mpsc::sync_channel(0);
    std::thread::spawn(move || {
        match tokio::runtime::Runtime::new() {
            Ok(rt) => {
                let send = async move {
                    let headers = headers.join("\r\n");
                    let input_header =
                        format!("GET {url} HTTP/1.1\r\n{headers}\r\n\r\n");
                    let mock_io = tokio_test::io::Builder::new()
                        .read(input_header.as_bytes())
                        .build();

                    let mut session =
                        pingora::proxy::Session::new_h1(Box::new(mock_io));
                    session.read_request().await.unwrap();
                    let _ = tx.send(Some(session));
                };
                rt.block_on(send);
            },
            Err(_e) => {
                let _ = tx.send(None);
            },
        };
    });
    rx
}

#[allow(clippy::unwrap_used)]
fn bench_hash_strategy(c: &mut Criterion) {
    let mut g = c.benchmark_group("hash strategy");
    let session = new_get_session(
        [
            "Host: github.com",
            "Referer: https://github.com/",
            "User-Agent: pingap/0.1.1",
            "Cookie: deviceId=abc",
            "Accept: application/json",
            "X-Forwarded-For: 1.1.1.1",
        ]
        .into_iter()
        .map(|item| item.to_string())
        .collect(),
        "/vicanso/pingap?id=1234".to_string(),
    )
    .recv()
    .unwrap()
    .unwrap();

    g.bench_function("ip", |b| {
        b.iter(|| {
            let value = HashStrategy::Ip.get_value(&session, &None);
            if value != "1.1.1.1" {
                panic!("value is invalid");
            }
        });
    });

    g.bench_function("header", |b| {
        b.iter(|| {
            let value = HashStrategy::Header("User-Agent".to_string())
                .get_value(&session, &None);
            if value != "pingap/0.1.1" {
                panic!("value is invalid");
            }
        });
    });

    g.bench_function("cookie", |b| {
        b.iter(|| {
            let value = HashStrategy::Cookie("deviceId".to_string())
                .get_value(&session, &None);
            if value != "abc" {
                panic!("value is invalid");
            }
        });
    });

    g.bench_function("query", |b| {
        b.iter(|| {
            let value = HashStrategy::Query("id".to_string())
                .get_value(&session, &None);
            if value != "1234" {
                panic!("value is invalid");
            }
        });
    });

    g.bench_function("path", |b| {
        b.iter(|| {
            let value = HashStrategy::Path.get_value(&session, &None);
            if value != "/vicanso/pingap" {
                panic!("value is invalid");
            }
        });
    });

    g.bench_function("url", |b| {
        b.iter(|| {
            let value = HashStrategy::Url.get_value(&session, &None);
            if value != "/vicanso/pingap?id=1234" {
                panic!("value is invalid");
            }
        });
    });

    g.finish();
}

criterion_group!(benches, bench_hash_strategy,);
criterion_main!(benches);
