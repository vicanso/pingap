use criterion::{criterion_group, criterion_main, Criterion};
use http::StatusCode;
use pingap_core::{
    CompressionStat, ConnectionInfo, Ctx, Features, RequestState, Timing,
    UpstreamInfo,
};
use pingap_logger::Parser;
use pingora::proxy::Session;
use std::sync::mpsc;
use std::time::Duration;
use tokio_test::io::Builder;

fn get_logger_session() -> mpsc::Receiver<Option<Session>> {
    let (tx, rx) = mpsc::sync_channel(0);
    std::thread::spawn(move || {
        match tokio::runtime::Runtime::new() {
            Ok(rt) => {
                let send = async move {
                    let headers = [
                        "Host: github.com",
                        "Referer: https://github.com/",
                        "user-agent: pingap/0.1.1",
                        "Cookie: deviceId=abc",
                        "Accept: application/json",
                        "X-Forwarded-For: 1.1.1.1, 2.2.2.2",
                    ]
                    .join("\r\n");
                    let input_header = format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
                    let mock_io =
                        Builder::new().read(input_header.as_bytes()).build();

                    let mut session = Session::new_h1(Box::new(mock_io));
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

fn bench_logger_format(c: &mut Criterion) {
    let session = get_logger_session().recv().unwrap().unwrap();
    c.bench_function("logger format", |b| {
        let p: Parser =
            "{host} {method} {path} {proto} {query} {remote} {client_ip} \
{scheme} {uri} {referer} {user_agent} {when} {when_utc_iso} \
{when_unix} {size} {size_human} {status} {latency} \
{payload_size} {latency_human} {payload_size} \
{payload_size_human} {request_id} \
{:upstream_reused} {:upstream_addr} {:processing} {:upstream_connect_time_human} \
{:upstream_connected} {:upstream_processing_time_human} {:upstream_response_time_human} \
{:location} {:established} {:tls_version} {:compression_time_human} \
{:compression_ratio} {:cache_lookup_time_human} {:cache_lock_time_human} \
{~deviceId} {>accept} {:reused}"
                .into();
        let ctx = Ctx {
            timing: Timing {
                connection_duration: 300,
                upstream_connect: Some(30),
                upstream_processing: Some(50),
                upstream_response: Some(5),
                cache_lookup: Some(3),
                cache_lock: Some(8),
                ..Default::default()
            },
            state: RequestState {
                request_id: Some("AMwBhEil".to_string()),
                status: Some(StatusCode::OK),
                payload_size: 512,
                processing_count: 10,
                ..Default::default()
            },
            upstream: UpstreamInfo {
                address: "192.168.1.1:5000".to_string(),
                location: "".to_string(),
                reused: true,
                connected_count: Some(10),
                ..Default::default()
            },
            conn: ConnectionInfo {
                tls_version: Some("tls1.2".to_string()),
                ..Default::default()
            },
            features: Some(Features{
                compression_stat: Some(CompressionStat {
                    in_bytes: 50 * 1024,
                    out_bytes: 12 * 1024,
                    duration: Duration::from_millis(8),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        b.iter(|| {
            let _ = p.format(&session, &ctx);
        })
    });
}

criterion_group!(benches, bench_logger_format);
criterion_main!(benches);
