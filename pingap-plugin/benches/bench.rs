use criterion::{Criterion, criterion_group, criterion_main};
use pingap_config::PluginConf;
use pingap_core::{Ctx, PluginStep};
use pingap_plugin::get_plugin_factory;
use pingora::proxy::Session;
use tokio_test::io::Builder;

// Signed with the secret `123123`, never expires.
const HS256_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiIsImFkbWluIjp0cnVlLCJleHAiOjIzNDgwNTUyNjV9.j6sYJ2dCCSxskwPmvHM7WniGCbkT30z2BrjfsuQLFJc";

async fn new_session(input: &str) -> Session {
    let mock_io = Builder::new().read(input.as_bytes()).build();
    let mut session = Session::new_h1(Box::new(mock_io));
    session.read_request().await.expect("request must parse");
    session
}

fn bench_auth(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let mut group = c.benchmark_group("auth plugins");

    let jwt = get_plugin_factory()
        .create(
            &toml::from_str::<PluginConf>(
                "category = \"jwt\"\nheader = \"Authorization\"\nsecret = \"123123\"\n",
            )
            .expect("valid toml"),
        )
        .expect("plugin config");
    let mut session = rt.block_on(new_session(&format!(
        "GET / HTTP/1.1\r\nAuthorization: Bearer {HS256_TOKEN}\r\n\r\n"
    )));
    let mut ctx = Ctx::default();
    // The future borrows the session, so it is driven to completion inside
    // the closure; the runtime's block_on cost is the same on both sides.
    group.bench_function("jwt hs256 verify", |b| {
        b.iter(|| {
            rt.block_on(jwt.handle_request(
                PluginStep::Request,
                &mut session,
                &mut ctx,
            ))
        })
    });

    // spellchecker:off
    let basic = get_plugin_factory()
        .create(
            &toml::from_str::<PluginConf>(
                "category = \"basic_auth\"\nauthorizations = [\"YWRtaW46MTIzMTIz\"]\n",
            )
            .expect("valid toml"),
        )
        .expect("plugin config");
    let mut session = rt.block_on(new_session(
        "GET / HTTP/1.1\r\nAuthorization: Basic YWRtaW46MTIzMTIz\r\n\r\n",
    ));
    // spellchecker:on
    group.bench_function("basic auth verify", |b| {
        b.iter(|| {
            rt.block_on(basic.handle_request(
                PluginStep::Request,
                &mut session,
                &mut ctx,
            ))
        })
    });
    group.finish();
}

fn bench_sub_filter(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let mut group = c.benchmark_group("sub_filter");
    let plugin = get_plugin_factory()
        .create(
            &toml::from_str::<PluginConf>(
                r#"
category = "sub_filter"
filters = [
    "sub_filter 'http://old.example.com' 'https://new.example.com' g",
    "subs_filter '<title>(.*?)</title>' '<title>$1 - Docs</title>' i",
    "sub_filter '</head>' '<script src=\"/a.js\"></script></head>'",
]
"#,
            )
            .expect("valid toml"),
        )
        .expect("plugin config");
    // A 64 KiB page with a handful of matches, delivered in one chunk.
    let page = format!(
        "<html><head><title>Page</title></head><body>{}</body></html>",
        "<p>text <a href=\"http://old.example.com/x\">link</a></p>\n"
            .repeat(1200)
    );
    let body = bytes::Bytes::from(page);
    let mut session = rt.block_on(new_session("GET /docs HTTP/1.1\r\n\r\n"));
    group.throughput(criterion::Throughput::Bytes(body.len() as u64));
    group.bench_function("rewrite 64k page", |b| {
        b.iter(|| {
            let mut ctx = Ctx::default();
            let mut resp = pingora::http::ResponseHeader::build(200, None)
                .expect("response header");
            rt.block_on(plugin.handle_response(
                &mut session,
                &mut ctx,
                &mut resp,
            ))
            .expect("response");
            let mut chunk = Some(body.clone());
            plugin
                .handle_response_body(&mut session, &mut ctx, &mut chunk, true)
                .expect("body");
            chunk
        })
    });
    group.finish();
}

fn bench_ua_restriction(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let mut group = c.benchmark_group("ua_restriction");
    // A typical bot block list: twenty patterns, and a browser that
    // matches none of them.
    let patterns = [
        "AhrefsBot",
        "SemrushBot",
        "MJ12bot",
        "DotBot",
        "PetalBot",
        "Bytespider",
        "GPTBot",
        "CCBot",
        "python-requests",
        "curl/",
        "wget/",
        "Go-http-client",
        "Java/",
        "libwww-perl",
        "masscan",
        "zgrab",
        "nikto",
        "sqlmap",
        "(Twitterspider)/(\\d+)\\.(\\d+)",
        "^$",
    ];
    let ua_list = patterns
        .iter()
        // TOML literal strings, so a regex backslash needs no escaping.
        .map(|p| format!("'{p}'"))
        .collect::<Vec<_>>()
        .join(", ");
    let plugin = get_plugin_factory()
        .create(
            &toml::from_str::<PluginConf>(&format!(
                "category = \"ua_restriction\"\ntype = \"deny\"\nua_list = [{ua_list}]\n"
            ))
            .expect("valid toml"),
        )
        .expect("plugin config");
    let mut session = rt.block_on(new_session(
        "GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36\r\n\r\n",
    ));
    let mut ctx = Ctx::default();
    group.bench_function("20 patterns, browser ua", |b| {
        b.iter(|| {
            rt.block_on(plugin.handle_request(
                PluginStep::Request,
                &mut session,
                &mut ctx,
            ))
        })
    });
    group.finish();
}

criterion_group!(benches, bench_auth, bench_sub_filter, bench_ua_restriction);
criterion_main!(benches);
