# Pingap 6-Tier Multi-Competitor Benchmark Suite

`scripts/bench/run.sh` implements a reproducible, correctness-verified **6-tier** HTTP/TLS/HTTP2/reload benchmark suite comparing **Pingap** against **Nginx**, **Caddy**, **Traefik**, and **HAProxy** (auto-detecting whichever engines and load generators are installed on the machine).

## Tiers Covered

| Tier | Scenario | What it isolates |
| :--- | :--- | :--- |
| **T1 (`t1`)** | `/ping` short-circuit (no upstream, no access log) | Listener dispatch, HTTP parser, routing overhead, `Ctx` allocation |
| **T2a (`t2a`)** | HTTP/1.1 Keep-Alive proxy (`64 KB` JSON, no compression) | Upstream Keep-Alive pooling (`128`) and body forwarding |
| **T2b (`t2b`)** | HTTP/1.1 Keep-Alive proxy (`64 KB` JSON + `gzip` level 6) | Proxy compression CPU/throughput parity under `Accept-Encoding: gzip` |
| **T3 (`t3`)** | TLS 1.3 handshake flood (ECDSA P-256, Keep-Alive disabled) | Downstream TLS offload threadpool / OpenSSL vs Rustls handshake cost (`oha --disable-keepalive` or `wrk -H "Connection: close"`) |
| **T4 (`t4`)** | HTTP/2 multiplexing over TLS | Stream multiplexing (`h2load -m 100` or `oha --http2`) |
| **T5 (`t5`)** | Production middleware stack (`200` routes + buffered access log + IP rate limit + `X-Gateway`) | Route-table matching at scale, access logging overhead, rate-limit cost |
| **T6 (`t6`)** | Hot reload under live load | Latency tail (`P99` / `Max`), error count, and live verification across 2 hot reloads (`v1 -> v2 -> v3`) while `wrk` runs |

## Prerequisites

- **Required**: `wrk`, `nginx` (also acts as high-speed origin), `openssl`, `curl`, `python3`
- **Optional engines**: `caddy`, `traefik`, `haproxy`
- **Optional HTTP/2 / TLS flood load tools**: `h2load` (for T4 multiplexing), `oha` (for true `--disable-keepalive` TLS handshake flood in T3 and `--http2` fallback in T4)
- Missing optional competitors or T4 tools (`h2load`/`oha`) are skipped cleanly without failing the suite.

## Usage

```bash
# 1. Build Pingap release binary
cargo build --release --features=full

# 2. Run all detected engines & all 6 tiers (via Makefile target or directly)
make bench-suite
./scripts/bench/run.sh --bin target/release/pingap

# 3. Compare only Pingap vs Nginx on selected tiers with baseline save/compare
./scripts/bench/run.sh \
  --bin target/release/pingap \
  --engines pingap,nginx \
  --tiers t1,t2a,t2b,t5,t6 \
  --save-baseline /tmp/pingap-suite-before.tsv

# Re-run after optimization and print RPS deltas + JSON report
./scripts/bench/run.sh \
  --bin target/release/pingap \
  --engines pingap,nginx \
  --compare /tmp/pingap-suite-before.tsv \
  --output-json /tmp/pingap-suite-after.json
```

### Linux CPU Pinning (Recommended for Dedicated Hosts)

Prevent load generators (`wrk` / `oha` / `h2load`) from competing for CPU cores with proxy workers:

```bash
./scripts/bench/run.sh \
  --bin target/release/pingap \
  --workers 4 \
  --threads 4 \
  --conns 128 \
  --pin-proxy-cpus 0-3 \
  --pin-load-cpus 4-7
```

## Fair Comparison Guarantees

- Every proxy runs with the same worker/thread count (`--workers`), same ECDSA P-256 certificate, TLS 1.2+, upstream Keep-Alive pool (`128`), and buffered access logs in T5 (`channel_buffer=8192` / `flush_timeout=1s` vs Nginx `buffer=64k flush=1s` vs Caddy/HAProxy buffered stdout/file).
- Every scenario verifies `HTTP 200`, expected body/header (`pong` / JSON payload / `Content-Encoding: gzip` / `X-Gateway` / `HTTP/2` / `X-Reload-Gen: v3`) with `curl` before starting timers.
- Socket errors and non-2xx responses reported by load generators are extracted and printed alongside `RPS`, `Avg`, `P50`, `P99`, `Max`, and process-tree `RSS (MB)`.
