#!/usr/bin/env bash
set -euo pipefail

# 6-Tier Multi-Competitor Benchmark Suite for Pingap
# Compares Pingap against Nginx, Caddy, Traefik, and HAProxy (auto-detected).
#
# Tiers:
#   t1   - /ping short-path baseline (no upstream, no access log)
#   t2a  - HTTP/1.1 Keep-Alive reverse proxy of large JSON payload (no compression)
#   t2b  - HTTP/1.1 Keep-Alive reverse proxy of large JSON payload + gzip compression
#   t3   - Short-lived TLS 1.3 (ECDSA P-256) handshake flood
#   t4   - HTTP/2 multiplexing over TLS (uses h2load or oha if installed)
#   t5   - Production middleware stack (N routes + buffered access log + IP rate limit + X-Gateway)
#   t6   - Live hot-reload stability under active traffic (2 reloads v1->v2->v3)
#
# Exit codes:
#   0 - Completed successfully
#   1 - Configuration, runtime, or correctness assertion failure
#   2 - Missing required base tool (wrk, nginx, openssl, curl, python3) or no engines available

SCRIPT_NAME=$(basename "$0")
PINGAP_BIN=""
ENGINES_ARG="auto"
TIERS_ARG="all"
WORKERS="${WORKERS:-2}"
WRK_THREADS="${WRK_THREADS:-2}"
WRK_CONNS="${WRK_CONNS:-64}"
WRK_WARMUP="${WRK_WARMUP:-2}"
WRK_DURATION="${WRK_DURATION:-8}"
ROUTES="${ROUTES:-200}"
PAYLOAD_KB="${PAYLOAD_KB:-64}"
PIN_PROXY_CPUS=""
PIN_LOAD_CPUS=""
SAVE_BASELINE=""
COMPARE_BASELINE=""
OUTPUT_JSON=""

usage() {
  cat <<EOF
Usage: $SCRIPT_NAME [options]

Options:
  --bin <path>            Path to pingap binary (auto-detected if omitted)
  --engines <list>        'auto' (default) or comma-separated: pingap,nginx,caddy,traefik,haproxy
  --tiers <list>          'all' (default) or comma-separated: t1,t2a,t2b,t3,t4,t5,t6
  --workers <n>           Worker threads/processes aligned across engines (default: $WORKERS)
  --threads <n>           Load generator client threads (default: $WRK_THREADS)
  --conns <n>             Concurrent client connections (default: $WRK_CONNS)
  --warmup <sec>          Warmup duration in seconds (default: $WRK_WARMUP)
  --duration <sec>        Measurement duration in seconds (default: $WRK_DURATION)
  --routes <n>            Number of routes generated in T5 (default: $ROUTES)
  --payload-kb <n>        JSON origin payload size in KiB for T2a/T2b (default: $PAYLOAD_KB)
  --pin-proxy-cpus <list> Linux taskset CPU list for proxy processes (e.g. 0-3)
  --pin-load-cpus <list>  Linux taskset CPU list for load generator (e.g. 4-7)
  --save-baseline <file>  Save TSV metrics for later --compare
  --compare <file>        Compare current Pingap metrics against baseline TSV
  --output-json <file>    Write structured JSON benchmark report
  -h, --help              Show this help message
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --bin) PINGAP_BIN="${2:?missing value for --bin}"; shift 2 ;;
    --engines) ENGINES_ARG="${2:?missing value for --engines}"; shift 2 ;;
    --tiers) TIERS_ARG="${2:?missing value for --tiers}"; shift 2 ;;
    --workers) WORKERS="${2:?missing value for --workers}"; shift 2 ;;
    --threads) WRK_THREADS="${2:?missing value for --threads}"; shift 2 ;;
    --conns) WRK_CONNS="${2:?missing value for --conns}"; shift 2 ;;
    --warmup) WRK_WARMUP="${2:?missing value for --warmup}"; shift 2 ;;
    --duration) WRK_DURATION="${2:?missing value for --duration}"; shift 2 ;;
    --routes) ROUTES="${2:?missing value for --routes}"; shift 2 ;;
    --payload-kb) PAYLOAD_KB="${2:?missing value for --payload-kb}"; shift 2 ;;
    --pin-proxy-cpus) PIN_PROXY_CPUS="${2:?missing value for --pin-proxy-cpus}"; shift 2 ;;
    --pin-load-cpus) PIN_LOAD_CPUS="${2:?missing value for --pin-load-cpus}"; shift 2 ;;
    --save-baseline) SAVE_BASELINE="${2:?missing value for --save-baseline}"; shift 2 ;;
    --compare) COMPARE_BASELINE="${2:?missing value for --compare}"; shift 2 ;;
    --output-json) OUTPUT_JSON="${2:?missing value for --output-json}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done

list_has() {
  case ",$1," in
    *",$2,"*) return 0 ;;
    *) return 1 ;;
  esac
}

require_tool() {
  local tool=$1
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "Skipping benchmark suite: required tool '$tool' not found in PATH." >&2
    exit 2
  fi
}

require_tool wrk
require_tool nginx
require_tool openssl
require_tool curl
require_tool python3

resolve_pingap_bin() {
  if [ -n "$PINGAP_BIN" ]; then
    return 0
  fi
  if [ -n "${CARGO_TARGET_DIR:-}" ] && [ -x "${CARGO_TARGET_DIR}/release/pingap" ]; then
    PINGAP_BIN="${CARGO_TARGET_DIR}/release/pingap"
    return 0
  fi
  if [ -x "./target/release/pingap" ]; then
    PINGAP_BIN="./target/release/pingap"
    return 0
  fi
  local target_dir
  target_dir=$(cargo metadata --no-deps --format-version 1 2>/dev/null \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])' 2>/dev/null || true)
  if [ -n "$target_dir" ] && [ -x "${target_dir}/release/pingap" ]; then
    PINGAP_BIN="${target_dir}/release/pingap"
    return 0
  fi
  echo "Could not locate release pingap binary. Build with 'cargo build --release --features=full' or pass --bin <path>." >&2
  exit 1
}

if [ "$ENGINES_ARG" = "auto" ] || list_has "$ENGINES_ARG" "pingap"; then
  resolve_pingap_bin
  if [ ! -x "$PINGAP_BIN" ]; then
    echo "Pingap binary is not executable: $PINGAP_BIN" >&2
    exit 1
  fi
fi

if [ -n "$COMPARE_BASELINE" ] && [ ! -f "$COMPARE_BASELINE" ]; then
  echo "Baseline file not found: $COMPARE_BASELINE" >&2
  exit 1
fi

WRK_BIN=$(command -v wrk)
NGINX_BIN=$(command -v nginx)
OPENSSL_BIN=$(command -v openssl)
CADDY_BIN=$(command -v caddy 2>/dev/null || true)
TRAEFIK_BIN=$(command -v traefik 2>/dev/null || true)
HAPROXY_BIN=$(command -v haproxy 2>/dev/null || true)
OHA_BIN=$(command -v oha 2>/dev/null || true)
H2LOAD_BIN=$(command -v h2load 2>/dev/null || true)
TASKSET_BIN=""
if command -v taskset >/dev/null 2>&1; then
  TASKSET_BIN=$(command -v taskset)
fi

ACTIVE_ENGINES=""
add_engine() {
  local eng=$1
  if [ -z "$ACTIVE_ENGINES" ]; then
    ACTIVE_ENGINES="$eng"
  else
    ACTIVE_ENGINES="${ACTIVE_ENGINES},${eng}"
  fi
}

if [ "$ENGINES_ARG" = "auto" ]; then
  add_engine "pingap"
  [ -n "$NGINX_BIN" ] && add_engine "nginx"
  [ -n "$CADDY_BIN" ] && add_engine "caddy"
  [ -n "$TRAEFIK_BIN" ] && add_engine "traefik"
  [ -n "$HAPROXY_BIN" ] && add_engine "haproxy"
else
  OLD_IFS=$IFS
  IFS=','
  for eng in $ENGINES_ARG; do
    case "$eng" in
      pingap) add_engine "pingap" ;;
      nginx) [ -n "$NGINX_BIN" ] && add_engine "nginx" || echo "WARN: nginx not installed, skipping." >&2 ;;
      caddy) [ -n "$CADDY_BIN" ] && add_engine "caddy" || echo "WARN: caddy not installed, skipping." >&2 ;;
      traefik) [ -n "$TRAEFIK_BIN" ] && add_engine "traefik" || echo "WARN: traefik not installed, skipping." >&2 ;;
      haproxy) [ -n "$HAPROXY_BIN" ] && add_engine "haproxy" || echo "WARN: haproxy not installed, skipping." >&2 ;;
      *) echo "Unknown engine: $eng (expected pingap,nginx,caddy,traefik,haproxy)" >&2; exit 1 ;;
    esac
  done
  IFS=$OLD_IFS
fi

if [ -z "$ACTIVE_ENGINES" ]; then
  echo "No requested benchmark engines are available." >&2
  exit 2
fi

ALL_TIERS="t1,t2a,t2b,t3,t4,t5,t6"
if [ "$TIERS_ARG" = "all" ]; then
  ACTIVE_TIERS="$ALL_TIERS"
else
  ACTIVE_TIERS="$TIERS_ARG"
  OLD_IFS=$IFS
  IFS=','
  for t in $ACTIVE_TIERS; do
    if ! list_has "$ALL_TIERS" "$t"; then
      echo "Unknown tier: $t (expected one of: $ALL_TIERS)" >&2
      exit 1
    fi
  done
  IFS=$OLD_IFS
fi

BENCH_DIR=$(mktemp -d "${TMPDIR:-/tmp}/pingap-bench-suite.XXXXXX")
RESULTS_TSV="$BENCH_DIR/results.tsv"
printf "tier\tengine\ttool\trps\tavg\tp50\tp99\tmax\terrors\trss_mb\n" > "$RESULTS_TSV"

PORT_BASE=$((20000 + ($$ % 450) * 20))
ORIGIN_PORT=$((PORT_BASE + 0))
PINGAP_HTTP=$((PORT_BASE + 1))
PINGAP_HTTPS=$((PORT_BASE + 2))
NGINX_HTTP=$((PORT_BASE + 3))
NGINX_HTTPS=$((PORT_BASE + 4))
CADDY_HTTP=$((PORT_BASE + 5))
CADDY_HTTPS=$((PORT_BASE + 6))
CADDY_ADMIN=$((PORT_BASE + 7))
TRAEFIK_HTTP=$((PORT_BASE + 8))
TRAEFIK_HTTPS=$((PORT_BASE + 9))
HAPROXY_HTTP=$((PORT_BASE + 10))
HAPROXY_HTTPS=$((PORT_BASE + 11))

PIDS=""

record_pid() {
  if [ -z "$PIDS" ]; then
    PIDS="$1"
  else
    PIDS="$PIDS $1"
  fi
}

cleanup() {
  local pid
  for pid in $PIDS; do
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      kill -9 "$pid" 2>/dev/null || true
    fi
  done
  if [ -n "${BENCH_DIR:-}" ] && [ -d "$BENCH_DIR" ]; then
    pkill -9 -f "$BENCH_DIR" 2>/dev/null || true
    rm -rf "$BENCH_DIR"
  fi
}
trap cleanup EXIT INT TERM

mkdir -p "$BENCH_DIR/confs" "$BENCH_DIR/logs" "$BENCH_DIR/origin_www" \
  "$BENCH_DIR/traefik_dyn" "$BENCH_DIR/nginx_tmp/client" "$BENCH_DIR/nginx_tmp/proxy" \
  "$BENCH_DIR/nginx_tmp/fcgi" "$BENCH_DIR/nginx_tmp/uwsgi" "$BENCH_DIR/nginx_tmp/scgi"

# Generate deterministic ECDSA P-256 cert + combined PEM for HAProxy
"$OPENSSL_BIN" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -nodes -days 1 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout "$BENCH_DIR/tls.key" -out "$BENCH_DIR/tls.crt" 2>/dev/null
cat "$BENCH_DIR/tls.crt" "$BENCH_DIR/tls.key" > "$BENCH_DIR/haproxy.pem"

# Generate PAYLOAD_KB valid JSON document for T2a/T2b/T3/T4/T5/T6
python3 - "$BENCH_DIR/origin_www/payload.json" "$PAYLOAD_KB" <<'PY'
import json, sys
out_path = sys.argv[1]
target_bytes = int(sys.argv[2]) * 1024
prefix = '{"ok":true,"service":"origin","padding":"'
suffix = '"}'
pad_len = max(16, target_bytes - len(prefix) - len(suffix))
doc = prefix + ("x" * pad_len) + suffix
with open(out_path, "w", encoding="utf-8") as f:
    f.write(doc)
# Sanity check valid JSON
json.loads(doc)
PY

# Start shared Nginx Origin server
cat > "$BENCH_DIR/confs/origin_nginx.conf" <<EOF
worker_processes $WORKERS;
daemon off;
pid $BENCH_DIR/origin.pid;
error_log $BENCH_DIR/logs/origin_error.log crit;

events {
    worker_connections 4096;
}

http {
    access_log off;
    gzip off;
    sendfile on;
    tcp_nopush on;
    client_body_temp_path $BENCH_DIR/nginx_tmp/client;
    proxy_temp_path $BENCH_DIR/nginx_tmp/proxy;
    fastcgi_temp_path $BENCH_DIR/nginx_tmp/fcgi;
    uwsgi_temp_path $BENCH_DIR/nginx_tmp/uwsgi;
    scgi_temp_path $BENCH_DIR/nginx_tmp/scgi;
    keepalive_timeout 65;
    keepalive_requests 10000000;

    server {
        listen 127.0.0.1:$ORIGIN_PORT;
        location = /api/json {
            alias $BENCH_DIR/origin_www/payload.json;
            default_type application/json;
        }
    }
}
EOF

"$NGINX_BIN" -t -c "$BENCH_DIR/confs/origin_nginx.conf" >/dev/null 2>&1
"$NGINX_BIN" -c "$BENCH_DIR/confs/origin_nginx.conf" >/dev/null 2>&1 &
ORIGIN_PID=$!
record_pid "$ORIGIN_PID"

wait_for_url() {
  local url=$1
  local expect=$2
  local extra_flag=${3:-}
  local attempts=${4:-80}
  local body i
  i=0
  while [ "$i" -lt "$attempts" ]; do
    if [ -n "$extra_flag" ]; then
      # shellcheck disable=SC2086
      body=$(curl -fsS $extra_flag "$url" 2>/dev/null || true)
    else
      body=$(curl -fsS "$url" 2>/dev/null || true)
    fi
    case "$body" in
      *"$expect"*) return 0 ;;
    esac
    sleep 0.1
    i=$((i + 1))
  done
  echo "Timed out waiting for $url to contain '$expect'" >&2
  return 1
}

wait_for_header() {
  local url=$1
  local expect_header=$2
  local extra_flag=${3:-}
  local attempts=${4:-100}
  local hdrs i
  i=0
  while [ "$i" -lt "$attempts" ]; do
    if [ -n "$extra_flag" ]; then
      # shellcheck disable=SC2086
      hdrs=$(curl -fsS -D - -o /dev/null $extra_flag "$url" 2>/dev/null || true)
    else
      hdrs=$(curl -fsS -D - -o /dev/null "$url" 2>/dev/null || true)
    fi
    if printf '%s\n' "$hdrs" | grep -qi "$expect_header"; then
      return 0
    fi
    sleep 0.1
    i=$((i + 1))
  done
  echo "Timed out waiting for header '$expect_header' at $url" >&2
  return 1
}

wait_for_url "http://127.0.0.1:$ORIGIN_PORT/api/json" '"service":"origin"'

rss_mb_for_pid_tree() {
  local root_pid=$1
  local pids="$root_pid"
  local children
  children=$(pgrep -P "$root_pid" 2>/dev/null || true)
  if [ -n "$children" ]; then
    pids="$pids $children"
  fi
  local total_kb=0
  local p kb
  for p in $pids; do
    kb=$(ps -o rss= -p "$p" 2>/dev/null | tr -d ' ' || echo 0)
    case "$kb" in
      ''|*[!0-9]*) kb=0 ;;
    esac
    total_kb=$((total_kb + kb))
  done
  awk "BEGIN { printf \"%.1f\", $total_kb / 1024.0 }"
}

stop_proc_tree() {
  local root_pid=$1
  local children c
  children=$(pgrep -P "$root_pid" 2>/dev/null || true)
  for c in $children; do
    kill -9 "$c" 2>/dev/null || true
  done
  kill -9 "$root_pid" 2>/dev/null || true
  wait "$root_pid" 2>/dev/null || true
}

start_proxy() {
  if [ -n "$PIN_PROXY_CPUS" ] && [ -n "$TASKSET_BIN" ]; then
    "$TASKSET_BIN" -c "$PIN_PROXY_CPUS" "$@" >/dev/null 2>&1 &
  else
    "$@" >/dev/null 2>&1 &
  fi
  PROXY_PID=$!
  record_pid "$PROXY_PID"
}

run_load_cmd() {
  if [ -n "$PIN_LOAD_CPUS" ] && [ -n "$TASKSET_BIN" ]; then
    "$TASKSET_BIN" -c "$PIN_LOAD_CPUS" "$@"
  else
    "$@"
  fi
}

parse_and_record() {
  local tier=$1
  local engine=$2
  local tool=$3
  local outfile=$4
  local rss=$5
  python3 - "$tier" "$engine" "$tool" "$outfile" "$rss" "$RESULTS_TSV" <<'PY'
import json, re, sys

tier, engine, tool, outfile, rss, tsv = sys.argv[1:]
text = open(outfile, "r", encoding="utf-8", errors="replace").read()

rps = "0"
avg = p50 = p99 = max_lat = "n/a"
errors = 0

def fmt_secs(val):
    if val <= 0:
        return "0ms"
    if val < 0.001:
        return f"{val*1e6:.0f}us"
    if val < 1.0:
        return f"{val*1e3:.2f}ms"
    return f"{val:.2f}s"

if tool == "wrk":
    m = re.search(r"Requests/sec:\s*([\d.]+)", text)
    if m:
        rps = m.group(1)
    m = re.search(r"^\s*Latency\s+(\S+)\s+(\S+)\s+(\S+)", text, re.M)
    if m:
        avg, max_lat = m.group(1), m.group(3)
    m = re.search(r"^\s*50%\s+(\S+)", text, re.M)
    if m:
        p50 = m.group(1)
    m = re.search(r"^\s*99%\s+(\S+)", text, re.M)
    if m:
        p99 = m.group(1)
    m = re.search(r"Socket errors:\s*connect\s*(\d+),\s*read\s*(\d+),\s*write\s*(\d+),\s*timeout\s*(\d+)", text)
    if m:
        errors += sum(int(x) for x in m.groups())
    m = re.search(r"Non-2xx or 3xx responses:\s*(\d+)", text)
    if m:
        errors += int(m.group(1))
elif tool == "h2load":
    m = re.search(r"finished in\s+[\d.]+\w*,\s+([\d.]+)\s+req/s", text)
    if m:
        rps = m.group(1)
    m = re.search(r"time for request:\s+\S+\s+(\S+)\s+(\S+)", text)
    if m:
        max_lat, avg = m.group(1), m.group(2)
    m = re.search(r"requests:\s+\d+\s+total.*?(\d+)\s+failed,\s+(\d+)\s+errored", text, re.S)
    if m:
        errors = int(m.group(1)) + int(m.group(2))
elif tool == "oha":
    try:
        data = json.loads(text)
        s = data.get("summary", {})
        rps = f"{float(s.get('requestsPerSec', 0)):.2f}"
        avg = fmt_secs(float(s.get("average", 0)))
        max_lat = fmt_secs(float(s.get("slowest", 0)))
        pct = data.get("latencyPercentiles", {})
        if "p50" in pct:
            p50 = fmt_secs(float(pct["p50"]))
        if "p99" in pct:
            p99 = fmt_secs(float(pct["p99"]))
        dist = data.get("statusCodeDistribution", {})
        for code, cnt in dist.items():
            if not str(code).startswith("2"):
                errors += int(cnt)
        errors += sum(int(v) for v in data.get("errorDistribution", {}).values())
    except Exception:
        m = re.search(r"Requests/sec:\s*([\d.]+)", text)
        if m:
            rps = m.group(1)

with open(tsv, "a", encoding="utf-8") as f:
    f.write(f"{tier}\t{engine}\t{tool}\t{rps}\t{avg}\t{p50}\t{p99}\t{max_lat}\t{errors}\t{rss}\n")
print(f"[{tier.upper()} {engine} via {tool}] RPS={rps} Avg={avg} P50={p50} P99={p99} Max={max_lat} Errors={errors} RSS={rss}MB")
PY
}

# Probe Nginx HTTP/2 syntax compatibility
NGINX_HTTP2_DIRECTIVE="listen 127.0.0.1:$NGINX_HTTPS ssl http2;"
if [ -n "$NGINX_BIN" ]; then
  cat > "$BENCH_DIR/confs/probe_h2.conf" <<EOF
events { worker_connections 16; }
http {
    server {
        listen 127.0.0.1:$NGINX_HTTPS ssl;
        http2 on;
        ssl_certificate $BENCH_DIR/tls.crt;
        ssl_certificate_key $BENCH_DIR/tls.key;
    }
}
EOF
  if "$NGINX_BIN" -t -c "$BENCH_DIR/confs/probe_h2.conf" >/dev/null 2>&1; then
    NGINX_HTTP2_DIRECTIVE="listen 127.0.0.1:$NGINX_HTTPS ssl;
        http2 on;"
  fi
fi

# Generate T5 routes helper (Python for speed & clean formatting)
generate_configs() {
  python3 - "$BENCH_DIR" "$ORIGIN_PORT" "$WORKERS" "$ROUTES" \
    "$PINGAP_HTTP" "$PINGAP_HTTPS" "$NGINX_HTTP" "$NGINX_HTTPS" "$NGINX_HTTP2_DIRECTIVE" \
    "$CADDY_HTTP" "$CADDY_HTTPS" "$CADDY_ADMIN" \
    "$TRAEFIK_HTTP" "$TRAEFIK_HTTPS" \
    "$HAPROXY_HTTP" "$HAPROXY_HTTPS" <<'PY'
import os, sys

(
    bench_dir, origin_port, workers, routes_n,
    p_http, p_https, n_http, n_https, n_h2_dir,
    c_http, c_https, c_admin,
    t_http, t_https,
    h_http, h_https,
) = sys.argv[1:]
routes_n = int(routes_n)
confs = os.path.join(bench_dir, "confs")
cert = os.path.join(bench_dir, "tls.crt")
key = os.path.join(bench_dir, "tls.key")
hbundle = os.path.join(bench_dir, "haproxy.pem")
log_dir = os.path.join(bench_dir, "logs")
dyn_dir = os.path.join(bench_dir, "traefik_dyn")

def write(name, content):
    with open(os.path.join(confs, name), "w", encoding="utf-8") as f:
        f.write(content)

# ---------------- PINGAP ----------------
pingap_base = f"""[basic]
threads = {workers}
pid_file = "{bench_dir}/pingap.pid"
upgrade_sock = "{bench_dir}/pingap_upgrade.sock"
upstream_keepalive_pool_size = 128
log_level = "error"
"""

write("pingap_t1.toml", pingap_base + f"""
[plugins.pingPath]
category = "ping"
path = "/ping"

[locations.ping]
path = "/ping"
plugins = ["pingPath"]

[servers.bench]
addr = "127.0.0.1:{p_http}"
threads = {workers}
locations = ["ping"]
""")

write("pingap_t2a.toml", pingap_base + f"""
[upstreams.origin]
addrs = ["127.0.0.1:{origin_port}"]
idle_timeout = "60s"

[locations.api]
path = "/"
upstream = "origin"
enable_reverse_proxy_headers = true

[servers.bench]
addr = "127.0.0.1:{p_http}"
threads = {workers}
locations = ["api"]
""")

write("pingap_t2b.toml", pingap_base + f"""
[upstreams.origin]
addrs = ["127.0.0.1:{origin_port}"]
idle_timeout = "60s"

[plugins.gzipComp]
category = "compression"
gzip_level = 6
min_length = 256
types = ["application/json", "text/"]

[locations.api]
path = "/"
upstream = "origin"
enable_reverse_proxy_headers = true
plugins = ["gzipComp"]

[servers.bench]
addr = "127.0.0.1:{p_http}"
threads = {workers}
locations = ["api"]
""")

for tname, h2_flag in [("t3", "false"), ("t4", "true")]:
    write(f"pingap_{tname}.toml", pingap_base + f"""
[certificates.bench]
tls_cert = "{cert}"
tls_key = "{key}"
is_default = true

[upstreams.origin]
addrs = ["127.0.0.1:{origin_port}"]
idle_timeout = "60s"

[locations.api]
path = "/"
upstream = "origin"
enable_reverse_proxy_headers = true

[servers.bench]
addr = "127.0.0.1:{p_https}"
threads = {workers}
global_certificates = true
enabled_h2 = {h2_flag}
locations = ["api"]
""")

p_locs = []
p_loc_names = []
for i in range(max(0, routes_n - 1)):
    lname = f"r_{i:04d}"
    p_loc_names.append(f'"{lname}"')
    p_locs.append(f"""[locations.{lname}]
host = "svc{i:04d}.bench.local"
path = "/route-{i:04d}"
upstream = "origin"
""")
p_loc_names.append('"api"')

write("pingap_t5.toml", pingap_base + f"""
[upstreams.origin]
addrs = ["127.0.0.1:{origin_port}"]
idle_timeout = "60s"

[plugins.rateLimit]
category = "limit"
type = "rate"
tag = "ip"
max = 10000000
interval = "60s"

[plugins.gwHeader]
category = "response_headers"
add_headers = ["X-Gateway: pingap"]

{"".join(p_locs)}
[locations.api]
path = "/"
upstream = "origin"
enable_reverse_proxy_headers = true
plugins = ["rateLimit", "gwHeader"]

[servers.bench]
addr = "127.0.0.1:{p_http}"
threads = {workers}
access_log = "{log_dir}/pingap_t5_access.log?rolling=never&channel_buffer=8192&flush_timeout=1s combined"
locations = [{", ".join(p_loc_names)}]
""")

write("pingap_t6.toml", f"""[basic]
threads = {workers}
pid_file = "{bench_dir}/pingap_t6.pid"
upgrade_sock = "{bench_dir}/pingap_t6_upgrade.sock"
upstream_keepalive_pool_size = 128
auto_restart_check_interval = "1s"
log_level = "error"

[upstreams.origin]
addrs = ["127.0.0.1:{origin_port}"]
idle_timeout = "60s"

[plugins.reloadGen]
category = "response_headers"
set_headers = ["X-Reload-Gen: v1"]

[locations.api]
path = "/"
upstream = "origin"
enable_reverse_proxy_headers = true
plugins = ["reloadGen"]

[servers.bench]
addr = "127.0.0.1:{p_http}"
threads = {workers}
locations = ["api"]
""")

# ---------------- NGINX ----------------
nginx_head = f"""worker_processes {workers};
daemon off;
pid {bench_dir}/nginx_proxy.pid;
error_log {log_dir}/nginx_error.log crit;

events {{
    worker_connections 4096;
}}

http {{
    client_body_temp_path {bench_dir}/nginx_tmp/client;
    proxy_temp_path {bench_dir}/nginx_tmp/proxy;
    fastcgi_temp_path {bench_dir}/nginx_tmp/fcgi;
    uwsgi_temp_path {bench_dir}/nginx_tmp/uwsgi;
    scgi_temp_path {bench_dir}/nginx_tmp/scgi;
    keepalive_timeout 65;
    keepalive_requests 10000000;
"""

nginx_proxy_common = """            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-Host $host;
            proxy_set_header X-Forwarded-Port $server_port;
            proxy_pass http://origin;
"""

nginx_upstream = f"""    upstream origin {{
        server 127.0.0.1:{origin_port};
        keepalive 128;
        keepalive_requests 10000000;
    }}
"""

write("nginx_t1.conf", nginx_head + f"""    access_log off;
    server {{
        listen 127.0.0.1:{n_http};
        location = /ping {{
            default_type text/plain;
            return 200 "pong";
        }}
    }}
}}
""")

write("nginx_t2a.conf", nginx_head + "    access_log off;\n" + nginx_upstream + f"""    server {{
        listen 127.0.0.1:{n_http};
        location / {{
{nginx_proxy_common}        }}
    }}
}}
""")

write("nginx_t2b.conf", nginx_head + """    access_log off;
    gzip on;
    gzip_comp_level 6;
    gzip_min_length 256;
    gzip_types application/json text/plain;
""" + nginx_upstream + f"""    server {{
        listen 127.0.0.1:{n_http};
        location / {{
{nginx_proxy_common}        }}
    }}
}}
""")

write("nginx_t3.conf", nginx_head + "    access_log off;\n" + nginx_upstream + f"""    server {{
        listen 127.0.0.1:{n_https} ssl;
        ssl_certificate {cert};
        ssl_certificate_key {key};
        ssl_protocols TLSv1.2 TLSv1.3;
        location / {{
{nginx_proxy_common}        }}
    }}
}}
""")

write("nginx_t4.conf", nginx_head + "    access_log off;\n" + nginx_upstream + f"""    server {{
        {n_h2_dir}
        ssl_certificate {cert};
        ssl_certificate_key {key};
        ssl_protocols TLSv1.2 TLSv1.3;
        location / {{
{nginx_proxy_common}        }}
    }}
}}
""")

n_locs = []
for i in range(max(0, routes_n - 1)):
    n_locs.append(f"""        location /route-{i:04d} {{
{nginx_proxy_common}        }}
""")

write("nginx_t5.conf", nginx_head + f"""    log_format combined_std '$remote_addr "$request_method $request_uri $server_protocol" $status $bytes_sent "$http_referer" "$http_user_agent"';
    access_log {log_dir}/nginx_t5_access.log combined_std buffer=64k flush=1s;
    limit_req_zone $binary_remote_addr zone=ip:10m rate=1000000r/s;
""" + nginx_upstream + f"""    server {{
        listen 127.0.0.1:{n_http};
{"".join(n_locs)}        location / {{
            limit_req zone=ip burst=1000000 nodelay;
            add_header X-Gateway nginx;
{nginx_proxy_common}        }}
    }}
}}
""")

write("nginx_t6.conf", nginx_head + "    access_log off;\n" + nginx_upstream + f"""    server {{
        listen 127.0.0.1:{n_http};
        location / {{
            add_header X-Reload-Gen v1;
{nginx_proxy_common}        }}
    }}
}}
""")

# ---------------- CADDY ----------------
caddy_global = "{\n    auto_https off\n    admin off\n}\n"
caddy_global_admin = f"{{\n    auto_https off\n    admin localhost:{c_admin}\n}}\n"

write("caddy_t1.caddy", caddy_global + f"""http://127.0.0.1:{c_http} {{
    respond /ping "pong" 200
}}
""")

write("caddy_t2a.caddy", caddy_global + f"""http://127.0.0.1:{c_http} {{
    reverse_proxy 127.0.0.1:{origin_port}
}}
""")

write("caddy_t2b.caddy", caddy_global + f"""http://127.0.0.1:{c_http} {{
    encode {{
        gzip 6
    }}
    reverse_proxy 127.0.0.1:{origin_port}
}}
""")

for tname in ("t3", "t4"):
    write(f"caddy_{tname}.caddy", caddy_global + f"""https://127.0.0.1:{c_https} {{
    tls {cert} {key}
    reverse_proxy 127.0.0.1:{origin_port}
}}
""")

c_routes = []
for i in range(max(0, routes_n - 1)):
    c_routes.append(f"""    handle /route-{i:04d}* {{
        reverse_proxy 127.0.0.1:{origin_port}
    }}
""")

write("caddy_t5.caddy", caddy_global + f"""http://127.0.0.1:{c_http} {{
    log {{
        output file {log_dir}/caddy_t5_access.log
        format json
    }}
{"".join(c_routes)}    handle {{
        header X-Gateway caddy
        reverse_proxy 127.0.0.1:{origin_port}
    }}
}}
""")

write("caddy_t6.caddy", caddy_global_admin + f"""http://127.0.0.1:{c_http} {{
    header X-Reload-Gen v1
    reverse_proxy 127.0.0.1:{origin_port}
}}
""")

# ---------------- TRAEFIK ----------------
with open(os.path.join(dyn_dir, "common.yml"), "w", encoding="utf-8") as f:
    f.write(f"""tls:
  certificates:
    - certFile: {cert}
      keyFile: {key}
http:
  middlewares:
    gw-headers:
      headers:
        customResponseHeaders:
          X-Gateway: traefik
    gzip-comp:
      compress:
        minResponseBodyBytes: 256
    ip-rate:
      rateLimit:
        average: 10000000
        burst: 10000000
  services:
    origin:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:{origin_port}"
""")

def write_traefik_dyn(name, yaml_body):
    d = os.path.join(bench_dir, f"traefik_{name}_dyn")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "routes.yml"), "w", encoding="utf-8") as f:
        f.write(open(os.path.join(dyn_dir, "common.yml")).read() + yaml_body)
    return d

d_t2a = write_traefik_dyn("t2a", """  routers:
    api:
      rule: "PathPrefix(`/`)"
      entryPoints: ["web"]
      service: origin
""")

d_t2b = write_traefik_dyn("t2b", """  routers:
    api:
      rule: "PathPrefix(`/`)"
      entryPoints: ["web"]
      middlewares: ["gzip-comp"]
      service: origin
""")

d_tls = write_traefik_dyn("tls", """  routers:
    api:
      rule: "PathPrefix(`/`)"
      entryPoints: ["websecure"]
      tls: {}
      service: origin
""")

t_routers = []
for i in range(max(0, routes_n - 1)):
    t_routers.append(f"""    r-{i:04d}:
      rule: "PathPrefix(`/route-{i:04d}`)"
      entryPoints: ["web"]
      service: origin
""")

d_t5 = write_traefik_dyn("t5", f"""  routers:
{"".join(t_routers)}    api:
      rule: "PathPrefix(`/`)"
      priority: 1
      entryPoints: ["web"]
      middlewares: ["ip-rate", "gw-headers"]
      service: origin
""")

d_t6 = write_traefik_dyn("t6", """  middlewares:
    reload-gen:
      headers:
        customResponseHeaders:
          X-Reload-Gen: v1
  routers:
    api:
      rule: "PathPrefix(`/`)"
      entryPoints: ["web"]
      middlewares: ["reload-gen"]
      service: origin
""")

# ---------------- HAPROXY ----------------
ha_head = f"""global
    nbthread {workers}
    log stdout format raw local0 err

defaults
    mode http
    timeout connect 5s
    timeout client 60s
    timeout server 60s
    option http-keep-alive

backend origin
    server s1 127.0.0.1:{origin_port} maxconn 256
"""

write("haproxy_t1.cfg", ha_head + f"""
frontend http_in
    bind 127.0.0.1:{h_http}
    http-request return status 200 content-type text/plain string "pong" if {{ path /ping }}
    default_backend origin
""")

write("haproxy_t2a.cfg", ha_head + f"""
frontend http_in
    bind 127.0.0.1:{h_http}
    option forwardfor
    default_backend origin
""")

write("haproxy_t2b.cfg", ha_head + f"""
frontend http_in
    bind 127.0.0.1:{h_http}
    option forwardfor
    compression algo gzip
    compression type application/json text/plain
    default_backend origin
""")

write("haproxy_t3.cfg", ha_head + f"""
frontend https_in
    bind 127.0.0.1:{h_https} ssl crt {hbundle}
    option forwardfor
    default_backend origin
""")

write("haproxy_t4.cfg", ha_head + f"""
frontend https_in
    bind 127.0.0.1:{h_https} ssl crt {hbundle} alpn h2,http/1.1
    option forwardfor
    default_backend origin
""")

ha_acls = []
for i in range(max(0, routes_n - 1)):
    ha_acls.append(f"    use_backend origin if {{ path_beg /route-{i:04d} }}\n")

write("haproxy_t5.cfg", f"""global
    nbthread {workers}
    log {log_dir}/haproxy_t5_access.log local0 info

defaults
    mode http
    timeout connect 5s
    timeout client 60s
    timeout server 60s
    option http-keep-alive

backend origin
    server s1 127.0.0.1:{origin_port} maxconn 256

frontend http_in
    bind 127.0.0.1:{h_http}
    option forwardfor
    log global
    option httplog
    stick-table type ip size 100k expire 60s store http_req_rate(60s)
    http-request track-sc0 src
    http-request deny deny_status 429 if {{ sc_http_req_rate(0) gt 10000000 }}
    http-response set-header X-Gateway haproxy
{"".join(ha_acls)}    default_backend origin
""")
PY
}

generate_configs

# Validate generated configs upfront where CLI supports it
if list_has "$ACTIVE_ENGINES" "pingap"; then
  for tier in t1 t2a t2b t3 t4 t5 t6; do
    if list_has "$ACTIVE_TIERS" "$tier"; then
      "$PINGAP_BIN" -c "$BENCH_DIR/confs/pingap_${tier}.toml" -t --strict >/dev/null
    fi
  done
fi
if list_has "$ACTIVE_ENGINES" "nginx"; then
  for tier in t1 t2a t2b t3 t4 t5 t6; do
    if list_has "$ACTIVE_TIERS" "$tier"; then
      "$NGINX_BIN" -t -c "$BENCH_DIR/confs/nginx_${tier}.conf" >/dev/null 2>&1
    fi
  done
fi

start_engine_for_tier() {
  local eng=$1
  local tier=$2
  case "$eng:$tier" in
    pingap:t6)
      start_proxy "$PINGAP_BIN" -c "$BENCH_DIR/confs/pingap_t6.toml" --autoreload --log "$BENCH_DIR/logs/pingap_t6.log"
      ;;
    pingap:*)
      start_proxy "$PINGAP_BIN" -c "$BENCH_DIR/confs/pingap_${tier}.toml" --log "$BENCH_DIR/logs/pingap_app.log"
      ;;
    nginx:*)
      start_proxy "$NGINX_BIN" -c "$BENCH_DIR/confs/nginx_${tier}.conf"
      ;;
    caddy:*)
      start_proxy env GOMAXPROCS="$WORKERS" "$CADDY_BIN" run --config "$BENCH_DIR/confs/caddy_${tier}.caddy" --adapter caddyfile
      ;;
    traefik:t1)
      start_proxy env GOMAXPROCS="$WORKERS" "$TRAEFIK_BIN" \
        --entryPoints.web.address="127.0.0.1:$TRAEFIK_HTTP" \
        --ping=true --ping.entryPoint=web --log.level=ERROR
      ;;
    traefik:t2a|traefik:t2b|traefik:t5|traefik:t6)
      start_proxy env GOMAXPROCS="$WORKERS" "$TRAEFIK_BIN" \
        --entryPoints.web.address="127.0.0.1:$TRAEFIK_HTTP" \
        --providers.file.directory="$BENCH_DIR/traefik_${tier}_dyn" \
        --providers.file.watch=true --log.level=ERROR
      ;;
    traefik:t3|traefik:t4)
      start_proxy env GOMAXPROCS="$WORKERS" "$TRAEFIK_BIN" \
        --entryPoints.websecure.address="127.0.0.1:$TRAEFIK_HTTPS" \
        --providers.file.directory="$BENCH_DIR/traefik_tls_dyn" \
        --providers.file.watch=true --log.level=ERROR
      ;;
    haproxy:*)
      start_proxy "$HAPROXY_BIN" -W -db -f "$BENCH_DIR/confs/haproxy_${tier}.cfg"
      ;;
  esac
}

engine_port() {
  local eng=$1
  local mode=$2 # http | https
  case "$eng:$mode" in
    pingap:http) echo "$PINGAP_HTTP" ;;
    pingap:https) echo "$PINGAP_HTTPS" ;;
    nginx:http) echo "$NGINX_HTTP" ;;
    nginx:https) echo "$NGINX_HTTPS" ;;
    caddy:http) echo "$CADDY_HTTP" ;;
    caddy:https) echo "$CADDY_HTTPS" ;;
    traefik:http) echo "$TRAEFIK_HTTP" ;;
    traefik:https) echo "$TRAEFIK_HTTPS" ;;
    haproxy:http) echo "$HAPROXY_HTTP" ;;
    haproxy:https) echo "$HAPROXY_HTTPS" ;;
  esac
}

run_wrk_case() {
  local tier=$1
  local eng=$2
  local url=$3
  local pid=$4
  local extra_hdr=${5:-}
  local out_file="$BENCH_DIR/logs/${tier}_${eng}.out"
  if [ -n "$extra_hdr" ]; then
    run_load_cmd "$WRK_BIN" -t"$WRK_THREADS" -c"$WRK_CONNS" -d"${WRK_WARMUP}s" -H "$extra_hdr" "$url" >/dev/null 2>&1 || true
    run_load_cmd "$WRK_BIN" -t"$WRK_THREADS" -c"$WRK_CONNS" -d"${WRK_DURATION}s" -H "$extra_hdr" --latency "$url" > "$out_file"
  else
    run_load_cmd "$WRK_BIN" -t"$WRK_THREADS" -c"$WRK_CONNS" -d"${WRK_WARMUP}s" "$url" >/dev/null 2>&1 || true
    run_load_cmd "$WRK_BIN" -t"$WRK_THREADS" -c"$WRK_CONNS" -d"${WRK_DURATION}s" --latency "$url" > "$out_file"
  fi
  local rss
  rss=$(rss_mb_for_pid_tree "$pid")
  parse_and_record "$tier" "$eng" "wrk" "$out_file" "$rss"
}

benchmark_standard_tier() {
  local tier=$1
  local scheme=$2
  local path=$3
  local expect=$4
  local curl_extra=${5:-}
  local wrk_extra=${6:-}
  local verify_hdr=${7:-}

  local OLD_IFS=$IFS
  IFS=','
  for eng in $ACTIVE_ENGINES; do
    IFS=$OLD_IFS
    local port
    port=$(engine_port "$eng" "$scheme")
    local url="${scheme}://127.0.0.1:${port}${path}"
    local expect_str=$expect
    if [ "$tier" = "t1" ] && [ "$eng" = "traefik" ]; then
      expect_str="OK"
    fi

    start_engine_for_tier "$eng" "$tier"
    wait_for_url "$url" "$expect_str" "$curl_extra"
    if [ -n "$verify_hdr" ]; then
      local expected_h="$verify_hdr"
      if [ "$tier" = "t5" ]; then
        expected_h="x-gateway: $eng"
      fi
      wait_for_header "$url" "$expected_h" "$curl_extra" 20
    fi

    if [ "$tier" = "t3" ]; then
      local out_file="$BENCH_DIR/logs/${tier}_${eng}.out"
      if [ -n "$OHA_BIN" ]; then
        run_load_cmd "$OHA_BIN" --no-tui --disable-keepalive --insecure -t "$WRK_THREADS" -c "$WRK_CONNS" -z "${WRK_WARMUP}s" "$url" >/dev/null 2>&1 || true
        run_load_cmd "$OHA_BIN" --no-tui --disable-keepalive --insecure --output-format json -t "$WRK_THREADS" -c "$WRK_CONNS" -z "${WRK_DURATION}s" "$url" > "$out_file"
        parse_and_record "$tier" "$eng" "oha" "$out_file" "$(rss_mb_for_pid_tree "$PROXY_PID")"
      else
        run_wrk_case "$tier" "$eng" "$url" "$PROXY_PID" "Connection: close"
      fi
    elif [ "$tier" = "t4" ]; then
      local out_file="$BENCH_DIR/logs/${tier}_${eng}.out"
      if [ -n "$H2LOAD_BIN" ]; then
        curl -fsS -k --http2 "$url" >/dev/null
        local h2_reqs=$((WORKERS * 25000))
        run_load_cmd "$H2LOAD_BIN" -t"$WRK_THREADS" -c"$WRK_CONNS" -m 100 -n "$h2_reqs" "$url" > "$out_file"
        parse_and_record "$tier" "$eng" "h2load" "$out_file" "$(rss_mb_for_pid_tree "$PROXY_PID")"
      elif [ -n "$OHA_BIN" ]; then
        run_load_cmd "$OHA_BIN" --no-tui --http2 --insecure --output-format json -t "$WRK_THREADS" -c "$WRK_CONNS" -z "${WRK_DURATION}s" "$url" > "$out_file"
        parse_and_record "$tier" "$eng" "oha" "$out_file" "$(rss_mb_for_pid_tree "$PROXY_PID")"
      fi
    else
      run_wrk_case "$tier" "$eng" "$url" "$PROXY_PID" "$wrk_extra"
    fi

    stop_proc_tree "$PROXY_PID"
    sleep 0.2
  done
  IFS=$OLD_IFS
}

atomic_replace_gen() {
  local file=$1
  local from=$2
  local to=$3
  local tmp="${file}.tmp.$$"
  sed "s/$from/$to/g" "$file" > "$tmp"
  mv "$tmp" "$file"
}

run_t6_reload() {
  local t6_dur=$WRK_DURATION
  if [ "$t6_dur" -lt 6 ]; then
    t6_dur=6
  fi
  local OLD_IFS=$IFS
  IFS=','
  for eng in $ACTIVE_ENGINES; do
    IFS=$OLD_IFS
    if [ "$eng" = "haproxy" ]; then
      echo "Skipping T6 hot-reload on haproxy (no runtime file-watch reload in baseline config)." >&2
      continue
    fi
    local port url
    port=$(engine_port "$eng" "http")
    url="http://127.0.0.1:${port}/api/json"

    start_engine_for_tier "$eng" "t6"
    wait_for_url "$url" '"service":"origin"'
    wait_for_header "$url" "x-reload-gen: v1" "" 30

    local out_file="$BENCH_DIR/logs/t6_${eng}.out"
    run_load_cmd "$WRK_BIN" -t"$WRK_THREADS" -c"$WRK_CONNS" -d"${t6_dur}s" --latency "$url" > "$out_file" &
    local wrk_pid=$!

    local gen
    for gen in v2 v3; do
      local prev="v1"
      [ "$gen" = "v3" ] && prev="v2"
      case "$eng" in
        pingap)
          atomic_replace_gen "$BENCH_DIR/confs/pingap_t6.toml" "X-Reload-Gen: $prev" "X-Reload-Gen: $gen"
          ;;
        nginx)
          atomic_replace_gen "$BENCH_DIR/confs/nginx_t6.conf" "X-Reload-Gen $prev" "X-Reload-Gen $gen"
          kill -HUP "$PROXY_PID"
          ;;
        caddy)
          atomic_replace_gen "$BENCH_DIR/confs/caddy_t6.caddy" "X-Reload-Gen $prev" "X-Reload-Gen $gen"
          "$CADDY_BIN" reload --config "$BENCH_DIR/confs/caddy_t6.caddy" --adapter caddyfile >/dev/null 2>&1
          ;;
        traefik)
          atomic_replace_gen "$BENCH_DIR/traefik_t6_dyn/routes.yml" "X-Reload-Gen: $prev" "X-Reload-Gen: $gen"
          ;;
      esac
      wait_for_header "$url" "x-reload-gen: $gen" "" 100
    done

    wait "$wrk_pid"
    local rss
    rss=$(rss_mb_for_pid_tree "$PROXY_PID")
    parse_and_record "t6" "$eng" "wrk" "$out_file" "$rss"
    stop_proc_tree "$PROXY_PID"
    sleep 0.2
  done
  IFS=$OLD_IFS
}

echo "Running 6-Tier Benchmark Suite (engines=$ACTIVE_ENGINES workers=$WORKERS threads=$WRK_THREADS conns=$WRK_CONNS payload=${PAYLOAD_KB}KB routes=$ROUTES)"

list_has "$ACTIVE_TIERS" "t1" && benchmark_standard_tier "t1" "http" "/ping" "pong"
list_has "$ACTIVE_TIERS" "t2a" && benchmark_standard_tier "t2a" "http" "/api/json" '"service":"origin"'
list_has "$ACTIVE_TIERS" "t2b" && benchmark_standard_tier "t2b" "http" "/api/json" "" "-H Accept-Encoding:gzip --compressed" "Accept-Encoding: gzip" "content-encoding: gzip"
list_has "$ACTIVE_TIERS" "t3" && benchmark_standard_tier "t3" "https" "/api/json" '"service":"origin"' "-k"
if list_has "$ACTIVE_TIERS" "t4"; then
  if [ -n "$H2LOAD_BIN" ] || [ -n "$OHA_BIN" ]; then
    benchmark_standard_tier "t4" "https" "/api/json" '"service":"origin"' "-k --http2"
  else
    echo "Skipping T4 (HTTP/2 multiplexing): install 'h2load' or 'oha' to run T4." >&2
  fi
fi
list_has "$ACTIVE_TIERS" "t5" && benchmark_standard_tier "t5" "http" "/api/json" '"service":"origin"' "" "" "x-gateway"
list_has "$ACTIVE_TIERS" "t6" && run_t6_reload

if [ -n "$SAVE_BASELINE" ]; then
  mkdir -p "$(dirname "$SAVE_BASELINE")"
  cp "$RESULTS_TSV" "$SAVE_BASELINE"
  echo "Saved baseline metrics to: $SAVE_BASELINE"
fi

if [ -n "$OUTPUT_JSON" ]; then
  mkdir -p "$(dirname "$OUTPUT_JSON")"
  python3 - "$RESULTS_TSV" "$OUTPUT_JSON" "$WORKERS" "$WRK_THREADS" "$WRK_CONNS" "$PAYLOAD_KB" "$ROUTES" <<'PY'
import csv, json, sys
tsv_path, json_path, workers, threads, conns, payload_kb, routes = sys.argv[1:]
rows = list(csv.DictReader(open(tsv_path, encoding="utf-8"), delimiter="\t"))
doc = {
    "config": {
        "workers": int(workers),
        "threads": int(threads),
        "connections": int(conns),
        "payload_kb": int(payload_kb),
        "t5_routes": int(routes),
    },
    "results": rows,
}
with open(json_path, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2)
print(f"Wrote JSON report to: {json_path}")
PY
fi

echo ""
echo "=== Summary ==="
python3 - "$RESULTS_TSV" "${COMPARE_BASELINE:-}" <<'PY'
import csv, sys

tsv_path, baseline_path = sys.argv[1], sys.argv[2]
rows = list(csv.DictReader(open(tsv_path, encoding="utf-8"), delimiter="\t"))
base = {}
if baseline_path:
    for r in csv.DictReader(open(baseline_path, encoding="utf-8"), delimiter="\t"):
        base[(r["tier"], r["engine"])] = r

if baseline_path:
    print("| Tier | Engine | Tool | RPS | Before RPS | Delta | Avg / P99 / Max | Errors | RSS (MB) |")
    print("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for r in rows:
        b = base.get((r["tier"], r["engine"]))
        before_rps = b["rps"] if b else "n/a"
        delta = "n/a"
        if b and float(b["rps"]) > 0:
            pct = (float(r["rps"]) - float(b["rps"])) / float(b["rps"]) * 100.0
            delta = f"{pct:+.1f}%"
        print(f"| {r['tier'].upper()} | {r['engine']} | {r['tool']} | {r['rps']} | {before_rps} | {delta} | {r['avg']} / {r['p99']} / {r['max']} | {r['errors']} | {r['rss_mb']} |")
else:
    print("| Tier | Engine | Tool | RPS | Avg / P50 / P99 / Max | Errors | RSS (MB) |")
    print("| --- | --- | --- | --- | --- | --- | --- |")
    for r in rows:
        print(f"| {r['tier'].upper()} | {r['engine']} | {r['tool']} | {r['rps']} | {r['avg']} / {r['p50']} / {r['p99']} / {r['max']} | {r['errors']} | {r['rss_mb']} |")
PY
