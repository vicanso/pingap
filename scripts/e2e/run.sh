#!/usr/bin/env bash
# End-to-end checks of a built pingap: what the unit tests cannot see,
# because it takes a process, a socket, another server or a second process.
#
#   scripts/e2e/run.sh [path to pingap]      default: target/release/pingap
#
#   E2E_ONLY="reload restart"   run only these cases (names as listed below)
#   E2E_KEEP=1                  leave the working directory behind
#   E2E_PORT_BASE=28100         the first of the ports that are used
#
#   E2E_SYSTEMD=1               also run `systemd`: installs a unit made
#                               from pingap.service under /run, and so
#                               needs systemd and a sudo that asks nothing
#
# Needs bash, curl, python3 and openssl. nginx is used where it is
# installed, as a backend that reads the PROXY protocol; node, or the
# brotli command, as a strict brotli decoder (`compression` skips its
# decoding without either). The cases that
# hand listening sockets from one process to the next (`restart`,
# `restart_guard`, `upgrade`, `systemd`) run on Linux only: pingora does
# not do it anywhere else.
#
# Every check prints one line, `ok` or `FAIL`; the exit status is the
# number of checks that failed. A case that fails prints the end of the
# logs of the processes it ran.
set -u

CASES="samples proxy compression retry_cache reload webhook abnormal_exit foreground proxy_protocol stream daemon restart restart_guard upgrade systemd"

BIN_ARG=${1:-target/release/pingap}
if [ ! -x "$BIN_ARG" ]; then
  echo "no pingap at $BIN_ARG: build one (make release) or pass its path" >&2
  exit 2
fi
BIN=$(cd "$(dirname "$BIN_ARG")" && pwd)/$(basename "$BIN_ARG")
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
# Short: the upgrade socket of a daemon is a path in it, and a socket
# path has room for a hundred characters or so.
WORK=$(mktemp -d /tmp/pingap-e2e.XXXXXX)
PORT_BASE=${E2E_PORT_BASE:-28100}
LINUX=0
[ "$(uname -s)" = "Linux" ] && LINUX=1

PASSED=0
FAILED=0
SKIPPED=0
CASE=
PIDS=()
LOGS=()

ok() {
  PASSED=$((PASSED + 1))
  printf 'ok    %s: %s\n' "$CASE" "$1"
}

# fail <what> [detail]...
fail() {
  FAILED=$((FAILED + 1))
  printf 'FAIL  %s: %s\n' "$CASE" "$1"
  shift
  for line in "$@"; do printf '        %s\n' "$line"; done
}

skip() {
  SKIPPED=$((SKIPPED + 1))
  printf 'skip  %s: %s\n' "$CASE" "$1"
}

# expect <what> <wanted> <got>
expect() {
  if [ "$2" = "$3" ]; then ok "$1"; else fail "$1" "wanted: $2" "got:    $3"; fi
}

# expect_match <what> <extended regex> <got>
expect_match() {
  if printf '%s' "$3" | grep -Eq -- "$2"; then
    ok "$1"
  else
    fail "$1" "wanted something like: $2" "got: $3"
  fi
}

plain() { sed $'s/\x1b\\[[0-9;]*m//g'; }

# run_bg <log file> <command>...: in the background, to be killed at the end
run_bg() {
  local log=$1
  shift
  "$@" >"$log" 2>&1 &
  LAST_PID=$!
  PIDS+=("$LAST_PID")
  LOGS+=("$log")
}

alive() { kill -0 "$1" 2>/dev/null; }

stop() {
  [ -n "${1:-}" ] || return 0
  kill -9 "$1" 2>/dev/null
  wait "$1" 2>/dev/null
  return 0
}

# wait_port <port> [tenths of a second]
wait_port() {
  local _
  for _ in $(seq "${2:-100}"); do
    (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0
    sleep 0.1
  done
  return 1
}

# wait_for <seconds> <command>...: until the command succeeds. By the
# clock, not by the number of tries: a try may take seconds itself.
wait_for() {
  local end=$((SECONDS + $1))
  shift
  while [ "$SECONDS" -lt "$end" ]; do
    "$@" >/dev/null 2>&1 && return 0
    sleep 0.2
  done
  "$@" >/dev/null 2>&1
}

status() { curl -s -o /dev/null -m 8 -w '%{http_code}' "$@"; }
body() { curl -s -m 8 "$@"; }
# status_is <code> <curl arguments>...
status_is() {
  local code=$1
  shift
  [ "$(status "$@")" = "$code" ]
}

backend() { # <port> <name> [plain|proxy]
  run_bg "$DIR/$2.out" python3 "$HERE/backend.py" "$1" "$DIR/$2.log" "${3:-plain}"
  wait_port "$1" || fail "backend $2 listens on $1"
}

# pingap <log file> <arguments>...: in the foreground of a background job
pingap() {
  local log=$1
  shift
  run_bg "$log" "$BIN" "$@"
}

cleanup() {
  local pid file
  # What a case started as root, ahead of the rest: nobody else can end
  # it, and waiting for it would wait for ever. The pattern is written so
  # that it is not the command line of the pkill that looks for it.
  if [ "$LINUX" = 1 ] && sudo -n true 2>/dev/null; then
    sudo pkill -9 -f "[/]${WORK#/}" 2>/dev/null
    sudo chown -R "$(id -u)" "$WORK" 2>/dev/null
  fi
  for pid in "${PIDS[@]:-}"; do stop "$pid"; done
  [ "${E2E_SYSTEMD:-0}" = 1 ] && systemd_cleanup
  # daemons are nobody's child: by their pid files, and by the directory
  # every one of them was started with
  for file in "$WORK"/*/pingap.pid; do
    [ -f "$file" ] && kill -9 "$(cat "$file")" 2>/dev/null
  done
  pkill -9 -f "$WORK" 2>/dev/null
  if [ "${E2E_KEEP:-0}" = 1 ]; then
    echo "kept: $WORK"
  else
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT

# The settings every case starts from. A second is as often as a change
# of the configuration is looked for. LOG_LEVEL= leaves the level out.
basic_conf() { # <directory> [more lines of [basic]]
  mkdir -p "$1"
  {
    echo '[basic]'
    [ -n "${LOG_LEVEL-info}" ] && echo "log_level = \"${LOG_LEVEL-info}\""
    echo 'auto_restart_check_interval = "1s"'
    echo "pid_file = \"$DIR/pingap.pid\""
    echo "upgrade_sock = \"$DIR/pingap_upgrade.sock\""
    [ $# -gt 1 ] && printf '%s\n' "${@:2}"
  } >"$1/basic.toml"
}

# ---------------------------------------------------------------------------
# samples: what the repository tells people to copy is a configuration this
# binary takes, without a key it does not know.
case_samples() {
  local out name
  # The samples name directories under /opt/pingap (a cache, the files of
  # a site), and validating builds the plugins that use them: they are
  # pointed into the directory of this case, which is all that is changed.
  local_paths() {
    find "$1" -type f \( -name '*.toml' -o -name '*.hcl' -o -name '*.kdl' \) \
      -exec sed -i.orig "s#/opt/pingap#$DIR/opt#g" {} \;
    find "$1" -name '*.orig' -delete
  }
  cp -R "$ROOT/conf" "$DIR/conf"
  local_paths "$DIR/conf"
  out=$("$BIN" -t --strict -c "$DIR/conf" 2>&1 | plain)
  expect_match "conf/ validates with --strict" 'Validate config success' "$out"

  "$BIN" --template >"$DIR/template.toml" 2>/dev/null
  out=$("$BIN" -t --strict -c "$DIR/template.toml" 2>&1 | plain)
  expect_match "--template validates" 'Validate config success' "$out"

  for name in "$ROOT"/examples/*/; do
    name=$(basename "$name")
    cp -R "$ROOT/examples/$name" "$DIR/$name"
    rm -f "$DIR/$name/README.md"
    local_paths "$DIR/$name"
    out=$("$BIN" -t --strict -c "$DIR/$name" 2>&1 | plain)
    expect_match "examples/$name validates" 'Validate config success' "$out"
  done

  # what one format writes the other reads
  for name in hcl kdl; do
    if "$BIN" -c "$DIR/conf" "--to-$name" >"$DIR/converted.$name" 2>"$DIR/convert.err"; then
      out=$("$BIN" -t -c "$DIR/converted.$name" 2>&1 | plain)
      expect_match "--to-$name gives a configuration that validates" \
        'Validate config success' "$out"
    else
      fail "--to-$name" "$(plain <"$DIR/convert.err" | tail -3)"
    fi
  done

  out=$("$BIN" --version 2>&1)
  expect_match "--version names the version of Cargo.toml" \
    "$(sed -n 's/^version = "\(.*\)"$/\1/p' "$ROOT/Cargo.toml" | head -1 | sed 's/\./\\./g')" "$out"
  # A binary that was built from a checkout says which commit it is: one
  # that says `unknown` was built where git could not be asked, which has
  # happened to released binaries.
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    expect_match "--version names the commit" '\([0-9a-f]{40}, tls=' "$out"
  fi

  # Every page of a plugin is in the sidebar of the documentation site:
  # one that is not can only be reached from the index.
  out=
  for name in "$ROOT"/pingap-plugin/docs/*.md; do
    name=$(basename "$name" .md)
    grep -q "/plugins/$name\`" "$ROOT/website/.vitepress/config.mts" || out="$out $name"
  done
  expect "every plugin page is in the sidebar of the site" "" "$out"
}

# ---------------------------------------------------------------------------
# proxy: a request goes through to a backend, and the admin is in the
# binary with its page.
case_proxy() {
  local proxy=$((PORT_BASE + 10)) admin=$((PORT_BASE + 11)) up=$((PORT_BASE + 12))
  backend $up b1
  basic_conf "$DIR/c"
  printf '[upstreams.b1]\naddrs = ["127.0.0.1:%s"]\n' $up >"$DIR/c/upstreams.toml"
  printf '[locations.b1]\nupstream = "b1"\npath = "/"\n' >"$DIR/c/locations.toml"
  printf '[servers.main]\naddr = "127.0.0.1:%s"\nlocations = ["b1"]\n' $proxy >"$DIR/c/servers.toml"
  pingap "$DIR/pingap.log" -c "$DIR/c" --admin "127.0.0.1:$admin"
  wait_port $proxy || fail "pingap listens on $proxy"

  expect "GET through the proxy" "plain - - - path=/hello?a=1 200" \
    "$(curl -s -m 8 -w ' %{http_code}' "http://127.0.0.1:$proxy/hello?a=1" | tr -d '\n' | sed 's/ conn=[0-9]* req=[0-9]*//')"
  expect "POST with a body" 200 \
    "$(status -X POST --data-binary @"$HERE/backend.py" "http://127.0.0.1:$proxy/upload")"
  # the admin page and its assets are built into the binary
  wait_port $admin || fail "the admin listens on $admin"
  expect_match "the admin serves its page" '<div id="root"' "$(body "http://127.0.0.1:$admin/")"
  local asset
  asset=$(body "http://127.0.0.1:$admin/" | grep -o 'assets/index-[A-Za-z0-9_-]*\.js' | head -1)
  expect "the admin serves the script the page names ($asset)" 200 \
    "$(status "http://127.0.0.1:$admin/$asset")"
  expect "the admin API answers" 200 "$(status "http://127.0.0.1:$admin/api/basic")"

  # A key that takes a cargo feature. A build that has it reads the key;
  # one that has not says so, and refuses it with --strict.
  local features out strict
  features=$(body "http://127.0.0.1:$admin/api/basic" |
    python3 -c 'import json,sys; print(" ".join(json.load(sys.stdin)["features"]))' 2>/dev/null)
  # The plugins that are registered when the factory is first used, not
  # before `main`: the ones of the binary, and image_optim in a full build.
  local supported
  supported=$(body "http://127.0.0.1:$admin/api/basic" |
    python3 -c 'import json,sys; print(" ".join(json.load(sys.stdin)["supported_plugins"]))' 2>/dev/null)
  expect_match "the plugins of the binary are registered (admin, health, stats)" \
    ' admin .* health .* stats ' " $supported "
  case " $features " in
  *" full "*)
    expect_match "and image_optim, in a full build" ' image_optim ' " $supported " ;;
  esac
  mkdir -p "$DIR/m" && cp "$DIR"/c/*.toml "$DIR/m/"
  printf 'prometheus_metrics = "/metrics"\n' >>"$DIR/m/servers.toml"
  out=$("$BIN" -t -c "$DIR/m" 2>&1 | plain)
  strict=$("$BIN" -t --strict -c "$DIR/m" 2>&1 | plain)
  case " $features " in
  *" tracing "*)
    expect_match "prometheus_metrics, in a build with tracing: taken with --strict" \
      'Validate config success' "$strict"
    expect "and nothing is said about the build" 0 "$(printf '%s' "$out" | grep -c 'needs a build')"
    ;;
  *)
    expect_match "prometheus_metrics, in a build without tracing: said" \
      'server\(main\): "prometheus_metrics" needs a build with the tracing feature' "$out"
    expect_match "as a warning: the configuration validates" 'Validate config success' "$out"
    expect_match "and as an error with --strict" 'this build of pingap does not read' "$strict"
    expect "which does not validate" 0 "$(printf '%s' "$strict" | grep -c 'Validate config success')"
    ;;
  esac
}

# ---------------------------------------------------------------------------
# compression: a `br` body is a whole brotli stream, which a strict decoder
# reads to its end (pingora 0.9.0 leaves the end out, pingap#256), coded by
# pingora's module for a response of a plugin and of an upstream, and by
# the plugin in upstream mode. An empty body is sent as it is.
case_compression() {
  local proxy=$((PORT_BASE + 110)) origin=$((PORT_BASE + 111))
  local decoder route
  if command -v node >/dev/null; then
    decoder=node
  elif command -v brotli >/dev/null; then
    decoder=brotli
  fi
  mkdir -p "$DIR/www"
  seq 1 20000 | sed 's|^|upstream location /api/|' >"$DIR/www/page.txt"
  : >"$DIR/www/empty.txt"
  basic_conf "$DIR/c"
  printf '[upstreams.origin]\naddrs = ["127.0.0.1:%s"]\n' $origin >"$DIR/c/upstreams.toml"
  cat >"$DIR/c/locations.toml" <<CONF
[locations.static]
path = "/"
plugins = ["files", "compress"]

[locations.up]
path = "/up/"
upstream = "origin"
rewrite = "^/up/(.*)$ /\$1"
plugins = ["compress"]

[locations.upmode]
path = "/upmode/"
upstream = "origin"
rewrite = "^/upmode/(.*)$ /\$1"
plugins = ["compressUp"]

[locations.origin]
plugins = ["files"]
CONF
  cat >"$DIR/c/servers.toml" <<CONF
[servers.web]
addr = "127.0.0.1:$proxy"
locations = ["static", "up", "upmode"]

[servers.origin]
addr = "127.0.0.1:$origin"
locations = ["origin"]
CONF
  cat >"$DIR/c/plugins.toml" <<CONF
[plugins.files]
category = "directory"
path = "$DIR/www"

[plugins.compress]
category = "compression"
br_level = 5

[plugins.compressUp]
category = "compression"
br_level = 5
mode = "upstream"
CONF
  pingap "$DIR/pingap.log" -c "$DIR/c"
  wait_port $proxy || fail "pingap listens on $proxy"
  wait_port $origin || fail "pingap listens on $origin"

  for route in / /up/ /upmode/; do
    curl -s -m 8 -H 'Accept-Encoding: br' -D "$DIR/h" -o "$DIR/br" \
      "http://127.0.0.1:$proxy${route}page.txt"
    expect "${route}page.txt is coded as br" br \
      "$(grep -i '^content-encoding:' "$DIR/h" | tr -d '\r' | awk '{print $2}')"
    case $decoder in
    node)
      node -e 'process.stdout.write(require("zlib").brotliDecompressSync(require("fs").readFileSync(0)))' \
        <"$DIR/br" >"$DIR/decoded" 2>"$DIR/decode.err" ;;
    brotli) brotli -dc "$DIR/br" >"$DIR/decoded" 2>"$DIR/decode.err" ;;
    *)
      skip "${route}page.txt read by a strict decoder: no node, no brotli"
      continue ;;
    esac
    expect "${route}page.txt is a whole stream of the file ($decoder)" same \
      "$(cmp -s "$DIR/decoded" "$DIR/www/page.txt" && echo same || head -c 200 "$DIR/decode.err")"
  done
  # Nothing passes the body filter of an empty body, so nothing would be
  # coded under the Content-Encoding.
  expect "/upmode/empty.txt is sent without a Content-Encoding" 0 \
    "$(curl -s -m 8 -H 'Accept-Encoding: br' -D - -o /dev/null \
      "http://127.0.0.1:$proxy/upmode/empty.txt" | grep -ci '^content-encoding:')"
}

# ---------------------------------------------------------------------------
# retry_cache: status-code retries without fallback spillover, use_stale on
# error/503/429 with stale_if_error, min_uses threshold, and prefix / tag PURGE.
case_retry_cache() {
  local proxy=$((PORT_BASE + 170)) up1=$((PORT_BASE + 171)) up2=$((PORT_BASE + 172))
  local fb=$((PORT_BASE + 173)) origin=$((PORT_BASE + 174)) err_origin=$((PORT_BASE + 175))
  local err_pid i status_code cache_status body_out purged_count total_post

  cat >"$DIR/rc_origin.py" <<'PY'
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1])
LOG = sys.argv[2]
MODE = sys.argv[3]

LOCK = threading.Lock()
STATUS = 200
COUNTS = {}


def log_req(method, path, code):
    with LOCK:
        with open(LOG, "a") as f:
            f.write(f"{method} {path} {code}\n")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        pass

    def _send(self, code, body, extra_headers=None):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        if extra_headers:
            for k, v in extra_headers:
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _drain_body(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length > 0:
            self.rfile.read(length)

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        global STATUS
        self._drain_body()
        if MODE == "cache" and self.path.startswith("/__mode/"):
            with LOCK:
                STATUS = int(self.path.split("/__mode/", 1)[1])
            self._send(200, f"mode={STATUS}\n")
            return
        self._handle("POST")

    def _handle(self, method):
        if MODE == "fail_503":
            log_req(method, self.path, 503)
            self._send(503, "fail-503\n")
            return
        if MODE == "retry_ok":
            if self.path.startswith("/retry/"):
                log_req(method, self.path, 200)
                self._send(200, "from-ok\n")
            else:
                log_req(method, self.path, 503)
                self._send(503, "up2-503\n")
            return
        if MODE == "fallback":
            log_req(method, self.path, 200)
            self._send(200, "from-fallback\n")
            return
        if MODE == "cache_err":
            log_req(method, self.path, 200)
            self._send(200, "err-cached\n")
            return

        with LOCK:
            code = STATUS
            n = COUNTS.get(self.path, 0) + 1
            COUNTS[self.path] = n
        log_req(method, self.path, code)
        if code == 200:
            headers = []
            if self.path in ("/items/1", "/other/1"):
                headers.append(("Cache-Tag", "group-a, all"))
            elif self.path == "/items/2":
                headers.append(("Cache-Tag", "group-b"))
            elif self.path == "/other/2":
                headers.append(("Cache-Tag", "group-c"))
            self._send(200, f"origin:{self.path}:n={n}\n", headers)
        else:
            self._send(code, f"err:{code}\n")


class ReuseServer(ThreadingHTTPServer):
    allow_reuse_address = True


ReuseServer(("127.0.0.1", PORT), Handler).serve_forever()
PY

  run_bg "$DIR/up1.out" python3 "$DIR/rc_origin.py" $up1 "$DIR/up1.log" fail_503
  run_bg "$DIR/up2.out" python3 "$DIR/rc_origin.py" $up2 "$DIR/up2.log" retry_ok
  run_bg "$DIR/fb.out" python3 "$DIR/rc_origin.py" $fb "$DIR/fb.log" fallback
  run_bg "$DIR/origin.out" python3 "$DIR/rc_origin.py" $origin "$DIR/origin.log" cache
  run_bg "$DIR/err_origin.out" python3 "$DIR/rc_origin.py" $err_origin "$DIR/err_origin.log" cache_err
  err_pid=$LAST_PID

  wait_port $up1 || fail "up1 listens on $up1"
  wait_port $up2 || fail "up2 listens on $up2"
  wait_port $fb || fail "fb listens on $fb"
  wait_port $origin || fail "origin listens on $origin"
  wait_port $err_origin || fail "err_origin listens on $err_origin"

  : >"$DIR/up1.log"
  : >"$DIR/up2.log"
  : >"$DIR/fb.log"
  : >"$DIR/origin.log"
  : >"$DIR/err_origin.log"

  basic_conf "$DIR/c"
  cat >"$DIR/c/upstreams.toml" <<CONF
[upstreams.retry_pair]
addrs = ["127.0.0.1:$up1", "127.0.0.1:$up2"]
algo = "round_robin"

[upstreams.fb_up]
addrs = ["127.0.0.1:$fb"]

[upstreams.origin_up]
addrs = ["127.0.0.1:$origin"]

[upstreams.err_up]
addrs = ["127.0.0.1:$err_origin"]
CONF
  cat >"$DIR/c/locations.toml" <<CONF
[locations.retry_loc]
path = "/retry"
upstream = "retry_pair"
fallback_upstream = "fb_up"
retry_status_codes = "502,503"
max_retries = 1

[locations.post_loc]
path = "/post-503"
upstream = "retry_pair"
fallback_upstream = "fb_up"
retry_status_codes = "502,503"
max_retries = 1

[locations.stale_loc]
path = "/stale/"
upstream = "origin_up"
rewrite = "^/stale/(.*)$ /\$1"
plugins = ["cache_stale"]

[locations.stale_err_loc]
path = "/stale-err/"
upstream = "err_up"
rewrite = "^/stale-err/(.*)$ /\$1"
plugins = ["cache_stale"]

[locations.min_loc]
path = "/min/"
upstream = "origin_up"
rewrite = "^/min/(.*)$ /\$1"
plugins = ["cache_min"]

[locations.purge_loc]
path = "/purge/"
upstream = "origin_up"
rewrite = "^/purge/(.*)$ /\$1"
plugins = ["cache_purge"]
CONF
  cat >"$DIR/c/servers.toml" <<CONF
[servers.main]
addr = "127.0.0.1:$proxy"
locations = ["retry_loc", "post_loc", "stale_loc", "stale_err_loc", "min_loc", "purge_loc"]
CONF
  cat >"$DIR/c/plugins.toml" <<CONF
[plugins.cache_stale]
category = "cache"
directory = "$DIR/cache-stale"
default_ttl = "1s"
stale_if_error = "60s"
use_stale = ["error", "http_503", "http_429"]

[plugins.cache_min]
category = "cache"
directory = "$DIR/cache-min"
default_ttl = "30s"
min_uses = 2
predictor = true

[plugins.cache_purge]
category = "cache"
directory = "$DIR/cache-purge"
default_ttl = "60s"
purge_ip_list = ["127.0.0.1"]
CONF

  pingap "$DIR/pingap.log" -c "$DIR/c"
  wait_port $proxy || fail "pingap listens on $proxy"

  rc_get() {
    local path=$1
    status_code=$(curl -s -m 8 -D "$DIR/rc.h" -o "$DIR/rc.b" -w '%{http_code}' "http://127.0.0.1:$proxy$path")
    cache_status=$(grep -i '^x-cache-status:' "$DIR/rc.h" | tr -d '\r' | awk '{print $2}')
    body_out=$(tr -d '\r\n' <"$DIR/rc.b")
  }

  # 1. Status-code retry: GET 503 -> 200 failover across backends; exhausted retry
  #    and POST stay 503; never spills over to fallback_upstream.
  for i in 1 2 3 4; do
    rc_get "/retry/ping"
    expect "GET /retry/ping #$i returns 200 from healthy backend" "200 from-ok" "$status_code $body_out"
  done
  expect_match "at least one GET /retry/ping hit up1 and retried from 503" '^[1-9]' \
    "$(grep -c 'GET /retry/ping 503' "$DIR/up1.log")"
  expect "GET /retry/ping never spilled over to fallback_upstream" 0 \
    "$(wc -l <"$DIR/fb.log" | tr -d ' ')"

  rc_get "/retry-exhausted"
  expect "exhausted status retry returns 503 instead of fallback" 503 "$status_code"
  expect "exhausted status retry still never uses fallback_upstream" 0 \
    "$(wc -l <"$DIR/fb.log" | tr -d ' ')"

  status_code=$(curl -s -m 8 -o /dev/null -w '%{http_code}' -X POST -d 'hello' "http://127.0.0.1:$proxy/post-503")
  expect "POST is non-idempotent and stays 503" 503 "$status_code"
  total_post=$(($(grep -c 'POST /post-503' "$DIR/up1.log") + $(grep -c 'POST /post-503' "$DIR/up2.log")))
  expect "POST /post-503 sent to upstream once (no retry)" 1 "$total_post"

  # 2. use_stale + stale_if_error + default_ttl: warm -> sleep past 1s TTL ->
  #    origin 503, 429, and connection error all serve stale 200; 404 does not.
  rc_get "/stale/a"
  expect "stale warmup returns 200 miss" "200 miss origin:/a:n=1" "$status_code $cache_status $body_out"
  rc_get "/stale/a"
  expect "warm entry returns 200 hit" "200 hit origin:/a:n=1" "$status_code $cache_status $body_out"
  rc_get "/stale-err/b"
  expect "stale-err warmup returns 200 miss" "200 miss err-cached" "$status_code $cache_status $body_out"

  sleep 2
  curl -s -m 5 -X POST "http://127.0.0.1:$origin/__mode/503" >/dev/null
  rc_get "/stale/a"
  expect "expired + origin 503 serves stale 200" "200 stale origin:/a:n=1" "$status_code $cache_status $body_out"

  curl -s -m 5 -X POST "http://127.0.0.1:$origin/__mode/429" >/dev/null
  rc_get "/stale/a"
  expect "expired + origin 429 serves stale 200" "200 stale origin:/a:n=1" "$status_code $cache_status $body_out"

  curl -s -m 5 -X POST "http://127.0.0.1:$origin/__mode/404" >/dev/null
  rc_get "/stale/a"
  expect "expired + unconfigured 404 is not served stale" 404 "$status_code"
  curl -s -m 5 -X POST "http://127.0.0.1:$origin/__mode/200" >/dev/null

  stop "$err_pid"
  rc_get "/stale-err/b"
  expect "expired + connection refused (error) serves stale 200" "200 stale err-cached" \
    "$status_code $cache_status $body_out"

  # 3. min_uses = 2: 1st GET does not store, 2nd GET stores, 3rd GET hits.
  rc_get "/min/hot"
  expect "min_uses #1 misses without storing" "200 origin:/hot:n=1" "$status_code $body_out"
  rc_get "/min/hot"
  expect "min_uses #2 misses and stores" "200 miss origin:/hot:n=2" "$status_code $cache_status $body_out"
  rc_get "/min/hot"
  expect "min_uses #3 serves from cache" "200 hit origin:/hot:n=2" "$status_code $cache_status $body_out"

  # 4. Prefix PURGE /items/* and Cache-Tag PURGE evict only matching entries.
  for p in /purge/items/1 /purge/items/2 /purge/other/1 /purge/other/2; do
    rc_get "$p"
    expect "warm $p miss" "200 miss" "$status_code $cache_status"
    rc_get "$p"
    expect "warm $p hit" "200 hit" "$status_code $cache_status"
  done

  status_code=$(curl -s -m 8 -X PURGE -D "$DIR/purge_prefix.h" -o /dev/null -w '%{http_code}' \
    "http://127.0.0.1:$proxy/purge/items/*")
  purged_count=$(grep -i '^x-purged-count:' "$DIR/purge_prefix.h" | tr -d '\r' | awk '{print $2}')
  expect "prefix PURGE /items/* returns 204 count=2" "204 2" "$status_code $purged_count"

  rc_get "/purge/items/1"
  expect "prefix PURGE evicted /items/1" "200 miss" "$status_code $cache_status"
  rc_get "/purge/items/2"
  expect "prefix PURGE evicted /items/2" "200 miss" "$status_code $cache_status"
  rc_get "/purge/other/1"
  expect "prefix PURGE spared /other/1" "200 hit" "$status_code $cache_status"
  rc_get "/purge/other/2"
  expect "prefix PURGE spared /other/2" "200 hit" "$status_code $cache_status"

  # Re-verify /items/1 and /items/2 are warm hits after re-fetching above, then purge by Cache-Tag.
  rc_get "/purge/items/1"
  expect "/items/1 re-cached before tag purge" "200 hit" "$status_code $cache_status"
  rc_get "/purge/items/2"
  expect "/items/2 re-cached before tag purge" "200 hit" "$status_code $cache_status"

  status_code=$(curl -s -m 8 -X PURGE -H "Cache-Tag: group-a" -D "$DIR/purge_tag.h" -o /dev/null -w '%{http_code}' \
    "http://127.0.0.1:$proxy/purge/")
  purged_count=$(grep -i '^x-purged-count:' "$DIR/purge_tag.h" | tr -d '\r' | awk '{print $2}')
  expect "Cache-Tag: group-a PURGE returns 204 count=2" "204 2" "$status_code $purged_count"

  rc_get "/purge/items/1"
  expect "tag PURGE evicted /items/1 (group-a)" "200 miss" "$status_code $cache_status"
  rc_get "/purge/other/1"
  expect "tag PURGE evicted /other/1 (group-a)" "200 miss" "$status_code $cache_status"
  rc_get "/purge/items/2"
  expect "tag PURGE spared /items/2 (group-b)" "200 hit" "$status_code $cache_status"
  rc_get "/purge/other/2"
  expect "tag PURGE spared /other/2 (group-c)" "200 hit" "$status_code $cache_status"
}

# ---------------------------------------------------------------------------
# reload: with --autoreload a change of the configuration is applied by
# the process that runs, and one that is no configuration is left out.
case_reload() {
  local proxy=$((PORT_BASE + 20)) up1=$((PORT_BASE + 21)) up2=$((PORT_BASE + 22))
  local moved=$((PORT_BASE + 23))
  backend $up1 b1
  backend $up2 b2
  basic_conf "$DIR/c"
  printf '[upstreams.b1]\naddrs = ["127.0.0.1:%s"]\n\n[upstreams.b2]\naddrs = ["127.0.0.1:%s"]\n' \
    $up1 $up2 >"$DIR/c/upstreams.toml"
  printf '[locations.one]\nupstream = "b1"\nhost = "one.test"\npath = "/"\n' >"$DIR/c/locations.toml"
  printf '[servers.main]\naddr = "127.0.0.1:%s"\nlocations = ["one"]\n' $proxy >"$DIR/c/servers.toml"
  pingap "$DIR/pingap.log" -c "$DIR/c" --autoreload
  local pid=$LAST_PID
  wait_port $proxy || fail "pingap listens on $proxy"
  expect "before: one.test is served" 200 "$(status -H 'Host: one.test' "http://127.0.0.1:$proxy/")"
  expect "before: two.test is not" 404 "$(status -H 'Host: two.test' "http://127.0.0.1:$proxy/")"

  # The level of the log is taken out of the configuration: the log goes
  # on at the level it has without one, and does not fall silent.
  LOG_LEVEL='' basic_conf "$DIR/c"
  wait_for 10 grep -q 'reload log level' "$DIR/pingap.log"

  # a location more, and the server that has it
  printf '\n[locations.two]\nupstream = "b2"\nhost = "two.test"\npath = "/"\n' >>"$DIR/c/locations.toml"
  printf '[servers.main]\naddr = "127.0.0.1:%s"\nlocations = ["one", "two"]\n' $proxy >"$DIR/c/servers.toml"
  wait_for 15 status_is 200 -H 'Host: two.test' "http://127.0.0.1:$proxy/"
  expect "after the change: two.test is served" 200 \
    "$(status -H 'Host: two.test' "http://127.0.0.1:$proxy/")"
  expect "by the same process" yes "$(alive "$pid" && echo yes || echo no)"
  expect_match "and said in the log, which has no level of its own any more" '^[1-9]' \
    "$(plain <"$DIR/pingap.log" | sed -n '/reload log level/,$p' | grep -c 'reload location success')"

  # A change only a restart applies, in a process that never restarts by
  # itself: it says so, and goes on as it was started. The files are put
  # in place whole: a file read while it is written is another change.
  put() { # <file of the configuration> <printf arguments>...
    local file=$1
    shift
    # shellcheck disable=SC2059
    printf "$@" >"$DIR/put.next" && mv -f "$DIR/put.next" "$DIR/c/$file"
  }
  put servers.toml '[servers.main]\naddr = "127.0.0.1:%s"\nlocations = ["one", "two"]\n' $moved
  wait_for 10 grep -q 'takes a restart to apply' "$DIR/pingap.log"
  expect_match "a new addr of a server: the log says it takes a restart, and what" \
    "takes a restart to apply.*127.0.0.1:$moved" "$(plain <"$DIR/pingap.log" | grep 'takes a restart to apply')"
  expect "the address it was started with is still served" 200 \
    "$(status -H 'Host: one.test' "http://127.0.0.1:$proxy/")"
  expect "and the new one is not listened on" 000 "$(status "http://127.0.0.1:$moved/")"
  # Another change that leaves the same waiting: not said a second time.
  put locations.toml '%s\n[locations.four]\nupstream = "b1"\nhost = "four.test"\npath = "/"\n' \
    "$(cat "$DIR/c/locations.toml")"
  put servers.toml '[servers.main]\naddr = "127.0.0.1:%s"\nlocations = ["one", "two", "four"]\n' $moved
  wait_for 15 status_is 200 -H 'Host: four.test' "http://127.0.0.1:$proxy/"
  expect "what a reload does apply is applied all the same" 200 \
    "$(status -H 'Host: four.test' "http://127.0.0.1:$proxy/")"
  expect "and the wait for a restart is said once" 1 \
    "$(plain <"$DIR/pingap.log" | grep -c 'takes a restart to apply')"
  put servers.toml '[servers.main]\naddr = "127.0.0.1:%s"\nlocations = ["one", "two", "four"]\n' $proxy

  # A change that is no configuration: what runs stays as it is.
  printf '\n[locations.three]\nupstream = "nowhere"\nhost = "three.test"\npath = "/"\n' >>"$DIR/c/locations.toml"
  wait_for 15 grep -q 'nowhere' "$DIR/pingap.log"
  expect "a location of an upstream there is none of: one.test is still served" 200 \
    "$(status -H 'Host: one.test' "http://127.0.0.1:$proxy/")"
  expect "and the process is still there" yes "$(alive "$pid" && echo yes || echo no)"
  expect_match "and the log says why" 'nowhere' "$(plain <"$DIR/pingap.log" | grep -i 'error\|invalid\|fail' | tail -5)"
}

# ---------------------------------------------------------------------------
# webhook: a notification for ntfy is posted the way ntfy takes it, to a
# receiver that writes down what it was sent.
case_webhook() {
  local proxy=$((PORT_BASE + 90)) hook=$((PORT_BASE + 91)) out
  run_bg "$DIR/hook.out" python3 "$HERE/hook.py" $hook "$DIR/hook.log"
  wait_port $hook || fail "the receiver listens on $hook"
  # The deployment has a name and labels, one of them from its
  # environment: what tells it from another that runs the same
  # configuration.
  export E2E_CLUSTER=sh-e2e
  basic_conf "$DIR/c" "webhook = \"http://127.0.0.1:$hook/alerts?from=e2e\"" \
    'webhook_type = "ntfy"' 'webhook_notifications = ["*"]' \
    'webhook_batch_window = "0s"' 'webhook_headers = ["Authorization: Bearer tk_e2e"]' \
    'name = "edge-e2e"' 'labels = ["cluster:$ENV:E2E_CLUSTER", "env:test"]'
  printf '[upstreams.b1]\naddrs = ["127.0.0.1:9"]\n' >"$DIR/c/upstreams.toml"
  printf '[locations.b1]\nupstream = "b1"\npath = "/"\n' >"$DIR/c/locations.toml"
  printf '[servers.main]\naddr = "127.0.0.1:%s"\nlocations = ["b1"]\naccess_log = "{$name} {$label:cluster} {$label:none}- {path}"\n' \
    $proxy >"$DIR/c/servers.toml"
  pingap "$DIR/pingap.log" -c "$DIR/c" --autoreload
  wait_port $proxy || fail "pingap listens on $proxy"

  # A line of the access log says which deployment it is from.
  status "http://127.0.0.1:$proxy/who" >/dev/null
  wait_for 10 grep -q 'edge-e2e sh-e2e - /who' "$DIR/pingap.log"
  expect_match "the access log has the name and a label of the deployment" \
    'edge-e2e sh-e2e - /who' "$(plain <"$DIR/pingap.log" | grep '/who')"

  # A change that is reloaded is one of the things that are told.
  printf '[locations.b1]\nupstream = "b1"\npath = "/api"\n' >"$DIR/locations.next"
  mv -f "$DIR/locations.next" "$DIR/c/locations.toml"
  wait_for 15 grep -q reload_config "$DIR/hook.log"
  out=$(grep reload_config "$DIR/hook.log" 2>/dev/null | head -1)
  expect_match "ntfy: posted to the server, not to the topic, with what follows the ?" \
    '^POST /\?from=e2e ' "$out"
  expect_match "with the header it was given" ' auth=Bearer tk_e2e ' "$out"
  expect_match "the topic is named in the body" '"topic":"alerts"' "$out"
  expect_match "the title is the category, after the name of the deployment" \
    '"title":"edge-e2e: reload_config"' "$out"
  expect_match "the level is the priority" '"priority":3[,}]' "$out"
  expect_match "and the first of the tags, ahead of the category and the labels" \
    '"tags":\["information_source","reload_config","cluster=sh-e2e","env=test"\]' "$out"
  wait_for 5 grep -q 'send webhook success' "$DIR/pingap.log"
  expect_match "and pingap takes it for sent" 'send webhook success' "$(plain <"$DIR/pingap.log")"
  # `*` is every category: the difference of the reload came as well.
  wait_for 5 grep -q '"title":"edge-e2e: diff_config"' "$DIR/hook.log"
  expect_match "webhook_notifications = [\"*\"] sends the other categories too" '^[1-9]' \
    "$(grep -c '"title":"edge-e2e: diff_config"' "$DIR/hook.log")"

  # a label without a value, and one whose variable is not there
  mkdir -p "$DIR/label" && cp "$DIR"/c/*.toml "$DIR/label/"
  sed -i.orig 's#"env:test"#"env"#' "$DIR/label/basic.toml" && rm -f "$DIR/label/basic.toml.orig"
  expect_match "a label that is no key:value is a configuration error" \
    'labels: "env" should be `key:value`' "$("$BIN" -t -c "$DIR/label" 2>&1 | plain)"
  expect_match "and so is one whose variable is not set" \
    'basic: labels\[0\]: environment variable E2E_CLUSTER is not set' \
    "$(env -u E2E_CLUSTER "$BIN" -t -c "$DIR/c" 2>&1 | plain)"

  # the url of a server is no url of a topic
  mkdir -p "$DIR/bad" && cp "$DIR"/c/*.toml "$DIR/bad/"
  sed -i.orig 's#/alerts?from=e2e##' "$DIR/bad/basic.toml" && rm -f "$DIR/bad/basic.toml.orig"
  expect_match "a url that names no topic is a configuration error" \
    'the url of ntfy names no topic' "$("$BIN" -t -c "$DIR/bad" 2>&1 | plain)"

  # The name and the labels are read when the process starts: a change
  # of one waits for a restart, and is said to.
  sed 's#"env:test"#"env:prod"#' "$DIR/c/basic.toml" >"$DIR/basic.next"
  mv -f "$DIR/basic.next" "$DIR/c/basic.toml"
  wait_for 10 grep -q 'takes a restart to apply' "$DIR/pingap.log"
  expect_match "a label that is changed is reported as waiting for a restart" \
    'takes a restart to apply.*env:prod' \
    "$(plain <"$DIR/pingap.log" | grep 'takes a restart to apply')"
  unset E2E_CLUSTER
}

# ---------------------------------------------------------------------------
# abnormal_exit: a process that was killed is told of by the next start, in
# the log and to the webhook; one that was stopped is not, and two
# instances of one machine have marks of their own.
case_abnormal_exit() {
  local proxy=$((PORT_BASE + 100)) hook=$((PORT_BASE + 101)) other=$((PORT_BASE + 102))
  local pid mark third
  run_bg "$DIR/hook.out" python3 "$HERE/hook.py" $hook "$DIR/hook.log"
  wait_port $hook || fail "the receiver listens on $hook"
  basic_conf "$DIR/c" "webhook = \"http://127.0.0.1:$hook/alerts\"" 'webhook_type = "ntfy"' \
    'webhook_notifications = ["abnormal_exit"]' 'webhook_batch_window = "0s"' \
    'grace_period = "1s"' 'graceful_shutdown_timeout = "1s"'
  printf '[upstreams.b1]\naddrs = ["127.0.0.1:9"]\n' >"$DIR/c/upstreams.toml"
  printf '[locations.b1]\nupstream = "b1"\npath = "/"\n' >"$DIR/c/locations.toml"
  printf '[servers.main]\naddr = "127.0.0.1:%s"\nlocations = ["b1"]\n' $proxy >"$DIR/c/servers.toml"

  pingap "$DIR/first.log" -c "$DIR/c"
  pid=$LAST_PID
  wait_port $proxy || fail "pingap listens on $proxy"
  wait_for 10 sh -c "ls '$DIR'/pingap-*.state"
  mark=$(ls "$DIR"/pingap-*.state 2>/dev/null | head -1)
  expect_match "the process leaves a mark beside its pid file" "\"pid\":$pid[,}]" \
    "$(cat "$mark" 2>/dev/null)"

  # Stopped: the mark is taken away, and the next start tells nothing.
  kill -TERM "$pid"
  wait_for 20 gone "$pid"
  expect "a stop takes the mark away" no "$([ -e "$mark" ] && echo yes || echo no)"
  pingap "$DIR/second.log" -c "$DIR/c"
  pid=$LAST_PID
  wait_port $proxy || fail "pingap listens on $proxy again"
  wait_for 10 test -e "$mark"
  expect "a start after a stop tells nothing" 0 \
    "$(plain <"$DIR/second.log" | grep -c 'did not end cleanly')"

  # Killed, as by the kernel out of memory: the next start tells it.
  kill -9 "$pid"
  wait "$pid" 2>/dev/null
  expect "a kill leaves the mark" yes "$([ -e "$mark" ] && echo yes || echo no)"
  pingap "$DIR/third.log" -c "$DIR/c"
  third=$LAST_PID
  wait_port $proxy || fail "pingap listens on $proxy after the kill"
  wait_for 10 grep -q 'did not end cleanly' "$DIR/third.log"
  expect_match "the start after a kill tells it, with the pid of the run" \
    "the last run of pingap \(pid $pid, started [^)]+\) did not end cleanly" \
    "$(plain <"$DIR/third.log")"
  wait_for 10 grep -q abnormal_exit "$DIR/hook.log"
  expect_match "and posts an abnormal_exit notification, as an error" \
    '"priority":5,"tags":\["rotating_light","abnormal_exit"\],"title":"abnormal_exit"' \
    "$(cat "$DIR/hook.log" 2>/dev/null)"

  # A stop that takes longer than the supervisor waits, which ends it with
  # a SIGKILL during the grace period (pingora waits the whole of it): a
  # stop all the same, since the mark goes as it begins.
  kill -TERM "$third"
  wait_for 20 gone "$third"
  sed 's/^grace_period = .*/grace_period = "30s"/' "$DIR/c/basic.toml" >"$DIR/basic.next"
  mv -f "$DIR/basic.next" "$DIR/c/basic.toml"
  pingap "$DIR/fourth.log" -c "$DIR/c"
  pid=$LAST_PID
  wait_port $proxy || fail "pingap listens on $proxy with a grace period of 30s"
  wait_for 10 test -e "$mark"
  kill -TERM "$pid"
  wait_for 5 sh -c "! test -e '$mark'"
  expect "a stop that has begun has taken the mark away" "no yes" \
    "$([ -e "$mark" ] && echo yes || echo no) $(alive "$pid" && echo yes || echo no)"
  kill -9 "$pid"
  wait "$pid" 2>/dev/null
  pingap "$DIR/fifth.log" -c "$DIR/c"
  wait_port $proxy || fail "pingap listens on $proxy after the stop that was cut short"
  wait_for 10 test -e "$mark"
  expect "a start after a stop that was cut short tells nothing" 0 \
    "$(plain <"$DIR/fifth.log" | grep -c 'did not end cleanly')"

  # Another instance of the machine, on a configuration of its own.
  mkdir -p "$DIR/d" && cp "$DIR"/c/*.toml "$DIR/d/"
  sed "s/$proxy/$other/" "$DIR/c/servers.toml" >"$DIR/d/servers.toml"
  pingap "$DIR/other.log" -c "$DIR/d"
  wait_port $other || fail "the second instance listens on $other"
  wait_for 10 sh -c "[ \$(ls '$DIR'/pingap-*.state | wc -l) -eq 2 ]"
  expect "two instances, a mark each" 2 "$(ls "$DIR"/pingap-*.state 2>/dev/null | wc -l | tr -d ' ')"
  expect "and the second tells nothing" 0 \
    "$(plain <"$DIR/other.log" | grep -c 'did not end cleanly')"
}

# ---------------------------------------------------------------------------
# foreground: a restart hands the sockets to a daemon and lets the process
# that was started exit, which is the end of the service to whatever
# started it - of the container, where it is the first process of one.
# A process that is no daemon makes no such restart: it says why, and
# with --autorestart it reloads and reports what waits.
case_foreground() {
  local proxy=$((PORT_BASE + 100)) admin=$((PORT_BASE + 101)) moved=$((PORT_BASE + 102))
  local proxy1=$((PORT_BASE + 103)) admin1=$((PORT_BASE + 104)) pid out want
  basic_info() { # <admin port> <field>
    body "http://127.0.0.1:$1/api/basic" |
      python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$2" 2>/dev/null
  }
  restart_asked() { # <admin port>: the answer and its status
    curl -s -m 20 -X POST -w ' %{http_code}' "http://127.0.0.1:$1/api/restart"
  }
  basic_conf "$DIR/c"
  printf '[upstreams.b1]\naddrs = ["127.0.0.1:9"]\n' >"$DIR/c/upstreams.toml"
  printf '[locations.b1]\nupstream = "b1"\npath = "/"\n' >"$DIR/c/locations.toml"
  printf '[servers.main]\naddr = "127.0.0.1:%s"\nlocations = ["b1"]\n' $proxy >"$DIR/c/servers.toml"
  pingap "$DIR/pingap.log" -c "$DIR/c" --admin "127.0.0.1:$admin" --autorestart
  pid=$LAST_PID
  wait_port $proxy || fail "pingap listens on $proxy"
  wait_port $admin || fail "the admin listens on $admin"

  want=platform
  [ "$LINUX" = 1 ] && want=foreground
  expect "the admin is told why no restart is made from it" "$want" \
    "$(basic_info $admin restart_unsupported)"
  out=$(restart_asked $admin)
  expect_match "a restart that is asked for is refused, with the reason" \
    '(runs in the foreground|on Linux only).* 400$' "$out"
  expect "and nothing is started for it" 0 \
    "$(plain <"$DIR/pingap.log" | grep -c 'new pingap process spawned')"
  expect_match "--autorestart says that it only reloads here" \
    'autorestart only reloads here' "$(plain <"$DIR/pingap.log")"

  # What only a restart applies is said, and waits for one.
  printf '[servers.main]\naddr = "127.0.0.1:%s"\nlocations = ["b1"]\n' $moved >"$DIR/servers.next"
  mv -f "$DIR/servers.next" "$DIR/c/servers.toml"
  wait_for 10 grep -q 'takes a restart to apply' "$DIR/pingap.log"
  expect_match "a new addr of a server is reported as waiting for a restart" \
    "takes a restart to apply.*127.0.0.1:$moved" \
    "$(plain <"$DIR/pingap.log" | grep 'takes a restart to apply')"
  expect "by the process that was started, which goes on" "yes $proxy" \
    "$(alive "$pid" && echo yes || echo no) $(wait_port $proxy 10 && echo $proxy)"

  # The first process of a container: of a pid namespace of its own here,
  # which is what a container makes of it.
  if [ "$LINUX" != 1 ] || ! command -v unshare >/dev/null || ! sudo -n true 2>/dev/null ||
    ! sudo unshare --pid --fork --kill-child --mount-proc true 2>/dev/null; then
    skip "as the first process of a container: takes Linux, a sudo that asks nothing and an unshare that is allowed"
    return
  fi
  cp -R "$DIR/c" "$DIR/c1"
  printf '[servers.main]\naddr = "127.0.0.1:%s"\nlocations = ["b1"]\n' $proxy1 >"$DIR/c1/servers.toml"
  # --kill-child: the process ends with the unshare that started it
  run_bg "$DIR/pid1.log" sudo unshare --pid --fork --kill-child --mount-proc \
    "$BIN" -c "$DIR/c1" --admin "127.0.0.1:$admin1" --autorestart
  wait_port $admin1 || fail "the first process of the namespace listens on $admin1"
  expect "as the first process of a container: its pid is 1" 1 "$(basic_info $admin1 pid)"
  expect "the admin is told that it is one" container "$(basic_info $admin1 restart_unsupported)"
  out=$(restart_asked $admin1)
  expect_match "a restart is refused, with the container as the thing to restart" \
    'first process of a container.*restart the container.* 400$' "$out"
  sleep 1
  expect "and the process goes on serving" 200 "$(status "http://127.0.0.1:$admin1/api/basic")"
  # root's, like what it wrote; see cleanup for the pattern
  sudo pkill -9 -f "[/]${DIR#/}/c1" 2>/dev/null
  sudo chown -R "$(id -u)" "$DIR" 2>/dev/null
  return 0
}

# ---------------------------------------------------------------------------
# proxy_protocol: `send_proxy_protocol` of an upstream tells the backend
# which client a connection is for, a connection is kept for that client,
# the health check says it is nobody's, and a listener that reads the
# header itself passes the address on.
case_proxy_protocol() {
  local proxy=$((PORT_BASE + 30)) behind=$((PORT_BASE + 31)) py=$((PORT_BASE + 32))
  local other=$((PORT_BASE + 33)) ng=$((PORT_BASE + 34)) ngtls=$((PORT_BASE + 35))
  local names='"v1", "v2", "plain"' nginx=0 fastopen=0 out port

  backend $py py proxy
  backend $other other

  # nginx as a backend that reads the header, where there is one
  if command -v nginx >/dev/null && command -v openssl >/dev/null; then
    mkdir -p "$DIR/ng/tmp"
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$DIR/ng/key.pem" \
      -out "$DIR/ng/cert.pem" -days 2 -subj /CN=nginx.test 2>/dev/null
    cat >"$DIR/ng/nginx.conf" <<EOT
daemon off;
master_process off;
error_log $DIR/ng/error.log info;
pid $DIR/ng/nginx.pid;
events { worker_connections 128; }
http {
  access_log off;
  client_body_temp_path $DIR/ng/tmp/a;
  proxy_temp_path $DIR/ng/tmp/b;
  fastcgi_temp_path $DIR/ng/tmp/c;
  uwsgi_temp_path $DIR/ng/tmp/d;
  scgi_temp_path $DIR/ng/tmp/e;
  server {
    listen 127.0.0.1:$ng proxy_protocol;
    listen 127.0.0.1:$ngtls ssl proxy_protocol;
    ssl_certificate $DIR/ng/cert.pem;
    ssl_certificate_key $DIR/ng/key.pem;
    location / {
      default_type text/plain;
      return 200 "nginx \$scheme client=\$proxy_protocol_addr:\$proxy_protocol_port to=\$proxy_protocol_server_port\n";
    }
  }
}
EOT
    run_bg "$DIR/ng/stderr.log" nginx -c "$DIR/ng/nginx.conf" -p "$DIR/ng"
    if wait_port $ng 50; then
      nginx=1
      names="$names, \"ng\", \"ngtls\""
    else
      skip "nginx did not start: $(tail -2 "$DIR/ng/stderr.log" | tr '\n' ' ')"
    fi
  else
    skip "no nginx on this machine: the backend of the checks stands in for it"
  fi
  # TCP fast open towards the backend, where the kernel does it for clients
  if [ "$LINUX" = 1 ] && [ $(($(cat /proc/sys/net/ipv4/tcp_fastopen 2>/dev/null || echo 0) & 1)) = 1 ]; then
    fastopen=1
    names="$names, \"fastopen\""
  fi

  basic_conf "$DIR/c" 'trusted_proxies = ["127.0.0.1"]'
  cat >"$DIR/c/upstreams.toml" <<EOT
[upstreams.v1]
addrs = ["127.0.0.1:$py"]
send_proxy_protocol = "v1"

[upstreams.v2]
addrs = ["127.0.0.1:$py"]
send_proxy_protocol = "v2"
health_check = "http://v2.test/ping"

[upstreams.plain]
addrs = ["127.0.0.1:$other"]

[upstreams.ng]
addrs = ["127.0.0.1:$ng"]
send_proxy_protocol = "v2"

[upstreams.ngtls]
addrs = ["127.0.0.1:$ngtls"]
sni = "nginx.test"
verify_cert = false
send_proxy_protocol = "v1"

[upstreams.fastopen]
addrs = ["127.0.0.1:$py"]
send_proxy_protocol = "v2"
tcp_fast_open = true
EOT
  : >"$DIR/c/locations.toml"
  for name in v1 v2 plain ng ngtls fastopen; do
    printf '[locations.%s]\nupstream = "%s"\nhost = "%s.test"\npath = "/"\n\n' \
      $name $name $name >>"$DIR/c/locations.toml"
  done
  cat >"$DIR/c/servers.toml" <<EOT
[servers.main]
addr = "127.0.0.1:$proxy"
locations = [$names]

[servers.behind]
addr = "127.0.0.1:$behind"
proxy_protocol = true
locations = [$names]
EOT
  pingap "$DIR/pingap.log" -c "$DIR/c"
  wait_port $proxy || fail "pingap listens on $proxy"
  wait_port $behind || fail "pingap listens on $behind"

  # What the backend was told, with the port curl really came from put
  # in the place of PORT.
  told() { # <host>
    out=$(curl -s -m 8 -H "Host: $1.test" -w '\n%{local_port}' "http://127.0.0.1:$proxy/")
    port=$(printf '%s' "$out" | tail -1)
    printf '%s' "$out" | head -1 | sed "s/:$port /:PORT /; s/ conn=.*//"
  }
  expect "v1 names the client and where it came to" \
    "v1 TCP4 127.0.0.1:PORT 127.0.0.1:$proxy" "$(told v1)"
  expect "v2 names the client and where it came to" \
    "v2 TCP4 127.0.0.1:PORT 127.0.0.1:$proxy" "$(told v2)"
  if [ $nginx = 1 ]; then
    expect "nginx reads version 2" "nginx http client=127.0.0.1:PORT to=$proxy" "$(told ng)"
    expect "nginx reads version 1 ahead of TLS" \
      "nginx https client=127.0.0.1:PORT to=$proxy" "$(told ngtls)"
  fi
  if [ $fastopen = 1 ]; then
    expect "with tcp_fast_open" "v2 TCP4 127.0.0.1:PORT 127.0.0.1:$proxy" "$(told fastopen)"
  fi

  # Three requests of one client connection, then one of another client:
  # which connections of the backend they came on.
  conns() { # <host>
    {
      curl -s -m 8 -H "Host: $1.test" "http://127.0.0.1:$proxy/a" \
        "http://127.0.0.1:$proxy/b" "http://127.0.0.1:$proxy/c"
      curl -s -m 8 -H "Host: $1.test" "http://127.0.0.1:$proxy/d"
    } | sed -n 's/.* conn=\([0-9]*\) req=\([0-9]*\) .*/\1/p' | uniq -c | awk '{printf "%s ", $1}'
  }
  expect "a kept connection is for the client connection it was opened for" "3 1 " "$(conns v2)"
  expect "and is shared without the option" "4 " "$(conns plain)"

  # A listener that reads the header: the client it names is passed on.
  out=$(python3 - "$behind" <<'EOT'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=8)
s.sendall(b"PROXY TCP4 203.0.113.9 198.51.100.7 4444 443\r\n"
          b"GET / HTTP/1.1\r\nHost: v2.test\r\nConnection: close\r\n\r\n")
data = b""
while True:
    chunk = s.recv(4096)
    if not chunk:
        break
    data += chunk
print(data.decode(errors="replace").split("\r\n\r\n", 1)[-1].strip())
EOT
  )
  expect "the client a load balancer named is the one the backend is told" \
    "v2 TCP4 203.0.113.9:4444 127.0.0.1:$behind" "$(printf '%s' "$out" | sed 's/ conn=.*//')"

  # The checks of the upstreams came with a header that names nobody,
  # and nothing came without one.
  expect_match "the health checks send a header of their own" '^[1-9]' \
    "$(grep -c ' local ' "$DIR/py.log")"
  expect "no connection came without a header" 0 "$(grep -c 'no header' "$DIR/py.log")"
  if [ $nginx = 1 ]; then
    expect "nginx saw no broken header" 0 \
      "$(grep -c 'broken header' "$DIR/ng/error.log" 2>/dev/null)"
  fi

  # a version there is none of is refused
  sed 's/send_proxy_protocol = "v1"/send_proxy_protocol = "v3"/' "$DIR/c/upstreams.toml" >"$DIR/bad.toml"
  mkdir -p "$DIR/bad" && cp "$DIR"/c/*.toml "$DIR/bad/" && cp "$DIR/bad.toml" "$DIR/bad/upstreams.toml"
  expect_match "send_proxy_protocol = \"v3\" is a configuration error" \
    'send proxy protocol should be one of v1, v2' "$("$BIN" -t -c "$DIR/bad" 2>&1 | plain)"
}

# ---------------------------------------------------------------------------
# What the cases below share: a daemon with its pid file, its sockets and
# its log in the directory of the case, started from a copy of the binary
# that a case may put something else in the place of.
TOKEN=e2e-token
TOKEN_SHA=$(printf '%s' "$TOKEN" | python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())')

daemon_setup() { # <proxy port> <backend port>
  cp "$BIN" "$DIR/pingap"
  backend "$2" b1
  basic_conf "$DIR/c" 'grace_period = "3s"' 'graceful_shutdown_timeout = "2s"' \
    'restart_ready_timeout = "8s"'
  printf '[upstreams.b1]\naddrs = ["127.0.0.1:%s"]\n' "$2" >"$DIR/c/upstreams.toml"
  printf '[locations.b1]\nupstream = "b1"\npath = "/"\n' >"$DIR/c/locations.toml"
  printf '[servers.main]\naddr = "127.0.0.1:%s"\nlocations = ["b1"]\n' "$1" >"$DIR/c/servers.toml"
  LOGS+=("$DIR/pingap.log" "$DIR/launcher.out")
}

# daemon_start <admin port> [more flags]: the exit status of what started it
daemon_start() {
  local admin=$1
  shift
  "$DIR/pingap" -c "$DIR/c" --log "$DIR/pingap.log?rolling=never" \
    --admin "127.0.0.1:$admin?token=ci:$TOKEN_SHA" -d "$@" >>"$DIR/launcher.out" 2>&1
}

daemon_pid() { cat "$DIR/pingap.pid" 2>/dev/null; }
gone() { ! alive "$1"; }
# the pid of the process that answers on the admin port
serving_pid() { # <admin port>
  curl -s -m 5 -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$1/api/basic" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["pid"])' 2>/dev/null
}
# the pid file names a process that runs and is not <pid>
daemon_pid_is_not() {
  local now
  now=$(daemon_pid)
  [ -n "$now" ] && [ "$now" != "$1" ] && alive "$now"
}
restart_by_admin() { # <admin port>: the status and the body
  curl -s -m 20 -X POST -H "Authorization: Bearer $TOKEN" -w ' %{http_code}' \
    "http://127.0.0.1:$1/api/restart"
}

# hammer <url>: a request on a connection of its own every 50 ms until
# hammer_stop, which says how many were made and how many failed.
hammer() {
  : >"$DIR/hammer.failed"
  : >"$DIR/hammer.made"
  (
    while :; do
      code=$(curl -s -o /dev/null -m 5 -w '%{http_code}' "$1")
      echo >>"$DIR/hammer.made"
      [ "$code" = 200 ] || echo "$code" >>"$DIR/hammer.failed"
      sleep 0.05
    done
  ) &
  HAMMER=$!
  PIDS+=("$HAMMER")
}
hammer_stop() {
  stop "$HAMMER"
  HAMMERED=$(wc -l <"$DIR/hammer.made" | tr -d ' ')
  HAMMER_FAILED=$(wc -l <"$DIR/hammer.failed" | tr -d ' ')
  # The status codes that were not 200, in the order they happened.
  HAMMER_CODES=$(tr '\n' ' ' <"$DIR/hammer.failed" | sed 's/ $//')
}
# handover_drops <what> <max>: how many requests a hand-over may lose.
#
# pingora's HttpProxy::handle_new_request races the request read against
# shutdown. A connection it has already accept()ed, whose request bytes
# are not readable yet, is closed when the old process stops accepting
# (after the 5s it keeps accepting once the sockets are sent). hammer
# has one request in flight, so that is one lost request per process
# that exits. A stretch where nothing is listening loses one every 50ms
# and lands past <max>.
handover_drops() {
  if [ "$HAMMER_FAILED" -le "$2" ]; then
    if [ "$HAMMER_FAILED" = 0 ]; then
      ok "$1"
    else
      ok "$1 ($HAMMER_FAILED dropped: $HAMMER_CODES)"
    fi
  else
    fail "$1" "wanted: at most $2" "got:    $HAMMER_FAILED ($HAMMER_CODES)"
  fi
}
# Puts a script in the place of the binary a restart starts.
replace_binary() { # <the lines of the script>
  printf '#!/bin/sh\n%s\n' "$1" >"$DIR/pingap.next"
  chmod +x "$DIR/pingap.next"
  mv -f "$DIR/pingap.next" "$DIR/pingap"
}
restore_binary() {
  cp "$BIN" "$DIR/pingap.next"
  mv -f "$DIR/pingap.next" "$DIR/pingap"
}

# ---------------------------------------------------------------------------
# daemon: -d leaves a process behind that is nobody's child, says who it
# is in the pid file, and ends on SIGTERM once the requests it has are
# answered.
case_daemon() {
  local proxy=$((PORT_BASE + 40)) admin=$((PORT_BASE + 41)) up=$((PORT_BASE + 42)) pid
  daemon_setup $proxy $up
  daemon_start $admin
  expect "what starts the daemon exits with 0" 0 $?
  wait_for 10 test -s "$DIR/pingap.pid"
  wait_port $proxy || fail "the daemon listens on $proxy"
  pid=$(daemon_pid)
  expect "the pid file names a process that runs" yes "$(alive "$pid" && echo yes || echo no)"
  expect "which is not a child of what started it" no \
    "$([ "$(ps -o ppid= -p "$pid" | tr -d ' ')" = "$$" ] && echo yes || echo no)"
  expect "and is the one that serves" "$pid" "$(serving_pid $admin)"
  expect "a request through the daemon" 200 "$(status "http://127.0.0.1:$proxy/")"
  expect_match "the log is written" 'server is running' "$(plain <"$DIR/pingap.log")"

  # SIGTERM: no new connection, the request that is under way is answered
  # (the backend takes two seconds for /slow), then the process is gone.
  status "http://127.0.0.1:$proxy/slow" >"$DIR/slow.status" &
  local slow=$!
  wait_for 5 grep -q 'start path=/slow' "$DIR/up.log"
  kill -TERM "$pid"
  wait_for 10 status_is 000 "http://127.0.0.1:$proxy/"
  expect "after SIGTERM no new connection is taken" 000 "$(status "http://127.0.0.1:$proxy/")"
  wait "$slow"
  expect "the request that was under way is answered" 200 "$(cat "$DIR/slow.status")"
  wait_for 15 gone "$pid"
  expect "and the process ends" yes "$(gone "$pid" && echo yes || echo no)"
}

# ---------------------------------------------------------------------------
# restart: a restart hands the listening sockets to a new process without
# a request being refused, and one that cannot be completed leaves the
# old process serving.
case_restart() {
  if [ "$LINUX" != 1 ]; then
    skip "the hand-over of listening sockets is Linux only"
    return
  fi
  local proxy=$((PORT_BASE + 50)) admin=$((PORT_BASE + 51)) up=$((PORT_BASE + 52))
  local second=$((PORT_BASE + 53)) first out new
  # Without a level of its own in the configuration: the replacement logs
  # at the default one as the first process does.
  LOG_LEVEL='' daemon_setup $proxy $up
  daemon_start $admin --autorestart
  wait_for 10 test -s "$DIR/pingap.pid"
  wait_port $proxy || fail "the daemon listens on $proxy"
  wait_port $admin || fail "the admin listens on $admin"
  first=$(daemon_pid)

  # A replacement that exits before it is ready: nothing changes.
  replace_binary 'exit 3'
  out=$(restart_by_admin $admin)
  expect_match "a replacement that exits at once: the restart is refused" \
    'before it was ready.* 400$' "$out"
  expect "and the process that ran still serves" "$first 200" \
    "$(serving_pid $admin) $(status "http://127.0.0.1:$proxy/")"

  # One that never says it is ready: given up after restart_ready_timeout.
  replace_binary 'exec sleep 311'
  out=$(restart_by_admin $admin)
  expect_match "a replacement that does not report: given up after 8s" \
    'did not report readiness within 8s.* 400$' "$out"
  expect "and the process that ran still serves" "$first 200" \
    "$(serving_pid $admin) $(status "http://127.0.0.1:$proxy/")"
  pkill -9 -f 'sleep 311' 2>/dev/null
  expect "the socket the report was waited for on is gone" no \
    "$([ -e "$DIR/pingap_upgrade.sock.ready" ] && echo yes || echo no)"

  # The real thing, asked for through the admin, under requests.
  restore_binary
  hammer "http://127.0.0.1:$proxy/"
  out=$(restart_by_admin $admin)
  expect_match "a restart through the admin is taken" ' 204$' "$out"
  # The replacement writes its pid as it starts. For some seconds both
  # processes take connections from the one socket, so which of them
  # answers says nothing until the first has ended.
  wait_for 30 daemon_pid_is_not "$first"
  new=$(daemon_pid)
  expect "the pid file names another process" yes \
    "$([ -n "$new" ] && [ "$new" != "$first" ] && echo yes || echo no)"
  wait_for 30 gone "$first"
  expect "the process before it has ended" yes "$(gone "$first" && echo yes || echo no)"
  expect "and the new one serves" "$new" "$(serving_pid $admin)"
  sleep 1
  hammer_stop
  handover_drops "no request failed during the hand-over ($HAMMERED made)" 1
  expect_match "the old process waited for the report" 'new pingap process is ready for the sockets' \
    "$(plain <"$DIR/pingap.log")"
  expect_match "which the new one gave" 'reported readiness to the previous pingap process' \
    "$(plain <"$DIR/pingap.log")"
  expect_match "the replacement logs at the level the first process had" '^[2-9]' \
    "$(plain <"$DIR/pingap.log" | grep -c 'server is running')"

  # --autorestart: a change that takes a new listener is applied by a
  # restart of its own, a minute after it is seen.
  first=$new
  hammer "http://127.0.0.1:$proxy/"
  printf '\n[servers.second]\naddr = "127.0.0.1:%s"\nlocations = ["b1"]\n' $second >>"$DIR/c/servers.toml"
  wait_for 100 status_is 200 "http://127.0.0.1:$second/"
  expect "a server that is added listens after the restart" 200 "$(status "http://127.0.0.1:$second/")"
  new=$(daemon_pid)
  expect "in another process again" yes "$([ -n "$new" ] && [ "$new" != "$first" ] && echo yes || echo no)"
  wait_for 30 gone "$first"
  expect "which is the one that serves" "$new" "$(serving_pid $admin)"
  sleep 1
  hammer_stop
  handover_drops "no request failed during that hand-over either ($HAMMERED made)" 1
  expect "one process is left" 1 "$(pgrep -f "$DIR/c" | wc -l | tr -d ' ')"
  # A restart is no abnormal exit: the process that took over has the
  # mark, the ones before took none of theirs along with it and left none.
  expect "after the restarts one mark is left" 1 \
    "$(ls "$DIR"/pingap-*.state 2>/dev/null | wc -l | tr -d ' ')"
  expect "and it is of the process that serves" "$new" \
    "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["pid"])' "$DIR"/pingap-*.state 2>/dev/null)"
}

# ---------------------------------------------------------------------------
# restart_guard: what the stored configuration asks for that a replacement
# could not have does not cost the process that runs. A new address that
# is taken is found before anything is started, and a changed upgrade
# socket is not what the two processes meet on.
case_restart_guard() {
  if [ "$LINUX" != 1 ]; then
    skip "the hand-over of listening sockets is Linux only"
    return
  fi
  local proxy=$((PORT_BASE + 70)) admin=$((PORT_BASE + 71)) up=$((PORT_BASE + 72))
  local taken=$((PORT_BASE + 73)) first out new
  daemon_setup $proxy $up
  # Without --autorestart: the restarts here are the ones asked for.
  daemon_start $admin
  wait_for 10 test -s "$DIR/pingap.pid"
  wait_port $proxy || fail "the daemon listens on $proxy"
  wait_port $admin || fail "the admin listens on $admin"
  first=$(daemon_pid)

  # Another program has the port a new server is given.
  backend $taken squatter
  cp "$DIR/c/servers.toml" "$DIR/servers.keep"
  printf '\n[servers.taken]\naddr = "127.0.0.1:%s"\nlocations = ["b1"]\n' $taken >>"$DIR/c/servers.toml"
  out=$(restart_by_admin $admin)
  expect_match "a new address another program listens on: the restart is refused" \
    "127.0.0.1:$taken.*cannot be bound here.* 400\$" "$out"
  expect "nothing was started for it" 0 \
    "$(plain <"$DIR/pingap.log" | grep -c 'new pingap process spawned')"
  sleep 6
  expect "and the process that ran still serves" "$first 200" \
    "$(serving_pid $admin) $(status "http://127.0.0.1:$proxy/")"
  cp "$DIR/servers.keep" "$DIR/c/servers.toml"

  # basic.upgrade_sock is changed while the process runs. The replacement
  # waits on the path the running process sends to.
  sed -i.orig "s#^upgrade_sock = .*#upgrade_sock = \"$DIR/other_upgrade.sock\"#" "$DIR/c/basic.toml"
  rm -f "$DIR/c/basic.toml.orig"
  hammer "http://127.0.0.1:$proxy/"
  out=$(restart_by_admin $admin)
  expect_match "a changed upgrade_sock: the restart is taken" ' 204$' "$out"
  wait_for 30 daemon_pid_is_not "$first"
  new=$(daemon_pid)
  wait_for 30 gone "$first"
  expect "the process before it has ended" yes "$(gone "$first" && echo yes || echo no)"
  expect "and the new one serves" "$new" "$(serving_pid $admin)"
  expect_match "which says that the socket in use is kept" \
    'basic.upgrade_sock is not the one the running process hands its sockets over on' \
    "$(plain <"$DIR/pingap.log")"
  # And from that process to the next, which is told the same path.
  first=$new
  out=$(restart_by_admin $admin)
  expect_match "the restart after that one is taken as well" ' 204$' "$out"
  wait_for 30 daemon_pid_is_not "$first"
  new=$(daemon_pid)
  wait_for 30 gone "$first"
  expect "and ends with the next process serving" "$new" "$(serving_pid $admin)"
  sleep 1
  hammer_stop
  # Two processes exit under this one hammer, so two such drops.
  handover_drops "no request failed during the two hand-overs ($HAMMERED made)" 2
  expect "one process is left" 1 "$(pgrep -f "$DIR/c" | wc -l | tr -d ' ')"
}

# ---------------------------------------------------------------------------
# systemd: the unit of the repository, with its paths pointed at this
# case, starts the daemon, follows it through a restart and stops it.
UNIT=pingap-e2e
case_systemd() {
  if [ "${E2E_SYSTEMD:-0}" != 1 ]; then
    skip "not asked for: E2E_SYSTEMD=1 installs a unit, which takes systemd and sudo"
    return
  fi
  if [ "$LINUX" != 1 ] || [ ! -d /run/systemd/system ] || ! sudo -n true 2>/dev/null; then
    skip "no systemd here, or no sudo that asks nothing"
    return
  fi
  local proxy=$((PORT_BASE + 80)) admin=$((PORT_BASE + 81)) up=$((PORT_BASE + 82))
  local pid_file=/run/$UNIT.pid first new out started
  unit() { systemctl show -p "$1" --value $UNIT; }
  unit_pid_is_not() { [ "$(unit MainPID)" != "$1" ] && [ "$(unit MainPID)" != 0 ]; }
  # The processes are root's: asked as anybody else, every one is gone.
  root_gone() { ! sudo kill -0 "$1" 2>/dev/null; }

  daemon_setup $proxy $up
  # Where a service keeps them, and where root is the one who writes.
  sed -i.orig -e "s#^pid_file = .*#pid_file = \"$pid_file\"#" \
    -e "s#^upgrade_sock = .*#upgrade_sock = \"/run/${UNIT}_upgrade.sock\"#" "$DIR/c/basic.toml"
  rm -f "$DIR/c/basic.toml.orig"
  # The unit as it is installed, with the paths of this case in it.
  sed -e "s#/usr/sbin/pingap#$DIR/pingap#g" \
    -e "s#/etc/pingap/conf?separation#$DIR/c#g" \
    -e "s#--log=/var/log/pingap#--log=$DIR/pingap.log?rolling=never#" \
    -e "s#^PIDFile=.*#PIDFile=$pid_file#" "$ROOT/pingap.service" >"$DIR/$UNIT.service"
  expect "the unit is one of a daemon that forks" "Type=forking" "$(grep '^Type=' "$DIR/$UNIT.service")"
  sudo mkdir -p "/run/systemd/system/$UNIT.service.d"
  sudo cp "$DIR/$UNIT.service" "/run/systemd/system/$UNIT.service"
  printf '[Service]\nEnvironment=PINGAP_ADMIN_ADDR=127.0.0.1:%s?token=ci:%s\n' $admin "$TOKEN_SHA" |
    sudo tee "/run/systemd/system/$UNIT.service.d/admin.conf" >/dev/null
  sudo systemctl daemon-reload

  sudo systemctl start $UNIT
  expect "systemctl start comes back with 0" 0 $?
  expect "the unit is active" active "$(systemctl is-active $UNIT)"
  wait_port $proxy || fail "the service listens on $proxy"
  wait_port $admin || fail "the admin listens on $admin"
  first=$(sudo cat $pid_file 2>/dev/null)
  expect "its main process is the one of the pid file" "$first" "$(unit MainPID)"
  expect "which is the one that serves" "$first" "$(serving_pid $admin)"
  expect "a request through the service" 200 "$(status "http://127.0.0.1:$proxy/")"

  # A restart of pingap's own: the unit goes on with the new process.
  hammer "http://127.0.0.1:$proxy/"
  out=$(restart_by_admin $admin)
  expect_match "a restart through the admin is taken" ' 204$' "$out"
  wait_for 30 unit_pid_is_not "$first"
  wait_for 30 root_gone "$first"
  expect "the process before it has ended" yes "$(root_gone "$first" && echo yes || echo no)"
  new=$(sudo cat $pid_file 2>/dev/null)
  expect "the pid file names another process" yes \
    "$([ -n "$new" ] && [ "$new" != "$first" ] && echo yes || echo no)"
  expect "which systemd takes for the main process" "$new" "$(unit MainPID)"
  expect "of a unit that is still active" active "$(systemctl is-active $UNIT)"
  expect "and it is the one that serves" "$new" "$(serving_pid $admin)"
  sleep 1
  hammer_stop
  handover_drops "no request failed during the hand-over ($HAMMERED made)" 1
  # Past the time the first process took to end: nothing of the unit is
  # killed along with it.
  sleep 6
  expect "the unit is active after the old process is long gone" "active 200" \
    "$(systemctl is-active $UNIT) $(status "http://127.0.0.1:$proxy/")"

  started=$SECONDS
  sudo systemctl stop $UNIT
  expect "systemctl stop comes back with 0" 0 $?
  expect_match "within the time the unit gives it ($((SECONDS - started))s)" '^yes$' \
    "$([ $((SECONDS - started)) -le 15 ] && echo yes || echo no)"
  expect "the unit is inactive, and did not fail" "inactive success" \
    "$(systemctl is-active $UNIT) $(unit Result)"
  expect "nothing listens any more" 000 "$(status "http://127.0.0.1:$proxy/")"
  expect "and no process of it is left" 0 "$(pgrep -f "$DIR/c" | wc -l | tr -d ' ')"

  if [ "$FAILED" -gt "${CASE_FAILED_BEFORE:-0}" ]; then
    echo "---- systemctl status $UNIT"
    systemctl status $UNIT --no-pager -l 2>&1 | tail -30
    echo "---- journalctl -u $UNIT"
    sudo journalctl -u $UNIT --no-pager -n 40 2>&1
  fi
  systemd_cleanup
}

systemd_cleanup() {
  [ -e "/run/systemd/system/$UNIT.service" ] || return 0
  sudo systemctl stop $UNIT 2>/dev/null
  sudo rm -rf "/run/systemd/system/$UNIT.service" "/run/systemd/system/$UNIT.service.d" \
    "/run/$UNIT.pid" "/run/$UNIT.pid.old" "/run/${UNIT}_upgrade.sock"
  sudo systemctl daemon-reload
  sudo systemctl reset-failed $UNIT 2>/dev/null
  # what root wrote into the directory of the case
  sudo chown -R "$(id -u)" "$WORK" 2>/dev/null
  return 0
}

# ---------------------------------------------------------------------------
# upgrade: a second process started with -u takes the sockets over when
# the first is told to quit.
case_upgrade() {
  if [ "$LINUX" != 1 ]; then
    skip "the hand-over of listening sockets is Linux only"
    return
  fi
  local proxy=$((PORT_BASE + 60)) admin=$((PORT_BASE + 61)) up=$((PORT_BASE + 62)) first new
  daemon_setup $proxy $up
  daemon_start $admin
  wait_for 10 test -s "$DIR/pingap.pid"
  wait_port $proxy || fail "the daemon listens on $proxy"
  wait_port $admin || fail "the admin listens on $admin"
  first=$(daemon_pid)

  hammer "http://127.0.0.1:$proxy/"
  daemon_start $admin -u
  expect "what starts the second process exits with 0" 0 $?
  # Wait until the replacement has written its pid before signalling the old one.
  wait_for 15 daemon_pid_is_not "$first"
  new=$(daemon_pid)
  expect "the pid file names the second process" yes \
    "$([ -n "$new" ] && [ "$new" != "$first" ] && alive "$new" && echo yes || echo no)"
  kill -QUIT "$first"
  wait_for 30 gone "$first"
  expect "the first has ended" yes "$(gone "$first" && echo yes || echo no)"
  expect "and the second serves" "$new" "$(serving_pid $admin)"
  sleep 1
  hammer_stop
  handover_drops "no request failed during the upgrade ($HAMMERED made)" 1
  expect "a request through the second process" 200 "$(status "http://127.0.0.1:$proxy/")"
}

# ---------------------------------------------------------------------------
# stream: native L4 TCP + TLS SNI passthrough alongside L7 HTTP, fallback,
# half-close, live `--autoreload` SNI route switch, and `left_for_restart`.
case_stream() {
  if ! command -v openssl >/dev/null; then
    skip "openssl is required for case_stream"
    return
  fi
  local http_proxy=$((PORT_BASE + 160)) http_up=$((PORT_BASE + 161))
  local tcp_stream=$((PORT_BASE + 162)) tls_stream=$((PORT_BASE + 163))
  local moved_stream=$((PORT_BASE + 164)) tcp_up=$((PORT_BASE + 165))
  local tls_a_up=$((PORT_BASE + 166)) tls_b_up=$((PORT_BASE + 167))

  backend $http_up http

  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$DIR/a.key" -out "$DIR/a.crt" -days 2 \
    -subj "/CN=alpha.sni.test" \
    -addext "subjectAltName=DNS:alpha.sni.test" 2>/dev/null
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$DIR/b.key" -out "$DIR/b.crt" -days 2 \
    -subj "/CN=beta.sni.test" \
    -addext "subjectAltName=DNS:beta.sni.test,DNS:*.beta.sni.test,DNS:alpha.sni.test" 2>/dev/null
  cat "$DIR/a.crt" "$DIR/b.crt" >"$DIR/ca.pem"

  cat >"$DIR/stream_server.py" <<'PY'
import socket, ssl, sys, threading

mode, port_s, tag = sys.argv[1], sys.argv[2], sys.argv[3]
cert = sys.argv[4] if len(sys.argv) > 4 else None
key = sys.argv[5] if len(sys.argv) > 5 else None
ctx = None
if mode == "tls":
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)

def serve_plain(conn):
    try:
        chunks = []
        while True:
            data = conn.recv(4096)
            if not data:
                break
            if not chunks and data.startswith(b"INTERACTIVE:"):
                conn.sendall(b"ACK:" + data)
                continue
            chunks.append(data)
        if chunks:
            conn.sendall(b"PLAIN:" + b"".join(chunks))
        try:
            conn.shutdown(socket.SHUT_WR)
        except OSError:
            pass
    finally:
        conn.close()

def serve_tls(conn):
    tls_conn = None
    try:
        tls_conn = ctx.wrap_socket(conn, server_side=True)
        data = tls_conn.recv(4096)
        tls_conn.sendall(tag.encode() + b":" + data + b"\n")
    except Exception:
        pass
    finally:
        try:
            (tls_conn or conn).close()
        except Exception:
            pass

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", int(port_s)))
srv.listen(64)
while True:
    conn, _ = srv.accept()
    fn = serve_tls if mode == "tls" else serve_plain
    threading.Thread(target=fn, args=(conn,), daemon=True).start()
PY

  cat >"$DIR/stream_client.py" <<'PY'
import socket, ssl, sys

mode = sys.argv[1]
port = int(sys.argv[2])
if mode == "tcp":
    msg = sys.argv[3].encode()
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(msg)
        s.shutdown(socket.SHUT_WR)
        out = bytearray()
        while True:
            buf = s.recv(4096)
            if not buf:
                break
            out.extend(buf)
    print(out.decode(), end="")
elif mode == "tls":
    sni, ca, msg = sys.argv[3], sys.argv[4], sys.argv[5].encode()
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        with ctx.wrap_socket(raw, server_hostname=sni) as tls:
            cert = tls.getpeercert()
            cn = ""
            for rdn in cert.get("subject", ()):
                for k, v in rdn:
                    if k == "commonName":
                        cn = v
            tls.sendall(msg)
            out = bytearray()
            while True:
                buf = tls.recv(4096)
                if not buf:
                    break
                out.extend(buf)
                if out.endswith(b"\n"):
                    break
    print(f"cn={cn} {out.decode().strip()}", end="")
elif mode == "interactive":
    with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
        s.sendall(b"INTERACTIVE:hi\n")
        out = bytearray()
        while True:
            buf = s.recv(4096)
            if not buf:
                break
            out.extend(buf)
            if out.endswith(b"\n"):
                break
    print(out.decode().strip(), end="")
PY

  run_bg "$DIR/tcp_up.out" python3 "$DIR/stream_server.py" plain $tcp_up PLAIN
  run_bg "$DIR/tls_a.out" python3 "$DIR/stream_server.py" tls $tls_a_up ALPHA_TLS "$DIR/a.crt" "$DIR/a.key"
  run_bg "$DIR/tls_b.out" python3 "$DIR/stream_server.py" tls $tls_b_up BETA_TLS "$DIR/b.crt" "$DIR/b.key"
  wait_port $tcp_up || fail "tcp backend listens on $tcp_up"
  wait_port $tls_a_up || fail "tls A backend listens on $tls_a_up"
  wait_port $tls_b_up || fail "tls B backend listens on $tls_b_up"

  basic_conf "$DIR/c"
  cat >"$DIR/c/upstreams.toml" <<EOT
[upstreams.http_up]
addrs = ["127.0.0.1:$http_up"]

[upstreams.tcp_up]
addrs = ["127.0.0.1:$tcp_up"]

[upstreams.tls_a]
addrs = ["127.0.0.1:$tls_a_up"]

[upstreams.tls_b]
addrs = ["127.0.0.1:$tls_b_up"]
EOT
  cat >"$DIR/c/locations.toml" <<'EOT'
[locations.http_root]
upstream = "http_up"
path = "/"
EOT
  cat >"$DIR/c/servers.toml" <<EOT
[servers.http]
addr = "127.0.0.1:$http_proxy"
locations = ["http_root"]
EOT
  cat >"$DIR/c/streams.toml" <<EOT
[streams.tcp_plain]
addr = "127.0.0.1:$tcp_stream"
upstream = "tcp_up"
idle_timeout = "10s"

[streams.tls_mux]
addr = "127.0.0.1:$tls_stream"
upstream = "tcp_up"
sni_routes = { "alpha.sni.test" = "tls_a", "*.beta.sni.test" = "tls_b" }
sni_read_timeout = "3s"
idle_timeout = "10s"
EOT

  pingap "$DIR/pingap.log" -c "$DIR/c" --autoreload
  local pid=$LAST_PID
  wait_port $http_proxy || fail "L7 http listens on $http_proxy"
  wait_port $tcp_stream || fail "L4 tcp_plain listens on $tcp_stream"
  wait_port $tls_stream || fail "L4 tls_mux listens on $tls_stream"

  expect "L7 HTTP proxy runs alongside L4 streams" 200 \
    "$(status "http://127.0.0.1:$http_proxy/")"
  expect "L4 plain TCP passthrough with half-close" "PLAIN:ping-l4" \
    "$(python3 "$DIR/stream_client.py" tcp $tcp_stream ping-l4)"
  expect "L4 small interactive frame flushes without EOF" "ACK:INTERACTIVE:hi" \
    "$(python3 "$DIR/stream_client.py" interactive $tcp_stream)"
  expect "L4 TLS SNI exact match passthrough" "cn=alpha.sni.test ALPHA_TLS:hello-a" \
    "$(python3 "$DIR/stream_client.py" tls $tls_stream alpha.sni.test "$DIR/ca.pem" hello-a)"
  expect "L4 TLS SNI wildcard passthrough" "cn=beta.sni.test BETA_TLS:hello-b" \
    "$(python3 "$DIR/stream_client.py" tls $tls_stream app.beta.sni.test "$DIR/ca.pem" hello-b)"
  expect "L4 non-TLS fallback on SNI listener" "PLAIN:raw-fallback" \
    "$(python3 "$DIR/stream_client.py" tcp $tls_stream raw-fallback)"

  # Live hot reload of SNI routing table without process restart
  cat >"$DIR/streams.next" <<EOT
[streams.tcp_plain]
addr = "127.0.0.1:$tcp_stream"
upstream = "tcp_up"
idle_timeout = "10s"

[streams.tls_mux]
addr = "127.0.0.1:$tls_stream"
upstream = "tcp_up"
sni_routes = { "alpha.sni.test" = "tls_b", "*.beta.sni.test" = "tls_b" }
sni_read_timeout = "3s"
idle_timeout = "10s"
EOT
  mv -f "$DIR/streams.next" "$DIR/c/streams.toml"
  wait_for 15 sh -c "[ \"\$(python3 '$DIR/stream_client.py' tls $tls_stream alpha.sni.test '$DIR/ca.pem' after)\" = 'cn=beta.sni.test BETA_TLS:after' ]"
  expect "L4 SNI route hot-reloaded" "cn=beta.sni.test BETA_TLS:after" \
    "$(python3 "$DIR/stream_client.py" tls $tls_stream alpha.sni.test "$DIR/ca.pem" after)"
  expect "hot reload kept same process" yes "$(alive "$pid" && echo yes || echo no)"

  # Listener addr change under --autoreload logs left_for_restart and keeps old socket
  cat >"$DIR/streams.next" <<EOT
[streams.tcp_plain]
addr = "127.0.0.1:$moved_stream"
upstream = "tcp_up"
idle_timeout = "10s"

[streams.tls_mux]
addr = "127.0.0.1:$tls_stream"
upstream = "tcp_up"
sni_routes = { "alpha.sni.test" = "tls_b", "*.beta.sni.test" = "tls_b" }
sni_read_timeout = "3s"
idle_timeout = "10s"
EOT
  mv -f "$DIR/streams.next" "$DIR/c/streams.toml"
  wait_for 10 sh -c "plain() { sed \$'s/\\x1b\\[[0-9;]*m//g'; }; plain <'$DIR/pingap.log' | grep -q 'takes a restart to apply.*127.0.0.1:$moved_stream'"
  expect_match "stream addr change reports restart required" \
    "takes a restart to apply.*127.0.0.1:$moved_stream" \
    "$(plain <"$DIR/pingap.log" | grep 'takes a restart to apply')"
  expect "old L4 socket keeps serving" "PLAIN:still-up" \
    "$(python3 "$DIR/stream_client.py" tcp $tcp_stream still-up)"
  expect "moved L4 port is not bound before restart" 000 \
    "$(status "http://127.0.0.1:$moved_stream/")"
}

# ---------------------------------------------------------------------------
main() {
  local name before
  for name in $CASES; do
    if [ -n "${E2E_ONLY:-}" ] && ! printf ' %s ' "$E2E_ONLY" | grep -q " $name "; then
      continue
    fi
    CASE=$name
    DIR=$WORK/$name
    mkdir -p "$DIR"
    PIDS=()
    LOGS=()
    before=$FAILED
    CASE_FAILED_BEFORE=$FAILED
    if ! declare -F "case_$name" >/dev/null; then
      continue
    fi
    "case_$name"
    if [ "$FAILED" -gt "$before" ]; then
      for log in "${LOGS[@]:-}"; do
        [ -s "$log" ] || continue
        echo "---- the end of $log"
        plain <"$log" | tail -40
      done
    fi
    for pid in "${PIDS[@]:-}"; do stop "$pid"; done
    [ -f "$DIR/pingap.pid" ] && kill -9 "$(cat "$DIR/pingap.pid")" 2>/dev/null
  done
  echo
  echo "$PASSED passed, $FAILED failed, $SKIPPED skipped"
  exit "$FAILED"
}

main
