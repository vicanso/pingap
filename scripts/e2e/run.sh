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
# Needs bash, curl, python3 and openssl. nginx is used where it is
# installed, as a backend that reads the PROXY protocol. The cases that
# hand listening sockets from one process to the next (`restart`,
# `upgrade`) run on Linux only: pingora does not do it anywhere else.
#
# Every check prints one line, `ok` or `FAIL`; the exit status is the
# number of checks that failed. A case that fails prints the end of the
# logs of the processes it ran.
set -u

CASES="samples proxy reload proxy_protocol daemon restart upgrade"

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
  for pid in "${PIDS[@]:-}"; do stop "$pid"; done
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
}

# ---------------------------------------------------------------------------
# reload: with --autoreload a change of the configuration is applied by
# the process that runs, and one that is no configuration is left out.
case_reload() {
  local proxy=$((PORT_BASE + 20)) up1=$((PORT_BASE + 21)) up2=$((PORT_BASE + 22))
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

  # A change that is no configuration: what runs stays as it is.
  printf '\n[locations.three]\nupstream = "nowhere"\nhost = "three.test"\npath = "/"\n' >>"$DIR/c/locations.toml"
  sleep 4
  expect "a location of an upstream there is none of: one.test is still served" 200 \
    "$(status -H 'Host: one.test' "http://127.0.0.1:$proxy/")"
  expect "and the process is still there" yes "$(alive "$pid" && echo yes || echo no)"
  expect_match "and the log says why" 'nowhere' "$(plain <"$DIR/pingap.log" | grep -i 'error\|invalid\|fail' | tail -5)"
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
  sleep 0.5
  kill -TERM "$pid"
  sleep 1
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
  expect "no request failed during the hand-over ($HAMMERED made)" 0 "$HAMMER_FAILED"
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
  expect "no request failed during that hand-over either ($HAMMERED made)" 0 "$HAMMER_FAILED"
  expect "one process is left" 1 "$(pgrep -f "$DIR/c" | wc -l | tr -d ' ')"
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
  # It waits for the sockets for a few seconds: the first is told now.
  sleep 1
  new=$(daemon_pid)
  expect "the pid file names the second process" yes \
    "$([ -n "$new" ] && [ "$new" != "$first" ] && alive "$new" && echo yes || echo no)"
  kill -QUIT "$first"
  wait_for 30 gone "$first"
  expect "the first has ended" yes "$(gone "$first" && echo yes || echo no)"
  expect "and the second serves" "$new" "$(serving_pid $admin)"
  sleep 1
  hammer_stop
  expect "no request failed during the upgrade ($HAMMERED made)" 0 "$HAMMER_FAILED"
  expect "a request through the second process" 200 "$(status "http://127.0.0.1:$proxy/")"
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
