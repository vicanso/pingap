#!/usr/bin/env bash
# Assemble the bilingual GitHub Pages site under website/{en,zh}/.
# English: crate READMEs + pingap-plugin docs + docs/ + examples/
# Chinese: docs/zh/** (maintained translations)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SITE="${ROOT}/website"
EN="${SITE}/en"
ZH="${SITE}/zh"

CRATES=(
  util core config discovery health upstream location
  certificate acme cache plugin imageoptim logger
  performance otel sentry pyroscope webhook proxy
)

# --- link rewriting ----------------------------------------------------------

rewrite_links() {
  local file="$1"
  local kind="$2" # plugin | crate | guide | root

  local tmp
  tmp="$(mktemp)"

  sed -E \
    -e 's|\(\.\./\.\./pingap-plugin/docs/([a-z0-9_]+)\.md\)|(../plugins/\1.md)|g' \
    -e 's|\(\.\./pingap-plugin/docs/([a-z0-9_]+)\.md\)|(../plugins/\1.md)|g' \
    -e 's|\(docs/([a-z0-9_]+)\.md\)|(../plugins/\1.md)|g' \
    -e 's|\(\.\./\.\./pingap-cache/README\.md\)|(../crates/cache.md)|g' \
    -e 's|\(\.\./pingap-cache/README\.md\)|(../crates/cache.md)|g' \
    -e 's|\(\.\./\.\./pingap-plugin/README\.md[^)]*\)|(../plugins/)|g' \
    -e 's|\(\.\./pingap-plugin/README\.md[^)]*\)|(../plugins/)|g' \
    -e 's|\(\.\./pingap-config/README\.md\)|(../crates/config.md)|g' \
    -e 's|\(\.\./pingap-core/README\.md\)|(../crates/core.md)|g' \
    -e 's|\(\.\./pingap-upstream/README\.md\)|(../crates/upstream.md)|g' \
    -e 's|\(\.\./pingap-health/README\.md\)|(../crates/health.md)|g' \
    -e 's|\(\.\./pingap-discovery/README\.md\)|(../crates/discovery.md)|g' \
    -e 's|\(\.\./pingap-location/README\.md\)|(../crates/location.md)|g' \
    -e 's|\(\.\./pingap-certificate/README\.md\)|(../crates/certificate.md)|g' \
    -e 's|\(\.\./pingap-acme/README\.md\)|(../crates/acme.md)|g' \
    -e 's|\(\.\./pingap-logger/README\.md\)|(../crates/logger.md)|g' \
    -e 's|\(\.\./pingap-performance/README\.md\)|(../crates/performance.md)|g' \
    -e 's|\(\.\./pingap-otel/README\.md\)|(../crates/otel.md)|g' \
    -e 's|\(\.\./pingap-sentry/README\.md\)|(../crates/sentry.md)|g' \
    -e 's|\(\.\./pingap-pyroscope/README\.md\)|(../crates/pyroscope.md)|g' \
    -e 's|\(\.\./pingap-webhook/README\.md\)|(../crates/webhook.md)|g' \
    -e 's|\(\.\./pingap-proxy/README\.md\)|(../crates/proxy.md)|g' \
    -e 's|\(\.\./pingap-util/README\.md\)|(../crates/util.md)|g' \
    -e 's|\(\.\./pingap-imageoptim/README\.md\)|(../crates/imageoptim.md)|g' \
    -e 's|\(\.\./\.\./pingap-imageoptim/README\.md\)|(../crates/imageoptim.md)|g' \
    -e 's|\(\.\./docs/README\.md\)|(guide/modules.md)|g' \
    -e 's|\(\./docs/README\.md\)|(guide/modules.md)|g' \
    -e 's|\(\.\./examples/README\.md\)|(guide/examples.md)|g' \
    -e 's|\(\./examples/README\.md\)|(guide/examples.md)|g' \
    -e 's|\(\.\./README\.md\)|(/)|g' \
    -e 's|\(\./README_zh\.md\)|(../zh/)|g' \
    -e 's|\(\./asset/pingap-logo\.png\)|(../assets/logo.png)|g' \
    -e 's|\(\.\./asset/pingap-logo\.png\)|(../assets/logo.png)|g' \
    -e 's|\(assets/logo\.png\)|(../assets/logo.png)|g' \
    "$file" >"$tmp"

  if [[ "$kind" == "plugin" ]]; then
    sed -E \
      -e 's|\(\.\./\.\./pingap-([a-z0-9-]+)/README\.md\)|(../crates/\1.md)|g' \
      "$tmp" >"${tmp}.2" && mv "${tmp}.2" "$tmp"
  fi

  if [[ "$kind" == "crate" ]]; then
    sed -E \
      -e 's|\(\.\./pingap-([a-z0-9-]+)/README\.md\)|(./\1.md)|g' \
      -e 's|\(\.\./pingap-plugin/docs/([a-z0-9_]+)\.md\)|(../plugins/\1.md)|g' \
      "$tmp" >"${tmp}.2" && mv "${tmp}.2" "$tmp"
  fi

  mv "$tmp" "$file"
}

append_source_footer() {
  local file="$1"
  local label="$2"
  local url="$3"
  {
    echo ""
    echo "---"
    echo ""
    echo "*Source: [\`${label}\`](${url})*"
  } >>"$file"
}

# --- English assembly --------------------------------------------------------

build_en() {
  echo "Building English site → ${EN}"
  rm -rf "${EN}/crates" "${EN}/plugins" "${EN}/guide"
  mkdir -p "${EN}/crates" "${EN}/plugins" "${EN}/guide"

  for c in "${CRATES[@]}"; do
    local src="${ROOT}/pingap-${c}/README.md"
    local dst="${EN}/crates/${c}.md"
    if [[ ! -f "$src" ]]; then
      echo "  skip missing crate: pingap-${c}" >&2
      continue
    fi
    cp "$src" "$dst"
    rewrite_links "$dst" crate
    append_source_footer "$dst" "pingap-${c}/README.md" \
      "https://github.com/vicanso/pingap/blob/main/pingap-${c}/README.md"
  done

  cp "${ROOT}/pingap-plugin/README.md" "${EN}/plugins/README.md"
  rewrite_links "${EN}/plugins/README.md" plugin
  sed -E -i.bak \
    -e 's|\[docs/([a-z0-9_]+)\.md\]\(([^)]+)\)|[\1](\2)|g' \
    -e 's|\(docs/([a-z0-9_]+)\.md\)|(./\1.md)|g' \
    -e 's|\(\.\./plugins/([a-z0-9_]+)\.md\)|(./\1.md)|g' \
    "${EN}/plugins/README.md"
  rm -f "${EN}/plugins/README.md.bak"
  append_source_footer "${EN}/plugins/README.md" "pingap-plugin/README.md" \
    "https://github.com/vicanso/pingap/blob/main/pingap-plugin/README.md"

  for src in "${ROOT}"/pingap-plugin/docs/*.md; do
    local base
    base="$(basename "$src")"
    local dst="${EN}/plugins/${base}"
    cp "$src" "$dst"
    rewrite_links "$dst" plugin
    append_source_footer "$dst" "pingap-plugin/docs/${base}" \
      "https://github.com/vicanso/pingap/blob/main/pingap-plugin/docs/${base}"
  done

  cp "${ROOT}/docs/modules.md" "${EN}/guide/modules.md"
  rewrite_links "${EN}/guide/modules.md" guide
  append_source_footer "${EN}/guide/modules.md" "docs/modules.md" \
    "https://github.com/vicanso/pingap/blob/main/docs/modules.md"

  cp "${ROOT}/docs/acme_chart.md" "${EN}/guide/acme-flow.md"
  rewrite_links "${EN}/guide/acme-flow.md" guide
  append_source_footer "${EN}/guide/acme-flow.md" "docs/acme_chart.md" \
    "https://github.com/vicanso/pingap/blob/main/docs/acme_chart.md"

  cp "${ROOT}/examples/README.md" "${EN}/guide/examples.md"
  rewrite_links "${EN}/guide/examples.md" guide
  sed -E -i.bak \
    -e 's|\(\./([a-z0-9-]+)/README\.md\)|(https://github.com/vicanso/pingap/tree/main/examples/\1)|g' \
    -e 's|\(\./([a-z0-9-]+)/([a-z0-9.-]+)\)|(https://github.com/vicanso/pingap/tree/main/examples/\1/\2)|g' \
    "${EN}/guide/examples.md"
  rm -f "${EN}/guide/examples.md.bak"
  append_source_footer "${EN}/guide/examples.md" "examples/README.md" \
    "https://github.com/vicanso/pingap/blob/main/examples/README.md"

  # crates index
  cat >"${EN}/crates/README.md" <<'EOF'
# Crates / modules

Each workspace crate has a README describing ownership, configuration and place
in the dependency graph. Content on these pages is copied from the repository
at build time.

| Crate | What it does |
| --- | --- |
| [pingap-util](util.md) | Crypto, IP rules, PEM/base64, path and formatting helpers |
| [pingap-core](core.md) | `Ctx`, `HttpResponse`, the `Plugin` trait, background services, coarse clock |
| [pingap-config](config.md) | Configuration model, storage backends, TOML/HCL/KDL |
| [pingap-discovery](discovery.md) | Static / DNS / Docker / transparent backend discovery |
| [pingap-health](health.md) | TCP, HTTP(S) and gRPC health checks |
| [pingap-upstream](upstream.md) | Load balancing, circuit breaking, upstream connection options |
| [pingap-location](location.md) | Host/path matching, rewriting, per-location limits |
| [pingap-certificate](certificate.md) | SNI-based dynamic TLS certificate store |
| [pingap-acme](acme.md) | Let's Encrypt HTTP-01 and DNS-01 automation |
| [pingap-cache](cache.md) | Memory (TinyUFO) and file cache backends |
| [pingap-plugin](plugin.md) | Built-in plugins — see the [plugin index](../plugins/) |
| [pingap-imageoptim](imageoptim.md) | PNG/JPEG → WebP/AVIF conversion |
| [pingap-logger](logger.md) | Access logs, file/syslog writers, rotation and compression |
| [pingap-performance](performance.md) | Prometheus metrics and process introspection |
| [pingap-otel](otel.md) | OpenTelemetry distributed tracing |
| [pingap-sentry](sentry.md) | Sentry error reporting |
| [pingap-pyroscope](pyroscope.md) | Continuous CPU profiling |
| [pingap-webhook](webhook.md) | Operational notifications to WeCom / DingTalk / HTTP |
| [pingap-proxy](proxy.md) | The proxy engine: lifecycle, routing, server configuration |

Also see [Architecture](../guide/modules.md).
EOF

  # home
  cat >"${EN}/README.md" <<'EOF'
# Pingap

> High-performance reverse proxy powered by [Cloudflare Pingora](https://github.com/cloudflare/pingora).

[中文文档](../zh/) · [GitHub](https://github.com/vicanso/pingap) · [Releases](https://github.com/vicanso/pingap/releases) · [pingap.io](https://pingap.io/pingap-en/)

![Pingap Logo](../assets/logo.png)

## What is this site?

This English tree is **generated from the repository**:

| Section | Source of truth |
| --- | --- |
| [Plugins](plugins/) | `pingap-plugin/README.md` + `pingap-plugin/docs/*.md` |
| [Crates](crates/) | each `pingap-*/README.md` |
| [Architecture](guide/modules.md) | `docs/modules.md` |
| [Examples](guide/examples.md) | `examples/README.md` |

Chinese translations live under [`docs/zh/`](https://github.com/vicanso/pingap/tree/main/docs/zh) and are published at [../zh/](../zh/).

## Key features

- **High performance** — Rust + Pingora; HTTP/1.1, HTTP/2, gRPC-Web
- **Hot reload** — zero-downtime config changes (`--autoreload` / `--autorestart`)
- **Web admin** — manage servers, locations, upstreams and plugins in the UI
- **Plugins** — auth, access control, rate limit, cache, CORS, static files, and more
- **Discovery** — static list, DNS, Docker labels, transparent proxy
- **ACME** — Let's Encrypt HTTP-01 and DNS-01 (including wildcards)
- **Observability** — Prometheus, OpenTelemetry, access logs, Pyroscope, Sentry

## Quick start (Docker)

```yaml
services:
  pingap:
    image: vicanso/pingap:latest
    container_name: pingap-instance
    restart: always
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./pingap_data:/opt/pingap
    environment:
      - PINGAP_CONF=/opt/pingap/conf
      - PINGAP_ADMIN_ADDR=0.0.0.0:80/pingap
      - PINGAP_ADMIN_USER=pingap
      - PINGAP_ADMIN_PASSWORD=<YourSecurePassword>
    command: ["pingap", "--autoreload"]
```

```bash
mkdir pingap_data
docker compose up -d
# Admin UI: http://localhost/pingap
```

### Install binary

```bash
curl -sSL https://raw.githubusercontent.com/vicanso/pingap/main/install.sh | sh
# Full build: PINGAP_FULL=1 sh
```

### One-command HTTPS proxy

```bash
pingap --domain=pingap.io --upstream=192.168.1.1:3000
```

## Architecture

```mermaid
graph TD
    acme --> certificate
    acme --> config
    acme --> core
    cache --> core
    certificate --> config
    certificate --> core
    certificate --> util
    config --> core
    config --> discovery
    config --> util
    discovery --> core
    imageoptim --> config
    imageoptim --> core
    imageoptim --> plugin
    location --> config
    location --> core
    logger --> core
    logger --> util
    performance --> cache
    performance --> core
    performance --> location
    performance --> upstream
    plugin --> cache
    plugin --> config
    plugin --> core
    plugin --> util
    proxy --> acme
    proxy --> certificate
    proxy --> config
    proxy --> core
    proxy --> location
    proxy --> logger
    proxy --> otel
    proxy --> performance
    proxy --> upstream
    proxy --> util
    upstream --> config
    upstream --> core
    upstream --> discovery
    upstream --> health
    webhook --> core
```

See [Architecture](guide/modules.md) for module descriptions.

## Plugin categories

| Category | Examples |
| --- | --- |
| Authentication | `basic_auth`, `key_auth`, `jwt`, `combined_auth`, `forward_auth`, `csrf` |
| Access control | `ip_restriction`, `referer_restriction`, `ua_restriction`, `geo_restriction` |
| Traffic control | `limit`, `traffic_splitting`, `cache` |
| Content | `compression`, `directory`, `sub_filter`, `cors`, `redirect`, `image_optim` |
| Operations | `ping`, `mock`, `request_id`, `stats`, `admin` |

Full index: **[Plugins](plugins/)**.

## Configuration sketch

```toml
[servers.main]
addr = "0.0.0.0:6188"
locations = ["api"]

[locations.api]
upstream = "api"
path = "/api"
plugins = ["compression", "jwtAuth"]

[upstreams.api]
addrs = ["10.0.0.1:8080", "10.0.0.2:8080"]
discovery = "dns"
update_frequency = "30s"

[plugins.jwtAuth]
category = "jwt"
header = "Authorization"
secret = "change-me"
algorithm = "HS256"

[plugins.compression]
category = "compression"
gzip_level = 6
br_level = 6
zstd_level = 3
```

Supports **TOML**, **HCL** and **KDL**. Details in [pingap-config](crates/config.md).

## Request lifecycle

| Step | When | Typical use |
| --- | --- | --- |
| `early_request` | After headers, before routing | Accept-Encoding, compression negotiate |
| `request` | After location match | Auth, limit, cache, static files |
| `proxy_upstream` | Before backend selection | Checks that skip cache hits |
| `upstream_response` | Upstream response headers | Header rewrite, body transform |
| `response` | Before sending to client | Response headers, sub_filter |

See [pingap-proxy](crates/proxy.md) and [Plugin lifecycle](plugins/#lifecycle-steps).

## License

Apache-2.0.
EOF

  # sidebar + navbar
  cat >"${EN}/_sidebar.md" <<'EOF'
* [Home](/)
* **Guide**
  * [Architecture](guide/modules.md)
  * [ACME flow](guide/acme-flow.md)
  * [Examples](guide/examples.md)
* **Plugins**
  * [Overview](plugins/)
  * *Authentication*
  * [basic_auth](plugins/basic_auth.md)
  * [key_auth](plugins/key_auth.md)
  * [jwt](plugins/jwt.md)
  * [combined_auth](plugins/combined_auth.md)
  * [forward_auth](plugins/forward_auth.md)
  * [csrf](plugins/csrf.md)
  * *Access control*
  * [ip_restriction](plugins/ip_restriction.md)
  * [referer_restriction](plugins/referer_restriction.md)
  * [ua_restriction](plugins/ua_restriction.md)
  * [geo_restriction](plugins/geo_restriction.md)
  * *Traffic*
  * [limit](plugins/limit.md)
  * [traffic_splitting](plugins/traffic_splitting.md)
  * [cache](plugins/cache.md)
  * *Content*
  * [compression](plugins/compression.md)
  * [accept_encoding](plugins/accept_encoding.md)
  * [directory](plugins/directory.md)
  * [sub_filter](plugins/sub_filter.md)
  * [response_headers](plugins/response_headers.md)
  * [cors](plugins/cors.md)
  * [redirect](plugins/redirect.md)
  * [image_optim](plugins/image_optim.md)
  * *Operations*
  * [ping](plugins/ping.md)
  * [mock](plugins/mock.md)
  * [request_id](plugins/request_id.md)
  * [stats](plugins/stats.md)
  * [admin](plugins/admin.md)
* **Crates**
  * [Index](crates/)
  * [proxy](crates/proxy.md)
  * [core](crates/core.md)
  * [config](crates/config.md)
  * [plugin](crates/plugin.md)
  * [upstream](crates/upstream.md)
  * [location](crates/location.md)
  * [discovery](crates/discovery.md)
  * [health](crates/health.md)
  * [certificate](crates/certificate.md)
  * [acme](crates/acme.md)
  * [cache](crates/cache.md)
  * [logger](crates/logger.md)
  * [performance](crates/performance.md)
  * [otel](crates/otel.md)
  * [webhook](crates/webhook.md)
  * [sentry](crates/sentry.md)
  * [pyroscope](crates/pyroscope.md)
  * [imageoptim](crates/imageoptim.md)
  * [util](crates/util.md)
EOF

  cat >"${EN}/_navbar.md" <<'EOF'
* [中文](../zh/)
* [GitHub](https://github.com/vicanso/pingap)
* [Releases](https://github.com/vicanso/pingap/releases)
* [Languages](../)
EOF
}

# --- Chinese assembly --------------------------------------------------------

build_zh() {
  echo "Building Chinese site → ${ZH}"
  local SRC="${ROOT}/docs/zh"
  if [[ ! -d "$SRC" ]]; then
    echo "ERROR: missing ${SRC} — Chinese docs are required." >&2
    exit 1
  fi

  rm -rf "${ZH}/crates" "${ZH}/plugins" "${ZH}/guide"
  mkdir -p "${ZH}/crates" "${ZH}/plugins" "${ZH}/guide"

  if [[ ! -f "${SRC}/README.md" ]]; then
    echo "ERROR: missing docs/zh/README.md" >&2
    exit 1
  fi
  cp "${SRC}/README.md" "${ZH}/README.md"
  # logo path for language root (../assets relative to website/zh/)
  sed -E -i.bak \
    -e 's|\(\.\./\.\./asset/pingap-logo\.png\)|(../assets/logo.png)|g' \
    -e 's|\(assets/logo\.png\)|(../assets/logo.png)|g' \
    -e 's|\(\./assets/logo\.png\)|(../assets/logo.png)|g' \
    -e 's|\(\.\./assets/logo\.png\)|(../assets/logo.png)|g' \
    "${ZH}/README.md"
  rm -f "${ZH}/README.md.bak"

  # plugins
  if [[ -d "${SRC}/plugins" ]]; then
    for src in "${SRC}/plugins"/*.md; do
      [[ -f "$src" ]] || continue
      cp "$src" "${ZH}/plugins/$(basename "$src")"
    done
  fi
  # crates
  if [[ -d "${SRC}/crates" ]]; then
    for src in "${SRC}/crates"/*.md; do
      [[ -f "$src" ]] || continue
      cp "$src" "${ZH}/crates/$(basename "$src")"
    done
  fi
  # guide
  if [[ -d "${SRC}/guide" ]]; then
    for src in "${SRC}/guide"/*.md; do
      [[ -f "$src" ]] || continue
      cp "$src" "${ZH}/guide/$(basename "$src")"
    done
  fi

  # Validate minimum coverage
  local plugin_count crate_count
  plugin_count="$(find "${ZH}/plugins" -name '*.md' 2>/dev/null | wc -l | tr -d ' ')"
  crate_count="$(find "${ZH}/crates" -name '*.md' 2>/dev/null | wc -l | tr -d ' ')"
  if [[ "$plugin_count" -lt 20 ]]; then
    echo "ERROR: expected ≥20 Chinese plugin pages, found ${plugin_count}" >&2
    exit 1
  fi
  if [[ "$crate_count" -lt 15 ]]; then
    echo "ERROR: expected ≥15 Chinese crate pages, found ${crate_count}" >&2
    exit 1
  fi

  cat >"${ZH}/_sidebar.md" <<'EOF'
* [首页](/)
* **指南**
  * [架构](guide/modules.md)
  * [ACME 流程](guide/acme-flow.md)
  * [示例](guide/examples.md)
* **插件**
  * [概览](plugins/)
  * *认证与授权*
  * [basic_auth](plugins/basic_auth.md)
  * [key_auth](plugins/key_auth.md)
  * [jwt](plugins/jwt.md)
  * [combined_auth](plugins/combined_auth.md)
  * [forward_auth](plugins/forward_auth.md)
  * [csrf](plugins/csrf.md)
  * *访问控制*
  * [ip_restriction](plugins/ip_restriction.md)
  * [referer_restriction](plugins/referer_restriction.md)
  * [ua_restriction](plugins/ua_restriction.md)
  * [geo_restriction](plugins/geo_restriction.md)
  * *流量*
  * [limit](plugins/limit.md)
  * [traffic_splitting](plugins/traffic_splitting.md)
  * [cache](plugins/cache.md)
  * *内容*
  * [compression](plugins/compression.md)
  * [accept_encoding](plugins/accept_encoding.md)
  * [directory](plugins/directory.md)
  * [sub_filter](plugins/sub_filter.md)
  * [response_headers](plugins/response_headers.md)
  * [cors](plugins/cors.md)
  * [redirect](plugins/redirect.md)
  * [image_optim](plugins/image_optim.md)
  * *运维*
  * [ping](plugins/ping.md)
  * [mock](plugins/mock.md)
  * [request_id](plugins/request_id.md)
  * [stats](plugins/stats.md)
  * [admin](plugins/admin.md)
* **组件**
  * [索引](crates/)
  * [proxy](crates/proxy.md)
  * [core](crates/core.md)
  * [config](crates/config.md)
  * [plugin](crates/plugin.md)
  * [upstream](crates/upstream.md)
  * [location](crates/location.md)
  * [discovery](crates/discovery.md)
  * [health](crates/health.md)
  * [certificate](crates/certificate.md)
  * [acme](crates/acme.md)
  * [cache](crates/cache.md)
  * [logger](crates/logger.md)
  * [performance](crates/performance.md)
  * [otel](crates/otel.md)
  * [webhook](crates/webhook.md)
  * [sentry](crates/sentry.md)
  * [pyroscope](crates/pyroscope.md)
  * [imageoptim](crates/imageoptim.md)
  * [util](crates/util.md)
EOF

  cat >"${ZH}/_navbar.md" <<'EOF'
* [English](../en/)
* [GitHub](https://github.com/vicanso/pingap)
* [Releases](https://github.com/vicanso/pingap/releases)
* [语言](../)
EOF
}

# --- main --------------------------------------------------------------------

mkdir -p "${SITE}/assets" "${EN}" "${ZH}"
if [[ ! -f "${SITE}/assets/logo.png" ]]; then
  cp "${ROOT}/asset/pingap-logo.png" "${SITE}/assets/logo.png" 2>/dev/null \
    || cp "${ROOT}/icons/pingap-256.png" "${SITE}/assets/logo.png"
fi

# Remove legacy single-tree artifacts if present
rm -rf "${SITE}/crates" "${SITE}/plugins" "${SITE}/guide"
rm -f "${SITE}/_sidebar.md" "${SITE}/_navbar.md" "${SITE}/README.md"

build_en
build_zh

echo ""
echo "Website assembled:"
echo "  EN  crates=$(find "${EN}/crates" -name '*.md' | wc -l | tr -d ' ') plugins=$(find "${EN}/plugins" -name '*.md' | wc -l | tr -d ' ') guide=$(find "${EN}/guide" -name '*.md' | wc -l | tr -d ' ')"
echo "  ZH  crates=$(find "${ZH}/crates" -name '*.md' | wc -l | tr -d ' ') plugins=$(find "${ZH}/plugins" -name '*.md' | wc -l | tr -d ' ') guide=$(find "${ZH}/guide" -name '*.md' | wc -l | tr -d ' ')"
echo "Preview: python3 -m http.server -d website 8080"
echo "  http://127.0.0.1:8080/        language picker"
echo "  http://127.0.0.1:8080/en/     English"
echo "  http://127.0.0.1:8080/zh/     中文"
