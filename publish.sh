#!/bin/bash
# Publish every pingap-* crate (then the root `pingap` package) to crates.io
# in dependency order.
#
# Why this script exists: the root package depends on
# `pingap-acme = "^0.15.0"` (etc.). `cargo publish -p pingap` rewrites path
# deps to version deps and looks them up on crates.io, so publishing the root
# before the members yields:
#   failed to select a version for the requirement `pingap-acme = "^0.15.0"`
#   candidate versions found which didn't match: 0.13.1, ...
#
# Usage:
#   ./publish.sh              # publish members + root
#   ./publish.sh --dry-run    # cargo publish --dry-run for each
#   ./publish.sh --members    # only pingap-* crates (skip root binary)
#   ./publish.sh --root       # only the root `pingap` package
#
# Requires `cargo login` beforehand. Already-published crate/version pairs are
# skipped. After each real publish the script waits until crates.io serves the
# new version (or 5 minutes) before continuing.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

VERSION="$(
  python3 - <<'PY'
import tomllib
from pathlib import Path
print(tomllib.loads(Path("Cargo.toml").read_text())["workspace"]["package"]["version"])
PY
)"

DRY_RUN=0
DO_MEMBERS=1
DO_ROOT=1
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --members) DO_ROOT=0 ;;
    --root) DO_MEMBERS=0 ;;
    -h|--help)
      sed -n '2,20p' "$0"
      exit 0
      ;;
    *)
      echo "unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

# Dependency order among workspace members. Keep in sync with the graph in
# docs/modules.md / CLAUDE.md: util -> core -> … -> proxy / imageoptim.
MEMBERS=(
  pingap-util
  pingap-core
  pingap-discovery
  pingap-config
  pingap-logger
  pingap-certificate
  pingap-cache
  pingap-location
  pingap-health
  pingap-upstream
  pingap-acme
  pingap-otel
  pingap-performance
  pingap-plugin
  pingap-pyroscope
  pingap-sentry
  pingap-webhook
  pingap-proxy
  pingap-imageoptim
)

# Prints status to stdout: present | missing | unknown
crate_version_status() {
  local crate="$1"
  local want="$2"
  local code
  code="$(
    curl -sS -o /dev/null -w '%{http_code}' -A "pingap-publish/${VERSION}" \
      "https://crates.io/api/v1/crates/${crate}/${want}" 2>/dev/null || echo "000"
  )"
  case "$code" in
    200) echo present ;;
    404) echo missing ;;
    *)
      echo "warn: crates.io lookup for ${crate}@${want} returned HTTP ${code}" >&2
      echo unknown
      ;;
  esac
}

crate_version_on_crates_io() {
  [[ "$(crate_version_status "$1" "$2")" == "present" ]]
}

wait_for_crates_io() {
  local crate="$1"
  local want="$2"
  local i
  echo "Waiting for ${crate}@${want} on crates.io..."
  for i in $(seq 1 60); do
    if crate_version_on_crates_io "$crate" "$want"; then
      echo "${crate}@${want} is available."
      return 0
    fi
    sleep 5
  done
  echo "Timed out waiting for ${crate}@${want} on crates.io" >&2
  return 1
}

# cargo exits non-zero when the version is already on the registry; detect that
# so a race with the HTTP pre-check (or a stale CDN miss) does not abort the run.
cargo_already_published() {
  local log="$1"
  grep -qiE \
    'already exists on crates\.io|already uploaded|crate version .* already' \
    "$log"
}

publish_one() {
  local crate="$1"
  local status
  local log

  status="$(crate_version_status "$crate" "$VERSION")"
  if [[ "$status" == "present" ]]; then
    echo "Skip ${crate}@${VERSION} (already on crates.io)"
    SKIPPED=$((SKIPPED + 1))
    return 0
  fi

  echo "Publishing ${crate}@${VERSION}..."
  if [[ "$DRY_RUN" -eq 1 ]]; then
    # Root `pingap` is the workspace package; members are selected with -p.
    cargo publish --registry crates-io --dry-run -p "$crate"
    PUBLISHED=$((PUBLISHED + 1))
    return 0
  fi

  log="$(mktemp)"
  # pipefail is on: capture cargo's exit via PIPESTATUS
  set +e
  cargo publish --registry crates-io -p "$crate" 2>&1 | tee "$log"
  local cargo_rc=${PIPESTATUS[0]}
  set -e

  if [[ "$cargo_rc" -eq 0 ]]; then
    rm -f "$log"
    wait_for_crates_io "$crate" "$VERSION"
    PUBLISHED=$((PUBLISHED + 1))
    return 0
  fi

  if cargo_already_published "$log"; then
    echo "Skip ${crate}@${VERSION} (cargo reports already published)"
    rm -f "$log"
    SKIPPED=$((SKIPPED + 1))
    return 0
  fi

  echo "Failed to publish ${crate}@${VERSION}" >&2
  cat "$log" >&2 || true
  rm -f "$log"
  return 1
}

echo "Workspace version: ${VERSION}"

TO_PUBLISH=()
if [[ "$DO_MEMBERS" -eq 1 ]]; then
  TO_PUBLISH+=("${MEMBERS[@]}")
fi
if [[ "$DO_ROOT" -eq 1 ]]; then
  TO_PUBLISH+=("pingap")
fi

echo "Preflight: checking crates.io for ${#TO_PUBLISH[@]} package(s) at ${VERSION}..."
ALREADY=0
PENDING=0
for crate in "${TO_PUBLISH[@]}"; do
  status="$(crate_version_status "$crate" "$VERSION")"
  case "$status" in
    present)
      echo "  present  ${crate}@${VERSION}"
      ALREADY=$((ALREADY + 1))
      ;;
    missing)
      echo "  pending  ${crate}@${VERSION}"
      PENDING=$((PENDING + 1))
      ;;
    *)
      echo "  unknown  ${crate}@${VERSION} (will try publish)"
      PENDING=$((PENDING + 1))
      ;;
  esac
done
echo "Preflight summary: ${ALREADY} already published, ${PENDING} to publish."

if [[ "$PENDING" -eq 0 ]]; then
  echo "Nothing to do — every requested package is already on crates.io at ${VERSION}."
  exit 0
fi

# Root package rust-embeds `dist/`; it is gitignored and only lands in the
# crates.io tarball via `[package].include`. Build it before any root publish
# that is still pending.
if [[ "$DO_ROOT" -eq 1 ]] && ! crate_version_on_crates_io "pingap" "$VERSION"; then
  echo "Building admin UI into dist/ (required for rust-embed)..."
  make build-web
fi

SKIPPED=0
PUBLISHED=0

if [[ "$DO_MEMBERS" -eq 1 ]]; then
  for crate in "${MEMBERS[@]}"; do
    publish_one "$crate"
  done
fi

if [[ "$DO_ROOT" -eq 1 ]]; then
  # Root binary package depends on the members above via version requirements.
  publish_one "pingap"
fi

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "Dry run finished (nothing uploaded). would-publish=${PUBLISHED} skipped=${SKIPPED}"
else
  echo "Done at ${VERSION}: published=${PUBLISHED} skipped=${SKIPPED}."
fi

