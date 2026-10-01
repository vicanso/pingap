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

crate_version_on_crates_io() {
  local crate="$1"
  local want="$2"
  curl -fsSL -A "pingap-publish/${VERSION}" \
    "https://crates.io/api/v1/crates/${crate}/${want}" >/dev/null 2>&1
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

publish_one() {
  local crate="$1"

  if crate_version_on_crates_io "$crate" "$VERSION"; then
    echo "Skip ${crate}@${VERSION} (already on crates.io)"
    return 0
  fi

  echo "Publishing ${crate}@${VERSION}..."
  if [[ "$DRY_RUN" -eq 1 ]]; then
    # Root `pingap` is the workspace package; members are selected with -p.
    cargo publish --registry crates-io --dry-run -p "$crate"
    return 0
  fi

  cargo publish --registry crates-io -p "$crate"
  wait_for_crates_io "$crate" "$VERSION"
}

echo "Workspace version: ${VERSION}"

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
  echo "Dry run finished (nothing uploaded)."
else
  echo "All requested packages published at ${VERSION}."
fi
