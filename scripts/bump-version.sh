#!/usr/bin/env bash
# Set the workspace version in the two places that have to agree.
#
# `[workspace.package].version` is what every crate inherits through
# `version.workspace = true`. `[workspace.dependencies]` then repeats a version
# requirement per member, because cargo has no way to inherit the package
# version into a dependency requirement. Bumping one and not the other builds
# fine from a path checkout - the local crate satisfies the older requirement -
# and only goes wrong once the crates are resolved from the registry, where a
# stale requirement can pull an older sibling. That is how a binary ends up
# reporting one version while the admin panel reports another.
#
# Usage:
#   scripts/bump-version.sh major|minor|patch
#   scripts/bump-version.sh 1.2.3
#   scripts/bump-version.sh --check      # verify the two places agree

set -euo pipefail

cd "$(dirname "$0")/.."
MANIFEST="Cargo.toml"

# The version inside [workspace.package], not the per-member requirements below
# it and not the root [package], which has no literal to read.
current_version() {
    awk '/^\[workspace\.package\]/{f=1;next}
         f&&/^version = /{gsub(/"/,"",$3);print $3;exit}' "$MANIFEST"
}

# Every `pingap-x = { version = "..." , path = ... }` in [workspace.dependencies].
dependency_versions() {
    grep -oE '^pingap-[a-z0-9]+ = \{ version = "[^"]+"' "$MANIFEST" |
        grep -oE '"[^"]+"' | tr -d '"' | sort -u
}

usage() {
    echo "usage: $0 major|minor|patch|<x.y.z>|--check" >&2
    exit 1
}

[ $# -eq 1 ] || usage

CURRENT="$(current_version)"
[ -n "$CURRENT" ] || { echo "cannot find version in [workspace.package]" >&2; exit 1; }

if [ "$1" = "--check" ]; then
    mismatched="$(dependency_versions | grep -vFx "$CURRENT" || true)"
    if [ -n "$mismatched" ]; then
        echo "version mismatch: [workspace.package] is $CURRENT, but" >&2
        echo "[workspace.dependencies] also declares: $(echo "$mismatched" | tr '\n' ' ')" >&2
        echo "run: make bump V=$CURRENT" >&2
        exit 1
    fi
    echo "version $CURRENT is consistent across the manifest"
    exit 0
fi

IFS=. read -r major minor patch <<<"$CURRENT"
case "$1" in
    major) NEW="$((major + 1)).0.0" ;;
    minor) NEW="$major.$((minor + 1)).0" ;;
    patch) NEW="$major.$minor.$((patch + 1))" ;;
    [0-9]*.[0-9]*.[0-9]*) NEW="$1" ;;
    *) usage ;;
esac

# perl rather than sed: BSD and GNU sed disagree about in-place editing, and
# this runs on both a maintainer's mac and CI.
perl -0pi -e "s/(\\[workspace\\.package\\]\\nversion = \")[^\"]+(\")/\${1}$NEW\${2}/" "$MANIFEST"
perl -pi -e "s/^(pingap-[a-z0-9]+ = \\{ version = \")[^\"]+(\")/\${1}$NEW\${2}/" "$MANIFEST"

updated="$(current_version)"
[ "$updated" = "$NEW" ] || { echo "failed to update [workspace.package]" >&2; exit 1; }
stale="$(dependency_versions | grep -vFx "$NEW" || true)"
[ -z "$stale" ] || { echo "failed to update dependencies: $stale" >&2; exit 1; }

# Keep Cargo.lock in step, otherwise the next cargo command rewrites it and the
# bump lands across two commits.
cargo update --workspace --quiet

count="$(grep -cE '^pingap-[a-z0-9]+ = \{ version = ' "$MANIFEST" | tr -d ' ')"
echo "$CURRENT -> $NEW"
echo "  [workspace.package] and $count dependency requirement(s) updated"
echo "next: make version   # regenerate CHANGELOG.md for v$NEW"
