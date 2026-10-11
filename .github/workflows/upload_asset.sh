#!/bin/bash
set -euo pipefail

# Usage: upload_asset.sh <FILE> [TOKEN]
#
# Uploads FILE to the release of the current tag via the gh CLI, which is
# preinstalled on every GitHub-hosted runner.
#
# The release is there before any job that uploads runs: the `draft` job of
# publish.yml makes it (draft_release.sh), as a draft, and every job that
# uploads needs that one. This script makes none. It used to, whenever it
# found none - which it also did when the lookup itself had failed, and
# that left a second draft under the same tag, with a part of the assets
# in each.
#
# `gh release upload` finds a draft by its tag. `--clobber` replaces an
# asset of the same name, so re-running a single job does not fail with 422.

if [ $# -lt 1 ]; then
    echo "Usage: upload_asset.sh <FILE> [TOKEN]"
    exit 1
fi

repo="${GITHUB_REPOSITORY:-vicanso/pingap}"
file_path=$1

# gh reads GH_TOKEN / GITHUB_TOKEN from the environment; the second argument is
# kept so the existing publish.yml callers keep working unchanged.
if [ -n "${2:-}" ]; then
    export GH_TOKEN="$2"
fi

tag="$(git describe --tags --abbrev=0 || true)"
if [ -z "$tag" ]; then
    printf "\e[31mError: Unable to find git tag\e[0m\n"
    exit 1
fi
echo "Uploading $file_path to $repo@$tag"

gh release upload "$tag" "$file_path" -R "$repo" --clobber

printf "\e[32mSuccess\e[0m\n"
