#!/bin/bash
set -euo pipefail

# Usage: upload_asset.sh <FILE> [TOKEN]
#
# Uploads FILE to the release of the current tag via the gh CLI, which is
# preinstalled on every GitHub-hosted runner.
#
# Every platform job in publish.yml runs this independently and none of them
# wait for the others, so the release is created by whichever job gets there
# first and the rest just upload to it. `--clobber` replaces an asset of the
# same name, so re-running a single job does not fail with 422.
#
# The existence check goes through the Releases API rather than
# `gh release list | grep`: list+grep has been observed to miss a published
# release on macOS runners, after which `gh release create --draft` leaves an
# empty *untagged* draft next to the real release (GitHub allows several drafts
# with the same tag_name once the tag is bound to a published release).

if [ $# -lt 1 ]; then
    echo "Usage: upload_asset.sh <FILE> [TOKEN]"
    exit 1
fi

repo="vicanso/pingap"
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

# True when any release — published or draft — already claims this tag_name.
# `gh release view` only resolves published tags, so a draft created by a peer
# job would look missing and every job would race-create another one.
release_ids="$(
    gh api --paginate "repos/${repo}/releases" \
        -q ".[] | select(.tag_name == \"${tag}\") | .id" 2>/dev/null || true
)"

if [ -z "${release_ids}" ]; then
    echo "No release for $tag; creating draft..."
    # Ignore failure if a peer job won the race, or a published release appeared
    # between the check and the create. The upload below targets the tag either
    # way, and a second draft would be worse than a failed create. A genuine
    # problem (expired token, missing scope) surfaces on the upload instead.
    gh release create "$tag" -R "$repo" --draft --title "$tag" --notes "" || true
else
    echo "Found release for $tag (id(s): $(echo "$release_ids" | tr '\n' ' '))"
fi

gh release upload "$tag" "$file_path" -R "$repo" --clobber

printf "\e[32mSuccess\e[0m\n"
