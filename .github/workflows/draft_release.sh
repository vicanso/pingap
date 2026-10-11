#!/bin/bash
set -euo pipefail

# Usage: draft_release.sh <TAG>
#
# Creates the release of TAG as a draft, with the section CHANGELOG.md has
# for that version as its notes. publish.yml runs this first: the assets
# are uploaded into the draft by the jobs that build them, and
# publish_release.sh makes it public once they are all there. A release
# that is public from the start is one `install.sh` finds no files in, for
# as long as the builds take.
#
# A release that is there already - made by hand, or by an earlier run -
# is left as it is.

if [ $# -lt 1 ]; then
    echo "Usage: draft_release.sh <TAG>"
    exit 1
fi

tag=$1
repo="${GITHUB_REPOSITORY:-vicanso/pingap}"

# Through the Releases API, which lists drafts as well: see upload_asset.sh.
release_ids="$(
    gh api --paginate "repos/${repo}/releases" \
        -q ".[] | select(.tag_name == \"${tag}\") | .id"
)"
if [ -n "${release_ids}" ]; then
    echo "A release for $tag is there already (id(s): $(echo "$release_ids" | tr '\n' ' ')), leaving it as it is"
    exit 0
fi

# From the heading of this version to the next one.
notes="$(mktemp)"
awk -v version="${tag#v}" '
    index($0, "## [" version "]") == 1 { found = 1; print; next }
    found && /^## \[/ { exit }
    found { print }
' CHANGELOG.md > "$notes"
echo "Notes from CHANGELOG.md: $(wc -l < "$notes" | tr -d ' ') lines"

# Titled like the releases before it.
flags=(--draft --verify-tag --title "version ${tag#v}")
if [ -s "$notes" ]; then
    flags+=(--notes-file "$notes")
else
    # The changelog has no section for this version (`make version` was not
    # run): the list GitHub makes of what went in, which is better than a
    # release that goes public with nothing in it. The draft can be edited
    # while it is being built.
    echo "::warning::CHANGELOG.md has no section for ${tag#v}, the notes are generated"
    flags+=(--generate-notes)
fi
# v1.2.3-rc1 and the like are not what `releases/latest` should name.
case "$tag" in
    *-*) flags+=(--prerelease) ;;
esac

gh release create "$tag" -R "$repo" "${flags[@]}"
printf "\e[32mDraft created\e[0m\n"
