#!/bin/bash
set -euo pipefail

# Usage: publish_release.sh <TAG>
#
# Makes the draft release of TAG public, once every archive `install.sh`
# may ask for is in it. Run by publish.yml after all the jobs that upload
# have succeeded; a name that is missing all the same fails this job, and
# the release stays a draft nobody is pointed at.
#
# A release that is public already (it was made by hand) is left alone.

if [ $# -lt 1 ]; then
    echo "Usage: publish_release.sh <TAG>"
    exit 1
fi

tag=$1
repo="${GITHUB_REPOSITORY:-vicanso/pingap}"

# One archive per name: every build of every platform a release has.
expected="
pingap-darwin-aarch64 pingap-darwin-aarch64-full
pingap-darwin-x86 pingap-darwin-x86-full
pingap-linux-musl-x86 pingap-linux-musl-x86-full pingap-linux-musl-x86-rustls-full
pingap-linux-musl-aarch64 pingap-linux-musl-aarch64-full pingap-linux-musl-aarch64-rustls-full
pingap-linux-gnu-x86 pingap-linux-gnu-x86-full pingap-linux-gnu-x86-rustls-full
pingap-linux-gnu-aarch64 pingap-linux-gnu-aarch64-full pingap-linux-gnu-aarch64-rustls-full
"

# id, whether it is a draft, and the names of its assets. Through the
# Releases API, which lists drafts as well.
releases="$(
    gh api --paginate "repos/${repo}/releases" \
        -q ".[] | select(.tag_name == \"${tag}\") | [.id, .draft, ([.assets[].name] | join(\" \"))] | @tsv"
)"
count="$(printf '%s' "$releases" | grep -c . || true)"
if [ "$count" = 0 ]; then
    echo "::error::there is no release for $tag"
    exit 1
fi
if [ "$count" != 1 ]; then
    echo "::error::there are $count releases for $tag: remove the drafts that are not the one"
    exit 1
fi
IFS=$'\t' read -r id draft assets <<< "$releases"

missing=""
for name in $expected; do
    case " $assets " in
        *" $name.tar.gz "*) ;;
        *) missing="$missing $name.tar.gz" ;;
    esac
done
if [ -n "$missing" ]; then
    echo "::error::not publishing $tag, it has no:$missing"
    exit 1
fi
echo "All $(echo "$expected" | wc -w | tr -d ' ') archives of $tag are there"

if [ "$draft" != "true" ]; then
    echo "The release of $tag is public already"
    exit 0
fi
# `legacy`: the latest release is the one with the highest version, as it
# is for a release made on the page. Left to its default it would be this
# one whatever its version, a fix for an older line included, and the
# latest release is what `install.sh` installs.
gh api -X PATCH "repos/${repo}/releases/${id}" \
    -F draft=false -f make_latest=legacy -q '.html_url'
printf "\e[32mPublished\e[0m\n"
