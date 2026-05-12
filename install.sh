#!/usr/bin/env sh

set -eu
printf '\n'

BOLD="$(tput bold 2>/dev/null || printf '')"
GREY="$(tput setaf 0 2>/dev/null || printf '')"
GREEN="$(tput setaf 2 2>/dev/null || printf '')"
YELLOW="$(tput setaf 3 2>/dev/null || printf '')"
BLUE="$(tput setaf 4 2>/dev/null || printf '')"
RED="$(tput setaf 1 2>/dev/null || printf '')"
NO_COLOR="$(tput sgr0 2>/dev/null || printf '')"

info() {
  printf '%s\n' "${BOLD}${GREY}>${NO_COLOR} $*"
}

warn() {
  printf '%s\n' "${YELLOW}! $*${NO_COLOR}"
}

error() {
  printf '%s\n' "${RED}x $*${NO_COLOR}" >&2
}

completed() {
  printf '%s\n' "${GREEN}✓${NO_COLOR} $*"
}

has() {
  command -v "$1" 1>/dev/null 2>&1
}

REPO="vicanso/pingap"
SUPPORTED_TARGETS="Linux_x86_64 Linux_arm64 Darwin_x86_64 Darwin_arm64 Windows_x86_64"

# PINGAP_FULL=1 to install the -full variant (all features enabled)
FULL_SUFFIX=""
if [ "${PINGAP_FULL:-0}" = "1" ]; then
  FULL_SUFFIX="-full"
fi

# PINGAP_LIBC=gnu to use glibc build on Linux (default: musl, statically linked)
LINUX_LIBC="${PINGAP_LIBC:-musl}"

get_latest_release() {
  curl --silent "https://api.github.com/repos/${REPO}/releases/latest" |
    grep '"tag_name":' |
    sed -E 's/.*"([^"]+)".*/\1/'
}

detect_platform() {
  platform="$(uname -s)"
  case "${platform}" in
    Linux*) platform="Linux" ;;
    Darwin*) platform="Darwin" ;;
    MINGW*|MSYS*|CYGWIN*) platform="Windows" ;;
    *)
      error "Unsupported platform: ${platform}"
      exit 1
      ;;
  esac
  printf '%s' "${platform}"
}

detect_arch() {
  arch="$(uname -m)"
  case "${arch}" in
    x86_64|amd64) arch="x86_64" ;;
    aarch64|arm64) arch="arm64" ;;
    *)
      error "Unsupported architecture: ${arch}"
      exit 1
      ;;
  esac
  printf '%s' "${arch}"
}

# Map (platform, arch) -> archive filename + binary name inside the archive.
# Pingap release naming (see .github/workflows/publish.yml):
#   pingap-linux-musl-x86[-full].tar.gz       -> pingap-linux-musl-x86[-full]
#   pingap-linux-musl-aarch64[-full].tar.gz   -> pingap-linux-musl-aarch64[-full]
#   pingap-linux-gnu-x86[-full].tar.gz        -> pingap-linux-gnu-x86[-full]
#   pingap-linux-gnu-aarch64[-full].tar.gz    -> pingap-linux-gnu-aarch64[-full]
#   pingap-darwin-x86[-full].tar.gz           -> pingap-darwin-x86[-full]
#   pingap-darwin-aarch64[-full].tar.gz       -> pingap-darwin-aarch64[-full]
#   pingap-windows.exe.zip                    -> pingap-windows.exe
resolve_filename() {
  platform="$1"
  arch="$2"

  case "${platform}" in
    Linux)
      case "${LINUX_LIBC}" in
        musl|gnu) ;;
        *)
          error "PINGAP_LIBC must be musl or gnu (got: ${LINUX_LIBC})"
          exit 1
          ;;
      esac
      if [ "${arch}" = "x86_64" ]; then
        arch_tag="x86"
      else
        arch_tag="aarch64"
      fi
      basename="pingap-linux-${LINUX_LIBC}-${arch_tag}${FULL_SUFFIX}"
      filename="${basename}.tar.gz"
      binary_name="${basename}"
      ;;
    Darwin)
      if [ "${arch}" = "x86_64" ]; then
        arch_tag="x86"
      else
        arch_tag="aarch64"
      fi
      basename="pingap-darwin-${arch_tag}${FULL_SUFFIX}"
      filename="${basename}.tar.gz"
      binary_name="${basename}"
      ;;
    Windows)
      if [ -n "${FULL_SUFFIX}" ]; then
        warn "Windows release does not have a separate -full variant; PINGAP_FULL ignored."
      fi
      filename="pingap-windows.exe.zip"
      binary_name="pingap-windows.exe"
      ;;
  esac
}

download_and_install() {
  version="$1"
  platform="$2"
  arch="$3"

  resolve_filename "${platform}" "${arch}"

  url="https://github.com/${REPO}/releases/download/${version}/${filename}"

  info "Downloading pingap ${version}..."
  info "URL: ${url}"

  if has curl; then
    curl -sSL --fail "${url}" -o "${filename}"
  elif has wget; then
    wget -q "${url}" -O "${filename}"
  else
    error "curl or wget not found."
    exit 1
  fi

  info "Extracting ${filename}..."
  extract_dir="pingap_tmp"
  rm -rf "${extract_dir}"
  mkdir -p "${extract_dir}"

  if echo "${filename}" | grep -q '\.zip$'; then
    if ! has unzip; then error "unzip not found"; exit 1; fi
    unzip -q "${filename}" -d "${extract_dir}"
  else
    tar -xzf "${filename}" -C "${extract_dir}"
  fi

  info "Installing..."

  binary_path=$(find "${extract_dir}" -name "${binary_name}" -type f | head -n 1)

  # Fallback: if naming inside the archive ever changes, take the first regular file.
  if [ -z "${binary_path}" ]; then
    binary_path=$(find "${extract_dir}" -type f | head -n 1)
  fi

  if [ -z "${binary_path}" ]; then
    error "Binary not found in archive."
    ls -R "${extract_dir}"
    exit 1
  fi

  chmod +x "${binary_path}"

  if [ "${platform}" = "Windows" ]; then
    info "Windows detected. Please manually move ${binary_path} to a directory in your PATH."
  else
    target_bin="/usr/local/bin/pingap"
    if [ -w "$(dirname "${target_bin}")" ]; then
      mv "${binary_path}" "${target_bin}"
    elif has sudo; then
      sudo mv "${binary_path}" "${target_bin}"
    else
      error "No write permission to $(dirname "${target_bin}") and sudo not available."
      exit 1
    fi
    completed "Installed to ${target_bin}"
  fi

  rm -rf "${filename}" "${extract_dir}"
}

main() {
  platform="$(detect_platform)"
  arch="$(detect_arch)"

  info "Detected: ${platform} (${arch})"
  if [ "${platform}" = "Linux" ]; then
    info "Linux libc: ${LINUX_LIBC} (override with PINGAP_LIBC=gnu|musl)"
  fi
  if [ -n "${FULL_SUFFIX}" ]; then
    info "Variant: full (all features enabled)"
  else
    info "Variant: default (set PINGAP_FULL=1 for the full-featured build)"
  fi

  target="${platform}_${arch}"
  if ! echo "${SUPPORTED_TARGETS}" | grep -q "${target}"; then
    error "Unsupported target: ${target}"
    exit 1
  fi

  if [ "${platform}" = "Windows" ]; then
    warn "The Windows release job is currently disabled in publish.yml; the asset may not exist for the latest tag."
  fi

  version="$(get_latest_release)"
  if [ -z "${version}" ]; then
    error "Failed to fetch latest release tag from GitHub API."
    exit 1
  fi

  download_and_install "${version}" "${platform}" "${arch}"
}

main
