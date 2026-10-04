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

# PINGAP_TLS=rustls to install the rustls TLS backend build. Linux only, and
# only published with the full feature set, so it implies PINGAP_FULL=1.
TLS_BACKEND="${PINGAP_TLS:-openssl}"
case "${TLS_BACKEND}" in
  openssl|rustls) ;;
  *)
    error "PINGAP_TLS must be openssl or rustls (got: ${TLS_BACKEND})"
    exit 1
    ;;
esac
if [ "${TLS_BACKEND}" = "rustls" ]; then
  FULL_SUFFIX="-rustls-full"
fi

# PINGAP_SERVICE=1 to also install a systemd service. Linux with systemd only.
INSTALL_SERVICE="${PINGAP_SERVICE:-0}"

TARGET_BIN="/usr/local/bin/pingap"
SERVICE_UNIT="/etc/systemd/system/pingap.service"
SERVICE_CONF_DIR="/etc/pingap/conf"

# Downloads $1 to the file $2.
fetch() {
  if has curl; then
    curl -sSL --fail "$1" -o "$2"
  elif has wget; then
    wget -q "$1" -O "$2"
  else
    error "curl or wget not found."
    exit 1
  fi
}

# Runs a command as root: as it is when already root, through sudo otherwise.
as_root() {
  if [ "$(id -u)" = "0" ]; then
    "$@"
  elif has sudo; then
    sudo "$@"
  else
    error "Root permission is required (run as root or install sudo): $*"
    return 1
  fi
}

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
#   pingap-linux-{musl,gnu}-{x86,aarch64}-rustls-full.tar.gz (PINGAP_TLS=rustls)
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
      if [ "${TLS_BACKEND}" = "rustls" ]; then
        error "PINGAP_TLS=rustls is only published for Linux."
        exit 1
      fi
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
      if [ "${TLS_BACKEND}" = "rustls" ]; then
        error "PINGAP_TLS=rustls is only published for Linux."
        exit 1
      fi
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

  fetch "${url}" "${filename}"

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
    if [ -w "$(dirname "${TARGET_BIN}")" ]; then
      mv "${binary_path}" "${TARGET_BIN}"
    elif has sudo; then
      sudo mv "${binary_path}" "${TARGET_BIN}"
    else
      error "No write permission to $(dirname "${TARGET_BIN}") and sudo not available."
      exit 1
    fi
    completed "Installed to ${TARGET_BIN}"
  fi

  rm -rf "${filename}" "${extract_dir}"
}

# Installs the systemd unit from the repository, pointed at the binary this
# script installed, and the config directory the unit reads. Like the .deb it
# neither enables nor starts the service: the shipped configuration defines no
# server, so starting it would only produce a failed unit.
install_service() {
  version="$1"
  platform="$2"

  if [ "${platform}" != "Linux" ]; then
    warn "PINGAP_SERVICE needs Linux with systemd; service not installed."
    return 0
  fi
  if ! has systemctl || [ ! -d /run/systemd/system ]; then
    warn "systemd is not running here; service not installed."
    return 0
  fi

  info "Installing systemd service..."
  service_tmp="pingap_service_tmp"
  rm -rf "${service_tmp}"
  mkdir -p "${service_tmp}"

  # The unit comes from main, like this script, so the two always match; the
  # configuration comes from the release, like the binary.
  unit_url="https://raw.githubusercontent.com/${REPO}/main/pingap.service"
  conf_url="https://raw.githubusercontent.com/${REPO}/${version}/conf/basic.toml"

  if ! fetch "${unit_url}" "${service_tmp}/pingap.service.in"; then
    error "Failed to download ${unit_url}"
    rm -rf "${service_tmp}"
    exit 1
  fi
  # The unit is written for the .deb, which installs the binary to /usr/sbin.
  sed "s|/usr/sbin/pingap|${TARGET_BIN}|g" \
    "${service_tmp}/pingap.service.in" > "${service_tmp}/pingap.service"
  if ! grep -q "^ExecStart=${TARGET_BIN} " "${service_tmp}/pingap.service"; then
    error "Unexpected content in ${unit_url}; service not installed."
    rm -rf "${service_tmp}"
    exit 1
  fi

  as_root mkdir -p "$(dirname "${SERVICE_UNIT}")" "${SERVICE_CONF_DIR}"
  as_root cp "${service_tmp}/pingap.service" "${SERVICE_UNIT}"
  as_root chmod 644 "${SERVICE_UNIT}"
  completed "Installed ${SERVICE_UNIT}"

  # A config directory with anything in it is the user's: leave it alone.
  if [ -n "$(ls -A "${SERVICE_CONF_DIR}" 2>/dev/null)" ]; then
    info "Keeping the existing configuration in ${SERVICE_CONF_DIR}"
  elif fetch "${conf_url}" "${service_tmp}/basic.toml"; then
    as_root cp "${service_tmp}/basic.toml" "${SERVICE_CONF_DIR}/basic.toml"
    as_root chmod 644 "${SERVICE_CONF_DIR}/basic.toml"
    completed "Created ${SERVICE_CONF_DIR}/basic.toml"
  else
    warn "Failed to download ${conf_url}; create your configuration in ${SERVICE_CONF_DIR}."
  fi
  rm -rf "${service_tmp}"

  as_root systemctl daemon-reload

  if systemctl is-active --quiet pingap 2>/dev/null; then
    info "pingap is running. Use the new version with: sudo systemctl restart pingap"
  else
    info "Add your servers to ${SERVICE_CONF_DIR}, then run: sudo systemctl enable --now pingap"
  fi
}

main() {
  platform="$(detect_platform)"
  arch="$(detect_arch)"

  info "Detected: ${platform} (${arch})"
  if [ "${platform}" = "Linux" ]; then
    info "Linux libc: ${LINUX_LIBC} (override with PINGAP_LIBC=gnu|musl)"
  fi
  if [ "${TLS_BACKEND}" = "rustls" ]; then
    info "Variant: rustls-full (rustls TLS backend, all features enabled)"
  elif [ -n "${FULL_SUFFIX}" ]; then
    info "Variant: full (all features enabled)"
  else
    info "Variant: default (set PINGAP_FULL=1 for the full-featured build)"
  fi
  if [ "${INSTALL_SERVICE}" = "1" ]; then
    info "Service: systemd unit requested (PINGAP_SERVICE=1)"
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

  if [ "${INSTALL_SERVICE}" = "1" ]; then
    install_service "${version}" "${platform}"
  fi
}

main
