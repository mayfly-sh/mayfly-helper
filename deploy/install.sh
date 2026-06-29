#!/usr/bin/env bash
#
# install.sh — install mayfly-helper, the privileged root service that performs
# OpenSSH host operations on behalf of the unprivileged mayfly-agent.
# Idempotent and safe to re-run. See README.md and docs/ADR-0008.
#
# Install ORDER matters: install the helper FIRST (it creates the mayfly
# user/group, the capability token, and the managed directories), THEN install
# mayfly-agent from its own repository.
#
# Usage:
#   sudo ./install.sh
#
# Optional env:
#   BINDIR                 directory containing the built mayfly-helper (default: script dir)
#   MAYFLY_HELPER_BIN_DEST default /usr/local/sbin/mayfly-helper
#   MAYFLY_SKIP_CHECKSUM   set to 1 to skip SHA256SUMS verification
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly BINDIR="${BINDIR:-$SCRIPT_DIR}"

readonly MAYFLY_USER="mayfly"
readonly MAYFLY_GROUP="mayfly"
readonly HELPER_BIN_DEST="${MAYFLY_HELPER_BIN_DEST:-/usr/local/sbin/mayfly-helper}"
readonly CONFIG_DIR="/etc/mayfly-agent"
readonly TOKEN_FILE="$CONFIG_DIR/helper.token"
readonly STATE_DIR="/var/lib/mayfly"
readonly SSH_CA_DIR="/etc/ssh/mayfly"
readonly DROPIN_DIR="/etc/ssh/sshd_config.d"
readonly DROPIN_FILE="$DROPIN_DIR/90-mayfly.conf"
readonly UNIT_DIR="/etc/systemd/system"

log()  { printf '[install-helper] %s\n' "$*" >&2; }
die()  { printf '[install-helper] ERROR: %s\n' "$*" >&2; exit 1; }

require_root() {
  [ "$(id -u)" -eq 0 ] || die "must run as root"
}

verify_platform() {
  [ "$(uname -s)" = "Linux" ] || die "mayfly-helper supports Linux only"
  case "$(uname -m)" in
    x86_64|aarch64|armv7l|armv6l) : ;;
    *) die "unsupported architecture: $(uname -m)" ;;
  esac
}

verify_dependencies() {
  local missing=()
  for cmd in systemctl sshd getent install id od head; do
    command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
  done
  [ "${#missing[*]}" -eq 0 ] || die "missing required commands: ${missing[*]}"
}

verify_binary_present() {
  [ -f "$BINDIR/mayfly-helper" ] || die "mayfly-helper binary not found in $BINDIR"
}

verify_checksum() {
  [ "${MAYFLY_SKIP_CHECKSUM:-0}" != "1" ] || { log "checksum verification skipped"; return; }
  if [ -f "$BINDIR/SHA256SUMS" ]; then
    command -v sha256sum >/dev/null 2>&1 || die "sha256sum required to verify SHA256SUMS"
    ( cd "$BINDIR" && sha256sum -c SHA256SUMS ) || die "checksum verification failed"
    log "checksum verification passed"
  else
    log "no SHA256SUMS found; skipping checksum verification"
  fi
}

create_user_and_group() {
  getent group "$MAYFLY_GROUP" >/dev/null 2>&1 || { log "creating group $MAYFLY_GROUP"; groupadd --system "$MAYFLY_GROUP"; }
  if ! getent passwd "$MAYFLY_USER" >/dev/null 2>&1; then
    log "creating system user $MAYFLY_USER"
    useradd --system --gid "$MAYFLY_GROUP" --home-dir "$STATE_DIR" \
            --no-create-home --shell /usr/sbin/nologin "$MAYFLY_USER"
  fi
}

create_directories() {
  install -d -o root -g "$MAYFLY_GROUP" -m 0750 "$CONFIG_DIR"
  install -d -o root -g root            -m 0755 "$SSH_CA_DIR"
  install -d -o root -g root            -m 0755 "$DROPIN_DIR"
}

install_binary() {
  log "installing mayfly-helper"
  install -o root -g root -m 0755 "$BINDIR/mayfly-helper" "$HELPER_BIN_DEST"
}

generate_token() {
  if [ ! -s "$TOKEN_FILE" ]; then
    log "generating helper capability token"
    umask 077
    # 32 random bytes, hex-encoded; root:mayfly 0640 so the agent group can read.
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$TOKEN_FILE"
  fi
  chown root:"$MAYFLY_GROUP" "$TOKEN_FILE"
  chmod 0640 "$TOKEN_FILE"
}

install_sshd_dropin() {
  log "installing sshd drop-in"
  install -o root -g root -m 0644 "$SCRIPT_DIR/sshd/90-mayfly.conf" "$DROPIN_FILE"
  if ! grep -Eqs '^\s*[Ii]nclude\s+.*sshd_config\.d' /etc/ssh/sshd_config; then
    log "WARNING: /etc/ssh/sshd_config does not Include $DROPIN_DIR/*.conf"
    log "WARNING: the drop-in will be inert until you add: Include $DROPIN_DIR/*.conf"
  fi
}

install_unit() {
  log "installing systemd unit"
  install -o root -g root -m 0644 "$SCRIPT_DIR/systemd/mayfly-helper.service" "$UNIT_DIR/mayfly-helper.service"
  systemctl daemon-reload
}

start_service() {
  log "enabling and starting mayfly-helper"
  systemctl enable --now mayfly-helper.service
}

verify_installation() {
  log "verifying installation"
  systemctl is-active --quiet mayfly-helper.service || die "mayfly-helper failed to start"
  log "mayfly-helper is active"
}

main() {
  require_root
  verify_platform
  verify_dependencies
  verify_binary_present
  verify_checksum
  create_user_and_group
  create_directories
  install_binary
  generate_token
  install_sshd_dropin
  install_unit
  start_service
  verify_installation
  log "helper installation complete; now install mayfly-agent from its repository"
}

main "$@"
