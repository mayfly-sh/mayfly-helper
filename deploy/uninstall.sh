#!/usr/bin/env bash
#
# uninstall.sh — remove the mayfly-helper deployment artifacts. By default it
# PRESERVES the capability token and the SSH trust files so a re-install does not
# disrupt existing certificate logins. Uninstall the agent FIRST.
#
# Usage:
#   sudo ./uninstall.sh             # remove helper service/binary, keep token + SSH trust
#   sudo ./uninstall.sh --purge     # ALSO remove the drop-in, token, and SSH CA dir
set -euo pipefail

# Note: the shared mayfly user/group are owned by the agent installer and are
# only removed by the agent's `uninstall.sh --purge`.
readonly HELPER_BIN_DEST="${MAYFLY_HELPER_BIN_DEST:-/usr/local/sbin/mayfly-helper}"
readonly CONFIG_DIR="/etc/mayfly-agent"
readonly TOKEN_FILE="$CONFIG_DIR/helper.token"
readonly ENV_FILE="$CONFIG_DIR/helper.env"
readonly SSH_CA_DIR="/etc/ssh/mayfly"
readonly DROPIN_FILE="/etc/ssh/sshd_config.d/90-mayfly.conf"
readonly UNIT_DIR="/etc/systemd/system"

PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

log() { printf '[uninstall-helper] %s\n' "$*" >&2; }
die() { printf '[uninstall-helper] ERROR: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root"

stop_service() {
  if systemctl list-unit-files mayfly-helper.service >/dev/null 2>&1; then
    log "stopping and disabling mayfly-helper.service"
    systemctl disable --now mayfly-helper.service 2>/dev/null || true
  fi
}

remove_unit() {
  rm -f "$UNIT_DIR/mayfly-helper.service"
  systemctl daemon-reload
}

remove_binary() {
  rm -f "$HELPER_BIN_DEST"
}

purge_ssh() {
  # Removing the drop-in stops new cert logins via the Mayfly CA; reload sshd so
  # the change takes effect. We never touch the main sshd_config.
  if [ -f "$DROPIN_FILE" ]; then
    log "removing sshd drop-in and reloading sshd"
    rm -f "$DROPIN_FILE"
    if command -v sshd >/dev/null 2>&1 && sshd -t 2>/dev/null; then
      systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
    fi
  fi
  rm -f "$TOKEN_FILE"
  rm -f "$ENV_FILE"
  rm -rf "$SSH_CA_DIR"
}

main() {
  stop_service
  remove_unit
  remove_binary
  if [ "$PURGE" -eq 1 ]; then
    purge_ssh
  else
    log "preserving capability token and SSH trust files (use --purge to remove)"
  fi
  log "helper uninstall complete"
}

main "$@"
