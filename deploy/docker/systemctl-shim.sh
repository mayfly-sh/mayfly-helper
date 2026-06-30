#!/usr/bin/env bash
#
# systemctl-shim.sh — a minimal `systemctl` stand-in for containers without a
# real init system. The helper's SshdControl only ever calls `reload <svc>` and
# `is-active <svc>`; this maps those to direct sshd signals/checks so the full
# safe-reload workflow can run in a plain (non-systemd) container during e2e.
#
# Point the helper at it with MAYFLY_HELPER_SYSTEMCTL_BINARY=/usr/local/bin/systemctl-shim.sh
set -euo pipefail

action="${1:-}"

# Test-only fault injection (milestone 010D): when this sentinel exists, every
# `reload` fails WITHOUT signalling sshd, so the helper's safe-reload path takes
# its rollback branch deterministically. Production never creates this file; the
# integration provisioner writes it only when MAYFLY_INJECT_RELOAD_FAIL=1.
RELOAD_FAIL_SENTINEL="${MAYFLY_INJECT_RELOAD_FAIL_SENTINEL:-/run/mayfly/inject/reload-fail}"

sshd_pid() { pgrep -x sshd | head -n1; }

case "$action" in
  reload)
    if [ -e "$RELOAD_FAIL_SENTINEL" ]; then
      echo "systemctl-shim: reload failure injected (sentinel present)" >&2
      exit 1
    fi
    pid="$(sshd_pid || true)"
    [ -n "$pid" ] || { echo "sshd not running" >&2; exit 1; }
    kill -HUP "$pid"
    ;;
  is-active)
    if sshd_pid >/dev/null; then echo active; else echo inactive; exit 3; fi
    ;;
  *)
    echo "systemctl-shim: unsupported action: $action" >&2
    exit 64
    ;;
esac
