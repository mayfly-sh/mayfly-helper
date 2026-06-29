# ADR-0008: Privilege separation via a root helper with an authenticated UDS

> Note: this ADR originated in the `mayfly-agent` engineering history (milestone 007a), where the
> helper first shipped as a second binary in the agent crate. As of milestone 008 (ADR-0009) the
> helper lives in **this** repository. The design below is unchanged; only the packaging moved.

- **Status:** Accepted
- **Date:** 2026-06-29
- **Affects:** mayfly-helper (was: mayfly-agent)

## Context
The agent must replace `/etc/ssh/mayfly/trusted_user_ca_keys`, manage an `sshd` drop-in, validate
`sshd` config (`sshd -t`), and reload `sshd` — all root-only operations. Running the *entire* agent
(networking, JSON parsing, HTTP client, untrusted server responses) as root makes a remote-leaning
process the holder of the most dangerous capability on the host (granting SSH access). We want the
network-facing logic to be **unprivileged** and the privileged surface to be **tiny, explicit, and
auditable**.

Two constraints pull against a naive design:
1. The project's hard rule is **"no shell-outs"** (written to keep crypto pure-Rust and avoid `sh`).
2. There is **no pure-Rust way** to validate or reload `sshd`; it inherently requires executing
   `sshd -t` and a service-manager reload.

## Decision
Split into two cooperating programs:
- **`mayfly-agent`** — runs as the unprivileged `mayfly` user. Does enrollment, heartbeat, CA
  synchronisation, scheduling, networking, persistence. **Holds no root capability.**
- **`mayfly-helper`** — runs as root. Listens on a Unix Domain Socket and performs **only** a fixed
  allow-list of operations: ensure directories, install/refresh the sshd drop-in, apply
  `TrustedUserCAKeys` (atomic write + `sshd -t` + reload + verify + rollback), and verify state.

**IPC authentication (defence in depth):**
1. **OS perms** — socket at `/run/mayfly/helper.sock`, mode `0660`, owner `root:mayfly`; only root and
   the `mayfly` group may connect.
2. **Capability token** — a 32-byte random secret (`/etc/mayfly-agent/helper.token`, `0640`
   root:mayfly) included in every request and compared **constant-time** by the helper.
3. SO_PEERCRED uid pinning is a documented hardening follow-up (BL-016).

**Protocol** — length-prefixed (`u32` BE) compact JSON, body capped at 1 MiB, `protocol_version` on
every request, requests mapping **1:1 to explicit operations**. There is deliberately **no** generic
filesystem API and **no** arbitrary-command operation.

**The exec exception** — `mayfly-helper` (and only it) executes a **fixed allow-list** of absolute
binaries with fixed arguments: `/usr/sbin/sshd -t`, `systemctl reload <svc>`,
`systemctl is-active <svc>`. This uses `std::process::Command` directly (never `sh -c`, never
user-controlled arguments) and is injected behind the `SshdControl` trait so it is fully mockable.
This is the **only** sanctioned exception to the no-shell-outs rule, confined to the root helper.

## Consequences
- **Positive:** an agent compromise no longer implies root or the ability to rewrite the SSH trust
  list; the privileged surface is a handful of explicit ops behind two auth factors; the dangerous
  exec is a tiny fixed allow-list, isolated and testable.
- **Negative:** a new root-listening socket (new attack surface) and a second binary/unit to install
  and operate; the agent now depends on helper availability for apply (degrades to "cannot apply,
  retries" if the helper is down — never fails open).
- **Obligations:** keep the op allow-list closed; never log token/secret material; add SO_PEERCRED
  pinning (BL-016); the live wiring into `CaSyncService` lands behind the `BundleApplier` seam
  (BL-015) with Docker e2e (SSH cert login + rollback).

## Alternatives considered
- **Keep the whole agent root** — rejected: maximises blast radius of an agent compromise.
- **setuid helper / sudo rules** — rejected: setuid is error-prone; sudo is a broader, shell-adjacent
  surface. A long-lived root daemon with a narrow, authenticated, allow-listed socket is easier to
  reason about and audit.
- **D-Bus / polkit** — rejected: heavier dependency surface; out of scope.
- **Pure-Rust sshd validation/reload** — not possible; `sshd -t` and service reload require exec.
