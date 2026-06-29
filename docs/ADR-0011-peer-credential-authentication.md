# ADR-0011: SO_PEERCRED uid pinning as a third helper-IPC authentication factor

- **Status:** Accepted
- **Date:** 2026-06-29 (milestone 009A)
- **Deciders:** Mayfly maintainers
- **Affects:** mayfly-helper (server-side only; wire protocol unchanged)
- **Implements:** the SO_PEERCRED hardening flagged "planned" in ADR-0008 and tracked as BL-016 / R-009.

## Context
The agent↔helper Unix socket previously authenticated with two factors: OS socket permissions
(`0660 root:mayfly`) and a constant-time capability token (`/etc/mayfly-agent/helper.token`). Both
are necessary but neither pins the *identity of the connecting process*. Any local process that is a
member of the `mayfly` group **and** can read the token file could connect and drive privileged
`sshd` changes — a real, if narrow, lateral-movement path on a shared host (R-009).

Linux exposes the connecting peer's kernel-verified credentials via `getsockopt(SO_PEERCRED)`: the
uid/gid/pid the kernel recorded at `connect(2)` time, which the caller cannot forge.

## Decision
1. Add **kernel peer-credential verification** as a third, independent authentication factor in
   `mayfly-helper`. On each accepted connection the helper reads `SO_PEERCRED` and pins the peer
   **uid** to an allow-list before reading the request body.
2. The allow-list is the unprivileged agent's uid (`MAYFLY_HELPER_ALLOWED_UID`, written by the
   installer from the resolved `mayfly` user) **plus root (uid 0)**, which can already perform any
   host operation directly.
3. **Fail-closed when enforced:** if pinning is configured but the credential cannot be read, the
   request is rejected. **Backward-compatible default:** if `MAYFLY_HELPER_ALLOWED_UID` is unset,
   pinning is disabled with a prominent startup warning (socket perms + token still apply), so an
   existing deployment is never broken by the upgrade.
4. **No wire change.** Enforcement is entirely server-side; `PROTOCOL_VERSION` stays `1` and the
   agent IPC client is unaffected. The authorization decision is a pure function
   (`PeerPolicy::authorize`) unit-tested on all platforms; the `SO_PEERCRED` read is Linux-only.
5. The kernel-reported uid/gid/pid are added to the per-request **audit log** (with a correlation id
   and duration), improving traceability without ever logging the token or any path.

## Consequences
- **Positive:** a third, unforgeable factor closes R-009; even a token-reading `mayfly`-group process
  with the wrong uid is rejected; richer audit log; no protocol break, independent deploy safe.
- **Negative / accepted:** Linux-only (the helper is a Linux daemon; non-Linux dev hosts cannot read
  `SO_PEERCRED` — covered by the unenforced default + pure decision tests). The installer must keep
  `MAYFLY_HELPER_ALLOWED_UID` correct across uid changes (regenerated every install).
- **Not done here:** capability-token rotation tooling (runbook follow-up, still BL-016); gid pinning
  (uid + socket-group membership already bound; gid is logged, not gated).

## Alternatives considered
- **Gate on gid instead of uid** — weaker: any `mayfly`-group member would pass; uid is the precise
  identity.
- **Drop the capability token, rely on SO_PEERCRED alone** — rejected: defence in depth; the token
  also guards the (Linux-absent) edge and documents intent.
- **SCM_CREDENTIALS handshake message** — unnecessary; `SO_PEERCRED` needs no protocol field.
