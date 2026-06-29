# ADR-0009: Extract `mayfly-helper` into an independent repository

- **Status:** Accepted (2026-06-29, milestone 008)
- **Supersedes part of:** ADR-0008 (which introduced the helper as a *second binary in the agent
  crate*). The helper's design is unchanged; only its packaging changed.

## Context
ADR-0008 shipped `mayfly-helper` as a second binary inside the `mayfly-agent` crate. With the design
proven, the platform wants **three single-responsibility repositories**: `mayfly-server` (control
plane), `mayfly-agent` (unprivileged), and `mayfly-helper` (root). A single crate producing both an
unprivileged agent and a root helper blurred ownership and coupled their release cadence.

## Decision
1. **Extract** the helper library + binary + IPC protocol into this independent repository. The helper
   depends on **no** agent code; the agent depends on **no** helper code (independent builds, no
   cycles).
2. **IPC is a first-class, versioned protocol owned by `mayfly-helper`** (`src/protocol.rs`,
   `docs/helper-socket.json`). The agent consumes it via its `ipc` module. Wire format unchanged
   (`PROTOCOL_VERSION = 1`).
3. **The agent keeps only an IPC client.** The privileged implementation (`ops`, `server`,
   `sshd_control`) lives solely here.
4. **Temporary, documented duplication instead of a premature shared crate.** The IPC protocol and the
   small audited primitives (`security`, `ssh/sshd_config`, `ssh/trusted_ca`) are duplicated
   byte-for-byte across the two repos; the contract is the canonical spec both must satisfy.
5. **The helper owns its deploy assets:** systemd unit, `90-mayfly.conf` template, `systemctl` shim,
   and a helper-only installer.

## Consequences
- **Positive:** clean ownership (the root binary contains no networking/enrollment/authorization);
  independent build/test/review/release; IPC elevated to a contract.
- **Negative (accepted):** code duplication across repos (drift risk; mitigated by byte-identical
  copies + the canonical contract + reviews; tracked as **BL-017**); the single-crate Docker harness
  no longer applies — a three-repo harness is deferred (**BL-018**).

## Future work — shared protocol/primitives crate (planned, not implemented)
A `mayfly-protocol` (and/or `mayfly-common`) crate, or contract-generated types, would remove the
duplication. Deferred until a second consumer or a protocol change justifies the added versioning
coupling (BL-017).
