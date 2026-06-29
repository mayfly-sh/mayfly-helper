//! # mayfly-helper
//!
//! The **privileged** half of the Mayfly host integration. `mayfly-helper` runs
//! as **root** and does nothing but serve a small, explicit set of privileged
//! host operations over an authenticated Unix Domain Socket. Its only intended
//! client is the unprivileged `mayfly-agent`.
//!
//! This crate is deliberately tiny and self-contained: it has **no networking**,
//! performs **no enrollment, certificate, or bundle verification**, makes **no
//! authorization decisions**, and **schedules nothing**. All of that belongs to
//! `mayfly-agent` and `mayfly-server`. The helper is a privileged *execution
//! service* only.
//!
//! ## Operations (the entire allow-list)
//!
//! Every request maps 1:1 to one reviewed action — there is no generic
//! filesystem facility and no "run command" variant:
//!
//! * atomically replace `TrustedUserCAKeys` (rollback-safe);
//! * install/refresh the `sshd` drop-in (`/etc/ssh/sshd_config.d/90-mayfly.conf`);
//! * validate the `sshd` configuration (`sshd -t`);
//! * reload `sshd` and verify it is active;
//! * create the managed directories with safe ownership/permissions;
//! * verify the managed files' permissions/ownership.
//!
//! ## Modules
//!
//! * [`protocol`] — the agent↔helper wire types, length-prefixed framing, and
//!   constant-time token comparison (the canonical IPC contract; see
//!   `contracts/helper-socket.json` and ADR-0008/ADR-0009);
//! * [`sshd_control`] — the `SshdControl` seam: the *only* place that executes
//!   external programs (`sshd -t`, `systemctl`), behind a mockable trait;
//! * [`ops`] — the privileged operations, built on [`security`] and an injected
//!   [`sshd_control::SshdControl`];
//! * [`server`] — the UDS accept loop, authentication, and dispatch;
//! * [`security`] — hardened filesystem primitives (atomic write, `fsync`,
//!   symlink rejection, perm/owner validation);
//! * [`ssh`] — `TrustedUserCAKeys` parsing and `sshd` drop-in rendering;
//! * [`platform`] — root-privilege validation;
//! * [`shutdown`] — graceful-shutdown signalling;
//! * [`errors`] — a single, path-free error type;
//! * [`logging`] — structured `tracing` initialisation.
//!
//! ### Relationship to `mayfly-agent`
//!
//! The agent and helper share **no code dependency** (independent builds, no
//! cycles). The IPC protocol and the small audited primitives are currently
//! duplicated byte-for-byte in both repositories; a future shared crate is
//! planned in ADR-0009 (tracked as BL-017). The canonical specification is
//! `contracts/helper-socket.json`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod errors;
pub mod logging;
pub mod ops;
pub mod platform;
pub mod protocol;
pub mod security;
pub mod server;
pub mod shutdown;
pub mod ssh;
pub mod sshd_control;

pub use errors::{Error, Result};
pub use ops::{HelperOps, OpsConfig};
pub use protocol::{Operation, Outcome, Request, Response, MAX_BODY_BYTES, PROTOCOL_VERSION};
pub use server::HelperServer;
pub use sshd_control::{SshdControl, SshdControlConfig, SystemSshdControl};
