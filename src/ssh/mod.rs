//! SSH-facing data models.
//!
//! This module contains pure, read-only parsing and validation for the two SSH
//! artifacts the helper manages:
//!
//! * [`trusted_ca`] — the `TrustedUserCAKeys` file (a list of CA public keys);
//! * [`sshd_config`] — inspection and rendering of the `TrustedUserCAKeys`
//!   directive for the sshd drop-in.
//!
//! Nothing here performs I/O against the real system, fetches keys from the
//! network, or modifies `sshd_config`; these are parsing and rendering routines
//! only. The privileged writing/validation/reload built on top lives in
//! [`crate::ops`].
//!
//! > Note: these modules are duplicated byte-for-byte with `mayfly-agent`
//! > pending a shared crate (ADR-0009, BL-017).

pub mod sshd_config;
pub mod trusted_ca;
