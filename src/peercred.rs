//! Kernel peer-credential authentication for the control socket (`SO_PEERCRED`).
//!
//! Socket file permissions (`0660 root:mayfly`) already restrict *who* can
//! connect to root and the `mayfly` group, and the capability token proves the
//! caller possesses a shared secret. Peer-credential pinning adds a third,
//! independent factor that the kernel — not the caller — supplies: the
//! connecting process's real **uid** (and gid/pid for the audit log). The
//! helper pins the uid to an allow-list (the unprivileged agent's uid plus
//! root), so even another member of the `mayfly` group that can read the token
//! cannot drive privileged `sshd` changes (defence in depth; ADR-0008/ADR-0011).
//!
//! The credential *source* (`SO_PEERCRED`) is Linux-only; the *authorization
//! decision* ([`PeerPolicy::authorize`]) is pure and platform-independent so it
//! is unit-tested everywhere. The helper only runs on Linux; on other platforms
//! [`peer_cred`] returns [`Error::PeerCredUnavailable`].

use std::os::unix::net::UnixStream;

use crate::errors::{Error, Result};

/// The kernel-reported credentials of a socket peer at connect time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    /// Peer process real user id.
    pub uid: u32,
    /// Peer process real group id.
    pub gid: u32,
    /// Peer process id (for the audit log; never an authorization input).
    pub pid: i32,
}

/// Which connecting uids the helper will serve.
///
/// Built once at start-up. When `enforced` is false (no allow-list configured)
/// the helper logs a warning and falls back to the prior trust model (socket
/// perms + token only) for backward compatibility; when true, a peer whose uid
/// is not in `allowed_uids` is rejected, and an unreadable credential is treated
/// as a failure (fail-closed).
#[derive(Debug, Clone, Default)]
pub struct PeerPolicy {
    allowed_uids: Vec<u32>,
    enforced: bool,
}

impl PeerPolicy {
    /// Enforce uid pinning against the given allow-list.
    ///
    /// Root (uid 0) is always implicitly allowed: it can already perform any
    /// host operation directly, so admitting it over the socket grants nothing
    /// extra and keeps operator/debug access working.
    pub fn enforced(mut allowed_uids: Vec<u32>) -> Self {
        if !allowed_uids.contains(&0) {
            allowed_uids.push(0);
        }
        Self {
            allowed_uids,
            enforced: true,
        }
    }

    /// Disable uid pinning (backward-compatible fallback). The helper still
    /// authenticates with socket perms + the capability token.
    pub fn unenforced() -> Self {
        Self {
            allowed_uids: Vec::new(),
            enforced: false,
        }
    }

    /// Whether uid pinning is active.
    pub fn is_enforced(&self) -> bool {
        self.enforced
    }

    /// Decide whether a peer with the given credentials may be served.
    ///
    /// # Errors
    ///
    /// Returns [`Error::HelperUnauthenticated`] if pinning is enforced and the
    /// peer's uid is not allow-listed. Always `Ok` when pinning is disabled.
    pub fn authorize(&self, cred: &PeerCred) -> Result<()> {
        if !self.enforced || self.allowed_uids.contains(&cred.uid) {
            Ok(())
        } else {
            Err(Error::HelperUnauthenticated)
        }
    }
}

/// Read the connecting peer's kernel credentials from a connected stream.
///
/// # Errors
///
/// Returns [`Error::PeerCredUnavailable`] if the credentials cannot be read
/// (or on non-Linux platforms, where `SO_PEERCRED` is unavailable).
#[cfg(target_os = "linux")]
pub fn peer_cred(stream: &UnixStream) -> Result<PeerCred> {
    let ucred = rustix::net::sockopt::socket_peercred(stream).map_err(|_| {
        tracing::warn!("could not read SO_PEERCRED for a connecting peer");
        Error::PeerCredUnavailable
    })?;
    Ok(PeerCred {
        uid: ucred.uid.as_raw(),
        gid: ucred.gid.as_raw(),
        pid: ucred.pid.as_raw_pid(),
    })
}

/// Non-Linux fallback: kernel peer credentials are unavailable. The helper is a
/// Linux daemon; this path exists only so the crate builds (and its pure logic
/// is testable) on developer hosts.
#[cfg(not(target_os = "linux"))]
pub fn peer_cred(_stream: &UnixStream) -> Result<PeerCred> {
    Err(Error::PeerCredUnavailable)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn cred(uid: u32) -> PeerCred {
        PeerCred {
            uid,
            gid: uid,
            pid: 4242,
        }
    }

    #[test]
    fn enforced_policy_admits_allowed_uid() {
        let policy = PeerPolicy::enforced(vec![1000]);
        assert!(policy.is_enforced());
        assert!(policy.authorize(&cred(1000)).is_ok());
    }

    #[test]
    fn enforced_policy_rejects_other_uid() {
        let policy = PeerPolicy::enforced(vec![1000]);
        assert!(matches!(
            policy.authorize(&cred(1234)).unwrap_err(),
            Error::HelperUnauthenticated
        ));
    }

    #[test]
    fn enforced_policy_always_admits_root() {
        // Root is implicitly allowed even when not listed.
        let policy = PeerPolicy::enforced(vec![1000]);
        assert!(policy.authorize(&cred(0)).is_ok());
    }

    #[test]
    fn unenforced_policy_admits_anyone() {
        let policy = PeerPolicy::unenforced();
        assert!(!policy.is_enforced());
        assert!(policy.authorize(&cred(31337)).is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn peer_cred_reads_own_uid_on_linux() {
        // A socketpair connects the process to itself, so the peer uid is ours.
        let (a, _b) = UnixStream::pair().unwrap();
        let cred = peer_cred(&a).unwrap();
        assert_eq!(cred.uid, rustix::process::getuid().as_raw());
    }
}
