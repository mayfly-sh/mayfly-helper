//! `mayfly-helper` binary entry point — the privileged half of the platform.
//!
//! This process runs as **root** and does nothing but serve a small, explicit
//! set of privileged operations over an authenticated Unix Domain Socket (see
//! ADR-0008/ADR-0009 and `contracts/helper-socket.json`). The unprivileged
//! `mayfly-agent` (a separate repository) is its only intended client.
//!
//! Start-up:
//!
//! 1. initialise structured logging;
//! 2. require root (fail fast otherwise);
//! 3. read configuration from `MAYFLY_HELPER_*` environment variables;
//! 4. validate then load the capability token (token file must be a non-symlink,
//!    root-owned, mode ≤ `0640`, and at least 32 chars; the value is never logged);
//! 5. build the `SO_PEERCRED` uid-pinning policy (`MAYFLY_HELPER_ALLOWED_UID`);
//! 6. install `SIGINT`/`SIGTERM` handlers;
//! 7. bind the socket and serve until shutdown.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use mayfly_helper::errors::Error;
use mayfly_helper::ops::{HelperOps, OpsConfig};
use mayfly_helper::peercred::PeerPolicy;
use mayfly_helper::platform::validate_root;
use mayfly_helper::security;
use mayfly_helper::server::HelperServer;
use mayfly_helper::shutdown::{install_signal_handlers, Shutdown};
use mayfly_helper::sshd_control::{SshdControlConfig, SystemSshdControl};
use mayfly_helper::{logging, Result};

const DEFAULT_SOCKET_PATH: &str = "/run/mayfly/helper.sock";
const DEFAULT_TOKEN_PATH: &str = "/etc/mayfly-agent/helper.token";

/// Minimum acceptable capability-token length (characters). The installer writes
/// 32 random bytes hex-encoded (64 chars); anything shorter than 32 chars is
/// rejected fail-closed as too weak rather than served.
const MIN_TOKEN_LEN: usize = 32;

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn socket_path() -> PathBuf {
    env("MAYFLY_HELPER_SOCKET_PATH")
        .map_or_else(|| PathBuf::from(DEFAULT_SOCKET_PATH), PathBuf::from)
}

fn token_path() -> PathBuf {
    env("MAYFLY_HELPER_TOKEN_PATH").map_or_else(|| PathBuf::from(DEFAULT_TOKEN_PATH), PathBuf::from)
}

/// Optional numeric gid to own the socket file (so the agent's group can connect
/// at mode `0660`). The installer passes the `mayfly` group's gid.
fn socket_gid() -> Option<u32> {
    env("MAYFLY_HELPER_SOCKET_GID").and_then(|v| v.trim().parse::<u32>().ok())
}

/// Build the kernel peer-credential (`SO_PEERCRED`) policy from
/// `MAYFLY_HELPER_ALLOWED_UID` (the unprivileged agent's uid; root is always
/// implicitly allowed). When unset, uid pinning is disabled with a prominent
/// warning — socket perms + the capability token still apply.
fn peer_policy() -> PeerPolicy {
    match env("MAYFLY_HELPER_ALLOWED_UID").and_then(|v| v.trim().parse::<u32>().ok()) {
        Some(uid) => PeerPolicy::enforced(vec![uid]),
        None => {
            tracing::warn!(
                "MAYFLY_HELPER_ALLOWED_UID is not set; SO_PEERCRED uid pinning is DISABLED \
                 (socket permissions + capability token still enforced). Set it to the \
                 mayfly agent's uid for defence in depth."
            );
            PeerPolicy::unenforced()
        }
    }
}

/// Load the capability token, first verifying the token file is itself
/// trustworthy: not a symlink, owned by root, and not group/other-writable
/// (mode ≤ `0640`). A tamperable token file is rejected fail-closed.
fn load_token() -> Result<String> {
    let path = token_path();
    security::ensure_not_symlink(&path)?;
    security::ensure_owned_by_root(&path)?;
    security::validate_mode_at_most(&path, 0o640)?;
    let token = std::fs::read_to_string(&path).map_err(Error::Io)?;
    let token = token.trim().to_string();
    if token.is_empty() {
        tracing::error!("capability token file is empty");
        return Err(Error::HelperUnauthenticated);
    }
    if token.len() < MIN_TOKEN_LEN {
        // Length only — never the value — is logged.
        tracing::error!(
            min_len = MIN_TOKEN_LEN,
            "capability token is too short; refusing to start (rotate to a longer token)"
        );
        return Err(Error::HelperUnauthenticated);
    }
    Ok(token)
}

fn run() -> Result<()> {
    validate_root()?;

    let token = load_token()?;
    let ops = HelperOps::new(
        OpsConfig::from_env(env),
        SystemSshdControl::new(SshdControlConfig::from_env(env)),
    );
    let server = HelperServer::new(socket_path(), token, ops)
        .with_socket_group(socket_gid())
        .with_peer_policy(peer_policy());

    let shutdown = Shutdown::new();
    install_signal_handlers(&shutdown)?;

    let flag = shutdown.flag();
    server.run(&flag)
}

fn main() -> ExitCode {
    logging::init();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!(error = %err, "mayfly-helper failed");
            ExitCode::FAILURE
        }
    }
}
