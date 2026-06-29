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
//! 4. load the capability token from its file (never logged);
//! 5. install `SIGINT`/`SIGTERM` handlers;
//! 6. bind the socket and serve until shutdown.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use mayfly_helper::errors::Error;
use mayfly_helper::ops::{HelperOps, OpsConfig};
use mayfly_helper::platform::validate_root;
use mayfly_helper::server::HelperServer;
use mayfly_helper::shutdown::{install_signal_handlers, Shutdown};
use mayfly_helper::sshd_control::{SshdControlConfig, SystemSshdControl};
use mayfly_helper::{logging, Result};

const DEFAULT_SOCKET_PATH: &str = "/run/mayfly/helper.sock";
const DEFAULT_TOKEN_PATH: &str = "/etc/mayfly-agent/helper.token";

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

fn load_token() -> Result<String> {
    let path = token_path();
    let token = std::fs::read_to_string(&path).map_err(Error::Io)?;
    let token = token.trim().to_string();
    if token.is_empty() {
        tracing::error!("capability token file is empty");
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
    let server = HelperServer::new(socket_path(), token, ops).with_socket_group(socket_gid());

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
