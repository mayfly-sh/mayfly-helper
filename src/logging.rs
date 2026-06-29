//! Structured logging built on [`tracing`].
//!
//! The helper logs as one JSON object per line (suitable for journald / log
//! aggregation). Verbosity is taken from the `RUST_LOG` environment variable
//! when set, otherwise defaults to `info`. Initialisation is idempotent so it is
//! safe to call from both the binary and tests.
//!
//! The helper never logs capability tokens, file contents, or key material; see
//! the no-secret-logging policy enforced throughout [`crate`].

use tracing_subscriber::EnvFilter;

/// Initialise the global JSON subscriber at `info` (overridable via `RUST_LOG`).
///
/// Returns `true` if this call installed the subscriber, or `false` if one was
/// already installed (subsequent calls are no-ops rather than panics).
pub fn init() -> bool {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .json()
        .try_init()
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_is_idempotent() {
        // Whichever test wins the race installs the global subscriber; every
        // subsequent call must return false without panicking.
        let _ = init();
        assert!(!init());
    }
}
