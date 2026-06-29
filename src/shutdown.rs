//! Graceful-shutdown signalling.
//!
//! The helper must stop promptly on `SIGINT`/`SIGTERM` (systemd sends `SIGTERM`
//! and waits a bounded grace period before `SIGKILL`). Shutdown is modelled as a
//! shared [`AtomicBool`]: the signal handler — installed via [`signal_hook`],
//! whose handler only stores `true` (async-signal-safe) — flips the flag, and
//! the accept loop observes it between polls.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::errors::{Error, Result};

/// A shared, cheaply-cloneable shutdown flag.
#[derive(Clone, Debug, Default)]
pub struct Shutdown {
    flag: Arc<AtomicBool>,
}

impl Shutdown {
    /// Create a fresh, un-requested shutdown flag.
    pub fn new() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Whether shutdown has been requested.
    pub fn is_requested(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    /// Request shutdown (used by tests and by an in-process trigger).
    pub fn request(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    /// The underlying flag, for registering OS signal handlers against it.
    pub fn flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.flag)
    }
}

/// Install `SIGINT` and `SIGTERM` handlers that set `shutdown`'s flag.
///
/// The handlers are async-signal-safe (they only store into an [`AtomicBool`]);
/// no allocation, locking, or logging happens inside them.
///
/// # Errors
///
/// Returns [`Error::Io`] if a handler cannot be registered.
pub fn install_signal_handlers(shutdown: &Shutdown) -> Result<()> {
    use signal_hook::consts::{SIGINT, SIGTERM};

    let flag = shutdown.flag();
    signal_hook::flag::register(SIGTERM, Arc::clone(&flag)).map_err(Error::Io)?;
    signal_hook::flag::register(SIGINT, flag).map_err(Error::Io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn flag_round_trips() {
        let s = Shutdown::new();
        assert!(!s.is_requested());
        s.request();
        assert!(s.is_requested());
        // Clones share the same flag.
        let c = s.clone();
        assert!(c.is_requested());
    }

    #[test]
    fn installing_handlers_succeeds() {
        // Registering handlers must not error; we do not raise signals here to
        // avoid disturbing the test process.
        let shutdown = Shutdown::new();
        install_signal_handlers(&shutdown).unwrap();
    }
}
