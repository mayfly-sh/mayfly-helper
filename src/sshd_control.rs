//! The `sshd` control seam — the one place that executes external programs.
//!
//! Validating and reloading `sshd` cannot be done in pure Rust; it requires
//! running `sshd -t` and a service-manager reload. Per ADR-0008 this is the
//! single sanctioned exception to the project's no-shell-outs rule, and it is
//! confined to the **root helper**. All execution goes through a *fixed
//! allow-list* of absolute binaries with fixed arguments — never `sh -c`, never
//! caller-controlled arguments — and is hidden behind the [`SshdControl`] trait
//! so the privileged [`crate::ops`] are fully testable with a mock.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::errors::{Error, Result};

/// Default wall-clock bound for a single privileged sub-command (`sshd -t`,
/// `systemctl reload`/`is-active`). A hung child is killed and treated as a
/// failure so it can never pin the single-threaded helper loop.
pub const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(15);

/// How often the runner polls a spawned child for completion.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// The result of running one fixed sub-command to completion (or killing it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunOutcome {
    /// The command exited 0.
    Success,
    /// The command exited non-zero or could not be spawned.
    Failed,
    /// The command did not finish within the timeout and was killed.
    TimedOut,
}

/// Abstraction over validating, reloading, and probing `sshd`.
pub trait SshdControl: Send + Sync {
    /// Validate the effective `sshd` configuration (`sshd -t`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::SshdValidationFailed`] if `sshd` rejects the config or
    /// the validator could not be run.
    fn validate_config(&self) -> Result<()>;

    /// Reload `sshd` so a new configuration takes effect.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SshdInactive`] if the reload command fails.
    fn reload(&self) -> Result<()>;

    /// Verify `sshd` is active.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SshdInactive`] if the service is not active or the query
    /// fails.
    fn is_active(&self) -> Result<()>;
}

/// Configuration for [`SystemSshdControl`]: the absolute binary paths and the
/// service unit name. Defaults match a standard Debian/Ubuntu host; they are
/// configurable so container integration tests can point at the binaries and
/// service present in the test image.
#[derive(Debug, Clone)]
pub struct SshdControlConfig {
    /// Absolute path to the `sshd` binary (used as `<sshd> -t`).
    pub sshd_binary: PathBuf,
    /// Absolute path to `systemctl`.
    pub systemctl_binary: PathBuf,
    /// The `sshd` service/unit name (e.g. `ssh` or `sshd`).
    pub service_name: String,
    /// Wall-clock bound for each sub-command; a child exceeding it is killed and
    /// the operation fails (fail-closed). See [`DEFAULT_COMMAND_TIMEOUT`].
    pub command_timeout: Duration,
}

impl Default for SshdControlConfig {
    fn default() -> Self {
        Self {
            sshd_binary: PathBuf::from("/usr/sbin/sshd"),
            systemctl_binary: PathBuf::from("/usr/bin/systemctl"),
            service_name: "ssh".to_string(),
            command_timeout: DEFAULT_COMMAND_TIMEOUT,
        }
    }
}

impl SshdControlConfig {
    /// Build from `MAYFLY_HELPER_*` environment variables, falling back to
    /// [`Default`]. Used by the `mayfly-helper` binary.
    pub fn from_env<F>(get_env: F) -> Self
    where
        F: Fn(&str) -> Option<String>,
    {
        let mut cfg = Self::default();
        if let Some(v) = get_env("MAYFLY_HELPER_SSHD_BINARY") {
            cfg.sshd_binary = PathBuf::from(v);
        }
        if let Some(v) = get_env("MAYFLY_HELPER_SYSTEMCTL_BINARY") {
            cfg.systemctl_binary = PathBuf::from(v);
        }
        if let Some(v) = get_env("MAYFLY_HELPER_SERVICE_NAME") {
            cfg.service_name = v;
        }
        if let Some(secs) = get_env("MAYFLY_HELPER_SSHD_TIMEOUT_SECS")
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|&s| s > 0)
        {
            cfg.command_timeout = Duration::from_secs(secs);
        }
        cfg
    }
}

/// Production [`SshdControl`] backed by `std::process::Command`.
///
/// Each method runs exactly one fixed-shape command and inspects only its exit
/// status. No shell is involved and no argument is caller-controlled.
#[derive(Debug, Clone)]
pub struct SystemSshdControl {
    config: SshdControlConfig,
}

impl SystemSshdControl {
    /// Construct from explicit configuration.
    pub fn new(config: SshdControlConfig) -> Self {
        Self { config }
    }

    /// Run a fixed command to completion under [`SshdControlConfig::command_timeout`],
    /// returning a coarse [`RunOutcome`] and logging (but never returning) its
    /// captured stderr for diagnostics.
    ///
    /// The command is spawned with stdout discarded and stderr captured. A child
    /// that overruns the timeout is killed and reaped so it cannot become a
    /// zombie or pin the helper's single-threaded accept loop.
    fn run(&self, command: &mut Command, what: &str) -> RunOutcome {
        command.stdin(Stdio::null());
        command.stdout(Stdio::null());
        command.stderr(Stdio::piped());

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(err) => {
                tracing::warn!(command = what, error = %err, "failed to spawn privileged command");
                return RunOutcome::Failed;
            }
        };

        let deadline = Instant::now() + self.config.command_timeout;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let stderr = read_child_stderr(&mut child);
                    if status.success() {
                        return RunOutcome::Success;
                    }
                    tracing::warn!(
                        command = what,
                        code = status.code(),
                        stderr = %stderr.trim(),
                        "privileged command reported failure"
                    );
                    return RunOutcome::Failed;
                }
                Ok(None) => {
                    if Instant::now() >= deadline {
                        // Fail-closed: kill and reap a child that overran the bound.
                        let _ = child.kill();
                        let _ = child.wait();
                        tracing::warn!(
                            command = what,
                            timeout_secs = self.config.command_timeout.as_secs(),
                            timed_out = true,
                            "privileged command timed out; killed"
                        );
                        return RunOutcome::TimedOut;
                    }
                    std::thread::sleep(POLL_INTERVAL);
                }
                Err(err) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    tracing::warn!(command = what, error = %err, "error while awaiting privileged command");
                    return RunOutcome::Failed;
                }
            }
        }
    }
}

/// Drain a finished child's captured stderr (best-effort, for diagnostics only).
fn read_child_stderr(child: &mut std::process::Child) -> String {
    use std::io::Read as _;
    let mut buf = String::new();
    if let Some(mut stderr) = child.stderr.take() {
        let _ = stderr.read_to_string(&mut buf);
    }
    buf
}

impl SshdControl for SystemSshdControl {
    fn validate_config(&self) -> Result<()> {
        // `sshd -t` validates the effective configuration, including any
        // drop-ins pulled in via `Include`.
        let mut cmd = Command::new(&self.config.sshd_binary);
        cmd.arg("-t");
        match self.run(&mut cmd, "sshd -t") {
            RunOutcome::Success => Ok(()),
            // A timeout or a non-zero exit are both "config not known-good".
            RunOutcome::Failed | RunOutcome::TimedOut => Err(Error::SshdValidationFailed),
        }
    }

    fn reload(&self) -> Result<()> {
        let mut cmd = Command::new(&self.config.systemctl_binary);
        cmd.arg("reload").arg(&self.config.service_name);
        match self.run(&mut cmd, "systemctl reload") {
            RunOutcome::Success => Ok(()),
            RunOutcome::Failed | RunOutcome::TimedOut => Err(Error::SshdReloadFailed),
        }
    }

    fn is_active(&self) -> Result<()> {
        let mut cmd = Command::new(&self.config.systemctl_binary);
        cmd.arg("is-active").arg(&self.config.service_name);
        match self.run(&mut cmd, "systemctl is-active") {
            RunOutcome::Success => Ok(()),
            RunOutcome::Failed | RunOutcome::TimedOut => Err(Error::SshdInactive),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn control_with_missing_binaries() -> SystemSshdControl {
        SystemSshdControl::new(SshdControlConfig {
            sshd_binary: PathBuf::from("/nonexistent/sshd"),
            systemctl_binary: PathBuf::from("/nonexistent/systemctl"),
            service_name: "ssh".to_string(),
            command_timeout: Duration::from_secs(5),
        })
    }

    #[test]
    fn validate_config_fails_when_binary_missing() {
        // Exercises the exec-failure path deterministically without a real sshd.
        assert!(matches!(
            control_with_missing_binaries()
                .validate_config()
                .unwrap_err(),
            Error::SshdValidationFailed
        ));
    }

    #[test]
    fn reload_and_is_active_fail_when_binary_missing() {
        let c = control_with_missing_binaries();
        // A failed reload is now typed distinctly from an inactive service.
        assert!(matches!(c.reload().unwrap_err(), Error::SshdReloadFailed));
        assert!(matches!(c.is_active().unwrap_err(), Error::SshdInactive));
    }

    #[test]
    fn from_env_overrides_defaults() {
        let cfg = SshdControlConfig::from_env(|k| match k {
            "MAYFLY_HELPER_SERVICE_NAME" => Some("sshd".to_string()),
            "MAYFLY_HELPER_SSHD_BINARY" => Some("/usr/local/sbin/sshd".to_string()),
            "MAYFLY_HELPER_SSHD_TIMEOUT_SECS" => Some("42".to_string()),
            _ => None,
        });
        assert_eq!(cfg.service_name, "sshd");
        assert_eq!(cfg.sshd_binary, PathBuf::from("/usr/local/sbin/sshd"));
        assert_eq!(cfg.systemctl_binary, PathBuf::from("/usr/bin/systemctl"));
        assert_eq!(cfg.command_timeout, Duration::from_secs(42));
    }

    #[test]
    fn from_env_ignores_zero_and_garbage_timeout() {
        let cfg = SshdControlConfig::from_env(|k| match k {
            "MAYFLY_HELPER_SSHD_TIMEOUT_SECS" => Some("0".to_string()),
            _ => None,
        });
        assert_eq!(cfg.command_timeout, DEFAULT_COMMAND_TIMEOUT);
        let cfg = SshdControlConfig::from_env(|k| match k {
            "MAYFLY_HELPER_SSHD_TIMEOUT_SECS" => Some("not-a-number".to_string()),
            _ => None,
        });
        assert_eq!(cfg.command_timeout, DEFAULT_COMMAND_TIMEOUT);
    }

    /// A command that exits immediately succeeds within the timeout. Uses
    /// `/usr/bin/true` (or `/bin/true`), present on Linux and macOS dev hosts.
    #[test]
    fn run_returns_success_for_fast_command() {
        let true_bin = ["/usr/bin/true", "/bin/true"]
            .into_iter()
            .map(PathBuf::from)
            .find(|p| p.exists());
        let Some(true_bin) = true_bin else {
            return; // No `true` binary available; skip rather than fail.
        };
        let control = SystemSshdControl::new(SshdControlConfig {
            sshd_binary: true_bin,
            systemctl_binary: PathBuf::from("/nonexistent"),
            service_name: "ssh".to_string(),
            command_timeout: Duration::from_secs(5),
        });
        // `validate_config` runs `<sshd_binary> -t`; `true` ignores args and
        // exits 0, so this exercises the success path deterministically.
        assert!(control.validate_config().is_ok());
    }

    /// A command that overruns the timeout is killed and reported as
    /// [`RunOutcome::TimedOut`] (fail-closed). Deterministic: `sleep 30` cannot
    /// finish inside 150ms, and the runner returns promptly after the kill.
    #[test]
    fn run_times_out_and_kills_overrunning_command() {
        let sleep_bin = ["/usr/bin/sleep", "/bin/sleep"]
            .into_iter()
            .map(PathBuf::from)
            .find(|p| p.exists());
        let Some(sleep_bin) = sleep_bin else {
            return; // No `sleep` binary available; skip rather than fail.
        };
        let control = SystemSshdControl::new(SshdControlConfig {
            sshd_binary: PathBuf::from("/nonexistent"),
            systemctl_binary: PathBuf::from("/nonexistent"),
            service_name: "ssh".to_string(),
            command_timeout: Duration::from_millis(150),
        });
        // Call the private runner directly with a clean `sleep 30`.
        let mut cmd = Command::new(&sleep_bin);
        cmd.arg("30");
        let started = Instant::now();
        let outcome = control.run(&mut cmd, "sleep 30 (test)");
        assert_eq!(outcome, RunOutcome::TimedOut);
        // It returned promptly (killed), not after the full 30s sleep.
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
