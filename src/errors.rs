//! The crate's single error type.
//!
//! ## Security property: no path leakage
//!
//! User-facing error messages (the [`Display`](std::fmt::Display) output of
//! [`Error`]) **never** contain filesystem paths, file contents, capability
//! tokens, or other sensitive context. Diagnostic detail such as the offending
//! path is emitted via structured [`tracing`](https://docs.rs/tracing) at the
//! call site instead. The helper's responses to the agent carry only these
//! fixed, path-free strings.

use std::fmt;

/// The single, crate-wide result type.
pub type Result<T> = std::result::Result<T, Error>;

/// The single, crate-wide error type.
///
/// Variants are intentionally coarse-grained and path-free. When more detail is
/// useful for debugging it is logged with structured fields at the point of
/// failure rather than embedded here.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A filesystem operation failed. The path is logged, not included here.
    #[error("filesystem operation failed")]
    Io(#[source] std::io::Error),

    /// A managed path is a symlink where a regular file or directory is
    /// required.
    #[error("path failed security validation: unexpected symlink")]
    UnexpectedSymlink,

    /// A managed file has unsafe ownership (e.g. not owned by root).
    #[error("path failed security validation: insecure ownership")]
    InsecureOwnership,

    /// A managed file has unsafe permission bits (e.g. group/world writable).
    #[error("path failed security validation: insecure permissions")]
    InsecurePermissions,

    /// A required path component was missing (e.g. a file with no parent dir).
    #[error("path failed security validation: invalid path")]
    InvalidPath,

    /// The process is not running with the required privileges (root).
    #[error("insufficient privileges: root is required")]
    NotRoot,

    /// A trusted-CA-keys entry was malformed or used a disallowed algorithm.
    ///
    /// The contained reason is a fixed, non-sensitive description.
    #[error("invalid TrustedUserCAKeys entry: {0}")]
    InvalidTrustedCa(TrustedCaError),

    /// The peer could not be reached over the socket, or the connection dropped.
    #[error("privileged helper socket is unavailable")]
    HelperUnavailable,

    /// A request or response violated the socket protocol (bad framing,
    /// oversized body, unsupported protocol version, or malformed JSON).
    #[error("helper protocol error")]
    HelperProtocol,

    /// A request was rejected as unauthenticated (missing or wrong capability
    /// token, or an empty token file). The token value is never included.
    #[error("helper rejected the request: unauthenticated")]
    HelperUnauthenticated,

    /// `sshd -t` rejected the candidate configuration. The offending detail is
    /// logged, never included here.
    #[error("sshd configuration validation failed")]
    SshdValidationFailed,

    /// `sshd` was not active after a reload, or the service query failed.
    #[error("sshd is not active")]
    SshdInactive,
}

/// Fixed, non-sensitive reasons a `TrustedUserCAKeys` entry can be rejected.
///
/// A closed enum (rather than a free-form string) keeps rejection reasons
/// auditable and guarantees no caller-controlled or path data leaks into an
/// error message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TrustedCaError {
    /// The entry was empty or contained only whitespace.
    Empty,
    /// The entry did not have the expected `<algorithm> <base64>[ comment]`
    /// shape.
    Malformed,
    /// The key algorithm is not in the allow-list.
    DisallowedAlgorithm,
    /// The key blob was not valid base64.
    InvalidEncoding,
    /// The entry contained control characters or a NUL byte.
    IllegalCharacter,
}

impl fmt::Display for TrustedCaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::Empty => "entry is empty",
            Self::Malformed => "entry is malformed",
            Self::DisallowedAlgorithm => "key algorithm is not allowed",
            Self::InvalidEncoding => "key data is not valid base64",
            Self::IllegalCharacter => "entry contains illegal characters",
        };
        f.write_str(msg)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    /// Every error's user-facing message must be free of filesystem paths.
    #[test]
    fn display_never_contains_paths() {
        let sensitive = "/etc/ssh/mayfly/trusted_user_ca_keys";
        let errors = [
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                sensitive,
            )),
            Error::UnexpectedSymlink,
            Error::InsecureOwnership,
            Error::InsecurePermissions,
            Error::InvalidPath,
            Error::NotRoot,
            Error::InvalidTrustedCa(TrustedCaError::DisallowedAlgorithm),
            Error::HelperUnavailable,
            Error::HelperProtocol,
            Error::HelperUnauthenticated,
            Error::SshdValidationFailed,
            Error::SshdInactive,
        ];
        for err in errors {
            let shown = err.to_string();
            assert!(
                !shown.contains('/'),
                "error message leaked a path-like value: {shown:?}"
            );
            assert!(
                !shown.contains(sensitive),
                "error message leaked sensitive context: {shown:?}"
            );
        }
    }

    #[test]
    fn trusted_ca_error_messages_are_stable() {
        assert_eq!(TrustedCaError::Empty.to_string(), "entry is empty");
        assert_eq!(
            TrustedCaError::DisallowedAlgorithm.to_string(),
            "key algorithm is not allowed"
        );
    }

    #[test]
    fn io_source_is_preserved_for_diagnostics() {
        let err = Error::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "denied",
        ));
        assert!(std::error::Error::source(&err).is_some());
    }
}
