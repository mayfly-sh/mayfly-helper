//! The `mayfly-helper` Unix Domain Socket server.
//!
//! Binds a stream socket (restricted to mode `0660`), accepts one request per
//! connection, authenticates it (three independent factors: kernel peer-uid
//! pinning via `SO_PEERCRED`, the protocol version, and a constant-time
//! capability token), dispatches to [`HelperOps`], and replies with a single
//! framed [`Response`]. The accept loop is interruptible via a shared stop flag
//! so the process can shut down cleanly on `SIGTERM`/`SIGINT`.
//!
//! The loop is deliberately **single-threaded**: it handles one connection to
//! completion before accepting the next, which serialises privileged operations
//! (never two concurrent `ApplyTrustedCaKeys`) and removes a class of
//! concurrency bugs from the root process. A per-connection read/write timeout
//! bounds a stalled peer so it cannot pin the loop.
//!
//! Authentication failures receive an explicit (non-sensitive) response and the
//! connection is closed; the helper never performs an operation for a request it
//! has not authenticated. Every request is logged with a correlation id, the
//! kernel-reported peer uid/gid/pid, the operation, the outcome, and the
//! duration — and never the token, file contents, or any path.

use std::io::Read;
use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::errors::{Error, Result};
use crate::ops::HelperOps;
use crate::peercred::{self, PeerCred, PeerPolicy};
use crate::protocol::{self, Outcome, Request, Response, MAX_BODY_BYTES, PROTOCOL_VERSION};
use crate::sshd_control::SshdControl;

/// Socket file permission bits: owner+group read/write, no access for others.
const SOCKET_MODE: u32 = 0o660;

/// How long to nap between accept polls while idle (keeps shutdown responsive).
const ACCEPT_POLL: Duration = Duration::from_millis(100);

/// Per-connection read/write timeout, so a stalled peer cannot pin a slot.
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Process-local monotonic request counter, used only to correlate the log
/// lines of a single request. Not security-sensitive.
static REQUEST_SEQ: AtomicU64 = AtomicU64::new(1);

/// The privileged socket server.
pub struct HelperServer<C: SshdControl> {
    socket_path: PathBuf,
    token: String,
    ops: HelperOps<C>,
    socket_gid: Option<u32>,
    peer_policy: PeerPolicy,
}

impl<C: SshdControl> HelperServer<C> {
    /// Construct a server that will listen at `socket_path`, authenticate with
    /// `token`, and execute `ops`. Peer-uid pinning is disabled by default; call
    /// [`with_peer_policy`](Self::with_peer_policy) to enforce it.
    pub fn new(socket_path: PathBuf, token: String, ops: HelperOps<C>) -> Self {
        Self {
            socket_path,
            token,
            ops,
            socket_gid: None,
            peer_policy: PeerPolicy::unenforced(),
        }
    }

    /// Set the group (by numeric gid) that should own the socket file so the
    /// unprivileged agent's group can connect (mode `0660`). When unset, the
    /// socket keeps its default group (e.g. set via a setgid `RuntimeDirectory`).
    pub fn with_socket_group(mut self, gid: Option<u32>) -> Self {
        self.socket_gid = gid;
        self
    }

    /// Set the kernel peer-credential policy (`SO_PEERCRED` uid pinning).
    pub fn with_peer_policy(mut self, policy: PeerPolicy) -> Self {
        self.peer_policy = policy;
        self
    }

    /// Bind the socket and serve until `stop` becomes `true`.
    ///
    /// A stale socket from a previous run is removed and recreated, and the
    /// socket's permissions are tightened to [`SOCKET_MODE`] before any request
    /// is accepted. If the socket path already holds a **non-socket** file, the
    /// helper refuses to start rather than delete it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the socket cannot be bound or its permissions
    /// set, or [`Error::InvalidPath`] if the path holds a non-socket file.
    pub fn run(&self, stop: &AtomicBool) -> Result<()> {
        let listener = self.bind()?;
        listener.set_nonblocking(true).map_err(Error::Io)?;
        tracing::info!(
            peer_uid_pinning = self.peer_policy.is_enforced(),
            "mayfly-helper listening"
        );

        while !stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _addr)) => {
                    if let Err(err) = self.handle_connection(stream) {
                        tracing::warn!(error = %err, "helper connection error");
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(ACCEPT_POLL);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "helper accept failed");
                    std::thread::sleep(ACCEPT_POLL);
                }
            }
        }

        tracing::info!("mayfly-helper shutting down");
        let _ = std::fs::remove_file(&self.socket_path);
        Ok(())
    }

    fn bind(&self) -> Result<UnixListener> {
        if let Some(parent) = self.socket_path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                std::fs::create_dir_all(parent).map_err(Error::Io)?;
            }
        }
        // Remove a stale socket so bind does not fail with EADDRINUSE — but only
        // if it really is a socket. Refuse to clobber a regular file/symlink
        // that someone placed (or mis-configured) at the socket path.
        match std::fs::symlink_metadata(&self.socket_path) {
            Ok(meta) if meta.file_type().is_socket() => {
                std::fs::remove_file(&self.socket_path).map_err(Error::Io)?;
            }
            Ok(_) => {
                tracing::error!("socket path exists and is not a socket; refusing to start");
                return Err(Error::InvalidPath);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::Io(e)),
        }
        let listener = UnixListener::bind(&self.socket_path).map_err(Error::Io)?;
        if let Some(gid) = self.socket_gid {
            std::os::unix::fs::chown(&self.socket_path, None, Some(gid)).map_err(Error::Io)?;
        }
        set_socket_mode(&self.socket_path)?;
        Ok(listener)
    }

    /// Read one request, authenticate (peer creds + version + token), dispatch,
    /// reply, and emit one audit log line.
    fn handle_connection(&self, mut stream: UnixStream) -> Result<()> {
        let started = Instant::now();
        let req_id = REQUEST_SEQ.fetch_add(1, Ordering::Relaxed);

        stream
            .set_read_timeout(Some(IO_TIMEOUT))
            .map_err(Error::Io)?;
        stream
            .set_write_timeout(Some(IO_TIMEOUT))
            .map_err(Error::Io)?;

        // Kernel-reported peer credentials (Linux). `None` only on platforms
        // without `SO_PEERCRED`; the enforcement decision in `evaluate` treats a
        // missing credential as fail-closed when pinning is enabled.
        let peer = peercred::peer_cred(&stream).ok();

        let (response, op, proto) = match self.read_request(&mut stream) {
            Ok(request) => {
                let op = Some(request.op);
                let proto = Some(request.protocol_version);
                (self.evaluate(peer.as_ref(), &request), op, proto)
            }
            Err(_) => (
                Response::failure(Outcome::Unhealthy, "protocol error"),
                None,
                None,
            ),
        };

        self.audit(req_id, peer.as_ref(), op, proto, &response, started);

        let body = protocol::encode_response(&response)?;
        protocol::write_frame(&mut stream, &body)
    }

    fn read_request(&self, stream: &mut impl Read) -> Result<Request> {
        let body = protocol::read_frame(stream)?;
        if body.len() > MAX_BODY_BYTES {
            return Err(Error::HelperProtocol);
        }
        protocol::decode_request(&body)
    }

    /// Pure authentication + dispatch decision. Order: peer-uid pinning, then
    /// protocol version, then the capability token, then the operation. Kept
    /// side-effect-free (no I/O) so every rejection path is unit-testable.
    fn evaluate(&self, peer: Option<&PeerCred>, request: &Request) -> Response {
        match peer {
            Some(cred) if self.peer_policy.authorize(cred).is_err() => {
                return Response::failure(Outcome::Unhealthy, "peer not authorized");
            }
            None if self.peer_policy.is_enforced() => {
                // Pinning is required but the kernel credential is unreadable.
                return Response::failure(Outcome::Unhealthy, "peer credentials unavailable");
            }
            _ => {}
        }

        if request.protocol_version != PROTOCOL_VERSION {
            return Response::failure(Outcome::Unhealthy, "unsupported protocol version");
        }
        if !protocol::constant_time_eq(request.token.as_bytes(), self.token.as_bytes()) {
            return Response::failure(Outcome::Unhealthy, "unauthenticated");
        }
        self.ops.dispatch(request)
    }

    /// Emit exactly one structured audit line per connection. Includes the
    /// correlation id, the request's protocol version (when it parsed), the
    /// kernel peer uid/gid/pid, operation, outcome, success, and duration — never
    /// the token, file contents, or a path.
    fn audit(
        &self,
        req_id: u64,
        peer: Option<&PeerCred>,
        op: Option<crate::protocol::Operation>,
        protocol_version: Option<u32>,
        response: &Response,
        started: Instant,
    ) {
        let duration_ms = started.elapsed().as_millis();
        let (uid, gid, pid) = peer.map_or((None, None, None), |c| {
            (Some(c.uid), Some(c.gid), Some(c.pid))
        });
        if response.ok {
            tracing::info!(
                req_id,
                protocol_version,
                peer_uid = uid,
                peer_gid = gid,
                peer_pid = pid,
                op = ?op,
                outcome = ?response.outcome,
                success = response.ok,
                duration_ms,
                "helper request"
            );
        } else {
            tracing::warn!(
                req_id,
                protocol_version,
                peer_uid = uid,
                peer_gid = gid,
                peer_pid = pid,
                op = ?op,
                outcome = ?response.outcome,
                success = response.ok,
                detail = response.detail.as_deref(),
                duration_ms,
                "helper request rejected"
            );
        }
    }
}

/// Tighten the socket file's permissions to [`SOCKET_MODE`].
fn set_socket_mode(path: &Path) -> Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(SOCKET_MODE)).map_err(Error::Io)
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;
