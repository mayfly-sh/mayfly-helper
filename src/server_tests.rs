//! Tests for the UDS server: the pure auth/dispatch decision ([`HelperServer::evaluate`])
//! and the live socket lifecycle (bind, stale-socket cleanup, non-socket guard,
//! round-trips, malformed input, and concurrent clients).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use super::*;
use crate::ops::{HelperOps, OpsConfig};
use crate::protocol::{self, Operation, Request, Response};

const TOKEN: &str = "correct-horse-battery-staple";

/// A trivially healthy `SshdControl` (the socket tests only exercise `Ping`,
/// which never touches `sshd` or the filesystem).
struct MockSshd;

impl SshdControl for MockSshd {
    fn validate_config(&self) -> Result<()> {
        Ok(())
    }
    fn reload(&self) -> Result<()> {
        Ok(())
    }
    fn is_active(&self) -> Result<()> {
        Ok(())
    }
}

fn ops_in(dir: &std::path::Path) -> HelperOps<MockSshd> {
    HelperOps::new(
        OpsConfig {
            trusted_ca_path: dir.join("etc/ssh/mayfly/trusted_user_ca_keys"),
            dropin_path: dir.join("etc/ssh/sshd_config.d/90-mayfly.conf"),
            main_sshd_config: dir.join("etc/ssh/sshd_config"),
        },
        MockSshd,
    )
}

fn server_at(dir: &std::path::Path) -> HelperServer<MockSshd> {
    HelperServer::new(dir.join("helper.sock"), TOKEN.to_string(), ops_in(dir))
}

fn connect(path: &std::path::Path) -> UnixStream {
    for _ in 0..400 {
        if let Ok(stream) = UnixStream::connect(path) {
            return stream;
        }
        thread::sleep(Duration::from_millis(5));
    }
    panic!("server socket did not become connectable");
}

fn round_trip(path: &std::path::Path, request: &Request) -> Response {
    let mut stream = connect(path);
    let body = protocol::encode_request(request).unwrap();
    protocol::write_frame(&mut stream, &body).unwrap();
    let resp = protocol::read_frame(&mut stream).unwrap();
    protocol::decode_response(&resp).unwrap()
}

/// Run a server on a background thread; returns the stop flag + join handle.
fn spawn(server: HelperServer<MockSshd>) -> (Arc<AtomicBool>, thread::JoinHandle<()>) {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_thread = Arc::clone(&stop);
    let handle = thread::spawn(move || {
        server.run(&stop_for_thread).expect("server.run");
    });
    (stop, handle)
}

// --- Pure decision (`evaluate`) -------------------------------------------

#[test]
fn evaluate_accepts_valid_ping() {
    let dir = tempfile::tempdir().unwrap();
    let server = server_at(dir.path());
    let resp = server.evaluate(None, &Request::new(TOKEN, Operation::Ping));
    assert!(resp.ok);
}

#[test]
fn evaluate_rejects_unsupported_version() {
    let dir = tempfile::tempdir().unwrap();
    let server = server_at(dir.path());
    let mut req = Request::new(TOKEN, Operation::Ping);
    req.protocol_version = PROTOCOL_VERSION + 1;
    let resp = server.evaluate(None, &req);
    assert!(!resp.ok);
    assert_eq!(resp.detail.as_deref(), Some("unsupported protocol version"));
}

#[test]
fn evaluate_rejects_bad_token() {
    let dir = tempfile::tempdir().unwrap();
    let server = server_at(dir.path());
    let resp = server.evaluate(None, &Request::new("wrong-token", Operation::Ping));
    assert!(!resp.ok);
    assert_eq!(resp.detail.as_deref(), Some("unauthenticated"));
}

#[test]
fn evaluate_enforced_rejects_disallowed_peer() {
    let dir = tempfile::tempdir().unwrap();
    let server = server_at(dir.path()).with_peer_policy(PeerPolicy::enforced(vec![1000]));
    let intruder = PeerCred {
        uid: 1234,
        gid: 1234,
        pid: 9,
    };
    let resp = server.evaluate(Some(&intruder), &Request::new(TOKEN, Operation::Ping));
    assert!(!resp.ok);
    assert_eq!(resp.detail.as_deref(), Some("peer not authorized"));
}

#[test]
fn evaluate_enforced_admits_allowed_peer() {
    let dir = tempfile::tempdir().unwrap();
    let server = server_at(dir.path()).with_peer_policy(PeerPolicy::enforced(vec![1000]));
    let agent = PeerCred {
        uid: 1000,
        gid: 1000,
        pid: 9,
    };
    let resp = server.evaluate(Some(&agent), &Request::new(TOKEN, Operation::Ping));
    assert!(resp.ok);
}

#[test]
fn evaluate_enforced_fails_closed_without_peer_cred() {
    let dir = tempfile::tempdir().unwrap();
    let server = server_at(dir.path()).with_peer_policy(PeerPolicy::enforced(vec![1000]));
    // Pinning required but credentials unreadable -> reject.
    let resp = server.evaluate(None, &Request::new(TOKEN, Operation::Ping));
    assert!(!resp.ok);
    assert_eq!(resp.detail.as_deref(), Some("peer credentials unavailable"));
}

#[test]
fn evaluate_unenforced_admits_without_peer_cred() {
    let dir = tempfile::tempdir().unwrap();
    let server = server_at(dir.path()); // unenforced by default
    let resp = server.evaluate(None, &Request::new(TOKEN, Operation::Ping));
    assert!(resp.ok);
}

// --- Socket lifecycle ------------------------------------------------------

#[test]
fn bind_refuses_non_socket_path() {
    let dir = tempfile::tempdir().unwrap();
    let server = server_at(dir.path());
    // Place a regular file where the socket should go; bind must refuse it
    // rather than delete it.
    std::fs::write(dir.path().join("helper.sock"), b"not a socket").unwrap();
    assert!(matches!(server.bind().unwrap_err(), Error::InvalidPath));
    // The file is untouched.
    assert!(dir.path().join("helper.sock").exists());
}

#[test]
fn bind_replaces_stale_socket() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("helper.sock");
    // Create a stale socket and drop the listener; the file remains.
    let stale = UnixListener::bind(&path).unwrap();
    drop(stale);
    assert!(std::fs::symlink_metadata(&path).is_ok());

    let server = server_at(dir.path());
    let listener = server.bind().expect("rebind over stale socket");
    drop(listener);
}

#[test]
fn round_trip_ping_returns_version() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("helper.sock");
    let (stop, handle) = spawn(server_at(dir.path()));

    let resp = round_trip(&path, &Request::new(TOKEN, Operation::Ping));
    assert!(resp.ok);
    assert_eq!(
        resp.helper_version.as_deref(),
        Some(env!("CARGO_PKG_VERSION"))
    );

    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    handle.join().unwrap();
    // The socket file is cleaned up on shutdown.
    assert!(!path.exists());
}

#[test]
fn round_trip_rejects_bad_token_over_socket() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("helper.sock");
    let (stop, handle) = spawn(server_at(dir.path()));

    let resp = round_trip(&path, &Request::new("nope", Operation::Ping));
    assert!(!resp.ok);
    assert_eq!(resp.detail.as_deref(), Some("unauthenticated"));

    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    handle.join().unwrap();
}

#[test]
fn malformed_frame_gets_protocol_error_response() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("helper.sock");
    let (stop, handle) = spawn(server_at(dir.path()));

    let mut stream = connect(&path);
    // A valid frame whose body is not a valid request.
    protocol::write_frame(&mut stream, b"this is not json").unwrap();
    let resp = protocol::read_frame(&mut stream).unwrap();
    let resp = protocol::decode_response(&resp).unwrap();
    assert!(!resp.ok);
    assert_eq!(resp.detail.as_deref(), Some("protocol error"));

    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    handle.join().unwrap();
}

#[test]
fn concurrent_clients_are_all_served() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("helper.sock");
    let (stop, handle) = spawn(server_at(dir.path()));
    // Make sure the socket is up before fanning out.
    let _ = connect(&path);

    let mut workers = Vec::new();
    for _ in 0..8 {
        let p = path.clone();
        workers.push(thread::spawn(move || {
            round_trip(&p, &Request::new(TOKEN, Operation::Ping)).ok
        }));
    }
    let oks = workers
        .into_iter()
        .map(|w| w.join().unwrap())
        .filter(|&ok| ok)
        .count();
    assert_eq!(oks, 8);

    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    handle.join().unwrap();
}
