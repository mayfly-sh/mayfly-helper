# mayfly-helper

The **privileged** component of the Mayfly platform. `mayfly-helper` runs as **root** and does
nothing but perform a small, explicit set of OpenSSH host operations on behalf of the unprivileged
`mayfly-agent`, over an authenticated Unix Domain Socket.

```
mayfly-server  ──HTTPS──▶  mayfly-agent (unprivileged)  ──UDS──▶  mayfly-helper (root)  ──▶  host OS
```

It is **not** a remote-management agent. It has no network stack, does no enrollment, verifies no
certificates or bundle signatures, schedules nothing, and makes no authorization decisions. Those are
the agent's and server's jobs. The helper is a privileged *execution service* only.

## Responsibilities (the entire allow-list)

Every socket request maps 1:1 to one reviewed action — there is no generic filesystem facility and no
"run command" operation:

| Operation | What it does |
|-----------|--------------|
| `Ping` | liveness probe; returns the helper version |
| `EnsureDirectories` | create the managed dirs with safe ownership/permissions |
| `InstallSshdDropin` | write `/etc/ssh/sshd_config.d/90-mayfly.conf`, validate (`sshd -t`), reload — **rollback on any failure** |
| `ApplyTrustedCaKeys` | atomically replace `TrustedUserCAKeys`, validate, reload, verify — **rollback on any failure** |
| `VerifyState` | check the managed files' perms/ownership, that they **match the rendered expectation** (drop-in content, parseable trusted-CA), and that `sshd` is healthy — fail-closed |

The rollback-safe apply workflow:

```
validate content → write temp → fsync → atomic rename → sshd -t → reload → verify active → commit
  └─ on ANY failure: restore previous file → reload → verify   (the host is never left with an
     sshd config that sshd rejected)
```

## Architecture

```
ProtocolServer (server.rs)
  └─ Authentication (SO_PEERCRED uid pinning + protocol version + constant-time capability token)
      └─ Operation Dispatcher (ops.rs)
          └─ Host Services (security.rs atomic FS, ssh/ rendering+parsing)
              └─ Filesystem / systemd (sshd_control.rs — the only exec seam)
```

No business logic lives above Host Services. The accept loop is single-threaded by design: it
serialises privileged operations (never two concurrent `ApplyTrustedCaKeys`) and a per-connection
30s I/O timeout bounds a stalled peer. Every external sub-command (`sshd -t`,
`systemctl reload`/`is-active`) runs under a wall-clock timeout (default 15s,
`MAYFLY_HELPER_SSHD_TIMEOUT_SECS`); a child that overruns is killed and reaped and the operation
fails fail-closed, so a hung `sshd`/`systemctl` can never pin the root process.

## IPC protocol

`mayfly-helper` **owns** the agent↔helper IPC protocol (canonical definition: `src/protocol.rs`,
specified in [`docs/helper-socket.json`](docs/helper-socket.json)). The agent carries a byte-identical
copy in its own `ipc` module. The wire format is versioned (`PROTOCOL_VERSION = 1`): length-prefixed
(`u32` BE) compact JSON, body capped at 1 MiB.

> Until a shared protocol crate exists (see [ADR-0009](docs/ADR-0009-extract-helper-repository.md),
> tracked as BL-017), the protocol and a few audited primitives (`security`, `ssh/*`) are duplicated
> byte-for-byte between this repo and `mayfly-agent`. The contract is the single source of truth both
> copies must satisfy.

## Trust boundaries

Three independent authentication factors, checked in order before any operation runs:

1. **OS permissions** — the socket at `/run/mayfly/helper.sock` is `0660 root:mayfly`; only root and
   the `mayfly` group may connect.
2. **Kernel peer credentials (`SO_PEERCRED`)** — the helper reads the connecting process's
   kernel-verified **uid** and pins it to an allow-list (the agent's uid + root). Configured via
   `MAYFLY_HELPER_ALLOWED_UID` (the installer sets it); fail-closed when enforced, and disabled with
   a startup warning when unset. See [ADR-0011](docs/ADR-0011-peer-credential-authentication.md).
3. **Capability token** — a 32-byte random secret (`/etc/mayfly-agent/helper.token`, `0640`
   root:mayfly) is present in every request and compared in **constant time**. The helper also
   validates the token file is a non-symlink, root-owned, and mode ≤ `0640` before trusting it, and
   refuses to start if the token is empty or shorter than 32 characters.

The helper never returns file contents, paths, tokens, or secrets in responses or logs. Each request
is logged once with a correlation id, the request `protocol_version`, the kernel peer uid/gid/pid,
the operation, outcome, and duration. See [ADR-0008](docs/ADR-0008-privileged-helper-and-ipc.md) for
the full security rationale, including the single sanctioned exception to the no-shell-outs rule
(`sshd -t`, `systemctl reload/is-active`).

### Threat model (summary)

| Adversary | Capability assumed | Mitigation |
|-----------|--------------------|------------|
| Unprivileged local user (not in `mayfly`) | can run code as their own uid | socket is `0660 root:mayfly`; cannot connect |
| Member of the `mayfly` group, wrong uid | can reach the socket | `SO_PEERCRED` uid pinning rejects any uid but the agent's (+root) |
| Process that reaches the socket without the secret | crafted IPC requests | constant-time capability-token check; unauthenticated requests do nothing |
| Replayed/old client | resends a captured frame | requests are idempotent and carry no time-varying state; the helper performs only declarative, convergent operations |
| Tampering with managed files out-of-band | edits `90-mayfly.conf` / trusted-CA file | `VerifyState` detects content drift; symlink/perm checks reject unsafe files; writes are atomic |
| Hostile/hung `sshd`/`systemctl` | stalls a privileged sub-command | per-command timeout kills+reaps the child; operation fails closed |
| Attacker who can write the token file | forges a valid token | token file must be non-symlink, root-owned, mode ≤ `0640`; a tamperable file is rejected at start-up |

Out of the helper's threat model (handled by the agent/server): network adversaries, bundle/cert
forgery, and authorization — the helper trusts that the agent already verified the signed bundle.

## Build

Pure Rust, no OpenSSL/native-tls, `#![forbid(unsafe_code)]`. Targets x86_64/aarch64/armv7/armv6 Linux
(musl static for release).

```sh
cargo build --release            # produces target/release/mayfly-helper
cargo test                       # unit tests (no root required)
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Deploy

Install the helper **before** the agent (it creates the shared `mayfly` user/group, the capability
token, and the managed directories):

```sh
sudo BINDIR=/path/to/built/binary ./deploy/install.sh
# then install mayfly-agent from its own repository
```

`deploy/` contains:

- `systemd/mayfly-helper.service` — hardened root unit (runs `User=root Group=mayfly`).
- `sshd/90-mayfly.conf` — the managed drop-in template.
- `docker/systemctl-shim.sh` — a `systemctl` stand-in for non-systemd containers (e2e).
- `install.sh` / `uninstall.sh` — helper-only, idempotent.

## Configuration (environment)

| Variable | Default |
|----------|---------|
| `MAYFLY_HELPER_SOCKET_PATH` | `/run/mayfly/helper.sock` |
| `MAYFLY_HELPER_TOKEN_PATH` | `/etc/mayfly-agent/helper.token` |
| `MAYFLY_HELPER_ALLOWED_UID` | (unset → uid pinning disabled + warning; installer sets it to the `mayfly` uid) |
| `MAYFLY_HELPER_SOCKET_GID` | (unset; systemd sets the group via a setgid `RuntimeDirectory`) |
| `MAYFLY_HELPER_TRUSTED_CA_PATH` | `/etc/ssh/mayfly/trusted_user_ca_keys` |
| `MAYFLY_HELPER_DROPIN_PATH` | `/etc/ssh/sshd_config.d/90-mayfly.conf` |
| `MAYFLY_HELPER_MAIN_SSHD_CONFIG` | `/etc/ssh/sshd_config` |
| `MAYFLY_HELPER_SSHD_BINARY` | `/usr/sbin/sshd` |
| `MAYFLY_HELPER_SYSTEMCTL_BINARY` | `/usr/bin/systemctl` |
| `MAYFLY_HELPER_SERVICE_NAME` | `ssh` |
| `MAYFLY_HELPER_SSHD_TIMEOUT_SECS` | `15` (wall-clock bound per `sshd -t`/`systemctl` sub-command; `0`/invalid → default) |
| `RUST_LOG` | `info` |

## Operational guide

- **Service:** `systemctl status mayfly-helper` · logs via `journalctl -u mayfly-helper` (one JSON
  line per request: `req_id`, `peer_uid/gid/pid`, `op`, `outcome`, `duration_ms`).
- **Liveness:** the agent issues `Ping`; you can confirm the socket exists at
  `/run/mayfly/helper.sock` (`srw-rw---- root mayfly`).
- **Order:** install the helper **before** the agent; uninstall the agent **before** the helper.
- **Restart safety:** the helper removes a stale socket and rebinds on start; it refuses to start if
  a **non-socket** file occupies the socket path (it will not delete it).

### Capability token rotation

The token is read once at start-up (and validated: non-symlink, root-owned, mode ≤ `0640`, ≥ 32
chars). Rotation is deterministic and restart-based — there is no live-reload path to keep the
privileged surface minimal. The agent and helper must agree on the token, so rotate atomically:

```sh
# As root, on the host:
umask 077
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > /etc/mayfly-agent/helper.token.new
chown root:mayfly /etc/mayfly-agent/helper.token.new
chmod 0640        /etc/mayfly-agent/helper.token.new
mv /etc/mayfly-agent/helper.token.new /etc/mayfly-agent/helper.token   # atomic replace
systemctl restart mayfly-helper        # helper re-reads the token
systemctl restart mayfly-agent         # agent re-reads the same token
```

Because the agent and helper read the same file, a single atomic replace + restart of both keeps
them consistent. Re-running `deploy/install.sh` is a no-op for an existing non-empty token (it does
not rotate); rotate explicitly with the steps above.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Agent gets `unauthenticated` | wrong/missing token, or peer uid not allow-listed | confirm `/etc/mayfly-agent/helper.token` matches and the agent runs as the uid in `/etc/mayfly-agent/helper.env` (`MAYFLY_HELPER_ALLOWED_UID`) |
| Agent gets `peer credentials unavailable` | pinning enforced but `SO_PEERCRED` unreadable (not Linux / unusual socket) | run on Linux; this is fail-closed by design |
| Helper exits at startup | token file is a symlink / not root-owned / mode > `0640`, or not running as root | fix the token file perms (`chown root:mayfly`, `chmod 0640`); run as root |
| `sshd configuration validation failed` | `sshd -t` rejected the config, lacks `Include …/sshd_config.d/*.conf`, **or `sshd -t` timed out** | fix `sshd_config`; the helper rolls back and never leaves a config `sshd` rejects; raise `MAYFLY_HELPER_SSHD_TIMEOUT_SECS` only if `sshd -t` is legitimately slow |
| `sshd reload failed` | `systemctl reload` returned non-zero or timed out | check `journalctl -u ssh`/`-u sshd`; the helper rolls back the change |
| New CA not effective | drop-in inert (missing `Include`) | add `Include /etc/ssh/sshd_config.d/*.conf` to `/etc/ssh/sshd_config` |
| Helper exits at startup with "token is too short" | token file < 32 chars | rotate to a proper 32-byte token (see *Capability token rotation*) |

## License

Apache-2.0. See [LICENSE](LICENSE).
