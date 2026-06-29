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
| `InstallSshdDropin` | write `/etc/ssh/sshd_config.d/90-mayfly.conf`, validate (`sshd -t`), reload |
| `ApplyTrustedCaKeys` | atomically replace `TrustedUserCAKeys`, validate, reload, verify — **rollback on any failure** |
| `VerifyState` | check the managed files' perms/ownership and that `sshd` is healthy |

The rollback-safe apply workflow:

```
validate content → write temp → fsync → atomic rename → sshd -t → reload → verify active → commit
  └─ on ANY failure: restore previous file → reload → verify   (the host is never left with an
     sshd config that sshd rejected)
```

## Architecture

```
ProtocolServer (server.rs)
  └─ Authentication (protocol version + constant-time capability token)
      └─ Operation Dispatcher (ops.rs)
          └─ Host Services (security.rs atomic FS, ssh/ rendering+parsing)
              └─ Filesystem / systemd (sshd_control.rs — the only exec seam)
```

No business logic lives above Host Services.

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

1. **OS permissions** — the socket at `/run/mayfly/helper.sock` is `0660 root:mayfly`; only root and
   the `mayfly` group may connect.
2. **Capability token** — a 32-byte random secret (`/etc/mayfly-agent/helper.token`, `0640`
   root:mayfly) is present in every request and compared in **constant time**.
3. **Kernel peer credentials (`SO_PEERCRED`) uid pinning** — planned hardening (BL-016).

The helper never returns file contents, paths, tokens, or secrets in responses or logs. See
[ADR-0008](docs/ADR-0008-privileged-helper-and-ipc.md) for the full security rationale, including the
single sanctioned exception to the no-shell-outs rule (`sshd -t`, `systemctl reload/is-active`).

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
| `MAYFLY_HELPER_SOCKET_GID` | (unset; systemd sets the group via a setgid `RuntimeDirectory`) |
| `MAYFLY_HELPER_TRUSTED_CA_PATH` | `/etc/ssh/mayfly/trusted_user_ca_keys` |
| `MAYFLY_HELPER_DROPIN_PATH` | `/etc/ssh/sshd_config.d/90-mayfly.conf` |
| `MAYFLY_HELPER_MAIN_SSHD_CONFIG` | `/etc/ssh/sshd_config` |
| `MAYFLY_HELPER_SSHD_BINARY` | `/usr/sbin/sshd` |
| `MAYFLY_HELPER_SYSTEMCTL_BINARY` | `/usr/bin/systemctl` |
| `MAYFLY_HELPER_SERVICE_NAME` | `ssh` |
| `RUST_LOG` | `info` |

## License

Apache-2.0. See [LICENSE](LICENSE).
