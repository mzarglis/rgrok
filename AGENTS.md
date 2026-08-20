# AGENTS.md - rgrok Development Guide

This file provides guidance for AI agents working on the rgrok codebase.

## Project Overview

rgrok is a self-hosted ngrok alternative written in Rust. It exposes local servers via a public VPS using WebSocket+TLS as transport and yamux for stream multiplexing.

- **Prerequisites:** Rust 1.88+ (install via rustup)
- **License:** AGPL-3.0-only
- **Repository:** https://github.com/mzarglis/rgrok

## Build Commands

```bash
# Build all crates
cargo build --locked

# Build release binary
cargo build --release --locked

# Fast type-check without codegen
cargo check --all-targets --locked
```

## Lint Commands

```bash
# Run clippy lints (CI enforces zero warnings)
cargo clippy --all-targets -- -D warnings

# Check formatting (CI enforces this)
cargo fmt --all -- --check

# Format code
cargo fmt --all
```

## Test Commands

```bash
# Run all tests
cargo test --all

# Run a single test by name
cargo test test_name

# Run tests for a specific crate
cargo test -p rgrok-proto
cargo test -p rgrok-server
cargo test -p rgrok-client
```

Note: Integration tests in `crates/rgrok-server/src/main.rs` spin up a real in-process server. No external services required.

## Running Server and Client

```bash
# Server (requires config)
cargo run -p rgrok-server -- --config config/server.example.toml

# Generate auth token
cargo run -p rgrok-server -- --config config/server.example.toml token generate --label dev

# Client
cargo run -p rgrok-client -- http 8080
cargo run -p rgrok-client -- https 8443
cargo run -p rgrok-client -- tcp 22
cargo run -p rgrok-client -- authtoken <token>
```

The client uses encrypted `wss://` control transport by default and reconnects established
tunnels after transient failures. Set `[server].insecure = true` only when intentionally
connecting to a local development server that has no TLS listener. Random HTTP subdomains and
TCP ports are pinned after their first assignment so reconnects keep the same public endpoint.

## Workspace Structure

```
crates/
  rgrok-proto/    # Shared protocol: messages, framing, transport (no I/O)
  rgrok-server/   # VPS daemon — TLS termination, tunnel manager, HTTP proxy
  rgrok-client/   # CLI tool (binary: rgrok)
```

Dependency graph:
- rgrok-proto (no dependencies on other crates)
- rgrok-server depends on rgrok-proto
- rgrok-client depends on rgrok-proto

## Code Style Guidelines

### Formatting
- Use `cargo fmt` (enforced by CI). No manual exceptions.

### Lints
- Use `cargo clippy -- -D warnings` (enforced by CI)
- Fix all warnings before opening a PR
- Do not suppress with `#[allow(...)]` unless there's a compelling reason with a comment explaining it

### Error Handling
- Library crate (`rgrok-proto`): use `thiserror` with typed error enums
- Application crates (`rgrok-server`, `rgrok-client`): use `anyhow` with `.context("...")` for ergonomic error propagation

### Async
- Use `tokio` for async runtime
- Avoid blocking calls on async tasks; use `tokio::task::spawn_blocking` for CPU-bound work

### Logging
- Use `tracing` macros (`tracing::info!`, `tracing::debug!`, etc.)
- Prefer structured fields over format strings: `tracing::info!(tunnel_id = %id, "tunnel opened")`
- Log level controlled by `RUST_LOG` env var (e.g., `RUST_LOG=debug`)

### Comments
- Code should be self-explanatory where possible
- Add comments for non-obvious invariants or protocol decisions, not for restating what the code does

### Naming Conventions
- Standard Rust naming: camelCase for types, snake_case for functions/variables
- Serde fields use snake_case: `#[serde(rename_all = "snake_case")]`
- Enum variants use snake_case in serialized form

### Imports
- Group imports by module: std, external crates, local crates
- Use glob imports for re-exports in lib.rs (e.g., `pub use messages::*;`)

### Testing
- **Unit tests:** live in `#[cfg(test)]` modules within the relevant source file
- **Integration tests:** the server crate contains end-to-end tests that run a real in-process server
- All tests must pass before a PR is ready for review
- Tests should be deterministic; use `tokio::time::timeout` to prevent hangs rather than fixed sleeps

## Key Files

- `crates/rgrok-proto/src/messages.rs` — all protocol message types
- `crates/rgrok-proto/src/transport.rs` — framing/codec
- `crates/rgrok-proto/src/errors.rs` — typed errors (thiserror)
- `crates/rgrok-server/src/tunnel_manager.rs` — tunnel lifecycle
- `crates/rgrok-server/src/proxy.rs` — public HTTP→tunnel routing
- `crates/rgrok-server/src/tls.rs` — TLS + ACME logic
- `crates/rgrok-server/src/web_ui.rs` — request inspection web UI
- `crates/rgrok-server/src/metrics.rs` — Prometheus metrics endpoint
- `crates/rgrok-server/src/control.rs` — authenticated control sessions and tunnel registration
- `crates/rgrok-client/src/tunnel.rs` — client-side tunnel establishment
- `crates/rgrok-client/src/local_proxy.rs` — proxies public traffic to local port
- `crates/rgrok-client/src/cli.rs` — CLI argument parsing

## Configuration

- **Server:** `/etc/rgrok/server.toml` (copy from `config/server.example.toml`)
- **Client:** `~/.config/rgrok/config.toml` (auto-created by `rgrok authtoken`)
- **JWT secret:** generate with `openssl rand -hex 32`

Important server settings:

- `server.max_tunnels` includes active and in-flight HTTP/TCP registrations.
- `server.tunnel_idle_timeout_secs` closes tunnels with no active streams after the configured period.
- `server.max_request_body_bytes` and `server.max_response_body_bytes` bound public proxy buffering.
- `auth.tokens`, when non-empty, is an allowlist in addition to JWT signature validation.
- `cloudflare.per_tunnel_dns = true` requires Cloudflare credentials and `server.public_ip`.
- `inspect.ui_auth_token` is required when the server inspection UI binds off loopback. Inspection
  captures redact credential-bearing headers, bound body retention, require CSRF protection, and
  reject DNS-rebinding Host headers on loopback.

The client `[defaults].max_body_bytes` setting bounds inspection capture and replay-response
retention. Replays of requests whose bodies were truncated are rejected because they cannot be
reproduced faithfully.

## Git Commit Conventions

All commits to `main` go through pull requests (branch protection enforced). PRs are squash-merged.

PR titles must follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>[optional scope][!]: <description>
```

| Type | Description |
|---|---|
| `feat:` | New feature |
| `feat!:` | Breaking change |
| `fix:` | Bug fix |
| `perf:` | Performance improvement |
| `refactor:` | Code refactoring |
| `docs:` | Documentation only |
| `chore:` | Maintenance |
| `ci:` | CI/CD changes |
| `test:` | Tests only |
| `build:` | Build system |

## CI Requirements

All of these must pass before merging:
```bash
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets -- -D warnings
cargo test --all
```

## Gotchas

- **SIGHUP (Linux only):** Reloads only the `auth.revoked_jtis` blocklist and disconnects sessions
  whose JTIs become revoked; it does not reload the full config. Windows requires a restart.
- **Dev mode (no TLS):** The server control plane can start without TLS if no certificate files
  exist and Cloudflare ACME is not configured. Clients must explicitly set `server.insecure = true`.
- **`per_tunnel_dns = false` (recommended):** Use a wildcard `*.tunnel.domain.com` DNS A record instead of per-tunnel records.
- **TCP teardown:** A released port remains reserved until its listener confirms shutdown; do not
  bypass the owner-aware tunnel-manager cleanup helpers.
- **HTTP framing:** The public proxy de-frames local responses, strips hop-by-hop headers, rejects
  unsupported transfer codings, and enforces configured request/response limits.

## Deployment

- Docker: `deploy/Dockerfile`
- Docker runs as the unprivileged `rgrok` user and deliberately ships no default auth secret.
  Mount a readable operator-managed config at `/etc/rgrok/server.toml`; the entrypoint exits if it
  is missing.
- Systemd: `deploy/rgrok-server.service`
- CI/CD: `.github/workflows/ci.yml`, `.github/workflows/release.yml`
