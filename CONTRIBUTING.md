# Contributing to rgrok

Thanks for taking the time to contribute. This document covers how to get a development environment running, the project conventions, and the pull request process.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Code Style](#code-style)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Reporting Bugs](#reporting-bugs)
- [Requesting Features](#requesting-features)

## Getting Started

**Prerequisites:**
- Rust 1.75+ — install via [rustup](https://rustup.rs)
- A local server to tunnel to (any HTTP server on localhost works for testing)

**Clone and build:**
```bash
git clone https://github.com/your-org/rgrok
cd rgrok
cargo build
```

**Run the test suite:**
```bash
cargo test
```

The integration tests in `crates/rgrok-server/src/main.rs` spin up a real in-process server and run end-to-end against it. No external services required.

## Development Workflow

The workspace has three crates with a clear dependency graph:

```
rgrok-proto   (no I/O — shared types only)
    ↑
rgrok-server  (VPS daemon)
rgrok-client  (CLI)
```

When adding a new protocol message, start in `rgrok-proto`. When adding a new CLI flag, start in `rgrok-client/src/cli.rs`.

**Useful commands:**
```bash
cargo check --all-targets        # Fast type-check without codegen
cargo test --all                 # Run all tests
cargo clippy --all-targets       # Lint (CI enforces zero warnings)
cargo fmt --all                  # Format (CI enforces this)
RUST_LOG=debug cargo run -p rgrok-server -- --config config/server.example.toml
```

**Running server + client locally (no TLS):**

The server starts the control plane without TLS when no cert files are configured and Cloudflare ACME credentials are absent. This is the easiest way to iterate locally:

```bash
# Terminal 1 — server (dev mode, no TLS)
cargo run -p rgrok-server -- --config config/server.example.toml

# Terminal 2 — generate a token
cargo run -p rgrok-server -- --config config/server.example.toml token generate --label dev

# Terminal 3 — client
rgrok authtoken <token-from-above>
rgrok http 8080
```

## Code Style

- **Formatting:** `cargo fmt` (enforced by CI). No manual exceptions.
- **Lints:** `cargo clippy -- -D warnings` (enforced by CI). Fix all warnings before opening a PR; do not suppress with `#[allow(...)]` unless there is a compelling reason with a comment explaining it.
- **Errors:**
  - Library crate (`rgrok-proto`): use `thiserror` with typed error enums.
  - Application crates (`rgrok-server`, `rgrok-client`): use `anyhow` with `.context("...")` for ergonomic error propagation.
- **Async:** `tokio`. Avoid blocking calls on async tasks; use `tokio::task::spawn_blocking` for CPU-bound work.
- **Logging:** use `tracing` macros (`tracing::info!`, `tracing::debug!`, etc.). Prefer structured fields over format strings: `tracing::info!(tunnel_id = %id, "tunnel opened")`.
- **Comments:** code should be self-explanatory where possible. Add comments for non-obvious invariants or protocol decisions, not for restating what the code does.

## Testing

- **Unit tests:** live in `#[cfg(test)]` modules within the relevant source file.
- **Integration tests:** the server crate contains end-to-end tests that run a real in-process server. Add tests here when touching protocol or tunnel lifecycle logic.
- All tests must pass (`cargo test --all`) before a PR is ready for review.
- Tests should be deterministic. Use `tokio::time::timeout` to prevent hangs rather than fixed sleeps.

## Submitting Changes

1. **Fork** the repository and create a branch from `main`:
   ```bash
   git checkout -b feat/my-feature
   ```

2. **Make your changes.** Keep commits focused — one logical change per commit. Write clear commit messages in the imperative mood: `Add TCP tunnel idle timeout` not `Added timeout stuff`.

3. **Ensure CI passes locally:**
   ```bash
   cargo fmt --all -- --check
   cargo clippy --all-targets -- -D warnings
   cargo test --all
   ```

4. **Open a pull request** against `main`. Fill in the PR template: describe what changed and why, and include a brief testing plan.

5. **Review:** a maintainer will review within a few days. Address feedback in new commits (don't force-push during review); they'll be squashed on merge if needed.

### What makes a good PR

- **Minimal scope.** A PR that does one thing is easier to review and less likely to introduce regressions.
- **Tests included.** New behavior should have a test. Bug fixes should include a test that would have caught the bug.
- **No unrelated changes.** Don't clean up unrelated code in the same PR. Open a separate one.

## Reporting Bugs

Use the [Bug Report](.github/ISSUE_TEMPLATE/bug_report.yml) template. Include:
- rgrok version (`rgrok --version`)
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Relevant log output (`RUST_LOG=debug`)

## Requesting Features

Use the [Feature Request](.github/ISSUE_TEMPLATE/feature_request.yml) template. Explain the use case, not just the implementation. If you're willing to implement it, say so — it helps prioritization.

## Questions

Open a [Discussion](https://github.com/your-org/rgrok/discussions) for usage questions rather than an issue. Issues are for actionable bug reports and feature requests.
