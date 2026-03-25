# rgrok

A self-hosted [ngrok](https://ngrok.com) alternative written in Rust. Expose any local port to the internet through your own VPS — no third-party tunnel service, no data leaving your infrastructure.

[![CI](https://github.com/your-org/rgrok/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/rgrok/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)

```
  Browser                      Your VPS (rgrok-server)         Your Machine
    │                                    │                           │
    │  https://abc.tunnel.example.com ──►│                           │
    │                                    │◄── WebSocket/TLS tunnel ──│ rgrok http 3000
    │                                    │                           │
    │◄── response ───────────────────────│──── localhost:3000 ──────►│
```

## Features

- **HTTP, HTTPS, and TCP tunnels** — expose any local port with a single command
- **Automatic wildcard TLS** — ACME DNS-01 via Cloudflare; zero-downtime cert renewal
- **Request inspection** — live web UI at `localhost:4040` to replay and debug traffic
- **Basic auth** — protect tunnels with `--auth user:pass`, enforced server-side
- **JWT authentication** — token-based client auth with per-token revocation
- **Prometheus metrics** — built-in `/metrics` endpoint for your monitoring stack
- **Docker + systemd** — production-ready deployment artifacts included
- **Fully self-hosted** — your VPS, your domain, your data

## Quick Start

### 1. Install the client

**Pre-built binary** (Linux, macOS, Windows):
```bash
# Download from the latest release
curl -L https://github.com/your-org/rgrok/releases/latest/download/rgrok-x86_64-unknown-linux-gnu -o rgrok
chmod +x rgrok && sudo mv rgrok /usr/local/bin/
```

**Build from source:**
```bash
cargo install --git https://github.com/your-org/rgrok rgrok-client
```

### 2. Authenticate

Get a token from whoever runs your rgrok-server, then:
```bash
rgrok authtoken <your-token>
```

### 3. Expose a local port

```bash
# Expose a local HTTP server on port 3000
rgrok http 3000

# Output:
# Tunnel URL: https://abc123.tunnel.example.com
# Inspect:    http://localhost:4040
```

## Client Usage

```bash
rgrok http 3000                        # HTTP tunnel
rgrok https 3000                       # HTTPS (server terminates TLS, local gets plain HTTP)
rgrok tcp 22                           # Raw TCP tunnel (e.g. SSH)

rgrok http 3000 --subdomain myapp      # Request a specific subdomain
rgrok http 3000 --auth user:pass       # Protect with basic auth
rgrok http 3000 --no-inspect           # Disable request capture
rgrok http 3000 --server host:7835     # Connect to a specific server

rgrok authtoken <token>                # Save auth token to config
rgrok config                           # Print current config
```

See [docs/client-usage.md](docs/client-usage.md) for the full reference.

## Server Setup

You need a VPS with a domain pointing at it and Cloudflare managing DNS.

See **[docs/server-setup.md](docs/server-setup.md)** for the full guide covering:
- Binary installation and Docker deployment
- DNS and Cloudflare configuration
- TLS certificate provisioning (ACME) or bring-your-own certs
- Systemd service setup
- Token management and revoking access

## Architecture

rgrok uses a single persistent **WebSocket-over-TLS** connection (the control channel) between client and server, multiplexed with **yamux**. Each incoming HTTP request triggers a `StreamOpen` message; the client opens a new yamux stream, writes a 4-byte correlation ID, and the server stitches it to the waiting request.

```
crates/
  rgrok-proto/    # Shared protocol: MessagePack messages, framing, transport
  rgrok-server/   # VPS daemon — TLS termination, tunnel manager, HTTP proxy
  rgrok-client/   # CLI tool (binary: rgrok)
```

| Component | Technology |
|-----------|-----------|
| Transport | WebSocket over TLS (`tokio-tungstenite` + `rustls`) |
| Multiplexing | `yamux` virtual streams |
| Serialization | MessagePack (`rmp-serde`) |
| HTTP proxy | `hyper` + `axum` |
| TLS/ACME | `instant-acme` + Cloudflare DNS-01 |
| Auth | JWT (`jsonwebtoken`), bcrypt secrets |

For the full protocol specification see [docs/rgrok-spec.md](docs/rgrok-spec.md).

## Building from Source

**Prerequisites:** Rust 1.75+ ([rustup.rs](https://rustup.rs))

```bash
git clone https://github.com/your-org/rgrok
cd rgrok

cargo build --release

# Binaries:
#   target/release/rgrok          (client)
#   target/release/rgrok-server   (server)
```

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## Security

Please do not open public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md) for the responsible disclosure process.

## License

AGPL-3.0 — see [LICENSE](LICENSE).
