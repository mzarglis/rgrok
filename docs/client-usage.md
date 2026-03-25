# Client Usage Reference

## Installation

**Pre-built binary** (Linux, macOS, Windows):

Download `rgrok` from the [latest release](https://github.com/your-org/rgrok/releases/latest) and place it on your `$PATH`.

**Build from source:**
```bash
cargo install --git https://github.com/your-org/rgrok rgrok-client
```

## Setup

### Authenticate

Before opening tunnels you need a token from your server operator:

```bash
rgrok authtoken <your-token>
# Saved to ~/.config/rgrok/config.toml
```

### Config File

The config file is created automatically at `~/.config/rgrok/config.toml` on first use. Override the path with `--config`:

```bash
rgrok --config /path/to/config.toml http 3000
```

Example config file:
```toml
[server]
host = "tunnel.example.com"
port = 7835

[auth]
token = "eyJ..."

[defaults]
inspect = true
inspect_port = 4040

[logging]
level = "warn"
```

## Commands

### `rgrok http <port>`

Expose a local HTTP server.

```bash
rgrok http 3000
```

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--subdomain <name>` | Request a specific subdomain | Random |
| `--auth <user:pass>` | Require HTTP basic auth on the tunnel | None |
| `--host-header <host>` | Rewrite the `Host` header sent to your local server | Unchanged |
| `--no-inspect` | Disable request capture (lower memory usage) | Inspect on |
| `--inspect-port <port>` | Port for the local inspection web UI | `4040` |

**Examples:**
```bash
# Request a stable subdomain
rgrok http 3000 --subdomain myapp

# Protect with basic auth
rgrok http 3000 --auth alice:s3cret

# Rewrite Host header (useful for apps that check Host strictly)
rgrok http 3000 --host-header localhost:3000

# Disable inspection
rgrok http 3000 --no-inspect
```

---

### `rgrok https <port>`

Same as `http` but the server presents the public URL as `https://`. TLS is terminated at the server; your local service receives plain HTTP.

```bash
rgrok https 3000
```

Supports `--subdomain` and `--auth`. Does not support `--inspect` (inspection is HTTP-level).

---

### `rgrok tcp <port>`

Expose a raw TCP port. No HTTP parsing — bytes are forwarded directly.

```bash
# Expose local SSH
rgrok tcp 22

# Request a specific remote port (server may ignore if unavailable)
rgrok tcp 22 --remote-port 2222
```

**Output:**
```
TCP tunnel:  tcp://tunnel.example.com:12345
Forwarding:  localhost:22
```

---

### `rgrok authtoken <token>`

Save an auth token to the config file.

```bash
rgrok authtoken eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

---

### `rgrok config`

Print the current resolved configuration (useful for debugging).

```bash
rgrok config
```

---

## Global Flags

These flags apply to all commands:

| Flag | Description | Default |
|------|-------------|---------|
| `--config <path>` | Path to config file | `~/.config/rgrok/config.toml` |
| `--server <host:port>` | Override server address for this invocation | From config |

**Example:**
```bash
# One-off tunnel to a different server without editing config
rgrok --server other-server.example.com:7835 http 3000
```

---

## Request Inspection

When a tunnel is open, a local web UI is available at `http://localhost:4040` (or the port set with `--inspect-port`). It shows:

- All HTTP requests proxied through the tunnel
- Request and response headers and bodies
- Status codes and latency
- A **Replay** button to re-send any captured request

Inspection is enabled by default for `http` tunnels. Disable it with `--no-inspect` or set `inspect = false` in the config `[defaults]` section.

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `RUST_LOG` | Override log level (`error`, `warn`, `info`, `debug`, `trace`) |

```bash
RUST_LOG=debug rgrok http 3000
```

---

## Tunnel Output

When a tunnel opens, rgrok prints:

```
Tunnel URL:  https://abc123.tunnel.example.com
Forwarding:  http://localhost:3000
Inspect UI:  http://localhost:4040

Press Ctrl+C to close the tunnel.
```

The process exits cleanly on Ctrl+C, closing the tunnel.

---

## Common Scenarios

### Local development webhook testing

```bash
# Expose a webhook receiver on port 8000 with a stable URL
rgrok http 8000 --subdomain webhooks
# → https://webhooks.tunnel.example.com
```

### Sharing a local dev server with a colleague

```bash
rgrok http 5173 --auth demo:letmein
# Share https://xyz.tunnel.example.com — they'll be prompted for credentials
```

### Exposing a local SSH server

```bash
rgrok tcp 22
# Connect from anywhere: ssh -p <remote-port> user@tunnel.example.com
```

### Testing mobile app against local backend

```bash
rgrok https 3000
# Use the https:// URL in your mobile app's API config — no self-signed cert warnings
```

---

## Troubleshooting

**`auth failed: token expired`**
- Request a new token from your server operator (`rgrok authtoken <new-token>`)

**`subdomain already in use`**
- Another client has claimed that subdomain. Use `--subdomain` to request a different one or omit it for a random name.

**Tunnel opens but local server returns connection refused**
- Make sure your local server is actually running on the specified port
- Check `http://localhost:4040` — it will show the error responses

**`failed to connect to server`**
- Verify `host` and `port` in your config match the server
- Check that port 7835 is reachable: `nc -zv tunnel.example.com 7835`

**Inspection UI shows no requests**
- Ensure `--no-inspect` was not passed and `inspect = true` is in `[defaults]`
- Confirm you're looking at the right port (`--inspect-port`)
