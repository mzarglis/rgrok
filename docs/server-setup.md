# Server Setup Guide

This guide walks through deploying `rgrok-server` on a VPS from scratch.

## Prerequisites

- A VPS running Linux (Debian/Ubuntu recommended) with a public IP
- A domain name (e.g. `example.com`) with **Cloudflare** as the DNS provider
- Ports **80**, **443**, and **7835** open in your firewall/security group
- Root or sudo access on the VPS

## 1. DNS Configuration

Create these DNS records in Cloudflare pointing to your VPS IP:

| Type | Name | Value | Proxy |
|------|------|-------|-------|
| A | `tunnel.example.com` | `<your-vps-ip>` | DNS only (grey cloud) |
| A | `*.tunnel.example.com` | `<your-vps-ip>` | DNS only (grey cloud) |

> **Important:** The wildcard record must be **DNS only** (not proxied). rgrok terminates TLS itself and Cloudflare proxying will break the WebSocket connection.

## 2. Cloudflare API Token

rgrok uses Cloudflare DNS-01 ACME challenges to obtain a wildcard TLS certificate. Create an API token:

1. Go to Cloudflare dashboard → **My Profile** → **API Tokens** → **Create Token**
2. Use the **Edit zone DNS** template
3. Set **Zone Resources** → Include → Specific zone → `example.com`
4. Copy the token — you'll put it in the server config

## 3. Install rgrok-server

**Option A: Pre-built binary**
```bash
curl -L https://github.com/your-org/rgrok/releases/latest/download/rgrok-server-x86_64-unknown-linux-gnu \
  -o /usr/local/bin/rgrok-server
chmod +x /usr/local/bin/rgrok-server
```

**Option B: Build from source**
```bash
# Install Rust if needed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

git clone https://github.com/your-org/rgrok
cd rgrok
cargo build --release
cp target/release/rgrok-server /usr/local/bin/
```

**Option C: Docker** — see [Docker Deployment](#docker-deployment) below.

## 4. Configure the Server

Create the configuration directory and copy the example config:
```bash
sudo mkdir -p /etc/rgrok /var/lib/rgrok/certs
sudo cp config/server.example.toml /etc/rgrok/server.toml
sudo chmod 600 /etc/rgrok/server.toml
```

Edit `/etc/rgrok/server.toml`:

```toml
[server]
domain = "tunnel.example.com"   # your domain
control_port = 7835
https_port = 443
http_port = 80
tcp_port_range = [10000, 20000]
max_tunnels = 100
tunnel_idle_timeout_secs = 300

[auth]
# Generate with: openssl rand -hex 32
secret = "CHANGEME_replace_with_output_of_openssl_rand_hex_32"
tokens = []

[tls]
acme_env = "production"         # use "staging" for testing to avoid rate limits
acme_email = "admin@example.com"
cert_dir = "/var/lib/rgrok/certs"

[cloudflare]
api_token = "your-cloudflare-api-token"
zone_id = "your-cloudflare-zone-id"
dns_ttl = 1
per_tunnel_dns = false          # wildcard A record is sufficient (recommended)

[logging]
level = "info"
format = "json"                 # use "pretty" during initial setup for readability
```

> **Find your Zone ID:** Cloudflare dashboard → select your domain → right sidebar under **API**.

**Generate the JWT secret:**
```bash
openssl rand -hex 32
```

## 5. Create the rgrok System User

```bash
sudo useradd --system --create-home --shell /usr/sbin/nologin rgrok
sudo chown -R rgrok:rgrok /var/lib/rgrok
sudo chown rgrok:rgrok /etc/rgrok/server.toml
```

## 6. Run as a systemd Service

Copy the provided unit file:
```bash
sudo cp deploy/rgrok-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable rgrok-server
sudo systemctl start rgrok-server
```

Check it started successfully:
```bash
sudo systemctl status rgrok-server
sudo journalctl -u rgrok-server -f
```

On first start with ACME enabled, the server will:
1. Create a DNS TXT record in Cloudflare
2. Request a wildcard certificate from Let's Encrypt
3. Remove the TXT record and save the certificate to `cert_dir`

This takes 30–90 seconds. You'll see `rgrok-server ready` in the logs when complete.

## 7. Generate Client Auth Tokens

```bash
# Generate a token for a user
sudo -u rgrok rgrok-server --config /etc/rgrok/server.toml \
  token generate --label alice

# With an expiry (90 days)
sudo -u rgrok rgrok-server --config /etc/rgrok/server.toml \
  token generate --label alice --expires-in 7776000
```

Share the printed JWT with the user. They run `rgrok authtoken <token>` to save it.

## 8. Verify End-to-End

On your local machine:
```bash
rgrok authtoken <token-from-above>
rgrok http 8080    # or any local port
```

You should see a tunnel URL like `https://abc123.tunnel.example.com`.

## Token Revocation

To revoke a token, add its `jti` (JWT ID) to the server config and send SIGHUP:

```toml
[auth]
revoked_jtis = ["the-jti-from-the-jwt"]
```

```bash
# Reload the revocation list without restarting
sudo systemctl kill --signal=SIGHUP rgrok-server
```

To decode a JWT and find its `jti`:
```bash
echo "<jwt>" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
```

## TLS: Bring Your Own Certificate

If you already have a wildcard certificate (e.g. from Certbot), skip ACME and point directly to your cert files:

```toml
[tls]
cert_file = "/etc/ssl/certs/wildcard.crt"
key_file  = "/etc/ssl/private/wildcard.key"
# Leave acme_email and cloudflare sections empty
```

The server performs hot-reload every 12 hours — if the cert on disk changes, it picks it up without a restart.

## Docker Deployment

```bash
# Build
docker build -t rgrok-server -f deploy/Dockerfile .

# Run (mount your config and cert storage)
docker run -d \
  --name rgrok-server \
  --restart unless-stopped \
  -p 80:80 -p 443:443 -p 7835:7835 \
  -p 10000-10100:10000-10100 \
  -v /etc/rgrok:/etc/rgrok:ro \
  -v /var/lib/rgrok:/var/lib/rgrok \
  rgrok-server
```

> **Note:** The TCP port range (`10000-20000`) can be large. Map only the range you actually need to avoid slow Docker startup.

## Monitoring

The server exposes a Prometheus metrics endpoint. Enable it in config:

```toml
[server]
metrics_port = 9090
```

Then scrape `http://localhost:9090/metrics` from your Prometheus instance (bind to localhost — don't expose this publicly without auth).

Key metrics:
- `rgrok_active_tunnels` — currently connected tunnels
- `rgrok_ws_connections_active` — active WebSocket connections
- `rgrok_requests_total` — total HTTP requests proxied
- `rgrok_request_duration_seconds` — request latency histogram

## Firewall Reference

| Port | Protocol | Direction | Purpose |
|------|----------|-----------|---------|
| 80 | TCP | Inbound | HTTP (redirects to HTTPS) |
| 443 | TCP | Inbound | HTTPS proxy for tunnel traffic |
| 7835 | TCP | Inbound | Client WebSocket control plane |
| 10000–20000 | TCP | Inbound | TCP tunnel port range |
| 9090 | TCP | Localhost only | Prometheus metrics |

## Troubleshooting

**ACME fails with "DNS record not found"**
- Verify the Cloudflare API token has Zone:DNS:Edit permission
- Check the zone ID matches your domain
- Try `acme_env = "staging"` first to avoid rate limits

**Clients connect but get "auth failed"**
- Ensure `secret` in server config matches what was used to generate the token
- Check the token hasn't expired (`exp` claim in the JWT)
- Check `revoked_jtis` doesn't include the token's `jti`

**Port 443/80 already in use**
- Another process (nginx, Apache, Caddy) is binding those ports
- Either stop that process or configure rgrok to use different ports (and update DNS/firewall accordingly)

**"No TLS certs configured — control plane running without TLS (dev mode)"**
- Expected in local development. In production, ensure `cert_dir` is writable and Cloudflare credentials are set.
