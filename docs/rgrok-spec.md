# rgrok — Implementation Spec
## A self-hosted ngrok alternative in Rust

**Version:** 1.0  
**Target:** Production-ready, self-hostable tunnel server + CLI client

---

## Table of Contents

1. [Overview & Architecture](#1-overview--architecture)
2. [Repository Structure](#2-repository-structure)
3. [Core Crates & Dependencies](#3-core-crates--dependencies)
4. [Data Flow & Protocol Design](#4-data-flow--protocol-design)
5. [Server (rgrok-server)](#5-server-rgrok-server)
6. [Client (rgrok CLI)](#6-client-rgrok-cli)
7. [Web Inspection UI](#7-web-inspection-ui)
8. [Configuration](#8-configuration)
9. [Cloudflare DNS Integration](#9-cloudflare-dns-integration)
10. [TLS / Certificate Management](#10-tls--certificate-management)
11. [Authentication & Security](#11-authentication--security)
12. [Error Handling Strategy](#12-error-handling-strategy)
13. [Observability & Logging](#13-observability--logging)
14. [Testing Strategy](#14-testing-strategy)
15. [Deployment Guide](#15-deployment-guide)
16. [CLI Reference](#16-cli-reference)
17. [Milestones & Build Order](#17-milestones--build-order)
18. [QUIC Transport (Phase 6)](#18-quic-transport-phase-6)

---

## 1. Overview & Architecture

### What rgrok does

```
  User Browser                   VPS (rgrok-server)             Developer Machine
      │                                 │                               │
      │  HTTPS GET                      │                               │
      │  abc123.tunnel.mysite.com ────► │                               │
      │                                 │  WebSocket tunnel (TLS)       │
      │                                 │ ◄──────────────────────────── │ rgrok http 5173
      │                                 │                               │
      │                                 │ ──── forward request ───────► │ (localhost:5173)
      │                                 │ ◄─── response ─────────────── │
      │ ◄──── HTTPS response ────────── │                               │
```

### High-level component map

```
rgrok (workspace)
├── rgrok-server   ← runs on your VPS; manages tunnels, TLS, DNS
├── rgrok-client   ← the CLI you run locally ("rgrok http 5173")
├── rgrok-proto    ← shared types: Protobuf or MessagePack messages
└── rgrok-web      ← compiled-in web inspection UI (Axum + embedded HTML)
```

### Key design decisions

| Decision | Choice | Rationale |
|---|---|---|
| Tunnel transport | WebSocket over TLS (wss://) | Traverses most firewalls/proxies; binary frames for efficiency |
| Multiplexing | `yamux` over the WebSocket | Single connection, many virtual streams per tunnel |
| Async runtime | `tokio` | Ecosystem standard; excellent performance |
| HTTP framework | `axum` (web UI, API) + `hyper` (HTTP proxy) | Axum for structured endpoints; hyper directly for the proxy path (minimal overhead, streaming body support) |
| TLS | `rustls` + `rcgen` | Pure Rust; no OpenSSL dep; wildcard cert via ACME |
| Auth tokens | `HMAC-SHA256` signed JWTs (using `jsonwebtoken`) | Stateless server auth; revocable via secret rotation |
| Config format | TOML | Human-readable, well-supported in Rust ecosystem |
| Serialization | `serde` + `MessagePack` (rmpv) | Compact binary on hot path; JSON for config/API |

---

## 2. Repository Structure

```
rgrok/
├── Cargo.toml                  ← workspace manifest
├── Cargo.lock
├── README.md
├── .github/
│   └── workflows/
│       ├── ci.yml              ← test + clippy on every PR
│       └── release.yml         ← cross-compile binaries on tag
│
├── crates/
│   ├── rgrok-proto/            ← shared message types (no I/O)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       └── messages.rs     ← TunnelRequest, TunnelResponse, ProxyFrame, …
│   │
│   ├── rgrok-server/           ← the daemon that runs on your VPS
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs
│   │       ├── config.rs
│   │       ├── tunnel_manager.rs
│   │       ├── proxy.rs        ← HTTP/TCP proxy logic
│   │       ├── control.rs      ← WebSocket control plane handler
│   │       ├── dns.rs          ← Cloudflare API calls
│   │       ├── tls.rs          ← ACME + cert loading
│   │       ├── auth.rs         ← JWT validation, basic-auth middleware
│   │       ├── inspect.rs      ← request capture for web UI
│   │       └── web_ui.rs       ← inspection dashboard HTTP server
│   │
│   └── rgrok-client/           ← the "rgrok" binary users install
│       ├── Cargo.toml
│       └── src/
│           ├── main.rs
│           ├── cli.rs          ← clap arg parsing
│           ├── config.rs
│           ├── tunnel.rs       ← connects to server, manages streams
│           ├── local_proxy.rs  ← forwards to localhost:<port>
│           ├── inspect.rs      ← local web UI at :4040
│           └── output.rs       ← terminal pretty-printing
│
├── config/
│   ├── server.example.toml
│   └── client.example.toml
│
├── deploy/
│   ├── rgrok-server.service    ← systemd unit
│   └── Dockerfile
│
└── tests/
    └── integration/
        ├── http_tunnel.rs
        ├── tcp_tunnel.rs
        └── auth.rs
```

---

## 3. Core Crates & Dependencies

### Workspace `Cargo.toml`

```toml
[workspace]
members = [
    "crates/rgrok-proto",
    "crates/rgrok-server",
    "crates/rgrok-client",
]
resolver = "2"

[workspace.dependencies]
tokio          = { version = "1", features = ["full"] }
tokio-util     = { version = "0.7", features = ["rt"] }  # CancellationToken, codec helpers
tokio-tungstenite = { version = "0.21", features = ["rustls-tls-webpki-roots"] }
axum           = { version = "0.7", features = ["ws", "macros"] }
hyper          = { version = "1", features = ["http1", "server", "client"] }
hyper-util     = { version = "0.1", features = ["tokio"] }
tower          = { version = "0.4" }
tower-http     = { version = "0.5", features = ["trace", "cors", "auth"] }
rustls         = { version = "0.23" }
rustls-pemfile = "2"
rcgen          = "0.13"
instant-acme   = "0.5"         # ACME / Let's Encrypt
yamux          = "0.13"        # stream multiplexer
serde          = { version = "1", features = ["derive"] }
serde_json     = "1"
rmp-serde      = "1"           # MessagePack
jsonwebtoken   = "9"
clap           = { version = "4", features = ["derive", "env"] }
tracing        = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
uuid           = { version = "1", features = ["v4"] }
rand           = "0.8"
thiserror      = "1"
anyhow         = "1"
reqwest        = { version = "0.12", features = ["rustls-tls", "json"] }
tokio-rustls   = "0.26"
futures        = "0.3"
bytes          = "1"
http           = "1"
```

---

## 4. Data Flow & Protocol Design

### 4.1 Control Channel Protocol

All client↔server communication uses a single persistent WebSocket connection (the **control channel**). Frames carry `MessagePack`-encoded `ControlMessage` enums.

```rust
// crates/rgrok-proto/src/messages.rs

use serde::{Deserialize, Serialize};

/// Client → Server messages
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMsg {
    /// Authenticate and request a tunnel
    Auth {
        token: String,              // JWT
        version: String,            // client semver
    },
    /// Request a new tunnel
    TunnelRequest {
        id: String,                 // client-generated UUID
        tunnel_type: TunnelType,
        subdomain: Option<String>,  // preferred name, server may ignore
        basic_auth: Option<BasicAuthConfig>,
        options: TunnelOptions,
    },
    /// Heartbeat
    Ping { seq: u64 },
    /// Acknowledge a proxy stream open (not used — correlation happens via first bytes on yamux stream)
    StreamAck { correlation_id: u32 },
}

/// Server → Client messages
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMsg {
    /// Auth accepted
    AuthOk { session_id: String },
    /// Auth rejected
    AuthErr { reason: String },
    /// Tunnel is live
    TunnelAck {
        id: String,
        public_url: String,         // e.g. "https://abc123.tunnel.mysite.com"
        tunnel_type: TunnelType,
    },
    /// Server asking client to open a new proxy stream for an incoming request
    StreamOpen { correlation_id: u32, tunnel_id: String },
    /// Heartbeat response
    Pong { seq: u64 },
    /// Server-initiated error
    Error { code: u32, message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelType {
    Http,
    Https,
    Tcp { remote_port: Option<u16> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicAuthConfig {
    pub username: String,
    pub password: String,           // stored/compared as bcrypt hash server-side
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TunnelOptions {
    pub host_header: Option<String>,    // rewrite Host header
    pub inspect: bool,                  // capture requests for web UI
    pub response_header: Vec<(String, String)>,
}
```

### 4.2 Proxy Architecture Decision: Dual-Mode Proxy

rgrok uses a **dual-mode proxy** strategy to balance performance with features:

- **HTTP/HTTPS tunnels** — the server runs `hyper` as a lightweight reverse proxy, parsing requests at the HTTP level. This enables basic auth, header rewriting, Host-based routing, and request inspection without any hacks.
- **TCP tunnels** — the server does raw `copy_bidirectional` byte bridging with zero parsing overhead.

#### Why not raw bytes for everything?

| | Raw byte proxy (`copy_bidirectional`) | HTTP-level proxy (`hyper`) |
|---|---|---|
| **Latency** | Minimal — zero parsing, just memcpy between streams | ~5–15μs overhead per request for HTTP/1.1 parsing (negligible vs network RTT) |
| **Memory** | Near-zero per-stream overhead | Small per-request allocation for headers (~1–2 KB typical) |
| **Basic auth** | Impossible — can't read `Authorization` header without parsing HTTP | Natural — middleware reads the header before forwarding |
| **Request inspection** | Requires a custom streaming parser or tee-and-reparse, fragile and complex | Headers/status/body are already parsed; capture is trivial |
| **Host header rewrite** | Requires byte-scanning the raw stream for `Host:`, error-prone with chunked encoding | One line: `req.headers_mut().insert(HOST, new_value)` |
| **HTTP/2 future** | Would need a completely separate code path | `hyper` handles h1/h2 transparently |
| **WebSocket passthrough** | Works naturally (after initial HTTP upgrade) | `hyper` supports upgrade; post-upgrade bytes are raw |
| **Throughput ceiling** | Theoretical max — kernel-level splice possible | ~95–99% of raw throughput; `hyper` is zero-copy where possible |

**Bottom line:** For a tunneling tool that advertises inspection, basic auth, and header rewriting as features, the HTTP parsing cost is negligible (~microseconds) compared to the network RTT (~milliseconds). Raw byte proxying is reserved for TCP tunnels where HTTP semantics don't apply.

#### `hyper` keeps it lightweight

`hyper` is already an indirect dependency via `axum`. It adds no new binary size. Its HTTP/1.1 parser (`httparse`) is one of the fastest in any language — benchmarked at >1 GB/s parsing throughput. Request bodies are streamed (not buffered), so a 10 GB file upload passes through with constant memory usage.

### 4.3 Proxy Stream Protocol

After receiving `StreamOpen`, the client opens a new **yamux stream** over the same WebSocket. yamux assigns stream IDs automatically (odd for client-initiated, even for server-initiated) — IDs cannot be chosen manually. To correlate streams, the client writes a 4-byte `correlation_id` as the first bytes on each new yamux stream, which the server matches to the pending request.

```
  yamux stream 0   ← control channel (ControlMessage frames)
  yamux stream 1   ← proxy stream (client writes correlation_id first, then raw bytes)
  yamux stream 3   ← proxy stream
  …                   (odd IDs: client-initiated; yamux assigns automatically)
```

### 4.4 HTTP Tunnel Request Lifecycle

```
1. Browser → TLS → rgrok-server (port 443)
2. Server accepts TLS, extracts SNI to identify subdomain
3. Server parses HTTP request via hyper (gives us method, path, headers, streaming body)
4. Server checks basic auth (if configured) — rejects with 401 before touching the tunnel
5. Server captures request headers + start time (if inspect enabled)
6. Server sends StreamOpen{correlation_id: N} on control channel
7. Client opens a new yamux stream (yamux assigns the next available odd stream ID)
8. Client writes correlation_id (4 bytes) as the first bytes on the stream
9. Server reads correlation_id, matches to pending request
10. Server forwards the HTTP request (headers + streaming body) into the yamux stream
11. Client reads from yamux stream → forwards to localhost:PORT via TCP
12. Client reads response from localhost → writes back into yamux stream
13. Server reads response from yamux stream → sends back to browser via hyper
14. Server captures response headers/status (if inspect enabled)
15. Yamux stream is closed by both sides
```

---

## 5. Server (`rgrok-server`)

### 5.1 Entry Point & Listener Setup

```rust
// main.rs pseudocode — illustrates what needs to be wired up

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Load config (server.toml or $RGROK_CONFIG)
    let cfg = Config::load()?;

    // 2. Init tracing (JSON logs in prod, pretty in dev)
    init_tracing(&cfg);

    // 3. Load/provision TLS certs (wildcard via ACME)
    let tls_config = tls::provision_or_load(&cfg).await?;

    // 4. Shared state — includes a CancellationToken for coordinated shutdown
    let shutdown = CancellationToken::new();
    let state = Arc::new(ServerState::new(cfg.clone(), shutdown.clone()));

    // 5. Spawn: control-plane WebSocket listener (port 7835 default, TLS)
    tokio::spawn(control::serve(state.clone(), tls_config.clone()));

    // 6. Spawn: public HTTPS proxy listener (port 443)
    tokio::spawn(proxy::serve_https(state.clone(), tls_config.clone()));

    // 7. Spawn: public TCP proxy listener (port range from config)
    tokio::spawn(proxy::serve_tcp(state.clone(), tls_config.clone()));

    // 8. Spawn: web inspection API (port 4040, localhost only on server,
    //          but client also runs its own on :4040)
    tokio::spawn(web_ui::serve(state.clone()));

    // 9. Spawn: certificate hot-reload (checks expiry every 12h)
    tokio::spawn(tls::cert_renewal_loop(state.clone(), tls_config.clone()));

    // 10. Wait for shutdown signal (SIGTERM / SIGINT / Ctrl+C)
    shutdown_signal().await;

    // 11. Cancel all tasks — they select! on shutdown.cancelled()
    //     This ensures:
    //     - Active ACME challenges clean up TXT records
    //     - Client connections receive a clean disconnect
    //     - Listeners stop accepting new connections
    //     - In-flight proxy streams drain (with a 5s grace period)
    tracing::info!("Shutdown signal received, draining connections…");
    shutdown.cancel();

    // 12. Give tasks up to 5 seconds to finish gracefully
    tokio::time::sleep(Duration::from_secs(5)).await;
    Ok(())
}
```

All spawned tasks should `select!` on `state.shutdown.cancelled()` in their accept loops. Example pattern:

```rust
loop {
    tokio::select! {
        _ = state.shutdown.cancelled() => {
            tracing::info!("Shutting down HTTPS proxy listener");
            break;
        }
        result = listener.accept() => {
            let (stream, peer) = result?;
            // … handle connection
        }
    }
}
```

### 5.2 `ServerState`

```rust
pub struct ServerState {
    pub config: Config,
    /// Map from subdomain → active tunnel
    pub tunnels: DashMap<String, Arc<TunnelSession>>,
    /// Map from TCP port → active tunnel
    pub tcp_tunnels: DashMap<u16, Arc<TunnelSession>>,
    /// Inspection capture ring-buffer per tunnel (last 100 requests).
    /// DashMap provides per-shard locking internally — no extra Mutex needed.
    pub captures: DashMap<String, VecDeque<CapturedRequest>>,
    /// Broadcast channel for web UI live updates
    pub inspect_tx: broadcast::Sender<InspectEvent>,
    /// Shutdown signal propagated to all spawned tasks
    pub shutdown: CancellationToken,
}

pub struct TunnelSession {
    pub id: String,
    pub tunnel_type: TunnelType,
    pub subdomain: String,
    pub basic_auth: Option<BasicAuthConfig>,
    /// Cached bcrypt hash of basic_auth password (avoids re-hashing per request)
    pub basic_auth_hash: Option<String>,
    pub options: TunnelOptions,
    pub created_at: Instant,
    /// Sink to send StreamOpen messages to the connected client
    pub control_tx: mpsc::Sender<ServerMsg>,
    /// Next correlation ID (atomic counter, NOT a yamux stream ID)
    pub next_correlation_id: AtomicU32,
    /// Pending proxy streams: correlation_id → oneshot sender.
    /// Entries are removed on timeout (10s) to prevent leaks.
    pub pending_streams: DashMap<u32, oneshot::Sender<yamux::Stream>>,
}
```

### 5.3 Control Plane Handler

```rust
// control.rs
// Accepts a generic transport — works with both WebSocket+yamux and QUIC
pub async fn handle_client(
    transport: Arc<dyn TunnelTransport>,
    state: Arc<ServerState>,
) {
    // 1. Accept stream 0 from the transport — this is the control channel
    let mut ctrl_stream = transport.accept_stream().await?;

    // 2. Read first ClientMsg — must be Auth within 5 seconds or disconnect
    let auth = timeout(Duration::from_secs(5), read_control_msg(&mut ctrl_stream)).await??;
    let ClientMsg::Auth { token, .. } = auth else { return; };

    // 3. Validate JWT
    auth::validate_token(&token, &state.config.auth_secret)?;

    // 4. Send AuthOk + enter message loop
    write_control_msg(&mut ctrl_stream, ServerMsg::AuthOk { session_id }).await?;

    // 5. Spawn a task to accept incoming yamux streams from the client.
    //    When a client receives StreamOpen, it opens a new stream and writes
    //    the correlation_id (4 bytes) as the first data. This task reads that
    //    ID and resolves the corresponding oneshot in pending_streams.
    let transport_clone = transport.clone();
    let session_tunnels = session_tunnels.clone();
    tokio::spawn(async move {
        loop {
            match transport_clone.accept_stream().await {
                Ok(mut stream) => {
                    // Read 4-byte correlation_id
                    let mut buf = [0u8; 4];
                    if stream.read_exact(&mut buf).await.is_err() { continue; }
                    let corr_id = u32::from_be_bytes(buf);
                    // Find and resolve the pending oneshot
                    if let Some((_, tx)) = tunnel.pending_streams.remove(&corr_id) {
                        let _ = tx.send(stream);
                    }
                }
                Err(_) => break, // connection closed
            }
        }
    });

    // 6. Control message loop: handle TunnelRequest, Ping
    //    On TunnelRequest:
    //      a. Generate subdomain (random or requested)
    //      b. Register in state.tunnels
    //      c. Optionally create Cloudflare DNS record
    //      d. Reply with TunnelAck { public_url }

    // 7. On client disconnect: remove all tunnel registrations, release DNS,
    //    clean up any remaining pending_streams entries
}
```

### 5.4 HTTP Proxy (`proxy.rs`)

The proxy listener accepts all HTTPS connections on port 443, terminates TLS, and uses `hyper` to parse HTTP — giving us access to headers for routing, basic auth, and inspection.

**Important:** The `rustls::ServerConfig` must explicitly set ALPN to HTTP/1.1 only on the proxy listener. Many modern clients (browsers, curl) negotiate HTTP/2 via ALPN over TLS by default. Since we don't support HTTP/2 yet, we must advertise only `h1`:

```rust
let mut tls_config = rustls::ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(certs, key)?;
// Only advertise HTTP/1.1 — prevents clients from attempting h2
tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
```

```rust
pub async fn serve_https(state: Arc<ServerState>, tls: Arc<ServerConfig>) {
    let listener = TcpListener::bind("0.0.0.0:443").await?;
    loop {
        let (stream, peer) = listener.accept().await?;
        let state = state.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            // TLS handshake — SNI gives us the subdomain immediately
            let tls_stream = TlsAcceptor::from(tls).accept(stream).await?;
            let sni = extract_sni(&tls_stream);

            // Look up tunnel by subdomain
            let subdomain = sni
                .strip_suffix(&format!(".{}", state.config.domain))
                .ok_or(/* 404 */)?;
            let tunnel = state.tunnels.get(subdomain).ok_or(/* 502 */)?;

            // Serve HTTP via hyper — this parses the request, giving us headers
            let service = hyper::service::service_fn(|req: Request<Incoming>| {
                let tunnel = tunnel.clone();
                let state = state.clone();
                let subdomain = subdomain.to_string();
                async move {
                    proxy_http_request(req, &tunnel, &state, &subdomain).await
                }
            });
            hyper::server::conn::http1::Builder::new()
                .serve_connection(tls_stream, service)
                .with_upgrades()  // support WebSocket passthrough
                .await?;
        });
    }
}

async fn proxy_http_request(
    req: Request<Incoming>,
    tunnel: &Arc<TunnelSession>,
    state: &Arc<ServerState>,
    subdomain: &str,
) -> Result<Response<Body>, anyhow::Error> {
    // 1. Basic auth check — we have the headers, so this is straightforward
    if let Some(ba) = &tunnel.basic_auth {
        let auth_header = req.headers().get(AUTHORIZATION);
        if !validate_basic_auth(auth_header, &ba.username, &tunnel.basic_auth_hash) {
            return Ok(Response::builder()
                .status(401)
                .header("WWW-Authenticate", "Basic realm=\"rgrok\"")
                .body(Body::from("Unauthorized"))?);
        }
    }

    // 2. Capture request metadata (if inspect enabled) — headers are already parsed
    let capture_id = if tunnel.options.inspect {
        Some(start_capture(&req, state, subdomain))
    } else {
        None
    };

    // 3. Allocate correlation_id, register oneshot, send StreamOpen to client
    let corr_id = tunnel.next_correlation_id.fetch_add(1, Ordering::Relaxed);
    let (tx, rx) = oneshot::channel();
    tunnel.pending_streams.insert(corr_id, tx);
    tunnel.control_tx
        .send(ServerMsg::StreamOpen { correlation_id: corr_id, tunnel_id: tunnel.id.clone() })
        .await?;

    // 4. Wait for client to open the yamux stream (with timeout + cleanup)
    let proxy_stream = match timeout(Duration::from_secs(10), rx).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(_)) => {
            tunnel.pending_streams.remove(&corr_id); // clean up on cancel
            return Ok(Response::builder().status(504).body(Body::from("Tunnel client disconnected"))?);
        }
        Err(_) => {
            tunnel.pending_streams.remove(&corr_id); // clean up on timeout
            return Ok(Response::builder().status(504).body(Body::from("Tunnel client did not respond in time"))?);
        }
    };

    // 5. Forward the HTTP request into the yamux stream.
    //    Write the raw HTTP/1.1 request (hyper can serialize it back out),
    //    then stream the body. Read the response back and return it.
    let response = forward_through_tunnel(req, proxy_stream, &tunnel.options).await?;

    // 6. Capture response metadata if inspecting
    if let Some(id) = capture_id {
        finalize_capture(id, &response, state, subdomain);
    }

    Ok(response)
}
```

**Note on basic auth performance:** `bcrypt` verification is intentionally slow (~100ms at cost 10). To avoid adding 100ms latency to every proxied request, the `TunnelSession` stores the pre-computed `bcrypt` hash in `basic_auth_hash` at tunnel creation time. The per-request check compares the incoming password against this cached hash using `bcrypt::verify`. For repeated requests from the same client (which sends the same `Authorization` header), we additionally cache the last successful raw header value and skip bcrypt if it matches — this reduces the bcrypt cost to once per unique credential, not once per request.

### 5.5 TCP Proxy

Raw TCP tunnels work identically but skip HTTP parsing and basic-auth middleware. The server binds a fresh port from the configured range (e.g., 10000–20000) when a TCP tunnel is requested.

```rust
// On TunnelRequest { tunnel_type: TunnelType::Tcp { remote_port }, .. }:
// 1. Pick a port from config.tcp_port_range not already in use
// 2. Bind TcpListener on that port
// 3. Store in state.tcp_tunnels
// 4. Reply TunnelAck { public_url: "tcp://mysite.com:PORT" }
// 5. Per accepted connection: send StreamOpen, bridge streams
```

---

## 6. Client (`rgrok-client`)

### 6.1 CLI Argument Parsing (`cli.rs`)

```rust
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "rgrok", version, about = "Secure tunnels to localhost")]
pub struct Cli {
    /// Path to config file
    #[arg(short, long, default_value = "~/.config/rgrok/config.toml")]
    pub config: PathBuf,

    /// Server address override
    #[arg(long)]
    pub server: Option<String>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Forward HTTP traffic
    Http {
        /// Local port to expose
        port: u16,
        /// Request a specific subdomain
        #[arg(long)]
        subdomain: Option<String>,
        /// Protect with basic auth (user:pass)
        #[arg(long)]
        auth: Option<String>,
        /// Disable request inspection
        #[arg(long)]
        no_inspect: bool,
        /// Rewrite Host header sent to local server
        #[arg(long)]
        host_header: Option<String>,
        /// Inspection UI port
        #[arg(long, default_value = "4040")]
        inspect_port: u16,
    },
    /// Forward HTTPS traffic (terminates TLS, forwards plain HTTP locally)
    Https {
        port: u16,
        #[arg(long)]
        subdomain: Option<String>,
        #[arg(long)]
        auth: Option<String>,
    },
    /// Expose a raw TCP port
    Tcp {
        port: u16,
        /// Request a specific remote port
        #[arg(long)]
        remote_port: Option<u16>,
    },
    /// Print current config
    Config,
    /// Manage auth tokens
    Authtoken {
        token: String,
    },
}
```

### 6.2 Tunnel Manager (`tunnel.rs`)

```rust
pub struct TunnelClient {
    config: ClientConfig,
    cli_args: TunnelArgs,
}

impl TunnelClient {
    pub async fn run(self) -> anyhow::Result<()> {
        // 1. Connect to server control port (wss://SERVER:7835)
        //    Use exponential backoff: 1s, 2s, 4s … 60s, then give up
        let ws = connect_with_retry(&self.config).await?;
        
        // 2. Wrap in yamux
        let mut mux = yamux::Connection::new(
            ws_to_async_rw(ws), yamux_cfg(), yamux::Mode::Client
        );
        
        // 3. Open stream 0 for control messages
        let mut ctrl = mux.open_stream().await?;
        
        // 4. Send Auth
        write_msg(&mut ctrl, ClientMsg::Auth {
            token: self.config.auth_token.clone(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }).await?;
        
        // 5. Expect AuthOk
        let ServerMsg::AuthOk { session_id } = read_msg(&mut ctrl).await? else {
            anyhow::bail!("Auth rejected");
        };
        
        // 6. Send TunnelRequest
        let req_id = uuid::Uuid::new_v4().to_string();
        write_msg(&mut ctrl, ClientMsg::TunnelRequest { id: req_id.clone(), .. }).await?;
        
        // 7. Expect TunnelAck — print public URL to terminal
        let ServerMsg::TunnelAck { public_url, .. } = read_msg(&mut ctrl).await? else {
            anyhow::bail!("Tunnel creation failed");
        };
        output::print_tunnel_info(&public_url, self.cli_args.port);
        
        // 8. Spawn heartbeat task (ping every 30s)
        tokio::spawn(heartbeat_loop(ctrl_tx.clone()));
        
        // 9. Main loop: wait for StreamOpen from server
        loop {
            match read_msg(&mut ctrl).await? {
                ServerMsg::StreamOpen { correlation_id, .. } => {
                    let transport = transport.clone();
                    let local_port = self.cli_args.port;
                    let inspect_tx = self.inspect_tx.clone();
                    tokio::spawn(async move {
                        handle_proxy_stream(&*transport, correlation_id, local_port, inspect_tx).await;
                    });
                }
                ServerMsg::Pong { .. } => { /* reset heartbeat timer */ }
                ServerMsg::Error { message, .. } => {
                    tracing::error!("Server error: {}", message);
                }
                _ => {}
            }
        }
    }
}

async fn handle_proxy_stream(
    transport: &dyn TunnelTransport,
    correlation_id: u32,
    local_port: u16,
    inspect_tx: Option<mpsc::Sender<CapturedRequest>>,
) {
    // 1. Open a new yamux stream (yamux assigns the ID automatically)
    let mut proxy_stream = transport.open_stream().await?;

    // 2. Write the correlation_id as the first 4 bytes so the server can match
    //    this stream to the pending request
    proxy_stream.write_all(&correlation_id.to_be_bytes()).await?;

    // 3. Connect to localhost:PORT
    let mut local = TcpStream::connect(("127.0.0.1", local_port)).await
        .context("Could not connect to local port")?;

    // 4. Bidirectional copy: yamux stream ↔ local TCP
    //    Inspection capture happens server-side (at the HTTP layer via hyper),
    //    and optionally client-side by tee-ing the raw bytes.
    if let Some(tx) = inspect_tx {
        let (captured, proxy_stream, local) = tee_streams(proxy_stream, local, tx);
        tokio::io::copy_bidirectional(&mut proxy_stream, &mut local).await?;
    } else {
        tokio::io::copy_bidirectional(&mut proxy_stream, &mut local).await?;
    }
}
```

### 6.3 Terminal Output (`output.rs`)

```
╔══════════════════════════════════════════════════════╗
║                    rgrok v0.1.0                      ║
╠══════════════════════════════════════════════════════╣
║  Tunnel:    https://abc123.tunnel.mysite.com         ║
║  Forwarding to: http://localhost:5173               ║
║  Inspect:   http://localhost:4040                   ║
╠══════════════════════════════════════════════════════╣
║  Connections  Requests/min  Data In  Data Out        ║
║       0              0        0 B      0 B           ║
╠══════════════════════════════════════════════════════╣
║  Time    Method  URL              Status  Duration   ║
╚══════════════════════════════════════════════════════╝
```

Use `crossterm` for terminal control and live stats updates.

---

## 7. Web Inspection UI

### Architecture

The inspection UI runs as a small Axum server embedded in both client and server binaries. HTML/JS assets are embedded at compile time using `include_str!` or the `rust-embed` crate — no separate static file server needed.

### Client-side UI (`localhost:4040`)

The client captures full request/response pairs (headers + body, up to 1 MB) and serves them at `:4040`.

**Endpoints:**

| Method | Path | Description |
|---|---|---|
| GET | `/` | Dashboard HTML (single-page app) |
| GET | `/api/requests` | List of captured requests (JSON) |
| GET | `/api/requests/:id` | Full request/response detail |
| POST | `/api/requests/:id/replay` | Re-send the request to local port |
| DELETE | `/api/requests` | Clear all captured requests |
| GET | `/api/stream` | SSE stream for live updates |
| GET | `/api/status` | Tunnel status (URL, uptime, stats) |

**Data model:**

```rust
pub struct CapturedRequest {
    pub id: String,
    pub captured_at: DateTime<Utc>,
    pub duration_ms: Option<u64>,
    pub tunnel_id: String,
    
    // Request
    pub req_method: String,
    pub req_url: String,
    pub req_headers: Vec<(String, String)>,
    pub req_body: Option<Bytes>,        // capped at 1 MB
    
    // Response (filled in when stream closes)
    pub resp_status: Option<u16>,
    pub resp_headers: Option<Vec<(String, String)>>,
    pub resp_body: Option<Bytes>,       // capped at 1 MB
    pub resp_body_truncated: bool,
    
    // Metadata
    pub remote_addr: String,
    pub tls_version: Option<String>,
}
```

**Replay logic:**

```rust
// POST /api/requests/:id/replay
async fn replay(
    State(state): State<Arc<UiState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let cap = state.captures.get(&id)?;
    
    // Re-issue the HTTP request directly to localhost:PORT
    let client = reqwest::Client::new();
    let mut req = client.request(
        cap.req_method.parse()?,
        format!("http://127.0.0.1:{}{}", state.local_port, cap.req_url)
    );
    for (k, v) in &cap.req_headers {
        req = req.header(k, v);
    }
    if let Some(body) = &cap.req_body {
        req = req.body(body.clone());
    }
    let resp = req.send().await?;
    // Store new CapturedRequest for the replay
    Json(ReplayResult { new_request_id: new_id })
}
```

**Frontend (embedded HTML):**

A single `index.html` file with inline CSS and vanilla JS (no build step required). It polls `/api/requests` and `/api/stream` (SSE) for live updates. It displays:
- Left panel: request list with method badge, path, status code, duration
- Right panel: selected request detail with tabs for Headers / Body / Raw / Timing
- "Replay" button per request
- Filter bar (by method, status code, path regex)

The HTML is embedded in the binary:
```rust
const INDEX_HTML: &str = include_str!("../web/index.html");
```

---

## 8. Configuration

### Server config (`server.toml`)

```toml
# rgrok-server configuration

[server]
# Hostname of your VPS (used for TLS cert and DNS)
domain = "tunnel.mysite.com"

# Port the control WebSocket listens on (clients connect here)
control_port = 7835

# Port for the public HTTPS proxy (must be 443 for HTTPS)
https_port = 443

# Port for public HTTP (redirects to HTTPS)
http_port = 80

# Range of TCP ports available for TCP tunnels
tcp_port_range = [10000, 20000]

# Maximum concurrent tunnels
max_tunnels = 100

# Maximum tunnel idle time before server closes it
tunnel_idle_timeout_secs = 300

[auth]
# Secret for signing/verifying JWTs (generate with: openssl rand -hex 32)
# REQUIRED — no default
secret = "CHANGEME_hex_32_bytes"

# List of valid tokens (generated by `rgrok-server token generate`)
# Or leave empty and use the secret alone for single-user setups
tokens = []

[tls]
# Let's Encrypt ACME: "production" or "staging"
acme_env = "production"

# Email for Let's Encrypt registration
acme_email = "admin@mysite.com"

# Directory to persist certs
cert_dir = "/var/lib/rgrok/certs"

# Optional: bring-your-own cert (skips ACME)
# cert_file = "/etc/ssl/certs/wildcard.crt"
# key_file  = "/etc/ssl/private/wildcard.key"

[cloudflare]
# Cloudflare API token with Zone:DNS:Edit permission
api_token = "CHANGEME"

# Zone ID for your domain
zone_id = "CHANGEME"

# TTL for tunnel DNS records (seconds); 1 = automatic
dns_ttl = 1

# Set to true to create/delete DNS records per-tunnel
# Set to false if you use a wildcard *.tunnel.mysite.com A record (recommended)
per_tunnel_dns = false

[inspect]
# Port for the web inspection UI on the server (0 = disabled)
# Bind to 127.0.0.1 only when running on VPS
ui_port = 0
ui_bind = "127.0.0.1"

# Max requests to keep in memory per tunnel
buffer_size = 100

[logging]
# "trace" | "debug" | "info" | "warn" | "error"
level = "info"
# "pretty" (dev) | "json" (prod)
format = "json"
```

### Client config (`~/.config/rgrok/config.toml`)

```toml
[server]
# Address of your rgrok server
host = "tunnel.mysite.com"
port = 7835

[auth]
# Your auth token (set via `rgrok authtoken <token>`)
token = ""

[defaults]
# Default inspection UI port
inspect_port = 4040

# Enable request inspection by default
inspect = true

# Max body capture size in bytes (default 1 MB)
max_body_bytes = 1048576

[logging]
level = "info"
format = "pretty"
```

### Environment variable overrides

Every config key can be overridden via environment variable using the prefix `RGROK_`:

```
RGROK_SERVER_HOST=tunnel.mysite.com
RGROK_AUTH_TOKEN=your_token
RGROK_INSPECT_PORT=4041
```

---

## 9. Cloudflare DNS Integration

### Recommended approach: wildcard A record (simplest, most reliable)

In Cloudflare, create a single wildcard record:

```
Type: A
Name: *.tunnel.mysite.com
Value: <YOUR_VPS_IP>
Proxied: false   ← IMPORTANT: disable Cloudflare proxy; we handle TLS ourselves
TTL: Auto
```

With `per_tunnel_dns = false` (default), **no Cloudflare API calls are needed at runtime**. The wildcard handles all subdomains and rgrok-server routes by the `Host` header. This is recommended for production.

### Optional: per-tunnel DNS records (`per_tunnel_dns = true`)

If you want DNS records to only exist while tunnels are active:

```rust
// dns.rs
use reqwest::Client;

pub struct CloudflareClient {
    client: Client,
    api_token: String,
    zone_id: String,
}

impl CloudflareClient {
    pub async fn create_record(
        &self,
        subdomain: &str,
        ip: &str,
        ttl: u32,
    ) -> anyhow::Result<String> {   // returns record_id for later deletion
        let resp = self.client
            .post(format!(
                "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
                self.zone_id
            ))
            .bearer_auth(&self.api_token)
            .json(&serde_json::json!({
                "type": "A",
                "name": subdomain,
                "content": ip,
                "ttl": ttl,
                "proxied": false
            }))
            .send()
            .await?
            .error_for_status()?;
        
        let body: serde_json::Value = resp.json().await?;
        Ok(body["result"]["id"].as_str().unwrap().to_string())
    }
    
    pub async fn delete_record(&self, record_id: &str) -> anyhow::Result<()> {
        self.client
            .delete(format!(
                "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
                self.zone_id, record_id
            ))
            .bearer_auth(&self.api_token)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}
```

DNS records are cleaned up in the tunnel session `Drop` impl or the disconnect handler.

---

## 10. TLS / Certificate Management

### Strategy

Use a **wildcard TLS certificate** for `*.tunnel.mysite.com` obtained via **ACME DNS-01 challenge** through Cloudflare. This is required for wildcard certs — HTTP-01 challenge only works for specific hostnames.

### ACME DNS-01 flow using `instant-acme`

```rust
// tls.rs
use instant_acme::{Account, ChallengeType, NewOrder, OrderStatus};

pub async fn provision_wildcard_cert(
    config: &Config,
    cf: &CloudflareClient,
) -> anyhow::Result<(Vec<CertificateDer>, PrivateKeyDer)> {
    // 1. Create or load ACME account
    let account = Account::create_or_restore(
        &config.tls.acme_email,
        acme_directory_url(&config.tls.acme_env),
        &account_credentials_path(config),
    ).await?;
    
    // 2. Order wildcard cert
    let identifiers = vec![
        format!("*.{}", config.server.domain),
        config.server.domain.clone(),          // include apex too
    ];
    let mut order = account.new_order(&NewOrder { identifiers }).await?;
    
    // 3. Get DNS-01 challenges
    let challenges = order.dns01_challenges().await?;
    for challenge in &challenges {
        // TXT record name: _acme-challenge.<domain>
        // TXT record value: challenge.key_authorization_digest()
        cf.create_txt_record(
            &format!("_acme-challenge.{}", config.server.domain),
            &challenge.key_authorization_digest()?,
        ).await?;
    }
    
    // 4. Wait for DNS propagation (30s typical)
    tokio::time::sleep(Duration::from_secs(30)).await;
    
    // 5. Validate challenges
    for challenge in &challenges {
        order.set_challenge_ready(&challenge.url).await?;
    }
    
    // 6. Poll for order to become ready
    loop {
        match order.status().await? {
            OrderStatus::Ready => break,
            OrderStatus::Pending => tokio::time::sleep(Duration::from_secs(5)).await,
            s => anyhow::bail!("ACME order failed: {:?}", s),
        }
    }
    
    // 7. Generate key + CSR, finalize order
    let (private_key, csr) = generate_key_and_csr(&identifiers)?;
    order.finalize(&csr).await?;
    
    // 8. Download cert chain
    let cert_chain = order.certificate().await?;
    
    // 9. Persist to disk
    save_cert(&cert_chain, &private_key, config)?;
    
    // 10. Clean up TXT records
    cf.delete_txt_records(&format!("_acme-challenge.{}", config.server.domain)).await?;
    
    Ok((cert_chain, private_key))
}
```

### Certificate hot-reload

A background task checks cert expiry every 12 hours. If the cert expires within 30 days, it re-runs ACME provisioning and atomically swaps the `Arc<ServerConfig>` used by all listeners — no restart required.

```rust
tokio::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(12 * 3600));
    loop {
        interval.tick().await;
        if cert_expires_within(&tls_state, Duration::from_secs(30 * 24 * 3600)) {
            match renew_cert(&config, &cf_client).await {
                Ok(new_tls) => { *tls_state.write() = new_tls; }
                Err(e) => tracing::error!("Cert renewal failed: {}", e),
            }
        }
    }
});
```

---

## 11. Authentication & Security

### 11.1 Client Authentication (JWT)

Tokens are issued by the server operator via:

```bash
rgrok-server token generate --label "my-laptop"
# Output: rgrok_tok_<base64url-encoded-JWT>
```

The JWT payload:

```json
{
  "sub": "my-laptop",
  "iat": 1700000000,
  "exp": null,          // no expiry by default; use --expires-in 90d to set
  "jti": "unique-id",   // for revocation
  "ver": 1
}
```

Signed with `HS256` using the server's `auth.secret`. Tokens can be revoked by adding their `jti` to a blocklist in the config and sending `SIGHUP` to the server process.

### 11.2 Tunnel Basic Authentication

When `--auth user:pass` is passed:

1. Client includes `BasicAuthConfig { username, password }` in the `TunnelRequest`
2. Server hashes the password with `bcrypt` cost 10 on receipt and stores the hash in `TunnelSession.basic_auth_hash`
3. For each incoming HTTP request, the `proxy_http_request` function reads the `Authorization` header (available because `hyper` has already parsed the request) and validates it:
   - First, check if the raw `Authorization` header matches the last successful value (cached in `TunnelSession` as an atomic string). This fast path avoids bcrypt entirely for repeated requests from the same client.
   - On cache miss, run `bcrypt::verify` against the stored hash.
4. If absent or invalid, server returns `401 Unauthorized` with `WWW-Authenticate: Basic realm="rgrok"` — the request never reaches the tunnel client
5. The plaintext password is never stored on the server; only the bcrypt hash is kept

Basic auth is only available for HTTP/HTTPS tunnels, not TCP.

### 11.3 Security Hardening Checklist

**Transport:**
- All control channel traffic is TLS 1.2+ (enforced in `rustls` config)
- Only `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256` cipher suites
- HSTS headers added to all HTTPS proxy responses: `Strict-Transport-Security: max-age=31536000`
- HTTP (port 80) redirects to HTTPS with 301

**Server:**
- Control plane port (7835) accepts TLS client connections but does NOT require mTLS (would prevent easy client setup)
- Rate limiting on tunnel creation: max 10 `TunnelRequest` per auth token per minute (via `tower_governor` or manual token bucket)
- Subdomain validation: only `[a-z0-9-]{3,40}` allowed; reject reserved names (`www`, `api`, `mail`, etc.)
- Maximum request body size in inspection: 1 MB (configurable); larger requests are proxied without capture
- Timeouts: `StreamOpen` must be acknowledged within 10 seconds or the server closes the incoming connection
- No HTTP/2 on the proxy listener (simplifies implementation; can be added later). **The `rustls::ServerConfig` for the proxy listener must set `alpn_protocols = vec![b"http/1.1".to_vec()]`** to prevent clients from negotiating h2 and failing silently.

**Client:**
- Config file (`~/.config/rgrok/config.toml`) is created with `0600` permissions (owner read/write only)
- Auth token stored in config, never in command-line args (would be visible in `ps`)
- Local inspection UI binds to `127.0.0.1` only, never `0.0.0.0`

**Secrets:**
- `auth.secret` must be at least 32 bytes; server refuses to start otherwise
- Cloudflare API token is a scoped token (Zone:DNS:Edit only) — document this clearly
- Never log auth tokens, passwords, or the CF API token

---

## 12. Error Handling Strategy

Use `thiserror` for typed errors in library code and `anyhow` for application-level error propagation.

```rust
// In rgrok-proto and internal modules: typed errors
#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    #[error("authentication failed: {reason}")]
    AuthFailed { reason: String },
    
    #[error("subdomain '{subdomain}' is already in use")]
    SubdomainTaken { subdomain: String },
    
    #[error("no TCP ports available in range {start}–{end}")]
    NoPortsAvailable { start: u16, end: u16 },
    
    #[error("connection to local port {port} refused")]
    LocalPortRefused { port: u16 },
    
    #[error("tunnel session expired")]
    SessionExpired,
    
    #[error("protocol version mismatch: client={client}, server={server}")]
    VersionMismatch { client: String, server: String },
}
```

**Client-facing error messages** (printed to terminal, not raw Rust errors):

| Error | User-visible message |
|---|---|
| Local port refused | `✗ Cannot connect to localhost:5173 — is your server running?` |
| Auth failed | `✗ Invalid auth token — run: rgrok authtoken <your-token>` |
| Subdomain taken | `✗ Subdomain "myapp" is in use — try a different name or omit --subdomain` |
| Server unreachable | `✗ Cannot reach tunnel.mysite.com:7835 — check your connection` |
| TLS error | `✗ TLS handshake failed — server certificate may be invalid` |

---

## 13. Observability & Logging

### Structured logging (server)

```rust
// Log format in production (JSON, to stdout for log aggregator ingestion)
{
  "timestamp": "2024-01-15T10:23:45.123Z",
  "level": "INFO",
  "target": "rgrok_server::proxy",
  "tunnel_id": "abc123",
  "subdomain": "myapp",
  "method": "GET",
  "path": "/api/users",
  "status": 200,
  "duration_ms": 12,
  "bytes_in": 234,
  "bytes_out": 1872,
  "remote_ip": "1.2.3.4"
}
```

### Metrics (optional, `prometheus` feature flag)

Expose `/metrics` on a configurable port (default: 9090) with:

```
rgrok_active_tunnels           gauge
rgrok_requests_total{status}   counter
rgrok_request_duration_ms      histogram (buckets: 5,10,25,50,100,250,500,1000,2500)
rgrok_bytes_in_total           counter
rgrok_bytes_out_total          counter
rgrok_ws_connections_active    gauge
rgrok_tunnel_errors_total{kind} counter
```

---

## 14. Testing Strategy

### Unit tests (in-module, `#[cfg(test)]`)

- Subdomain generation uniqueness
- JWT sign/verify/expiry
- Config parsing (valid and invalid TOML)
- `ControlMessage` serialization round-trip
- BasicAuth header parsing and validation

### Integration tests (`tests/integration/`)

These spin up a real server on ephemeral ports and a client in the same process:

```rust
// tests/integration/http_tunnel.rs
#[tokio::test]
async fn test_http_tunnel_round_trip() {
    // 1. Start a minimal hyper server on a random port (the "local service")
    let local_port = start_test_server(|req| async {
        Response::new(Body::from("hello from local"))
    }).await;
    
    // 2. Start rgrok-server on ephemeral ports (no real TLS, no DNS)
    let server = TestServer::start().await;
    
    // 3. Connect client, request HTTP tunnel to local_port
    let client = TestClient::connect(&server, local_port).await;
    let public_url = client.tunnel_url();
    
    // 4. Make HTTP request directly to server (bypassing real DNS)
    let resp = reqwest::get(&public_url).await.unwrap();
    assert_eq!(resp.text().await.unwrap(), "hello from local");
}

#[tokio::test]
async fn test_basic_auth_rejects_unauthenticated() { ... }

#[tokio::test]
async fn test_tcp_tunnel() { ... }

#[tokio::test]
async fn test_client_reconnect_on_server_restart() { ... }
```

### End-to-end test

A `docker-compose.yml` in `tests/e2e/` runs the actual server binary and a local echo server, then the client binary, and validates the full flow including TLS (using a self-signed cert in tests).

---

## 15. Deployment Guide

### Prerequisites

- VPS with a public IP address (any cloud provider)
- A domain name with Cloudflare as the DNS provider
- Rust toolchain (for building) or pre-built binary from releases

### Step 1 — DNS setup (Cloudflare)

1. In Cloudflare dashboard → DNS → Add record:
   - Type: `A`, Name: `*.tunnel.mysite.com`, IPv4: `<your-vps-ip>`, Proxy: **Off**
   - Type: `A`, Name: `tunnel.mysite.com`, IPv4: `<your-vps-ip>`, Proxy: **Off**
2. Create a scoped API token: Profile → API Tokens → Create Token → "Edit zone DNS"
   - Zone Resources: Include → Specific zone → `mysite.com`

### Step 2 — Server config

```bash
# On your VPS
sudo mkdir -p /etc/rgrok /var/lib/rgrok/certs
sudo cp server.example.toml /etc/rgrok/server.toml
sudo nano /etc/rgrok/server.toml  # Fill in domain, secrets, CF token
sudo chmod 600 /etc/rgrok/server.toml  # Protect secrets
```

### Step 3 — Install & run server

```bash
# Option A: install from cargo
cargo install rgrok-server

# Option B: download pre-built binary
curl -Lo /usr/local/bin/rgrok-server \
  https://github.com/yourname/rgrok/releases/latest/download/rgrok-server-linux-x86_64
chmod +x /usr/local/bin/rgrok-server

# Install systemd service
sudo cp deploy/rgrok-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now rgrok-server

# Watch logs
journalctl -fu rgrok-server
```

**`rgrok-server.service`:**

```ini
[Unit]
Description=rgrok tunnel server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=rgrok
ExecStart=/usr/local/bin/rgrok-server --config /etc/rgrok/server.toml
Restart=always
RestartSec=5
# Allow binding port 443 and 80 without root
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

### Step 4 — Generate a client auth token

```bash
rgrok-server token generate --label "my-laptop"
# ► rgrok_tok_eyJhbGciOiJIUzI1NiJ9...
```

### Step 5 — Install & configure client

```bash
# On your developer machine
cargo install rgrok-client --bin rgrok

# Save config
rgrok authtoken rgrok_tok_eyJhbGciOiJIUzI1NiJ9...
rgrok config set server.host tunnel.mysite.com

# Start tunneling!
rgrok http 5173
```

---

## 16. CLI Reference

```
USAGE:
    rgrok [OPTIONS] <COMMAND>

OPTIONS:
    -c, --config <FILE>     Config file [default: ~/.config/rgrok/config.toml]
        --server <HOST>     Override server host
    -h, --help
    -V, --version

COMMANDS:
    http <PORT>             Forward HTTP traffic to local port
    https <PORT>            Forward HTTPS (TLS-terminated) to local port
    tcp <PORT>              Expose raw TCP port
    authtoken <TOKEN>       Save auth token to config
    config                  Show current configuration
    help                    Print help

HTTP OPTIONS:
    --subdomain <NAME>      Request specific subdomain (e.g. myapp)
    --auth <USER:PASS>      Enable HTTP basic authentication
    --host-header <HOST>    Rewrite Host header sent to local server
    --no-inspect            Disable request capture
    --inspect-port <PORT>   Inspection UI port [default: 4040]

TCP OPTIONS:
    --remote-port <PORT>    Request specific remote port

EXAMPLES:
    rgrok http 3000
    rgrok http 3000 --subdomain myapi --auth admin:secret
    rgrok https 3000
    rgrok tcp 22                          # expose SSH
    rgrok tcp 5432 --remote-port 15432   # expose Postgres on port 15432
```

---

## 17. Milestones & Build Order

Build in this order to maintain a working system at each phase:

### Phase 1 — Core tunnel (2–3 weeks)
- [ ] `rgrok-proto`: define `ClientMsg` / `ServerMsg` with serde + MessagePack
- [ ] `rgrok-server`: basic TCP listener, yamux, control plane handler (no TLS yet)
- [ ] `rgrok-client`: connect to server, send Auth + TunnelRequest, print URL
- [ ] End-to-end: plain HTTP tunnel works on localhost with no TLS

### Phase 2 — TLS & real deployment (1–2 weeks)
- [ ] Integrate `rustls` into server and client
- [ ] Implement ACME wildcard cert provisioning (`instant-acme` + Cloudflare DNS-01)
- [ ] Server routes by SNI / Host header to correct tunnel session
- [ ] Wildcard DNS setup docs + test on real VPS

### Phase 3 — TCP tunnels & auth (1 week)
- [ ] TCP tunnel type (dynamic port allocation)
- [ ] JWT auth token generation and validation
- [ ] HTTP basic auth middleware
- [ ] Rate limiting on tunnel creation

### Phase 4 — Web inspection UI (1–2 weeks)
- [ ] Client-side request capture (tee the yamux stream)
- [ ] `CapturedRequest` data model and in-memory ring buffer
- [ ] Axum inspection server at `:4040`
- [ ] Embedded HTML/JS dashboard
- [ ] Replay endpoint

### Phase 5 — Polish & hardening (1 week)
- [ ] Pretty terminal output with `crossterm`
- [ ] Exponential backoff reconnection in client
- [ ] Certificate hot-reload
- [ ] Full integration test suite
- [ ] `systemd` service file + deployment docs
- [ ] GitHub Actions CI/CD with cross-compiled release binaries

### Phase 6 — Nice-to-haves (post-v1)
- [ ] **QUIC transport** (see [Section 18](#18-quic-transport-phase-6))
- [ ] HTTP/2 support on proxy listener
- [ ] Prometheus metrics endpoint
- [ ] Custom response headers / request rewriting
- [ ] WebSocket tunnel inspection
- [ ] Admin API for listing/killing active tunnels
- [ ] Multi-user support with per-token tunnel quotas

---

## Appendix A — Subdomain Generation

```rust
const ADJECTIVES: &[&str] = &["amber", "brave", "calm", "dark", "eager", /* ... 50 more */];
const NOUNS: &[&str] = &["atlas", "beam", "coast", "dawn", "echo", /* ... 50 more */];

/// Generates a memorable, URL-safe subdomain like "amber-atlas-7f3a"
pub fn generate_subdomain() -> String {
    let mut rng = rand::thread_rng();
    let adj = ADJECTIVES[rng.gen_range(0..ADJECTIVES.len())];
    let noun = NOUNS[rng.gen_range(0..NOUNS.len())];
    let suffix: String = (0..4).map(|_| format!("{:x}", rng.gen::<u8>() & 0xF)).collect();
    format!("{}-{}-{}", adj, noun, suffix)
}
// Example output: "amber-atlas-7f3a", "brave-coast-3c9d"
```

## Appendix B — yamux over WebSocket bridge

`tokio-tungstenite` produces a `WebSocketStream` that implements `Stream + Sink`. yamux needs `AsyncRead + AsyncWrite`. A thin adapter:

```rust
use futures::{Stream, Sink, StreamExt, SinkExt};
use tokio::io::{AsyncRead, AsyncWrite};

pub struct WsCompat(pub WebSocketStream<MaybeTlsStream<TcpStream>>);

impl AsyncRead for WsCompat {
    fn poll_read(/* ... */) -> Poll<io::Result<usize>> {
        // Read the next binary WebSocket frame, copy bytes into buf
    }
}

impl AsyncWrite for WsCompat {
    fn poll_write(/* ... */) -> Poll<io::Result<usize>> {
        // Wrap bytes in a binary WebSocket frame, send it
    }
    // flush / shutdown implementations
}
```

Alternatively, use the `tokio-util` `FramedRead`/`FramedWrite` pattern with a `WebSocketCodec`.

**Important buffering consideration:** yamux writes arbitrary byte chunks (often small), but each `poll_write` on `WsCompat` would produce a separate WebSocket frame — potentially hundreds of tiny frames per HTTP request, each with 2–14 bytes of WS framing overhead. To avoid this:

- Buffer writes using `tokio::io::BufWriter` (e.g., 8 KB buffer) wrapping the `WsCompat`, so multiple yamux writes coalesce into a single WebSocket binary frame.
- On the read side, a single WebSocket frame may contain more data than yamux requests in one `poll_read`. Use an internal `BytesMut` buffer to hold the remainder and serve it across multiple reads.

```rust
pub struct WsCompat {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    read_buf: BytesMut,   // leftover bytes from last WS frame
}
```

---

## 18. QUIC Transport (Phase 6)

### Why bother

The WebSocket+yamux transport works well but has one structural limitation inherited from TCP: **head-of-line blocking**. If a single packet is dropped, TCP stalls retransmission — and because all yamux streams share one TCP connection, *every* concurrent proxy stream freezes until that packet is recovered. Under packet loss (mobile networks, congested links) this is noticeably worse than it needs to be.

QUIC solves this at the transport layer. Its streams are independent: a lost packet on one stream does not stall others. As a bonus, TLS 1.3 is intrinsic to QUIC (no separate handshake), and QUIC supports **0-RTT session resumption** so a client whose IP changes (WiFi → cellular) can rejoin without re-authenticating.

Crucially, yamux becomes **redundant** when using QUIC — QUIC already multiplexes streams natively — so the QUIC path is actually simpler code than the WebSocket path.

### Transport abstraction

The key to supporting both transports without duplicating the control/proxy logic is a thin trait over "a connection that can open and accept streams":

```rust
// crates/rgrok-proto/src/transport.rs

use tokio::io::{AsyncRead, AsyncWrite};

/// A bidirectional byte stream (one proxy request or the control channel)
pub trait TunnelStream: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

/// A multiplexed connection that can open/accept independent streams
#[async_trait::async_trait]
pub trait TunnelTransport: Send + Sync + 'static {
    /// Open a new outbound stream (client-side)
    async fn open_stream(&self) -> anyhow::Result<Box<dyn TunnelStream>>;

    /// Accept the next inbound stream (server-side)
    async fn accept_stream(&self) -> anyhow::Result<Box<dyn TunnelStream>>;

    /// Human-readable label for logs ("quic" | "websocket")
    fn kind(&self) -> &'static str;
}
```

Both backend implementations satisfy this trait. Everything above it — `control.rs`, `proxy.rs`, the inspection pipeline — touches only `Box<dyn TunnelTransport>` and never cares which transport is active.

### WebSocket + yamux implementation (existing)

```rust
pub struct YamuxTransport(Arc<Mutex<yamux::Connection<WsCompat>>>);

#[async_trait]
impl TunnelTransport for YamuxTransport {
    async fn open_stream(&self) -> anyhow::Result<Box<dyn TunnelStream>> {
        let stream = self.0.lock().await.open_stream().await?;
        Ok(Box::new(stream))
    }
    async fn accept_stream(&self) -> anyhow::Result<Box<dyn TunnelStream>> {
        let stream = self.0.lock().await.next_stream().await?
            .ok_or_else(|| anyhow::anyhow!("connection closed"))?;
        Ok(Box::new(stream))
    }
    fn kind(&self) -> &'static str { "websocket" }
}
```

### QUIC implementation (new)

```rust
// crates/rgrok-server/src/quic.rs  (and rgrok-client/src/quic.rs)

use quinn::{Connection, RecvStream, SendStream};

pub struct QuicTransport(Connection);

/// A QUIC stream wraps quinn's split send/recv into one AsyncRead+AsyncWrite
pub struct QuicStream {
    send: SendStream,
    recv: RecvStream,
}

impl AsyncRead for QuicStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context, buf: &mut ReadBuf)
        -> Poll<io::Result<()>>
    {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context, buf: &[u8])
        -> Poll<io::Result<usize>>
    {
        Pin::new(&mut self.send).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

impl TunnelStream for QuicStream {}

#[async_trait]
impl TunnelTransport for QuicTransport {
    async fn open_stream(&self) -> anyhow::Result<Box<dyn TunnelStream>> {
        let (send, recv) = self.0.open_bi().await?;
        Ok(Box::new(QuicStream { send, recv }))
    }
    async fn accept_stream(&self) -> anyhow::Result<Box<dyn TunnelStream>> {
        let (send, recv) = self.0.accept_bi().await?;
        Ok(Box::new(QuicStream { send, recv }))
    }
    fn kind(&self) -> &'static str { "quic" }
}
```

### Server-side QUIC endpoint

The server needs a UDP socket alongside its existing TCP listeners. The QUIC endpoint reuses the same `rustls::ServerConfig` already provisioned for TLS — no separate cert handling.

```rust
// rgrok-server/src/quic.rs

pub async fn serve_quic(state: Arc<ServerState>, tls: Arc<rustls::ServerConfig>) {
    // quinn's ServerConfig wraps rustls directly
    let quic_cfg = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls)?
    ));

    // Bind UDP on the same port number as the WebSocket control plane
    let endpoint = quinn::Endpoint::server(
        quic_cfg,
        format!("0.0.0.0:{}", state.config.server.control_port).parse()?
    )?;

    tracing::info!("QUIC endpoint listening on UDP :{}", state.config.server.control_port);

    while let Some(incoming) = endpoint.accept().await {
        let state = state.clone();
        tokio::spawn(async move {
            let conn = incoming.await?;
            let transport = Arc::new(QuicTransport(conn));
            // Hand off to the same control plane handler used by WebSocket
            control::handle_client(transport, state).await;
        });
    }
}
```

### Client-side: probe and fallback

The client tries QUIC first with a short timeout. If UDP appears to be blocked (connection timeout, ICMP unreachable, or explicit config), it falls back to WebSocket transparently.

```rust
// rgrok-client/src/tunnel.rs

pub async fn connect_transport(config: &ClientConfig) -> anyhow::Result<Box<dyn TunnelTransport>> {
    match config.transport.preferred.as_str() {
        "quic" => {
            tracing::debug!("Attempting QUIC connection…");
            match tokio::time::timeout(
                Duration::from_secs(2),
                connect_quic(config)
            ).await {
                Ok(Ok(t)) => {
                    tracing::info!("Connected via QUIC");
                    return Ok(Box::new(t));
                }
                Ok(Err(e)) => tracing::warn!("QUIC failed ({}), falling back to WebSocket", e),
                Err(_)     => tracing::warn!("QUIC timed out, falling back to WebSocket"),
            }
            // Fall through to WebSocket
        }
        "websocket" => { /* skip QUIC probe */ }
        other => anyhow::bail!("Unknown transport: {}", other),
    }

    tracing::debug!("Connecting via WebSocket…");
    let t = connect_websocket(config).await?;
    tracing::info!("Connected via WebSocket");
    Ok(Box::new(YamuxTransport::new(t)))
}

async fn connect_quic(config: &ClientConfig) -> anyhow::Result<QuicTransport> {
    // Build rustls ClientConfig — same roots as the WebSocket path
    let tls = build_client_tls_config()?;
    let quic_client_cfg = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)?
    ));

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(quic_client_cfg);

    let conn = endpoint
        .connect(
            (config.server.host.as_str(), config.server.control_port).to_socket_addrs()?.next().unwrap(),
            &config.server.host,
        )?
        .await?;

    Ok(QuicTransport(conn))
}
```

### 0-RTT reconnection

When a QUIC session is resumed after a network change, `quinn` provides `Connecting::into_0rtt()`. The client should attempt this on reconnect before falling back to a full handshake:

```rust
async fn reconnect_quic(endpoint: &quinn::Endpoint, config: &ClientConfig)
    -> anyhow::Result<QuicTransport>
{
    let connecting = endpoint.connect(server_addr, &config.server.host)?;

    // Try 0-RTT first; falls back to 1-RTT automatically if server rejects it
    let conn = match connecting.into_0rtt() {
        Ok((conn, _zero_rtt_accepted)) => conn,
        Err(connecting) => connecting.await?,  // full 1-RTT handshake
    };

    Ok(QuicTransport(conn))
}
```

**0-RTT security constraints:**

0-RTT data is **not replay-safe**. An attacker who captures 0-RTT packets can replay them to the server. This has critical implications:

- **Auth messages MUST NOT be sent in 0-RTT.** A replayed Auth message would grant the attacker a valid session using the victim's token. The client must wait for the 1-RTT handshake to complete before sending the `ClientMsg::Auth` message.
- **0-RTT is only safe for session resumption after initial authentication.** Use it to re-establish the QUIC connection faster after a network change (WiFi → cellular), but the Auth exchange must always happen over the replay-protected 1-RTT channel.
- **Proxy stream data in 0-RTT should be rejected.** The server should configure `quinn::ServerConfig` with `max_early_data_size = 0` for proxy streams. Only the connection setup benefits from 0-RTT; actual data transfer waits for the handshake to complete.

In practice, this means `into_0rtt()` speeds up the QUIC connection establishment, but the application-level Auth handshake still happens after the TLS handshake confirms the connection is not replayed.

### Configuration additions

```toml
# client config — new [transport] section
[transport]
# "quic" (try QUIC, fall back to websocket) | "websocket" (always websocket)
preferred = "quic"

# How long to wait for QUIC before falling back (milliseconds)
quic_probe_timeout_ms = 2000
```

```toml
# server config — new [transport] section
[transport]
# Enable QUIC endpoint (requires UDP port to be open in firewall)
quic_enabled = true

# QUIC and WebSocket control plane share this port
# UDP port = control_port for QUIC, TCP port = control_port for WebSocket
```

### Firewall note

Because QUIC runs over UDP, the VPS firewall must allow inbound UDP on the control port (default 7835):

```bash
# ufw
sudo ufw allow 7835/udp

# iptables
sudo iptables -A INPUT -p udp --dport 7835 -j ACCEPT
```

Document this prominently — forgetting the UDP rule is the most common QUIC deployment gotcha.

### Dependency addition

```toml
# Cargo.toml workspace dependencies — add:
quinn = { version = "0.11", features = ["rustls"] }
```

`quinn` 0.11 uses `rustls` 0.23, which matches the rest of the workspace. No new TLS stack is introduced.

### Implementation delta summary

| File | Change |
|---|---|
| `rgrok-proto/src/transport.rs` | **New** — `TunnelStream` + `TunnelTransport` traits |
| `rgrok-server/src/quic.rs` | **New** — `QuicTransport`, `serve_quic()` |
| `rgrok-client/src/quic.rs` | **New** — `connect_quic()`, `reconnect_quic()` |
| `rgrok-client/src/tunnel.rs` | **Modified** — `connect_transport()` probe/fallback logic |
| `rgrok-server/src/control.rs` | **Modified** — accept `Box<dyn TunnelTransport>` instead of concrete yamux type |
| `rgrok-server/src/main.rs` | **Modified** — spawn `serve_quic()` alongside existing listeners |
| `rgrok-server/src/config.rs` | **Modified** — add `[transport]` section |
| `rgrok-client/src/config.rs` | **Modified** — add `[transport]` section |
| `Cargo.toml` | **Modified** — add `quinn = "0.11"` |

Estimated effort: **2–3 days** after the WebSocket transport is stable. The trait abstraction is the only design decision that needs to be made upfront — once `TunnelTransport` is in place, the QUIC implementation slots in without touching the control or proxy layers.

---

## Appendix C — QUIC vs WebSocket transport comparison

| Property | WebSocket + yamux | QUIC |
|---|---|---|
| Protocol | TCP + TLS + WS + yamux | UDP + QUIC (TLS built-in) |
| Head-of-line blocking | Yes (TCP-level) | No (per-stream) |
| Multiplexing | yamux (userspace) | Native (kernel-assisted) |
| 0-RTT reconnect | No (full TLS + WS handshake) | Yes |
| Firewall compatibility | Excellent (TCP 443/7835) | Good (UDP may be blocked) |
| Implementation complexity | Lower | Slightly higher |
| Rust crate | `tokio-tungstenite` + `yamux` | `quinn` |
| When to prefer | Corporate networks, simplicity | Mobile, high-concurrency, packet loss |
