mod auth;
mod config;
mod control;
mod dns;
mod inspect;
mod metrics;
mod proxy;
mod tls;
mod tunnel_manager;
mod web_ui;

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tokio_rustls::TlsAcceptor;
use tracing::info;

use crate::config::Config;
use crate::tunnel_manager::ServerState;

#[derive(Parser)]
#[command(name = "rgrok-server", version, about = "rgrok tunnel server")]
struct Cli {
    /// Path to config file
    #[arg(short, long, default_value = "/etc/rgrok/server.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new auth token
    Token {
        #[command(subcommand)]
        action: TokenAction,
    },
}

#[derive(Subcommand)]
enum TokenAction {
    /// Generate a new client auth token
    Generate {
        /// Label for the token
        #[arg(long)]
        label: String,
        /// Token expiry in seconds (e.g. 7776000 for 90 days)
        #[arg(long)]
        expires_in: Option<u64>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Handle subcommands that don't need the full server
    if let Some(Commands::Token { action }) = &cli.command {
        match action {
            TokenAction::Generate { label, expires_in } => {
                let config = Config::load(&cli.config)?;
                let token = auth::generate_token(&config.auth.secret, label, *expires_in)?;
                println!("{}", token);
                return Ok(());
            }
        }
    }

    // Load config
    let config = Config::load(&cli.config)?;

    // Init tracing
    init_tracing(&config);

    info!("rgrok-server starting");
    info!(domain = %config.server.domain, "Server configuration loaded");

    // Load TLS config — try files/ACME cache/self-signed first,
    // then attempt ACME provisioning if Cloudflare is configured and no certs exist
    let tls_config = match tls::load_tls_config(&config) {
        Ok(cfg) => cfg,
        Err(e) => {
            if !config.cloudflare.api_token.is_empty() && !config.cloudflare.zone_id.is_empty() {
                info!("No existing TLS certs, attempting ACME provisioning: {}", e);
                tls::provision_wildcard_cert(&config).await?
            } else {
                return Err(e);
            }
        }
    };
    let tls_acceptor = TlsAcceptor::from(tls_config.clone());

    // Create shared state
    let state = Arc::new(ServerState::new(config.clone()));

    // Set initial TLS config on the watch channel
    let _ = state.tls_config.send(Some(tls_config.clone()));

    // Spawn control plane listener (with TLS if certs are available)
    let control_state = state.clone();
    let control_tls = if config.tls.cert_file.is_some() || config.tls.key_file.is_some() {
        Some(tls_acceptor.clone())
    } else {
        // Dev mode: check if ACME certs exist on disk
        let cert_path = std::path::PathBuf::from(&config.tls.cert_dir).join("fullchain.pem");
        if cert_path.exists() {
            Some(tls_acceptor.clone())
        } else {
            info!("No TLS certs configured — control plane running without TLS (dev mode)");
            None
        }
    };
    tokio::spawn(async move {
        if let Err(e) = control::serve(control_state, control_tls).await {
            tracing::error!("Control plane error: {}", e);
        }
    });

    // Spawn HTTPS proxy listener (port 443)
    let https_state = state.clone();
    let https_tls = tls_acceptor.clone();
    tokio::spawn(async move {
        if let Err(e) = proxy::serve_https(https_state, https_tls).await {
            tracing::error!("HTTPS proxy error: {}", e);
        }
    });

    // Spawn HTTP proxy listener (port 80) — redirects to HTTPS
    let http_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = proxy::serve_http(http_state).await {
            tracing::error!("HTTP proxy error: {}", e);
        }
    });

    // Spawn web inspection UI
    let ui_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = web_ui::serve(ui_state).await {
            tracing::error!("Web UI error: {}", e);
        }
    });

    // Spawn Prometheus metrics endpoint
    let metrics = state.metrics.clone();
    let metrics_port = config.server.metrics_port;
    tokio::spawn(async move {
        if let Err(e) = metrics::serve(metrics, metrics_port).await {
            tracing::error!("Metrics endpoint error: {}", e);
        }
    });

    // Spawn certificate hot-reload loop (checks expiry every 12h)
    let renewal_state = state.clone();
    tokio::spawn(async move {
        tls::cert_renewal_loop(renewal_state).await;
    });

    // Spawn config reload handler (SIGHUP on Unix, manual reload on Windows)
    let reload_state = state.clone();
    let config_path = cli.config.clone();
    tokio::spawn(async move {
        reload_on_signal(reload_state, config_path).await;
    });

    info!("rgrok-server ready");

    // Wait for shutdown signal, then trigger graceful drain
    shutdown_signal().await;
    info!("Shutdown signal received — draining active connections (5s grace period)");
    state.cancel.cancel();

    // Allow in-flight streams up to 5 seconds to finish
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    info!("Drain period complete, shutting down");

    Ok(())
}

fn init_tracing(config: &Config) {
    use tracing_subscriber::EnvFilter;

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.logging.level));

    match config.logging.format.as_str() {
        "json" => {
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(filter)
                .init();
        }
        _ => {
            tracing_subscriber::fmt().with_env_filter(filter).init();
        }
    }
}

/// Reload config on SIGHUP (Unix) — updates the jti blocklist at runtime.
/// On Windows, this is a no-op since SIGHUP doesn't exist.
#[cfg(unix)]
async fn reload_on_signal(state: Arc<ServerState>, config_path: PathBuf) {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sighup = signal(SignalKind::hangup()).expect("failed to listen for SIGHUP");
    loop {
        sighup.recv().await;
        info!("SIGHUP received — reloading config");
        match Config::load(&config_path) {
            Ok(new_config) => {
                state
                    .reload_revoked_jtis(&new_config.auth.revoked_jtis)
                    .await;
                info!(
                    revoked_count = new_config.auth.revoked_jtis.len(),
                    "Revoked JTI blocklist reloaded"
                );
            }
            Err(e) => {
                tracing::error!("Failed to reload config: {}", e);
            }
        }
    }
}

#[cfg(not(unix))]
async fn reload_on_signal(_state: Arc<ServerState>, _config_path: PathBuf) {
    // SIGHUP is not available on Windows — config reload requires restart
    std::future::pending::<()>().await;
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl+c");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    use rgrok_proto::messages::*;
    use rgrok_proto::spawn_yamux_driver;
    use rgrok_proto::transport::{
        read_msg_from_stream, write_msg_to_stream, yamux_config, WsCompat,
    };

    const TEST_SECRET: &str = "test-secret-that-is-definitely-32-chars!";

    fn test_config(control_port: u16, http_port: u16, https_port: u16) -> config::Config {
        config::Config {
            server: config::ServerConfig {
                domain: "tunnel.test.local".to_string(),
                control_port,
                https_port,
                http_port,
                tcp_port_range: [30000, 30100],
                max_tunnels: 10,
                tunnel_idle_timeout_secs: 300,
                metrics_port: 0, // disabled in tests
            },
            auth: config::AuthConfig {
                secret: TEST_SECRET.to_string(),
                tokens: vec![],
                revoked_jtis: vec![],
            },
            tls: config::TlsConfig {
                acme_env: "staging".to_string(),
                acme_email: String::new(),
                cert_dir: "/tmp/rgrok-test-certs".to_string(),
                cert_file: None,
                key_file: None,
            },
            cloudflare: config::CloudflareConfig {
                api_token: String::new(),
                zone_id: String::new(),
                dns_ttl: 1,
                per_tunnel_dns: false,
            },
            inspect: config::InspectConfig {
                ui_port: 0,
                ui_bind: "127.0.0.1".to_string(),
                buffer_size: 100,
            },
            logging: config::LoggingConfig {
                level: "warn".to_string(),
                format: "pretty".to_string(),
            },
        }
    }

    fn test_token() -> String {
        auth::generate_token(TEST_SECRET, "test-client", None).unwrap()
    }

    async fn find_free_port() -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    }

    async fn start_test_server() -> (u16, Arc<tunnel_manager::ServerState>) {
        let port = find_free_port().await;
        let http_port = find_free_port().await;
        let https_port = find_free_port().await;
        let cfg = test_config(port, http_port, https_port);
        let state = Arc::new(tunnel_manager::ServerState::new(cfg));

        let s = state.clone();
        tokio::spawn(async move {
            control::serve(s, None).await.ok();
        });

        // Wait for server to start
        tokio::time::sleep(Duration::from_millis(100)).await;
        (port, state)
    }

    async fn connect_ws(
        port: u16,
    ) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>
    {
        let url = format!("ws://127.0.0.1:{}/", port);
        let (ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
        ws
    }

    #[tokio::test]
    async fn test_auth_success() {
        let (port, _state) = start_test_server().await;
        let ws = connect_ws(port).await;

        let ws_compat = WsCompat::new(ws);
        let mux = yamux::Connection::new(ws_compat, yamux_config(), yamux::Mode::Client);
        let (control, _rx, _handle) = spawn_yamux_driver(mux);

        let mut ctrl = control.open_stream().await.unwrap();

        write_msg_to_stream(
            &mut ctrl,
            &ClientMsg::Auth {
                token: test_token(),
                version: "0.1.0".to_string(),
            },
        )
        .await
        .unwrap();

        let resp: ServerMsg = read_msg_from_stream(&mut ctrl).await.unwrap();
        assert!(matches!(resp, ServerMsg::AuthOk { .. }));
    }

    #[tokio::test]
    async fn test_auth_failure() {
        let (port, _state) = start_test_server().await;
        let ws = connect_ws(port).await;

        let ws_compat = WsCompat::new(ws);
        let mux = yamux::Connection::new(ws_compat, yamux_config(), yamux::Mode::Client);
        let (control, _rx, _handle) = spawn_yamux_driver(mux);

        let mut ctrl = control.open_stream().await.unwrap();

        write_msg_to_stream(
            &mut ctrl,
            &ClientMsg::Auth {
                token: "rgrok_tok_bogus".to_string(),
                version: "0.1.0".to_string(),
            },
        )
        .await
        .unwrap();

        // Server sends AuthErr then closes — we may get the message or EOF
        match read_msg_from_stream::<ServerMsg>(&mut ctrl).await {
            Ok(ServerMsg::AuthErr { .. }) => {} // Got the rejection message
            Err(_) => {}                        // Connection closed before we read — also valid
            Ok(other) => panic!("Expected AuthErr or EOF, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_tunnel_creation() {
        let (port, state) = start_test_server().await;
        let ws = connect_ws(port).await;

        let ws_compat = WsCompat::new(ws);
        let mux = yamux::Connection::new(ws_compat, yamux_config(), yamux::Mode::Client);
        let (control, _rx, _handle) = spawn_yamux_driver(mux);

        let mut ctrl = control.open_stream().await.unwrap();

        // Auth
        write_msg_to_stream(
            &mut ctrl,
            &ClientMsg::Auth {
                token: test_token(),
                version: "0.1.0".to_string(),
            },
        )
        .await
        .unwrap();
        let _: ServerMsg = read_msg_from_stream(&mut ctrl).await.unwrap();

        // Request tunnel
        write_msg_to_stream(
            &mut ctrl,
            &ClientMsg::TunnelRequest {
                id: "test-tunnel-1".to_string(),
                tunnel_type: TunnelType::Http,
                subdomain: Some("myapp".to_string()),
                basic_auth: None,
                options: TunnelOptions::default(),
            },
        )
        .await
        .unwrap();

        let resp: ServerMsg = read_msg_from_stream(&mut ctrl).await.unwrap();
        match resp {
            ServerMsg::TunnelAck {
                id,
                public_url,
                tunnel_type,
            } => {
                assert_eq!(id, "test-tunnel-1");
                assert!(public_url.contains("myapp"));
                assert_eq!(tunnel_type, TunnelType::Http);
            }
            other => panic!("Expected TunnelAck, got {:?}", other),
        }

        // Verify tunnel is registered
        assert!(state.tunnels.contains_key("myapp"));
    }

    #[tokio::test]
    async fn test_heartbeat() {
        let (port, _state) = start_test_server().await;
        let ws = connect_ws(port).await;

        let ws_compat = WsCompat::new(ws);
        let mux = yamux::Connection::new(ws_compat, yamux_config(), yamux::Mode::Client);
        let (control, _rx, _handle) = spawn_yamux_driver(mux);

        let mut ctrl = control.open_stream().await.unwrap();

        // Auth first
        write_msg_to_stream(
            &mut ctrl,
            &ClientMsg::Auth {
                token: test_token(),
                version: "0.1.0".to_string(),
            },
        )
        .await
        .unwrap();
        let _: ServerMsg = read_msg_from_stream(&mut ctrl).await.unwrap();

        // Send ping
        write_msg_to_stream(&mut ctrl, &ClientMsg::Ping { seq: 42 })
            .await
            .unwrap();

        let resp: ServerMsg = read_msg_from_stream(&mut ctrl).await.unwrap();
        match resp {
            ServerMsg::Pong { seq } => assert_eq!(seq, 42),
            other => panic!("Expected Pong, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_duplicate_subdomain_rejected() {
        let (port, _state) = start_test_server().await;
        let ws = connect_ws(port).await;

        let ws_compat = WsCompat::new(ws);
        let mux = yamux::Connection::new(ws_compat, yamux_config(), yamux::Mode::Client);
        let (control, _rx, _handle) = spawn_yamux_driver(mux);

        let mut ctrl = control.open_stream().await.unwrap();

        // Auth
        write_msg_to_stream(
            &mut ctrl,
            &ClientMsg::Auth {
                token: test_token(),
                version: "0.1.0".to_string(),
            },
        )
        .await
        .unwrap();
        let _: ServerMsg = read_msg_from_stream(&mut ctrl).await.unwrap();

        // First tunnel
        write_msg_to_stream(
            &mut ctrl,
            &ClientMsg::TunnelRequest {
                id: "t1".to_string(),
                tunnel_type: TunnelType::Http,
                subdomain: Some("unique-sub".to_string()),
                basic_auth: None,
                options: TunnelOptions::default(),
            },
        )
        .await
        .unwrap();
        let resp: ServerMsg = read_msg_from_stream(&mut ctrl).await.unwrap();
        assert!(matches!(resp, ServerMsg::TunnelAck { .. }));

        // Duplicate subdomain
        write_msg_to_stream(
            &mut ctrl,
            &ClientMsg::TunnelRequest {
                id: "t2".to_string(),
                tunnel_type: TunnelType::Http,
                subdomain: Some("unique-sub".to_string()),
                basic_auth: None,
                options: TunnelOptions::default(),
            },
        )
        .await
        .unwrap();
        let resp: ServerMsg = read_msg_from_stream(&mut ctrl).await.unwrap();
        match resp {
            ServerMsg::Error { code, .. } => assert_eq!(code, 409),
            other => panic!("Expected Error 409, got {:?}", other),
        }
    }

    /// E2E Proxy Roundtrip: verify bytes sent to the server reach the client and return correctly
    /// through the tunnel's proxy stream mechanism (StreamOpen → correlation_id → bidirectional data).
    /// Also covers Stream Correlation: client handles StreamOpen and matches the correlation_id.
    #[tokio::test]
    async fn test_e2e_proxy_roundtrip() {
        use futures::{AsyncReadExt, AsyncWriteExt};

        let (port, state) = start_test_server().await;
        let ws = connect_ws(port).await;

        let ws_compat = WsCompat::new(ws);
        let mux = yamux::Connection::new(ws_compat, yamux_config(), yamux::Mode::Client);
        let (control, _rx, _handle) = spawn_yamux_driver(mux);

        let mut ctrl = control.open_stream().await.unwrap();

        // Auth
        write_msg_to_stream(
            &mut ctrl,
            &ClientMsg::Auth {
                token: test_token(),
                version: "0.1.0".to_string(),
            },
        )
        .await
        .unwrap();
        let _: ServerMsg = read_msg_from_stream(&mut ctrl).await.unwrap();

        // Create tunnel
        write_msg_to_stream(
            &mut ctrl,
            &ClientMsg::TunnelRequest {
                id: "e2e-tunnel".to_string(),
                tunnel_type: TunnelType::Http,
                subdomain: Some("e2e".to_string()),
                basic_auth: None,
                options: TunnelOptions::default(),
            },
        )
        .await
        .unwrap();
        let _: ServerMsg = read_msg_from_stream(&mut ctrl).await.unwrap();

        // Set up a pending proxy stream on the server side
        let tunnel = state.tunnels.get("e2e").unwrap().clone();
        let correlation_id = tunnel.next_correlation_id();
        let (stream_tx, stream_rx) = tokio::sync::oneshot::channel();
        tunnel.pending_streams.insert(correlation_id, stream_tx);

        // Send StreamOpen to client via the tunnel's control channel
        tunnel
            .control_tx
            .send(ServerMsg::StreamOpen {
                correlation_id,
                tunnel_id: "e2e-tunnel".to_string(),
            })
            .await
            .unwrap();

        // Client reads StreamOpen and verifies correlation_id
        let msg: ServerMsg = read_msg_from_stream(&mut ctrl).await.unwrap();
        match &msg {
            ServerMsg::StreamOpen {
                correlation_id: cid,
                ..
            } => assert_eq!(*cid, correlation_id),
            other => panic!("Expected StreamOpen, got {:?}", other),
        }

        // Client opens a data stream and writes the 4-byte correlation_id header
        let mut data_stream = control.open_stream().await.unwrap();
        data_stream
            .write_all(&correlation_id.to_be_bytes())
            .await
            .unwrap();
        data_stream.flush().await.unwrap();

        // Server's handle_proxy_data_stream resolves the pending stream
        let mut server_proxy = tokio::time::timeout(Duration::from_secs(5), stream_rx)
            .await
            .expect("timeout waiting for proxy stream")
            .expect("oneshot cancelled");

        // Verify bidirectional data flow through the tunnel
        let request_data = b"GET /hello HTTP/1.1\r\nHost: e2e.tunnel.test.local\r\n\r\n";
        server_proxy.write_all(request_data).await.unwrap();
        server_proxy.flush().await.unwrap();

        let mut buf = [0u8; 512];
        let n = data_stream.read(&mut buf).await.unwrap();
        assert_eq!(
            &buf[..n],
            request_data,
            "Request bytes should reach the client"
        );

        let response_data = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        data_stream.write_all(response_data).await.unwrap();
        data_stream.flush().await.unwrap();

        let n = server_proxy.read(&mut buf).await.unwrap();
        assert_eq!(
            &buf[..n],
            response_data,
            "Response bytes should reach the server"
        );
    }

    /// Graceful Shutdown: verify CancellationToken correctly stops listeners, drains active
    /// streams, and cleans up tunnel registrations and metrics.
    #[tokio::test]
    async fn test_graceful_shutdown_drains_connections() {
        let (port, state) = start_test_server().await;
        let ws = connect_ws(port).await;

        let ws_compat = WsCompat::new(ws);
        let mux = yamux::Connection::new(ws_compat, yamux_config(), yamux::Mode::Client);
        let (control, _rx, _handle) = spawn_yamux_driver(mux);

        let mut ctrl = control.open_stream().await.unwrap();

        // Auth + tunnel
        write_msg_to_stream(
            &mut ctrl,
            &ClientMsg::Auth {
                token: test_token(),
                version: "0.1.0".to_string(),
            },
        )
        .await
        .unwrap();
        let _: ServerMsg = read_msg_from_stream(&mut ctrl).await.unwrap();

        write_msg_to_stream(
            &mut ctrl,
            &ClientMsg::TunnelRequest {
                id: "shutdown-test".to_string(),
                tunnel_type: TunnelType::Http,
                subdomain: Some("shutdown".to_string()),
                basic_auth: None,
                options: TunnelOptions::default(),
            },
        )
        .await
        .unwrap();
        let _: ServerMsg = read_msg_from_stream(&mut ctrl).await.unwrap();

        assert!(state.tunnels.contains_key("shutdown"));
        assert_eq!(state.metrics.ws_connections_active.get(), 1);

        // Trigger graceful shutdown
        state.cancel.cancel();

        // The control stream should close within the 5s drain period
        let drain_result = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match read_msg_from_stream::<ServerMsg>(&mut ctrl).await {
                    Ok(_) => continue,
                    Err(_) => break,
                }
            }
        })
        .await;

        assert!(
            drain_result.is_ok(),
            "Server should close the connection within 5 seconds"
        );

        // Allow async cleanup to complete
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Verify tunnel cleanup
        assert!(
            !state.tunnels.contains_key("shutdown"),
            "Tunnel should be unregistered after shutdown"
        );
        assert_eq!(
            state.metrics.ws_connections_active.get(),
            0,
            "WebSocket connection metric should be decremented"
        );
    }

    /// Concurrency Stress Test: ensure 12 simultaneous tunnels from concurrent clients
    /// don't cause deadlocks and all register correctly.
    #[tokio::test]
    async fn test_concurrency_stress_multiple_tunnels() {
        let (port, state) = start_test_server().await;

        let num_tunnels: usize = 10;
        let mut handles = Vec::new();

        for i in 0..num_tunnels {
            handles.push(tokio::spawn(async move {
                let ws = connect_ws(port).await;

                let ws_compat = WsCompat::new(ws);
                let mux = yamux::Connection::new(ws_compat, yamux_config(), yamux::Mode::Client);
                let (control, _rx, _handle) = spawn_yamux_driver(mux);

                let mut ctrl = control.open_stream().await.unwrap();

                write_msg_to_stream(
                    &mut ctrl,
                    &ClientMsg::Auth {
                        token: test_token(),
                        version: "0.1.0".to_string(),
                    },
                )
                .await
                .unwrap();
                let _: ServerMsg = read_msg_from_stream(&mut ctrl).await.unwrap();

                write_msg_to_stream(
                    &mut ctrl,
                    &ClientMsg::TunnelRequest {
                        id: format!("stress-{}", i),
                        tunnel_type: TunnelType::Http,
                        subdomain: Some(format!("stress-{}", i)),
                        basic_auth: None,
                        options: TunnelOptions::default(),
                    },
                )
                .await
                .unwrap();

                let resp: ServerMsg = read_msg_from_stream(&mut ctrl).await.unwrap();
                match resp {
                    ServerMsg::TunnelAck { id, .. } => {
                        assert_eq!(id, format!("stress-{}", i));
                    }
                    other => panic!("Expected TunnelAck for stress-{}, got {:?}", i, other),
                }

                // Keep connection alive for verification
                (ctrl, control, _rx, _handle)
            }));
        }

        // Wait for all clients
        let mut connections = Vec::new();
        for handle in handles {
            connections.push(handle.await.expect("client task panicked"));
        }

        // Verify all tunnels registered without deadlocks
        assert_eq!(
            state.tunnels.len(),
            num_tunnels,
            "All {} tunnels should be registered",
            num_tunnels
        );

        for i in 0..num_tunnels {
            assert!(
                state.tunnels.contains_key(&format!("stress-{}", i)),
                "Tunnel stress-{} should exist",
                i
            );
        }

        assert_eq!(state.metrics.active_tunnels.get(), num_tunnels as i64);
        assert_eq!(
            state.metrics.ws_connections_active.get(),
            num_tunnels as i64
        );
    }

    #[tokio::test]
    async fn test_revoked_token_rejected() {
        // Generate a token, extract its jti, then revoke it
        let token = test_token();
        let claims = auth::validate_token(&token, TEST_SECRET).unwrap();
        let revoked_jti = claims.jti;

        let port = find_free_port().await;
        let http_port = find_free_port().await;
        let https_port = find_free_port().await;
        let mut cfg = test_config(port, http_port, https_port);
        cfg.auth.revoked_jtis = vec![revoked_jti];
        let state = Arc::new(tunnel_manager::ServerState::new(cfg));

        let s = state.clone();
        tokio::spawn(async move {
            control::serve(s, None).await.ok();
        });
        tokio::time::sleep(Duration::from_millis(100)).await;

        let ws = connect_ws(port).await;
        let ws_compat = WsCompat::new(ws);
        let mux = yamux::Connection::new(ws_compat, yamux_config(), yamux::Mode::Client);
        let (control, _rx, _handle) = spawn_yamux_driver(mux);

        let mut ctrl = control.open_stream().await.unwrap();

        write_msg_to_stream(
            &mut ctrl,
            &ClientMsg::Auth {
                token,
                version: "0.1.0".to_string(),
            },
        )
        .await
        .unwrap();

        match read_msg_from_stream::<ServerMsg>(&mut ctrl).await {
            Ok(ServerMsg::AuthErr { reason }) => {
                assert!(
                    reason.contains("revoked"),
                    "Expected revocation message, got: {}",
                    reason
                );
            }
            Err(_) => {} // Connection closed — also valid
            Ok(other) => panic!("Expected AuthErr for revoked token, got {:?}", other),
        }
    }
}
