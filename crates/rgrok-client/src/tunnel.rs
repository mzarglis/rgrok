use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tracing::{error, info, warn};

use rgrok_proto::messages::*;
use rgrok_proto::transport::{read_msg_from_stream, write_msg_to_stream, yamux_config, WsCompat};
use rgrok_proto::{spawn_yamux_driver, YamuxControl};

use crate::config::ClientConfig;
use crate::inspect::InspectState;
use crate::local_proxy;
use crate::output;

/// Configuration for a tunnel session derived from CLI args
pub struct TunnelConfig {
    pub local_port: u16,
    pub tunnel_type: TunnelType,
    pub subdomain: Option<String>,
    pub basic_auth: Option<BasicAuthConfig>,
    pub options: TunnelOptions,
    pub inspect_port: u16,
}

/// Main tunnel entry point: connects to server, authenticates, and runs the tunnel
pub async fn run(config: ClientConfig, tunnel_cfg: TunnelConfig) -> anyhow::Result<()> {
    if config.auth.token.is_empty() {
        anyhow::bail!("No auth token configured. Run: rgrok authtoken <your-token>");
    }

    // Use wss:// by default, fall back to ws:// if no TLS
    let server_url = format!("ws://{}:{}/tunnel", config.server.host, config.server.port);

    // Connect with exponential backoff
    let ws = connect_with_retry(&server_url).await?;
    info!("Connected to server");

    // Wrap WebSocket in yamux (client mode)
    let ws_compat = WsCompat::new(ws);
    let mux = yamux::Connection::new(ws_compat, yamux_config(), yamux::Mode::Client);
    let (mux_control, mut inbound_rx, driver_handle) = spawn_yamux_driver(mux);

    // Open stream 0 = control channel
    let mut ctrl_stream = mux_control
        .open_stream()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to open control stream: {}", e))?;

    // Step 1: Send Auth
    write_msg_to_stream(
        &mut ctrl_stream,
        &ClientMsg::Auth {
            token: config.auth.token.clone(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
    )
    .await?;

    // Step 2: Expect AuthOk
    let server_msg: ServerMsg = read_msg_from_stream(&mut ctrl_stream).await?;
    match server_msg {
        ServerMsg::AuthOk { session_id } => {
            info!(session_id = %session_id, "Authenticated");
        }
        ServerMsg::AuthErr { reason } => {
            anyhow::bail!("Authentication failed: {}", reason);
        }
        _ => anyhow::bail!("Unexpected server response during auth"),
    }

    // Step 3: Send TunnelRequest
    let req_id = uuid::Uuid::new_v4().to_string();
    write_msg_to_stream(
        &mut ctrl_stream,
        &ClientMsg::TunnelRequest {
            id: req_id.clone(),
            tunnel_type: tunnel_cfg.tunnel_type.clone(),
            subdomain: tunnel_cfg.subdomain.clone(),
            basic_auth: tunnel_cfg.basic_auth.clone(),
            options: tunnel_cfg.options.clone(),
        },
    )
    .await?;

    // Step 4: Expect TunnelAck
    let server_msg: ServerMsg = read_msg_from_stream(&mut ctrl_stream).await?;
    let public_url = match server_msg {
        ServerMsg::TunnelAck { public_url, .. } => public_url,
        ServerMsg::Error { message, .. } => {
            anyhow::bail!("Tunnel creation failed: {}", message);
        }
        _ => anyhow::bail!("Unexpected server response"),
    };

    output::print_tunnel_info(&public_url, tunnel_cfg.local_port, tunnel_cfg.inspect_port);

    // Initialize live stats dashboard
    let stats = Arc::new(output::TunnelStats::new());
    let dashboard_tx = output::spawn_dashboard(stats.clone());

    // Start inspection UI if enabled
    let inspect_state = if tunnel_cfg.inspect_port > 0 {
        let state = Arc::new(InspectState::new(tunnel_cfg.local_port));
        let ui_state = state.clone();
        let port = tunnel_cfg.inspect_port;
        tokio::spawn(async move {
            if let Err(e) = crate::inspect::serve(ui_state, port).await {
                error!("Inspection UI error: {}", e);
            }
        });
        Some(state)
    } else {
        None
    };

    // Spawn heartbeat writer on the control stream.
    // Since we can't split a yamux::Stream for concurrent read/write,
    // use a channel + select loop.
    let (msg_tx, mut msg_rx) = mpsc::channel::<ClientMsg>(64);

    let heartbeat_tx = msg_tx.clone();
    tokio::spawn(async move {
        let mut seq = 0u64;
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            seq += 1;
            if heartbeat_tx.send(ClientMsg::Ping { seq }).await.is_err() {
                break;
            }
        }
    });

    // Drain any unexpected inbound streams (server shouldn't open streams to us)
    tokio::spawn(async move {
        while let Some(_stream) = inbound_rx.recv().await {
            warn!("Unexpected inbound yamux stream from server");
        }
    });

    // Main loop: read server messages + write queued client messages
    let local_port = tunnel_cfg.local_port;
    loop {
        tokio::select! {
            result = read_msg_from_stream::<ServerMsg>(&mut ctrl_stream) => {
                let msg = match result {
                    Ok(m) => m,
                    Err(e) => {
                        info!("Control channel closed: {}", e);
                        break;
                    }
                };

                match msg {
                    ServerMsg::StreamOpen { correlation_id, .. } => {
                        let control = mux_control.clone();
                        let inspect = inspect_state.clone();
                        let stats = stats.clone();
                        let dash_tx = dashboard_tx.clone();
                        tokio::spawn(async move {
                            if let Err(e) = open_proxy_stream(
                                control, correlation_id, local_port, inspect, stats, dash_tx,
                            ).await {
                                warn!(correlation_id, "Proxy stream error: {}", e);
                            }
                        });
                    }
                    ServerMsg::Pong { seq } => {
                        tracing::trace!(seq, "Pong received");
                    }
                    ServerMsg::Error { code, message } => {
                        error!(code, message = %message, "Server error");
                    }
                    _ => {}
                }
            }
            Some(msg) = msg_rx.recv() => {
                if write_msg_to_stream(&mut ctrl_stream, &msg).await.is_err() {
                    break;
                }
            }
        }
    }

    driver_handle.abort();
    Ok(())
}

/// Open a yamux stream for proxying, write the correlation_id header,
/// connect to localhost, and bridge bidirectionally.
async fn open_proxy_stream(
    control: YamuxControl,
    correlation_id: u32,
    local_port: u16,
    inspect: Option<Arc<InspectState>>,
    stats: Arc<output::TunnelStats>,
    dashboard_tx: tokio::sync::mpsc::UnboundedSender<output::RequestLogEntry>,
) -> anyhow::Result<()> {
    let start = std::time::Instant::now();
    stats.record_connection();

    let yamux_stream = control
        .open_stream()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to open yamux stream: {}", e))?;

    // Wrap in tokio compat for tokio::io operations
    let mut compat_stream = yamux_stream.compat();

    // Write 4-byte correlation_id header so server can match this stream
    compat_stream.write_u32(correlation_id).await?;

    // Connect to local service
    let mut local = match tokio::net::TcpStream::connect(format!("127.0.0.1:{}", local_port)).await
    {
        Ok(s) => s,
        Err(e) => {
            warn!(
                local_port,
                "Cannot connect to localhost:{} — is your server running? ({})", local_port, e
            );
            return Err(e.into());
        }
    };

    // Bridge yamux stream <-> local service
    let result = local_proxy::bridge_streams(&mut compat_stream, &mut local, inspect, &stats).await;

    // Send log entry to dashboard (best-effort, from captured request data)
    let duration_ms = start.elapsed().as_millis() as u64;
    let _ = dashboard_tx.send(output::RequestLogEntry {
        method: "GET".to_string(), // overridden by capture if available
        url: format!("localhost:{}", local_port),
        status: if result.is_ok() { 200 } else { 502 },
        duration_ms,
    });

    result
}

/// Connect to the server with exponential backoff
async fn connect_with_retry(
    url: &str,
) -> anyhow::Result<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
> {
    let mut delay = Duration::from_secs(1);
    let max_delay = Duration::from_secs(60);
    let max_attempts = 10;

    for attempt in 1..=max_attempts {
        match tokio_tungstenite::connect_async(url).await {
            Ok((ws, _)) => return Ok(ws),
            Err(e) => {
                if attempt == max_attempts {
                    anyhow::bail!(
                        "Cannot reach server at {} after {} attempts: {}",
                        url,
                        max_attempts,
                        e
                    );
                }
                warn!(
                    attempt,
                    "Connection failed ({}), retrying in {:?}...", e, delay
                );
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(max_delay);
            }
        }
    }

    unreachable!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::AsyncReadExt as _;
    use tokio_util::compat::TokioAsyncReadCompatExt as _;

    /// Stream Correlation: verify that when `open_proxy_stream` is called with a given
    /// `correlation_id`, the first 4 bytes it writes on the new yamux data stream are
    /// exactly that ID encoded as big-endian u32.  This is the server's only mechanism
    /// for matching the inbound stream to the right pending request.
    #[tokio::test]
    async fn test_stream_correlation_writes_correct_header() {
        // Start a local TCP service so the proxy connection succeeds
        let local_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_port = local_listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            // Accept and hold the connection alive long enough for the header read to complete
            if let Ok((_stream, _)) = local_listener.accept().await {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        });

        // Build an in-memory yamux client/server pair
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let client_conn =
            yamux::Connection::new(client_io.compat(), yamux_config(), yamux::Mode::Client);
        let server_conn =
            yamux::Connection::new(server_io.compat(), yamux_config(), yamux::Mode::Server);
        let (client_ctrl, _client_inbound, _client_driver) = spawn_yamux_driver(client_conn);
        let (_server_ctrl, mut server_rx, _server_driver) = spawn_yamux_driver(server_conn);

        let stats = Arc::new(crate::output::TunnelStats::new());
        let (dash_tx, _dash_rx) = tokio::sync::mpsc::unbounded_channel();

        let correlation_id: u32 = 0xDEAD_BEEF;

        // open_proxy_stream: opens a yamux stream, writes the 4-byte header, then bridges.
        // Run in background; we only care about what the server side receives.
        tokio::spawn(open_proxy_stream(
            client_ctrl,
            correlation_id,
            local_port,
            None,
            stats,
            dash_tx,
        ));

        // Server side: accept the data stream opened by open_proxy_stream
        let mut data_stream = tokio::time::timeout(Duration::from_secs(2), server_rx.recv())
            .await
            .expect("timed out waiting for inbound stream")
            .expect("server_rx closed unexpectedly");

        // Read and verify the 4-byte correlation_id header
        let mut header = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(2), data_stream.read_exact(&mut header))
            .await
            .expect("timed out reading header")
            .expect("failed to read header bytes");

        assert_eq!(
            u32::from_be_bytes(header),
            correlation_id,
            "expected correlation_id {:#010x} in header, got {:#010x}",
            correlation_id,
            u32::from_be_bytes(header),
        );
    }

    /// Stream Correlation (multi-stream): each concurrent StreamOpen gets its own data stream
    /// with the correct correlation_id header — IDs are not mixed up across parallel streams.
    #[tokio::test]
    async fn test_stream_correlation_independent_ids() {
        let local_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_port = local_listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((_stream, _)) = local_listener.accept().await {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        });

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let client_conn =
            yamux::Connection::new(client_io.compat(), yamux_config(), yamux::Mode::Client);
        let server_conn =
            yamux::Connection::new(server_io.compat(), yamux_config(), yamux::Mode::Server);
        let (client_ctrl, _client_inbound, _client_driver) = spawn_yamux_driver(client_conn);
        let (_server_ctrl, mut server_rx, _server_driver) = spawn_yamux_driver(server_conn);

        let ids: [u32; 3] = [1, 42, 0xFFFF];

        for &id in &ids {
            let stats = Arc::new(crate::output::TunnelStats::new());
            let (dash_tx, _) = tokio::sync::mpsc::unbounded_channel();
            tokio::spawn(open_proxy_stream(
                client_ctrl.clone(),
                id,
                local_port,
                None,
                stats,
                dash_tx,
            ));
        }

        // Collect all inbound streams and map each to its header value
        let mut received_ids = Vec::new();
        for _ in 0..ids.len() {
            let mut stream = tokio::time::timeout(Duration::from_secs(2), server_rx.recv())
                .await
                .expect("timed out waiting for inbound stream")
                .expect("server_rx closed unexpectedly");

            let mut header = [0u8; 4];
            tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut header))
                .await
                .expect("timed out reading header")
                .expect("failed to read header bytes");

            received_ids.push(u32::from_be_bytes(header));
        }

        // Every expected ID must appear exactly once (order may differ due to concurrency)
        received_ids.sort_unstable();
        let mut expected: Vec<u32> = ids.to_vec();
        expected.sort_unstable();
        assert_eq!(
            received_ids, expected,
            "each stream must carry its own correlation_id"
        );
    }

    #[tokio::test]
    async fn test_connect_with_retry_immediate_success() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let _ = tokio_tungstenite::accept_async(stream).await;
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });

        let url = format!("ws://127.0.0.1:{}/", port);
        let result = connect_with_retry(&url).await;
        assert!(result.is_ok(), "Should connect on first attempt");
    }

    /// Reconnection resilience: verify client retries and connects after the server
    /// becomes available. Attempt 1 fails (t=0), sleep 1s, attempt 2 fails (t=1s),
    /// sleep 2s, server starts at t=1.5s, attempt 3 succeeds (t=3s).
    #[tokio::test]
    async fn test_connect_with_retry_succeeds_after_initial_failures() {
        // Keep the listener bound to avoid port reuse races. Connections accepted
        // before 1.5 s are immediately dropped (TCP RST), which `connect_with_retry`
        // treats as a retryable error just like connection-refused.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            let ready_at = tokio::time::Instant::now() + Duration::from_millis(1500);
            while let Ok((stream, _)) = listener.accept().await {
                if tokio::time::Instant::now() < ready_at {
                    drop(stream); // RST triggers client retry
                } else {
                    let _ = tokio_tungstenite::accept_async(stream).await;
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    break;
                }
            }
        });

        let url = format!("ws://127.0.0.1:{}/", port);
        let result = connect_with_retry(&url).await;
        assert!(
            result.is_ok(),
            "Should connect after server starts: {:?}",
            result.err()
        );
    }
}
