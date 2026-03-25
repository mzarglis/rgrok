use std::sync::atomic::AtomicU32;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

use rgrok_proto::messages::*;
use rgrok_proto::transport::{read_msg_from_stream, write_msg_to_stream, yamux_config, WsCompat};
use rgrok_proto::{generate_subdomain, spawn_yamux_driver, validate_subdomain};

use crate::auth;
use crate::tunnel_manager::{ServerState, TunnelSession};

/// Start the control plane listener.
pub async fn serve(
    state: Arc<ServerState>,
    tls_acceptor: Option<TlsAcceptor>,
) -> anyhow::Result<()> {
    let bind_addr = format!("0.0.0.0:{}", state.config.server.control_port);
    let listener = TcpListener::bind(&bind_addr).await?;
    info!("Control plane listening on {}", bind_addr);

    loop {
        let (tcp_stream, peer_addr) = tokio::select! {
            result = listener.accept() => result?,
            _ = state.cancel.cancelled() => {
                info!("Control plane shutting down");
                return Ok(());
            }
        };
        let state = state.clone();
        let tls_acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            if let Some(acceptor) = tls_acceptor {
                match acceptor.accept(tcp_stream).await {
                    Ok(tls_stream) => match tokio_tungstenite::accept_async(tls_stream).await {
                        Ok(ws) => handle_client(ws, state).await,
                        Err(e) => {
                            warn!(peer = %peer_addr, "WebSocket upgrade failed: {}", e);
                        }
                    },
                    Err(e) => {
                        warn!(peer = %peer_addr, "TLS handshake failed: {}", e);
                    }
                }
            } else {
                match tokio_tungstenite::accept_async(tcp_stream).await {
                    Ok(ws) => handle_client(ws, state).await,
                    Err(e) => {
                        warn!(peer = %peer_addr, "WebSocket upgrade failed: {}", e);
                    }
                }
            }
        });
    }
}

/// Handle a single client session over yamux-multiplexed WebSocket.
async fn handle_client<S>(ws: tokio_tungstenite::WebSocketStream<S>, state: Arc<ServerState>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    state.metrics.ws_connections_active.inc();

    let ws_compat = WsCompat::new(ws);
    let mux = yamux::Connection::new(ws_compat, yamux_config(), yamux::Mode::Server);

    let (_mux_control, mut inbound_rx, driver_handle) = spawn_yamux_driver(mux);

    // Accept stream 0 = control channel (with timeout)
    let mut ctrl_stream =
        match tokio::time::timeout(Duration::from_secs(5), inbound_rx.recv()).await {
            Ok(Some(stream)) => stream,
            _ => {
                warn!("Client did not open control stream within 5 seconds");
                driver_handle.abort();
                return;
            }
        };

    // Step 1: Expect Auth within 5 seconds
    let auth_msg: ClientMsg = match tokio::time::timeout(
        Duration::from_secs(5),
        read_msg_from_stream(&mut ctrl_stream),
    )
    .await
    {
        Ok(Ok(msg)) => msg,
        Ok(Err(e)) => {
            warn!("Failed to read auth message: {}", e);
            driver_handle.abort();
            return;
        }
        Err(_) => {
            warn!("Client did not send auth within 5 seconds");
            driver_handle.abort();
            return;
        }
    };

    let (token, _version) = match auth_msg {
        ClientMsg::Auth { token, version } => (token, version),
        _ => {
            warn!("First message was not Auth");
            let _ = write_msg_to_stream(
                &mut ctrl_stream,
                &ServerMsg::Error {
                    code: 401,
                    message: "first message must be Auth".to_string(),
                },
            )
            .await;
            driver_handle.abort();
            return;
        }
    };

    // Step 2: Validate JWT
    let claims = match auth::validate_token(&token, &state.config.auth.secret) {
        Ok(c) => c,
        Err(e) => {
            warn!("Auth failed: {}", e);
            let _ = write_msg_to_stream(
                &mut ctrl_stream,
                &ServerMsg::AuthErr {
                    reason: "invalid auth token".to_string(),
                },
            )
            .await;
            driver_handle.abort();
            return;
        }
    };

    // Step 2b: Check jti blocklist
    if state.is_jti_revoked(&claims.jti).await {
        warn!(jti = %claims.jti, "Token has been revoked");
        let _ = write_msg_to_stream(
            &mut ctrl_stream,
            &ServerMsg::AuthErr {
                reason: "token has been revoked".to_string(),
            },
        )
        .await;
        driver_handle.abort();
        return;
    }

    let session_id = uuid::Uuid::new_v4().to_string();
    info!(session_id = %session_id, sub = %claims.sub, "Client authenticated");

    // Step 3: Send AuthOk
    if write_msg_to_stream(
        &mut ctrl_stream,
        &ServerMsg::AuthOk {
            session_id: session_id.clone(),
        },
    )
    .await
    .is_err()
    {
        driver_handle.abort();
        return;
    }

    // Step 4: Set up control message channel
    let (control_tx, mut control_rx) = mpsc::channel::<ServerMsg>(64);

    // Track resources for cleanup
    let mut registered_subdomains: Vec<String> = Vec::new();
    let mut registered_tcp_ports: Vec<u16> = Vec::new();

    // Spawn task to accept proxy data streams from client
    let accept_state = state.clone();
    let accept_handle = tokio::spawn(async move {
        while let Some(stream) = inbound_rx.recv().await {
            let state = accept_state.clone();
            tokio::spawn(async move {
                handle_proxy_data_stream(stream, state).await;
            });
        }
    });

    // Step 5: Main control loop — interleave reads and writes
    loop {
        tokio::select! {
            result = read_msg_from_stream::<ClientMsg>(&mut ctrl_stream) => {
                let msg = match result {
                    Ok(m) => m,
                    Err(_) => break,
                };
                handle_control_msg(
                    msg, &state, &control_tx,
                    &mut registered_subdomains, &mut registered_tcp_ports,
                ).await;
            }
            Some(msg) = control_rx.recv() => {
                if write_msg_to_stream(&mut ctrl_stream, &msg).await.is_err() {
                    break;
                }
            }
            _ = state.cancel.cancelled() => {
                info!(session_id = %session_id, "Graceful shutdown: closing client session");
                break;
            }
        }
    }

    // Cleanup
    info!(session_id = %session_id, "Client disconnected, cleaning up tunnels");
    for subdomain in &registered_subdomains {
        state.unregister_tunnel(subdomain);
    }
    for port in &registered_tcp_ports {
        state.unregister_tcp_tunnel(*port);
    }
    accept_handle.abort();
    driver_handle.abort();
    state.metrics.ws_connections_active.dec();
}

/// Handle a proxy data stream: read correlation_id header, match to pending_streams
async fn handle_proxy_data_stream(mut stream: yamux::Stream, state: Arc<ServerState>) {
    use futures::AsyncReadExt;

    let mut id_buf = [0u8; 4];
    match tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut id_buf)).await {
        Ok(Ok(())) => {}
        _ => return,
    }
    let correlation_id = u32::from_be_bytes(id_buf);

    // Resolve the pending oneshot
    for entry in state.tunnels.iter() {
        if let Some((_, tx)) = entry.value().pending_streams.remove(&correlation_id) {
            let _ = tx.send(stream);
            return;
        }
    }
    for entry in state.tcp_tunnels.iter() {
        if let Some((_, tx)) = entry.value().pending_streams.remove(&correlation_id) {
            let _ = tx.send(stream);
            return;
        }
    }
    warn!(correlation_id, "No pending stream found for correlation ID");
}

/// Process a control message from the client
async fn handle_control_msg(
    msg: ClientMsg,
    state: &Arc<ServerState>,
    control_tx: &mpsc::Sender<ServerMsg>,
    registered_subdomains: &mut Vec<String>,
    registered_tcp_ports: &mut Vec<u16>,
) {
    match msg {
        ClientMsg::TunnelRequest {
            id,
            tunnel_type,
            subdomain,
            basic_auth,
            options,
        } => {
            let assigned_subdomain = match &subdomain {
                Some(s) => {
                    if let Err(e) = validate_subdomain(s) {
                        let _ = control_tx
                            .send(ServerMsg::Error {
                                code: 400,
                                message: e,
                            })
                            .await;
                        return;
                    }
                    s.clone()
                }
                None => generate_subdomain(),
            };

            let basic_auth_hash = if let Some(ref ba) = basic_auth {
                match auth::hash_basic_auth_password(&ba.password) {
                    Ok(h) => Some(h),
                    Err(e) => {
                        let _ = control_tx
                            .send(ServerMsg::Error {
                                code: 500,
                                message: format!("Failed to hash password: {}", e),
                            })
                            .await;
                        return;
                    }
                }
            } else {
                None
            };

            let public_url = match &tunnel_type {
                TunnelType::Http | TunnelType::Https => {
                    format!(
                        "https://{}.{}",
                        assigned_subdomain, state.config.server.domain
                    )
                }
                TunnelType::Tcp { remote_port } => {
                    let port = match remote_port {
                        Some(p) => *p,
                        None => match state.allocate_tcp_port() {
                            Some(p) => p,
                            None => {
                                let _ = control_tx
                                    .send(ServerMsg::Error {
                                        code: 503,
                                        message: "no TCP ports available".to_string(),
                                    })
                                    .await;
                                return;
                            }
                        },
                    };
                    format!("tcp://{}:{}", state.config.server.domain, port)
                }
            };

            let session = Arc::new(TunnelSession {
                id: id.clone(),
                tunnel_type: tunnel_type.clone(),
                subdomain: assigned_subdomain.clone(),
                basic_auth,
                basic_auth_hash,
                options,
                created_at: Instant::now(),
                control_tx: control_tx.clone(),
                next_correlation_id: AtomicU32::new(1),
                pending_streams: dashmap::DashMap::new(),
                cached_auth_header: tokio::sync::Mutex::new(None),
            });

            match &tunnel_type {
                TunnelType::Http | TunnelType::Https => {
                    if let Err(e) = state.register_tunnel(session.clone()) {
                        let _ = control_tx
                            .send(ServerMsg::Error {
                                code: 409,
                                message: e.to_string(),
                            })
                            .await;
                        return;
                    }
                    registered_subdomains.push(assigned_subdomain.clone());
                }
                TunnelType::Tcp { .. } => {
                    if let Some(port_str) = public_url.rsplit(':').next() {
                        if let Ok(port) = port_str.parse::<u16>() {
                            state.register_tcp_tunnel(port, session.clone());
                            registered_tcp_ports.push(port);

                            let tcp_state = state.clone();
                            let tcp_tunnel = session.clone();
                            tokio::spawn(async move {
                                if let Err(e) =
                                    crate::proxy::serve_tcp_tunnel(tcp_state, port, tcp_tunnel)
                                        .await
                                {
                                    warn!(port, "TCP tunnel listener error: {}", e);
                                }
                            });
                        }
                    }
                }
            }

            info!(
                tunnel_id = %id,
                subdomain = %assigned_subdomain,
                public_url = %public_url,
                "Tunnel created"
            );

            let _ = control_tx
                .send(ServerMsg::TunnelAck {
                    id,
                    public_url,
                    tunnel_type,
                })
                .await;
        }

        ClientMsg::Ping { seq } => {
            let _ = control_tx.send(ServerMsg::Pong { seq }).await;
        }

        ClientMsg::StreamAck { correlation_id } => {
            tracing::debug!(correlation_id, "Stream acknowledged");
        }

        _ => {}
    }
}
