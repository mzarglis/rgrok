use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

use rgrok_proto::messages::*;
use rgrok_proto::transport::{read_msg_from_stream, write_msg_to_stream, yamux_config, WsCompat};
use rgrok_proto::{generate_subdomain, spawn_yamux_driver, validate_subdomain};

use crate::auth;
use crate::tunnel_manager::{ConnectionStreamState, ServerState, TunnelSession};

/// Start the control plane listener.
pub async fn serve(
    state: Arc<ServerState>,
    tls_acceptor: Option<TlsAcceptor>,
    listener: TcpListener,
) -> anyhow::Result<()> {
    let bind_addr = listener.local_addr()?;
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
        let mut tls_config_rx = state.tls_config_rx.clone();

        tokio::spawn(async move {
            if let Some(initial_acceptor) = tls_acceptor {
                // Build an acceptor from the latest config for every new
                // connection so certificate renewal takes effect without a
                // listener restart. Keep the startup acceptor as a fallback
                // for the short window before the initial watch update.
                let acceptor = tls_config_rx
                    .borrow_and_update()
                    .clone()
                    .map(TlsAcceptor::from)
                    .unwrap_or(initial_acceptor);
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
    // All tunnels registered by this authenticated client share one
    // correlation namespace and pending-stream registry. The accept task below
    // receives this exact registry, so an inbound stream can never resolve a
    // request belonging to another WebSocket connection.
    let stream_state = Arc::new(ConnectionStreamState::new());

    // Track resources for cleanup
    let mut registered_subdomains: Vec<String> = Vec::new();
    let mut registered_tcp_ports: Vec<u16> = Vec::new();

    // Spawn task to accept proxy data streams from client
    let accept_stream_state = stream_state.clone();
    let accept_handle = tokio::spawn(async move {
        while let Some(stream) = inbound_rx.recv().await {
            let stream_state = accept_stream_state.clone();
            tokio::spawn(async move {
                handle_proxy_data_stream(stream, stream_state).await;
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
                    &stream_state,
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
        if let Some(tunnel) = state.remove_tcp_tunnel(*port) {
            // Cancellation closes the accept loop. Wait for the listener task
            // to drop its socket before allowing this port to be reused.
            if let Some(listener_stopped) = tunnel.listener_stopped.lock().await.take() {
                let _ = tokio::time::timeout(Duration::from_secs(5), listener_stopped).await;
            }
        }
    }
    accept_handle.abort();
    driver_handle.abort();
    state.metrics.ws_connections_active.dec();
}

/// Handle a proxy data stream: read its correlation ID and resolve only the
/// pending request on the authenticated WebSocket that delivered this stream.
async fn handle_proxy_data_stream(
    mut stream: yamux::Stream,
    stream_state: Arc<ConnectionStreamState>,
) {
    use futures::AsyncReadExt;

    let mut id_buf = [0u8; 4];
    match tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut id_buf)).await {
        Ok(Ok(())) => {}
        _ => return,
    }
    let correlation_id = u32::from_be_bytes(id_buf);

    if !resolve_pending_stream(&stream_state.pending_streams, correlation_id, stream) {
        warn!(correlation_id, "No pending stream found for correlation ID");
    }
}

/// Resolve a pending stream from a connection-scoped correlation map.
fn resolve_pending_stream<T>(
    pending_streams: &dashmap::DashMap<u32, tokio::sync::oneshot::Sender<T>>,
    correlation_id: u32,
    stream: T,
) -> bool {
    match pending_streams.remove(&correlation_id) {
        Some((_, tx)) => tx.send(stream).is_ok(),
        None => false,
    }
}

/// Process a control message from the client
async fn handle_control_msg(
    msg: ClientMsg,
    state: &Arc<ServerState>,
    control_tx: &mpsc::Sender<ServerMsg>,
    stream_state: &Arc<ConnectionStreamState>,
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

            let tcp_port = match &tunnel_type {
                TunnelType::Tcp { remote_port } => {
                    let port = match state.reserve_tcp_port(*remote_port, &id) {
                        Ok(port) => port,
                        Err(e) => {
                            let code = match e {
                                rgrok_proto::TunnelError::TcpPortOutOfRange { .. } => 400,
                                rgrok_proto::TunnelError::TcpPortTaken { .. } => 409,
                                rgrok_proto::TunnelError::NoPortsAvailable { .. } => 503,
                                _ => 500,
                            };
                            let _ = control_tx
                                .send(ServerMsg::Error {
                                    code,
                                    message: e.to_string(),
                                })
                                .await;
                            return;
                        }
                    };
                    Some(port)
                }
                _ => None,
            };

            let public_url = match (&tunnel_type, tcp_port) {
                (TunnelType::Http, None) | (TunnelType::Https, None) => {
                    format!(
                        "https://{}.{}",
                        assigned_subdomain, state.config.server.domain
                    )
                }
                (TunnelType::Tcp { .. }, Some(port)) => {
                    format!("tcp://{}:{}", state.config.server.domain, port)
                }
                (TunnelType::Tcp { .. }, None) => unreachable!("TCP port was not reserved"),
                (TunnelType::Http | TunnelType::Https, Some(_)) => {
                    unreachable!("HTTP tunnel cannot have a TCP port")
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
                stream_state: stream_state.clone(),
                cached_auth_header: tokio::sync::Mutex::new(None),
                cancel: tokio_util::sync::CancellationToken::new(),
                listener_stopped: tokio::sync::Mutex::new(None),
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
                    let port = tcp_port.expect("TCP port was reserved above");

                    // Bind before publishing the tunnel. A failed bind is a
                    // client-visible error and must not result in a TunnelAck.
                    let listener = match TcpListener::bind(format!("0.0.0.0:{}", port)).await {
                        Ok(listener) => listener,
                        Err(e) => {
                            state.release_tcp_port_reservation(port, &id);
                            let _ = control_tx
                                .send(ServerMsg::Error {
                                    code: 500,
                                    message: format!("failed to bind TCP port {}: {}", port, e),
                                })
                                .await;
                            return;
                        }
                    };

                    let (listener_stopped_tx, listener_stopped_rx) = oneshot::channel();
                    *session.listener_stopped.lock().await = Some(listener_stopped_rx);

                    if let Err(e) = state.try_register_tcp_tunnel(port, session.clone()) {
                        drop(listener);
                        state.release_tcp_port_reservation(port, &id);
                        let _ = control_tx
                            .send(ServerMsg::Error {
                                code: 409,
                                message: e.to_string(),
                            })
                            .await;
                        return;
                    }
                    registered_tcp_ports.push(port);

                    let tcp_state = state.clone();
                    let tcp_tunnel = session.clone();
                    tokio::spawn(async move {
                        let result = crate::proxy::serve_tcp_tunnel_on_listener(
                            tcp_state, listener, tcp_tunnel,
                        )
                        .await;
                        let _ = listener_stopped_tx.send(());
                        if let Err(e) = result {
                            warn!(port, "TCP tunnel listener error: {}", e);
                        }
                    });
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

#[cfg(test)]
mod tests {
    use super::*;
    use futures::AsyncWriteExt;
    use tokio_util::compat::TokioAsyncReadCompatExt;

    #[tokio::test]
    async fn colliding_ids_are_scoped_to_their_control_connection() {
        let (first_client_io, first_server_io) = tokio::io::duplex(64 * 1024);
        let first_client_conn = yamux::Connection::new(
            first_client_io.compat(),
            yamux_config(),
            yamux::Mode::Client,
        );
        let first_server_conn = yamux::Connection::new(
            first_server_io.compat(),
            yamux_config(),
            yamux::Mode::Server,
        );
        let (first_control, _first_client_inbound, _first_client_driver) =
            spawn_yamux_driver(first_client_conn);
        let (_first_server_control, mut first_server_inbound, _first_server_driver) =
            spawn_yamux_driver(first_server_conn);

        let (second_client_io, second_server_io) = tokio::io::duplex(64 * 1024);
        let second_client_conn = yamux::Connection::new(
            second_client_io.compat(),
            yamux_config(),
            yamux::Mode::Client,
        );
        let second_server_conn = yamux::Connection::new(
            second_server_io.compat(),
            yamux_config(),
            yamux::Mode::Server,
        );
        let (second_control, _second_client_inbound, _second_client_driver) =
            spawn_yamux_driver(second_client_conn);
        let (_second_server_control, mut second_server_inbound, _second_server_driver) =
            spawn_yamux_driver(second_server_conn);

        let first_connection = Arc::new(ConnectionStreamState::new());
        let second_connection = Arc::new(ConnectionStreamState::new());

        // Each authenticated WebSocket may start at ID 1. The same ID must be
        // resolved only against the registry belonging to the stream's socket.
        let first_id = first_connection.next_correlation_id();
        let second_id = second_connection.next_correlation_id();
        assert_eq!(first_id, 1);
        assert_eq!(second_id, 1);

        let (first_tx, mut first_rx) = tokio::sync::oneshot::channel();
        let (second_tx, mut second_rx) = tokio::sync::oneshot::channel();
        first_connection.pending_streams.insert(first_id, first_tx);
        second_connection
            .pending_streams
            .insert(second_id, second_tx);

        let mut first_client_stream = first_control.open_stream().await.unwrap();
        first_client_stream
            .write_all(&first_id.to_be_bytes())
            .await
            .unwrap();
        first_client_stream.flush().await.unwrap();
        let first_server_stream =
            tokio::time::timeout(Duration::from_secs(1), first_server_inbound.recv())
                .await
                .unwrap()
                .unwrap();
        handle_proxy_data_stream(first_server_stream, first_connection).await;
        assert!(first_rx.try_recv().is_ok());
        assert!(second_rx.try_recv().is_err());
        assert!(second_connection.pending_streams.contains_key(&second_id));

        let mut second_client_stream = second_control.open_stream().await.unwrap();
        second_client_stream
            .write_all(&second_id.to_be_bytes())
            .await
            .unwrap();
        second_client_stream.flush().await.unwrap();
        let second_server_stream =
            tokio::time::timeout(Duration::from_secs(1), second_server_inbound.recv())
                .await
                .unwrap()
                .unwrap();
        handle_proxy_data_stream(second_server_stream, second_connection).await;
        assert!(second_rx.try_recv().is_ok());
    }

    #[test]
    fn tunnels_on_one_connection_share_correlation_namespace() {
        let stream_state = Arc::new(ConnectionStreamState::new());

        assert_eq!(stream_state.next_correlation_id(), 1);
        assert_eq!(stream_state.next_correlation_id(), 2);
    }

    use crate::config::Config;
    use crate::tunnel_manager::ServerState;

    fn tcp_config(port: u16) -> Config {
        let mut config = Config::default();
        config.server.tcp_port_range = [port, port.saturating_add(1)];
        config
    }

    async fn request_tcp(state: &Arc<ServerState>, id: &str, port: u16) -> ServerMsg {
        let (control_tx, mut control_rx) = mpsc::channel(4);
        let stream_state = Arc::new(ConnectionStreamState::new());
        let mut registered_subdomains = Vec::new();
        let mut registered_tcp_ports = Vec::new();
        handle_control_msg(
            ClientMsg::TunnelRequest {
                id: id.to_string(),
                tunnel_type: TunnelType::Tcp {
                    remote_port: Some(port),
                },
                subdomain: None,
                basic_auth: None,
                options: TunnelOptions::default(),
            },
            state,
            &control_tx,
            &stream_state,
            &mut registered_subdomains,
            &mut registered_tcp_ports,
        )
        .await;
        control_rx.recv().await.expect("TCP request response")
    }

    async fn remove_tcp_and_wait(state: &ServerState, port: u16) {
        let tunnel = state
            .remove_tcp_tunnel(port)
            .expect("TCP tunnel should be registered");
        let listener_stopped = tunnel.listener_stopped.lock().await.take();
        if let Some(listener_stopped) = listener_stopped {
            tokio::time::timeout(Duration::from_secs(1), listener_stopped)
                .await
                .expect("TCP listener should stop")
                .expect("TCP listener completion signal");
        }
    }

    #[tokio::test]
    async fn test_duplicate_tcp_port_is_rejected_without_overwrite() {
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        assert!(port < u16::MAX);
        let state = Arc::new(ServerState::new(tcp_config(port)));

        assert!(matches!(
            request_tcp(&state, "first", port).await,
            ServerMsg::TunnelAck { .. }
        ));
        let second = request_tcp(&state, "second", port).await;
        assert!(matches!(second, ServerMsg::Error { code: 409, .. }));
        assert_eq!(state.tcp_tunnels.get(&port).unwrap().id, "first");

        remove_tcp_and_wait(&state, port).await;
    }

    #[tokio::test]
    async fn test_tcp_bind_failure_is_reported_and_reservation_released() {
        let held = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let port = held.local_addr().unwrap().port();
        assert!(port < u16::MAX);
        let state = Arc::new(ServerState::new(tcp_config(port)));

        let response = request_tcp(&state, "bind-failure", port).await;
        match response {
            ServerMsg::Error { code, message } => {
                assert_eq!(code, 500);
                assert!(message.contains("failed to bind TCP port"));
            }
            other => panic!("expected bind error, got {other:?}"),
        }
        assert!(state.tcp_tunnels.is_empty());

        drop(held);
        assert!(matches!(
            request_tcp(&state, "after-bind-failure", port).await,
            ServerMsg::TunnelAck { .. }
        ));
        remove_tcp_and_wait(&state, port).await;
    }

    #[tokio::test]
    async fn test_tcp_disconnect_cancels_listener_and_reuses_port() {
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        assert!(port < u16::MAX);
        let state = Arc::new(ServerState::new(tcp_config(port)));

        assert!(matches!(
            request_tcp(&state, "disconnect", port).await,
            ServerMsg::TunnelAck { .. }
        ));
        remove_tcp_and_wait(&state, port).await;

        // The old accept loop has stopped and dropped its socket, so the same
        // explicit port can be bound and acknowledged immediately.
        assert!(matches!(
            request_tcp(&state, "reuse", port).await,
            ServerMsg::TunnelAck { .. }
        ));
        remove_tcp_and_wait(&state, port).await;
    }
}
