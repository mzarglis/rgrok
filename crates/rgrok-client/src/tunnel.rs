use std::sync::Arc;
use std::time::Duration;
use std::{future::Future, pin::Pin};

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

type WebSocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

const INITIAL_RECONNECT_DELAY: Duration = Duration::from_secs(1);
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(60);
const MAX_CONNECT_ATTEMPTS: usize = 10;
const STABLE_SESSION_THRESHOLD: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionFailureKind {
    Transient,
    Permanent,
}

#[derive(Debug)]
enum SessionFailure {
    Transient(anyhow::Error),
    Permanent(anyhow::Error),
}

impl SessionFailure {
    fn transient(error: impl Into<anyhow::Error>) -> Self {
        Self::Transient(error.into())
    }

    fn permanent(error: impl Into<anyhow::Error>) -> Self {
        Self::Permanent(error.into())
    }

    fn kind(&self) -> SessionFailureKind {
        match self {
            Self::Transient(_) => SessionFailureKind::Transient,
            Self::Permanent(_) => SessionFailureKind::Permanent,
        }
    }

    fn into_error(self) -> anyhow::Error {
        match self {
            Self::Transient(error) | Self::Permanent(error) => error,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionExit {
    Disconnected,
    Shutdown,
}

#[derive(Debug, Clone, Copy)]
struct ReconnectBackoff {
    next: Duration,
    max: Duration,
}

impl Default for ReconnectBackoff {
    fn default() -> Self {
        Self {
            next: INITIAL_RECONNECT_DELAY,
            max: MAX_RECONNECT_DELAY,
        }
    }
}

impl ReconnectBackoff {
    fn next_delay(&mut self) -> Duration {
        let delay = self.next;
        self.next = self.next.saturating_mul(2).min(self.max);
        delay
    }

    fn reset(&mut self) {
        self.next = INITIAL_RECONNECT_DELAY;
    }
}

struct EstablishedSession {
    control: YamuxControl,
    inbound_rx: mpsc::Receiver<yamux::Stream>,
    driver_handle: Option<tokio::task::JoinHandle<()>>,
    ctrl_stream: Option<yamux::Stream>,
}

impl EstablishedSession {
    async fn abort(mut self) {
        if let Some(driver_handle) = self.driver_handle.take() {
            driver_handle.abort();
            let _ = driver_handle.await;
        }
    }
}

#[derive(Debug)]
struct TunnelRegistration {
    public_url: String,
    tunnel_type: TunnelType,
}

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
pub async fn run(config: ClientConfig, mut tunnel_cfg: TunnelConfig) -> anyhow::Result<()> {
    validate_config(&config)?;

    let server_url = server_websocket_url(&config)?;
    if config.server.insecure {
        warn!(
            "INSECURE control transport enabled; the auth token will be sent over plaintext ws://"
        );
    }
    // These are deliberately created once. A reconnect must not rebind the dashboard or
    // inspection listener, and existing request history remains useful after recovery.
    let stats = Arc::new(output::TunnelStats::new());
    let dashboard_tx = output::spawn_dashboard(stats.clone());
    let inspect_state = if tunnel_cfg.inspect_port > 0 {
        let state = Arc::new(InspectState::with_max_body_bytes(
            tunnel_cfg.local_port,
            config.defaults.max_body_bytes,
        ));
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

    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    tokio::pin!(shutdown);

    let mut backoff = ReconnectBackoff::default();
    let mut printed_tunnel_info = false;
    loop {
        info!(server = %server_url, "Connecting to server");
        let established =
            match establish_session(&server_url, &config, &tunnel_cfg, shutdown.as_mut()).await {
                Ok(established) => established,
                Err(error) => {
                    if error.kind() == SessionFailureKind::Permanent {
                        return Err(error.into_error());
                    }
                    let delay = backoff.next_delay();
                    warn!(
                        delay = ?delay,
                        error = %error.into_error(),
                        "Transient session setup failure; reconnecting"
                    );
                    if wait_for_reconnect(delay, shutdown.as_mut()).await {
                        info!("Shutdown requested");
                        break;
                    }
                    continue;
                }
            };

        let Some((session, registration)) = established else {
            info!("Shutdown requested");
            break;
        };

        pin_assigned_endpoint(&mut tunnel_cfg, &registration);

        if !printed_tunnel_info {
            output::print_tunnel_info(
                &registration.public_url,
                tunnel_cfg.local_port,
                tunnel_cfg.inspect_port,
            );
            printed_tunnel_info = true;
        } else {
            info!(public_url = %registration.public_url, "Tunnel re-registered");
        }
        info!("Connected and tunnel registered");

        let established_at = std::time::Instant::now();
        match run_session(
            session,
            tunnel_cfg.local_port,
            inspect_state.clone(),
            stats.clone(),
            dashboard_tx.clone(),
            shutdown.as_mut(),
        )
        .await
        {
            SessionExit::Shutdown => {
                info!("Shutdown requested");
                break;
            }
            SessionExit::Disconnected => {
                if established_at.elapsed() >= STABLE_SESSION_THRESHOLD {
                    backoff.reset();
                }
                let delay = backoff.next_delay();
                warn!(delay = ?delay, "Tunnel session lost; reconnecting");
                if wait_for_reconnect(delay, shutdown.as_mut()).await {
                    info!("Shutdown requested");
                    break;
                }
            }
        }
    }

    Ok(())
}

fn validate_config(config: &ClientConfig) -> anyhow::Result<()> {
    if config.auth.token.is_empty() {
        anyhow::bail!("No auth token configured. Run: rgrok authtoken <your-token>");
    }
    if config.server.host.trim().is_empty() {
        anyhow::bail!("Server host cannot be empty");
    }
    if config.server.port == 0 {
        anyhow::bail!("Server port cannot be zero");
    }
    Ok(())
}

async fn establish_session<F>(
    url: &str,
    config: &ClientConfig,
    tunnel_cfg: &TunnelConfig,
    mut shutdown: Pin<&mut F>,
) -> Result<Option<(EstablishedSession, TunnelRegistration)>, SessionFailure>
where
    F: Future<Output = ()>,
{
    let Some(ws) = connect_with_retry_inner(url, shutdown.as_mut())
        .await
        .map_err(SessionFailure::transient)?
    else {
        return Ok(None);
    };

    let mut session = start_yamux_session(ws);
    let handshake = authenticate_and_register(&mut session, config, tunnel_cfg);
    let result = tokio::select! {
        _ = shutdown.as_mut() => {
            session.abort().await;
            return Ok(None);
        }
        result = handshake => result,
    };

    match result {
        Ok(public_url) => Ok(Some((session, public_url))),
        Err(error) => {
            session.abort().await;
            Err(error)
        }
    }
}

fn start_yamux_session(ws: WebSocket) -> EstablishedSession {
    // Keep WebSocket adaptation isolated from session lifecycle. This is the seam for
    // swapping in a secure or alternate tunnel transport without changing reconnect logic.
    let ws_compat = WsCompat::new(ws);
    let mux = yamux::Connection::new(ws_compat, yamux_config(), yamux::Mode::Client);
    let (control, inbound_rx, driver_handle) = spawn_yamux_driver(mux);

    // Opening the control stream is async and is completed by `authenticate_and_register`.
    // Keeping transport construction synchronous makes this seam straightforward to mock.
    EstablishedSession {
        control,
        inbound_rx,
        driver_handle: Some(driver_handle),
        ctrl_stream: None,
    }
}

async fn authenticate_and_register(
    session: &mut EstablishedSession,
    config: &ClientConfig,
    tunnel_cfg: &TunnelConfig,
) -> Result<TunnelRegistration, SessionFailure> {
    let ctrl_stream = session.control.open_stream().await.map_err(|e| {
        SessionFailure::transient(anyhow::anyhow!("Failed to open control stream: {}", e))
    })?;
    session.ctrl_stream = Some(ctrl_stream);
    let ctrl_stream = session
        .ctrl_stream
        .as_mut()
        .expect("control stream initialized");

    write_msg_to_stream(
        ctrl_stream,
        &ClientMsg::Auth {
            token: config.auth.token.clone(),
            version: rgrok_proto::CONTROL_PROTOCOL_VERSION.to_string(),
        },
    )
    .await
    .map_err(|e| SessionFailure::transient(e.context("Failed to send authentication")))?;

    let auth_response: ServerMsg = read_msg_from_stream(ctrl_stream).await.map_err(|e| {
        SessionFailure::transient(e.context("Failed to read authentication response"))
    })?;
    let session_id = classify_auth_response(auth_response)?;
    info!(session_id = %session_id, "Authenticated");

    let req_id = uuid::Uuid::new_v4().to_string();
    write_msg_to_stream(
        ctrl_stream,
        &ClientMsg::TunnelRequest {
            id: req_id,
            tunnel_type: tunnel_cfg.tunnel_type.clone(),
            subdomain: tunnel_cfg.subdomain.clone(),
            basic_auth: tunnel_cfg.basic_auth.clone(),
            options: tunnel_cfg.options.clone(),
        },
    )
    .await
    .map_err(|e| SessionFailure::transient(e.context("Failed to register tunnel")))?;

    let registration_response: ServerMsg =
        read_msg_from_stream(ctrl_stream).await.map_err(|e| {
            SessionFailure::transient(e.context("Failed to read tunnel registration response"))
        })?;
    classify_registration_response(registration_response)
}

fn classify_auth_response(response: ServerMsg) -> Result<String, SessionFailure> {
    match response {
        ServerMsg::AuthOk { session_id } => Ok(session_id),
        ServerMsg::AuthErr { reason } => Err(SessionFailure::permanent(anyhow::anyhow!(
            "Authentication failed: {}",
            reason
        ))),
        _ => Err(SessionFailure::permanent(anyhow::anyhow!(
            "Unexpected server response during auth"
        ))),
    }
}

fn classify_registration_response(
    response: ServerMsg,
) -> Result<TunnelRegistration, SessionFailure> {
    match response {
        ServerMsg::TunnelAck {
            public_url,
            tunnel_type,
            ..
        } => Ok(TunnelRegistration {
            public_url,
            tunnel_type,
        }),
        ServerMsg::Error { code, message } if code >= 500 || matches!(code, 409 | 429) => {
            Err(SessionFailure::transient(anyhow::anyhow!(
                "Tunnel creation temporarily failed ({}): {}",
                code,
                message
            )))
        }
        ServerMsg::Error { code, message } => Err(SessionFailure::permanent(anyhow::anyhow!(
            "Tunnel creation failed ({}): {}",
            code,
            message
        ))),
        _ => Err(SessionFailure::permanent(anyhow::anyhow!(
            "Unexpected server response during tunnel registration"
        ))),
    }
}

async fn run_session<F>(
    mut session: EstablishedSession,
    local_port: u16,
    inspect_state: Option<Arc<InspectState>>,
    stats: Arc<output::TunnelStats>,
    dashboard_tx: tokio::sync::mpsc::UnboundedSender<output::RequestLogEntry>,
    mut shutdown: Pin<&mut F>,
) -> SessionExit
where
    F: Future<Output = ()>,
{
    let (msg_tx, mut msg_rx) = mpsc::channel::<ClientMsg>(64);
    let heartbeat_tx = msg_tx.clone();
    let heartbeat_handle = tokio::spawn(async move {
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
    let mut proxy_tasks = tokio::task::JoinSet::new();
    let exit = loop {
        tokio::select! {
            _ = shutdown.as_mut() => break SessionExit::Shutdown,
            result = read_msg_from_stream::<ServerMsg>(session.ctrl_stream.as_mut().expect("established control stream")) => {
                let msg = match result {
                    Ok(m) => m,
                    Err(e) => {
                        info!(error = %e, "Control channel closed");
                        break SessionExit::Disconnected;
                    }
                };

                match msg {
                    ServerMsg::StreamOpen { correlation_id, .. } => {
                        let control = session.control.clone();
                        let inspect = inspect_state.clone();
                        let stats = stats.clone();
                        let dash_tx = dashboard_tx.clone();
                        proxy_tasks.spawn(async move {
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
                if let Err(e) = write_msg_to_stream(session.ctrl_stream.as_mut().expect("established control stream"), &msg).await {
                    info!(error = %e, "Control channel write failed");
                    break SessionExit::Disconnected;
                }
            }
            inbound = session.inbound_rx.recv() => {
                match inbound {
                    Some(_stream) => warn!("Unexpected inbound yamux stream from server"),
                    None => break SessionExit::Disconnected,
                }
            }
            result = session.driver_handle.as_mut().expect("yamux driver is running") => {
                session.driver_handle.take();
                if let Err(e) = result {
                    info!(error = %e, "Yamux driver stopped");
                } else {
                    info!("Yamux driver stopped");
                }
                break SessionExit::Disconnected;
            }
            Some(result) = proxy_tasks.join_next(), if !proxy_tasks.is_empty() => {
                if let Err(e) = result {
                    warn!("Proxy task stopped: {}", e);
                }
            }
        }
    };

    proxy_tasks.abort_all();
    while proxy_tasks.join_next().await.is_some() {}
    heartbeat_handle.abort();
    let _ = heartbeat_handle.await;
    session.abort().await;
    exit
}

fn pin_assigned_endpoint(tunnel_cfg: &mut TunnelConfig, registration: &TunnelRegistration) {
    match &mut tunnel_cfg.tunnel_type {
        TunnelType::Http | TunnelType::Https if tunnel_cfg.subdomain.is_none() => {
            tunnel_cfg.subdomain = assigned_subdomain_from_url(&registration.public_url);
        }
        TunnelType::Tcp { remote_port } if remote_port.is_none() => {
            *remote_port = match &registration.tunnel_type {
                TunnelType::Tcp {
                    remote_port: Some(port),
                } => Some(*port),
                _ => assigned_tcp_port_from_url(&registration.public_url),
            };
        }
        _ => {}
    }
}

fn assigned_subdomain_from_url(public_url: &str) -> Option<String> {
    let authority = public_url.split_once("://")?.1.split('/').next()?;
    let host = authority.split(':').next()?;
    let subdomain = host.split('.').next()?.trim();
    (!subdomain.is_empty()).then(|| subdomain.to_string())
}

fn assigned_tcp_port_from_url(public_url: &str) -> Option<u16> {
    let authority = public_url.split_once("://")?.1.split('/').next()?;
    authority.rsplit_once(':')?.1.parse().ok()
}

async fn wait_for_reconnect<F>(delay: Duration, mut shutdown: Pin<&mut F>) -> bool
where
    F: Future<Output = ()>,
{
    tokio::select! {
        _ = shutdown.as_mut() => true,
        _ = tokio::time::sleep(delay) => false,
    }
}

/// Build the control WebSocket URL. TLS is deliberately the default: auth is
/// sent immediately after the WebSocket handshake, so a plaintext fallback
/// would expose the token to anyone able to observe the connection.
fn server_websocket_url(config: &ClientConfig) -> anyhow::Result<String> {
    if config.server.host.is_empty()
        || config.server.host.contains("://")
        || config.server.host.contains('/')
        || config.server.host.contains('?')
        || config.server.host.contains('#')
    {
        anyhow::bail!(
            "Invalid server host '{}'; configure a hostname or IP address without a URL scheme",
            config.server.host
        );
    }

    let host = if config.server.host.contains(':') && !config.server.host.starts_with('[') {
        format!("[{}]", config.server.host)
    } else {
        config.server.host.clone()
    };
    let scheme = if config.server.insecure { "ws" } else { "wss" };
    Ok(format!(
        "{}://{}:{}/tunnel",
        scheme, host, config.server.port
    ))
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
#[cfg(test)]
async fn connect_with_retry(url: &str) -> anyhow::Result<WebSocket> {
    let shutdown = std::future::pending::<()>();
    tokio::pin!(shutdown);
    connect_with_retry_inner(url, shutdown.as_mut())
        .await?
        .ok_or_else(|| anyhow::anyhow!("connection retry interrupted"))
}

async fn connect_with_retry_inner<F>(
    url: &str,
    mut shutdown: Pin<&mut F>,
) -> anyhow::Result<Option<WebSocket>>
where
    F: Future<Output = ()>,
{
    let mut backoff = ReconnectBackoff::default();
    for attempt in 1..=MAX_CONNECT_ATTEMPTS {
        let connection = tokio::select! {
            _ = shutdown.as_mut() => return Ok(None),
            result = tokio_tungstenite::connect_async(url) => result,
        };
        match connection {
            Ok((ws, _)) => return Ok(Some(ws)),
            Err(e) => {
                if attempt == MAX_CONNECT_ATTEMPTS {
                    return Err(anyhow::anyhow!(
                        "Cannot reach server at {} after {} attempts: {}",
                        url,
                        MAX_CONNECT_ATTEMPTS,
                        e
                    ));
                }
                let delay = backoff.next_delay();
                warn!(
                    attempt,
                    delay = ?delay,
                    error = %e,
                    "Connection failed; retrying"
                );
                if wait_for_reconnect(delay, shutdown.as_mut()).await {
                    return Ok(None);
                }
            }
        }
    }

    unreachable!("connection retry loop always returns")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClientConfig;
    use futures::AsyncReadExt as _;
    use tokio_util::compat::TokioAsyncReadCompatExt as _;

    #[test]
    fn test_server_websocket_url_defaults_to_tls() {
        let config = ClientConfig::default();

        assert_eq!(
            server_websocket_url(&config).unwrap(),
            "wss://tunnel.example.com:7835/tunnel"
        );
    }

    #[test]
    fn test_server_websocket_url_requires_explicit_insecure_mode() {
        let mut config = ClientConfig::default();
        config.server.host = "127.0.0.1".to_string();
        config.server.insecure = true;

        assert_eq!(
            server_websocket_url(&config).unwrap(),
            "ws://127.0.0.1:7835/tunnel"
        );
    }

    #[test]
    fn test_server_websocket_url_brackets_ipv6_hosts() {
        let mut config = ClientConfig::default();
        config.server.host = "::1".to_string();

        assert_eq!(
            server_websocket_url(&config).unwrap(),
            "wss://[::1]:7835/tunnel"
        );
    }

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

    #[test]
    fn test_auth_and_registration_errors_are_classified() {
        let auth_error = classify_auth_response(ServerMsg::AuthErr {
            reason: "token revoked".to_string(),
        })
        .unwrap_err();
        assert_eq!(auth_error.kind(), SessionFailureKind::Permanent);

        let registration_error = classify_registration_response(ServerMsg::Error {
            code: 400,
            message: "subdomain is already in use".to_string(),
        })
        .unwrap_err();
        assert_eq!(registration_error.kind(), SessionFailureKind::Permanent);

        for code in [409, 429, 500, 503] {
            let retryable = classify_registration_response(ServerMsg::Error {
                code,
                message: "temporary registration failure".to_string(),
            })
            .unwrap_err();
            assert_eq!(retryable.kind(), SessionFailureKind::Transient);
        }

        assert_eq!(
            SessionFailure::transient(anyhow::anyhow!("connection reset")).kind(),
            SessionFailureKind::Transient
        );
    }

    #[test]
    fn assigned_endpoints_are_reused_after_reconnect() {
        let mut http = TunnelConfig {
            local_port: 8080,
            tunnel_type: TunnelType::Http,
            subdomain: None,
            basic_auth: None,
            options: TunnelOptions::default(),
            inspect_port: 0,
        };
        pin_assigned_endpoint(
            &mut http,
            &TunnelRegistration {
                public_url: "https://stable-name.tunnel.example.com".to_string(),
                tunnel_type: TunnelType::Http,
            },
        );
        assert_eq!(http.subdomain.as_deref(), Some("stable-name"));

        let mut tcp = TunnelConfig {
            local_port: 22,
            tunnel_type: TunnelType::Tcp { remote_port: None },
            subdomain: None,
            basic_auth: None,
            options: TunnelOptions::default(),
            inspect_port: 0,
        };
        pin_assigned_endpoint(
            &mut tcp,
            &TunnelRegistration {
                public_url: "tcp://tunnel.example.com:15432".to_string(),
                tunnel_type: TunnelType::Tcp {
                    remote_port: Some(15432),
                },
            },
        );
        assert_eq!(
            tcp.tunnel_type,
            TunnelType::Tcp {
                remote_port: Some(15432)
            }
        );
    }

    #[test]
    fn test_reconnect_backoff_resets_after_established_session() {
        let mut backoff = ReconnectBackoff::default();
        assert_eq!(backoff.next_delay(), Duration::from_secs(1));
        assert_eq!(backoff.next_delay(), Duration::from_secs(2));
        for _ in 0..10 {
            let _ = backoff.next_delay();
        }
        assert_eq!(backoff.next_delay(), MAX_RECONNECT_DELAY);

        backoff.reset();
        assert_eq!(backoff.next_delay(), INITIAL_RECONNECT_DELAY);
    }

    #[tokio::test(start_paused = true)]
    async fn test_reconnect_wait_uses_cancellable_paused_timer() {
        let waiter = tokio::spawn(async {
            let shutdown = std::future::pending::<()>();
            tokio::pin!(shutdown);
            wait_for_reconnect(Duration::from_secs(5), shutdown.as_mut()).await
        });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(5)).await;
        assert!(!waiter.await.unwrap());

        let shutdown_waiter = tokio::spawn(async {
            let shutdown = async {};
            tokio::pin!(shutdown);
            wait_for_reconnect(Duration::from_secs(60), shutdown.as_mut()).await
        });
        assert!(shutdown_waiter.await.unwrap());
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
