use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{AUTHORIZATION, HOST};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tracing::{info, warn};

use rgrok_proto::messages::ServerMsg;

use crate::auth;
use crate::tunnel_manager::{ServerState, TunnelSession};

/// Serve the public HTTP proxy that routes requests to tunnels (port 80)
/// All HTTP requests get a 301 redirect to HTTPS with HSTS.
pub async fn serve_http(state: Arc<ServerState>) -> anyhow::Result<()> {
    let bind_addr = format!("0.0.0.0:{}", state.config.server.http_port);
    let listener = TcpListener::bind(&bind_addr).await?;
    info!("HTTP proxy listening on {}", bind_addr);

    loop {
        let (stream, peer_addr) = tokio::select! {
            result = listener.accept() => result?,
            _ = state.cancel.cancelled() => {
                info!("HTTP proxy shutting down");
                return Ok(());
            }
        };
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_http_connection(stream, peer_addr, state).await {
                warn!("HTTP proxy error: {}", e);
            }
        });
    }
}

/// Serve the public HTTPS proxy with TLS termination (port 443).
/// Uses hyper to parse HTTP requests, enabling header-level features.
pub async fn serve_https(state: Arc<ServerState>, tls_acceptor: TlsAcceptor) -> anyhow::Result<()> {
    let bind_addr = format!("0.0.0.0:{}", state.config.server.https_port);
    let listener = TcpListener::bind(&bind_addr).await?;
    info!("HTTPS proxy listening on {}", bind_addr);

    loop {
        let (tcp_stream, peer_addr) = tokio::select! {
            result = listener.accept() => result?,
            _ = state.cancel.cancelled() => {
                info!("HTTPS proxy shutting down");
                return Ok(());
            }
        };
        let state = state.clone();
        let acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(tcp_stream).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(peer = %peer_addr, "TLS handshake failed: {}", e);
                    return;
                }
            };

            if let Err(e) = handle_https_connection(tls_stream, state).await {
                warn!("HTTPS proxy error: {}", e);
            }
        });
    }
}

/// Handle an HTTPS connection using hyper for HTTP parsing.
/// This gives us access to headers for routing, basic auth, HSTS injection, and inspection.
async fn handle_https_connection(
    tls_stream: tokio_rustls::server::TlsStream<TcpStream>,
    state: Arc<ServerState>,
) -> anyhow::Result<()> {
    let io = hyper_util::rt::TokioIo::new(tls_stream);

    let service = service_fn(move |req: Request<Incoming>| {
        let state = state.clone();
        async move { proxy_http_request(req, state).await }
    });

    hyper::server::conn::http1::Builder::new()
        .serve_connection(io, service)
        .with_upgrades()
        .await?;

    Ok(())
}

/// Process a single HTTP request through the tunnel proxy.
///
/// 1. Extract Host header → resolve subdomain → look up tunnel
/// 2. Check basic auth if configured
/// 3. Request a proxy stream from the client
/// 4. Serialize the HTTP request and write it into the yamux stream
/// 5. Read the HTTP response back from the yamux stream
/// 6. Inject HSTS and any configured response headers
async fn proxy_http_request(
    req: Request<Incoming>,
    state: Arc<ServerState>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    // Extract Host header for routing
    let host = match req.headers().get(HOST) {
        Some(h) => h
            .to_str()
            .unwrap_or("")
            .split(':')
            .next()
            .unwrap_or("")
            .to_string(),
        None => {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "Missing Host header",
            ));
        }
    };

    let subdomain = match host.strip_suffix(&format!(".{}", state.config.server.domain)) {
        Some(s) => s.to_string(),
        None => {
            return Ok(error_response(StatusCode::NOT_FOUND, "Unknown tunnel host"));
        }
    };

    let tunnel = match state.tunnels.get(&subdomain) {
        Some(t) => t.clone(),
        None => {
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                "Tunnel not found or offline",
            ));
        }
    };

    // Basic auth check with fast-path cache: if the Authorization header matches the
    // last successfully verified header, skip the expensive bcrypt verification (~100ms).
    if let (Some(ba), Some(hash)) = (&tunnel.basic_auth, &tunnel.basic_auth_hash) {
        let authorized = match req.headers().get(AUTHORIZATION) {
            Some(auth_val) => {
                let auth_str = auth_val.to_str().unwrap_or("");

                // Fast path: check if this header matches the cached successful value
                let cached = tunnel.cached_auth_header.lock().await;
                if cached.as_deref() == Some(auth_str) {
                    true
                } else {
                    drop(cached); // release lock before slow bcrypt
                    match auth::parse_basic_auth_header(auth_str) {
                        Some((user, pass)) => {
                            if user == ba.username && auth::verify_basic_auth_password(&pass, hash)
                            {
                                // Cache the successful header value
                                *tunnel.cached_auth_header.lock().await =
                                    Some(auth_str.to_string());
                                true
                            } else {
                                false
                            }
                        }
                        None => false,
                    }
                }
            }
            None => false,
        };
        if !authorized {
            return Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("WWW-Authenticate", "Basic realm=\"rgrok\"")
                .body(Full::new(Bytes::from("Unauthorized")))
                .unwrap());
        }
    }

    // Request a proxy stream from the client
    let mut proxy_stream = match request_proxy_stream(&tunnel).await {
        Some(s) => s,
        None => {
            return Ok(error_response(
                StatusCode::GATEWAY_TIMEOUT,
                "Tunnel client did not respond",
            ));
        }
    };

    let start = std::time::Instant::now();
    let inspect = tunnel.options.inspect;
    let method_str_for_metrics: String; // captured after parts destructure

    // Serialize the HTTP request into raw HTTP/1.1 and write into the yamux stream.
    // The client will forward this to the local service as-is.
    let (parts, body) = req.into_parts();
    method_str_for_metrics = parts.method.to_string();

    // Capture request metadata if inspection is enabled
    let capture_id = if inspect {
        let req_headers: Vec<(String, String)> = parts
            .headers
            .iter()
            .filter_map(|(k, v)| v.to_str().ok().map(|vs| (k.to_string(), vs.to_string())))
            .collect();
        let capture = rgrok_proto::inspect::CapturedRequest {
            id: uuid::Uuid::new_v4().to_string(),
            captured_at: chrono::Utc::now(),
            duration_ms: None,
            tunnel_id: tunnel.id.clone(),
            req_method: parts.method.to_string(),
            req_url: parts
                .uri
                .path_and_query()
                .map(|pq| pq.to_string())
                .unwrap_or_else(|| "/".to_string()),
            req_headers,
            req_body: None, // filled after body is read
            resp_status: None,
            resp_headers: None,
            resp_body: None,
            resp_body_truncated: false,
            remote_addr: String::new(),
            tls_version: None,
        };
        let id = capture.id.clone();
        state.store_capture(&subdomain, capture).await;
        Some(id)
    } else {
        None
    };

    // Build request line + headers
    let mut raw_request = format!(
        "{} {} HTTP/1.1\r\n",
        parts.method,
        parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/")
    );

    // Rewrite Host header if tunnel has a custom host_header option
    let mut host_written = false;
    if let Some(ref custom_host) = tunnel.options.host_header {
        raw_request.push_str(&format!("Host: {}\r\n", custom_host));
        host_written = true;
    }

    for (name, value) in &parts.headers {
        if host_written && name == HOST {
            continue; // Skip original Host header if we already wrote a custom one
        }
        if let Ok(v) = value.to_str() {
            raw_request.push_str(&format!("{}: {}\r\n", name, v));
        }
    }
    raw_request.push_str("\r\n");

    // Write headers into the proxy stream
    if proxy_stream
        .write_all(raw_request.as_bytes())
        .await
        .is_err()
    {
        return Ok(error_response(
            StatusCode::BAD_GATEWAY,
            "Failed to write to tunnel",
        ));
    }

    // Stream the request body
    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "Failed to read request body",
            ));
        }
    };
    if !body_bytes.is_empty() {
        if proxy_stream.write_all(&body_bytes).await.is_err() {
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                "Failed to write body to tunnel",
            ));
        }
    }

    // Read the HTTP response back from the proxy stream.
    // We read in chunks and parse the response status + headers, then the body.
    let mut response_buf = Vec::with_capacity(8192);
    let mut temp = [0u8; 8192];

    // Read until we have the full header section
    loop {
        let n = match proxy_stream.read(&mut temp).await {
            Ok(n) => n,
            Err(_) => {
                return Ok(error_response(
                    StatusCode::BAD_GATEWAY,
                    "Failed to read from tunnel",
                ));
            }
        };
        if n == 0 {
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                "Tunnel returned empty response",
            ));
        }
        response_buf.extend_from_slice(&temp[..n]);

        // Check if we have the full header section
        if response_buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if response_buf.len() > 65536 {
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                "Response headers too large",
            ));
        }
    }

    // Parse the response headers
    let header_end = response_buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap()
        + 4;

    let header_str = String::from_utf8_lossy(&response_buf[..header_end]);

    // Parse status line
    let first_line = header_str
        .lines()
        .next()
        .unwrap_or("HTTP/1.1 502 Bad Gateway");
    let status_code = first_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(502);

    let mut builder = Response::builder().status(status_code);

    // Parse response headers
    for line in header_str.lines().skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(": ") {
            // Skip hop-by-hop headers
            let name_lower = name.to_lowercase();
            if name_lower == "transfer-encoding" || name_lower == "connection" {
                continue;
            }
            builder = builder.header(name, value);
        }
    }

    // Inject HSTS and any configured response headers
    builder = builder.header("Strict-Transport-Security", "max-age=31536000");
    for (name, value) in &tunnel.options.response_header {
        builder = builder.header(name.as_str(), value.as_str());
    }

    // Collect body: what we already have past the header section + remaining data
    let mut body_data = response_buf[header_end..].to_vec();

    // Read remaining body data from the stream
    loop {
        let n = match tokio::time::timeout(Duration::from_secs(30), proxy_stream.read(&mut temp))
            .await
        {
            Ok(Ok(n)) => n,
            Ok(Err(_)) | Err(_) => break,
        };
        if n == 0 {
            break;
        }
        body_data.extend_from_slice(&temp[..n]);
    }

    // Capture response metadata if inspection is enabled
    if let Some(cap_id) = capture_id {
        let duration_ms = start.elapsed().as_millis() as u64;
        let resp_headers: Vec<(String, String)> = header_str
            .lines()
            .skip(1)
            .take_while(|l| !l.is_empty())
            .filter_map(|l| {
                l.split_once(": ")
                    .map(|(k, v)| (k.to_string(), v.to_string()))
            })
            .collect();

        let body_truncated = body_data.len() > 1_048_576;
        let captured_body = if body_data.is_empty() {
            None
        } else {
            let len = body_data.len().min(1_048_576);
            Some(Bytes::copy_from_slice(&body_data[..len]))
        };

        // Send completion event
        let _ = state
            .inspect_tx
            .send(rgrok_proto::inspect::InspectEvent::RequestCompleted {
                id: cap_id.clone(),
                duration_ms,
                resp_status: status_code,
            });

        // Update the capture in the ring buffer (best-effort)
        if let Some(captures) = state.captures.get(&subdomain) {
            let mut queue = captures.lock().await;
            // Find and update the existing capture by walking backwards (most recent first)
            for cap in queue.iter_mut().rev() {
                if cap.id == cap_id {
                    cap.duration_ms = Some(duration_ms);
                    cap.resp_status = Some(status_code);
                    cap.resp_headers = Some(resp_headers);
                    cap.resp_body = captured_body;
                    cap.resp_body_truncated = body_truncated;
                    break;
                }
            }
        }
    }

    // Record Prometheus metrics
    let duration_for_metrics = start.elapsed().as_millis() as f64;
    state
        .metrics
        .requests_total
        .with_label_values(&[&status_code.to_string()])
        .inc();
    state
        .metrics
        .request_duration_ms
        .with_label_values(&[&method_str_for_metrics])
        .observe(duration_for_metrics);
    state
        .metrics
        .bytes_in_total
        .inc_by(raw_request.len() as u64);
    state.metrics.bytes_out_total.inc_by(body_data.len() as u64);

    let response = builder
        .body(Full::new(Bytes::from(body_data)))
        .unwrap_or_else(|_| {
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Response build error")
        });

    Ok(response)
}

/// Handle a single incoming HTTP connection (port 80) — 301 redirect to HTTPS
async fn handle_http_connection(
    mut incoming: TcpStream,
    _peer_addr: std::net::SocketAddr,
    _state: Arc<ServerState>,
) -> anyhow::Result<()> {
    let mut buf = [0u8; 8192];
    let n = incoming.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    let request_data = String::from_utf8_lossy(&buf[..n]);

    let host = match extract_host_header(&request_data) {
        Some(h) => h,
        None => {
            let response =
                b"HTTP/1.1 400 Bad Request\r\nContent-Length: 16\r\n\r\nMissing Host header";
            incoming.write_all(response).await?;
            return Ok(());
        }
    };

    let redirect_url = format!("https://{}{}", host, extract_request_path(&request_data));
    let response = format!(
        "HTTP/1.1 301 Moved Permanently\r\n\
         Location: {}\r\n\
         Strict-Transport-Security: max-age=31536000\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\r\n",
        redirect_url
    );
    incoming.write_all(response.as_bytes()).await?;
    Ok(())
}

/// Request a proxy stream from the client via the tunnel's pending_streams mechanism.
/// Returns the yamux stream (wrapped for tokio compat) once the client opens it, or None on timeout.
async fn request_proxy_stream(
    tunnel: &TunnelSession,
) -> Option<tokio_util::compat::Compat<yamux::Stream>> {
    let correlation_id = tunnel.next_correlation_id();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tunnel.pending_streams.insert(correlation_id, tx);

    // Tell the client to open a proxy stream
    if tunnel
        .control_tx
        .send(ServerMsg::StreamOpen {
            correlation_id,
            tunnel_id: tunnel.id.clone(),
        })
        .await
        .is_err()
    {
        tunnel.pending_streams.remove(&correlation_id);
        return None;
    }

    // Wait for the client to connect the proxy stream (with timeout)
    match tokio::time::timeout(Duration::from_secs(10), rx).await {
        Ok(Ok(stream)) => Some(stream.compat()),
        _ => {
            tunnel.pending_streams.remove(&correlation_id);
            None
        }
    }
}

/// Serve TCP tunnels by binding dynamic ports — raw byte bridging (no HTTP parsing)
pub async fn serve_tcp_tunnel(
    state: Arc<ServerState>,
    port: u16,
    tunnel: Arc<TunnelSession>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    info!(port, "TCP tunnel listener started");

    loop {
        let (mut incoming, _peer_addr) = tokio::select! {
            result = listener.accept() => result?,
            _ = state.cancel.cancelled() => {
                info!(port, "TCP tunnel listener shutting down");
                return Ok(());
            }
        };
        let tunnel = tunnel.clone();

        tokio::spawn(async move {
            let mut proxy_stream = match request_proxy_stream(&tunnel).await {
                Some(s) => s,
                None => return,
            };

            let _ = tokio::io::copy_bidirectional(&mut incoming, &mut proxy_stream).await;
        });
    }
}

/// Build a simple error response
fn error_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(Full::new(Bytes::from(message.to_string())))
        .unwrap()
}

/// Extract the Host header from raw HTTP request data (used for port-80 redirect only)
fn extract_host_header(request: &str) -> Option<String> {
    for line in request.lines() {
        if let Some(value) = line
            .strip_prefix("Host: ")
            .or_else(|| line.strip_prefix("host: "))
        {
            return Some(value.trim().split(':').next()?.to_string());
        }
    }
    None
}

/// Extract the request path from the HTTP request line (used for port-80 redirect only)
fn extract_request_path(request: &str) -> String {
    if let Some(first_line) = request.lines().next() {
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() >= 2 {
            return parts[1].to_string();
        }
    }
    "/".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── extract_host_header ──

    #[test]
    fn test_extract_host_header_basic() {
        let raw = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(extract_host_header(raw), Some("example.com".to_string()));
    }

    #[test]
    fn test_extract_host_header_with_port() {
        let raw = "GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
        // The function strips the port, returning only the hostname
        assert_eq!(extract_host_header(raw), Some("example.com".to_string()));
    }

    #[test]
    fn test_extract_host_header_missing() {
        let raw = "GET / HTTP/1.1\r\nAccept: */*\r\n\r\n";
        assert_eq!(extract_host_header(raw), None);
    }

    // ── extract_request_path ──

    #[test]
    fn test_extract_request_path_simple() {
        let raw = "GET /foo HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(extract_request_path(raw), "/foo");
    }

    #[test]
    fn test_extract_request_path_with_query() {
        let raw = "GET /foo?bar=1 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(extract_request_path(raw), "/foo?bar=1");
    }

    // ── body truncation logic ──

    /// Helper that replicates the inline truncation logic from proxy_http_request.
    fn truncate_body(body_data: &[u8]) -> (Option<Bytes>, bool) {
        let body_truncated = body_data.len() > 1_048_576;
        let captured_body = if body_data.is_empty() {
            None
        } else {
            let len = body_data.len().min(1_048_576);
            Some(Bytes::copy_from_slice(&body_data[..len]))
        };
        (captured_body, body_truncated)
    }

    #[test]
    fn test_body_truncation_empty() {
        let (body, truncated) = truncate_body(&[]);
        assert!(body.is_none());
        assert!(!truncated);
    }

    #[test]
    fn test_body_truncation_small() {
        let data = vec![0xABu8; 100];
        let (body, truncated) = truncate_body(&data);
        assert!(!truncated);
        let body = body.expect("body should be Some for non-empty input");
        assert_eq!(body.len(), 100);
    }

    #[test]
    fn test_body_truncation_at_limit() {
        let data = vec![0x42u8; 1_048_576];
        let (body, truncated) = truncate_body(&data);
        assert!(!truncated);
        let body = body.expect("body should be Some");
        assert_eq!(body.len(), 1_048_576);
    }

    #[test]
    fn test_body_truncation_over_limit() {
        let data = vec![0x42u8; 1_048_577];
        let (body, truncated) = truncate_body(&data);
        assert!(truncated);
        let body = body.expect("body should be Some");
        assert_eq!(body.len(), 1_048_576);
    }

    #[test]
    fn test_body_truncation_large() {
        let data = vec![0x42u8; 2 * 1_048_576];
        let (body, truncated) = truncate_body(&data);
        assert!(truncated);
        let body = body.expect("body should be Some");
        assert_eq!(body.len(), 1_048_576);
    }
}
