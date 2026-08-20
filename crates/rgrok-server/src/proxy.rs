use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{AUTHORIZATION, HOST};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tracing::{info, warn};

use rgrok_proto::messages::ServerMsg;

use crate::auth;
use crate::tunnel_manager::{ServerState, TunnelSession};

const MAX_RESPONSE_HEADERS: usize = 65_536;
const READ_BUFFER_SIZE: usize = 8_192;

const HOP_BY_HOP_HEADERS: [&str; 9] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

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
        let mut tls_config_rx = state.tls_config_rx.clone();
        let initial_acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            // Build an acceptor from the latest watch value for each new
            // connection. Existing TLS sessions remain on their original
            // config while new sessions use a renewed certificate.
            let acceptor = tls_config_rx
                .borrow_and_update()
                .clone()
                .map(TlsAcceptor::from)
                .unwrap_or(initial_acceptor);
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
    if let (Some(username), Some(hash)) = (&tunnel.basic_auth_username, &tunnel.basic_auth_hash) {
        let authorized = match req.headers().get(AUTHORIZATION) {
            Some(auth_val) => {
                let auth_str = auth_val.to_str().unwrap_or("");
                let auth_fingerprint = auth::auth_header_fingerprint(auth_str);

                // Fast path: check if this header matches the cached successful value
                let cached = tunnel.cached_auth_fingerprint.lock().await;
                if cached.as_ref() == Some(&auth_fingerprint) {
                    true
                } else {
                    drop(cached); // release lock before the bounded bcrypt task
                    if state
                        .basic_auth_verifier
                        .verify_header(auth_str, username, hash)
                        .await
                    {
                        // Cache only a one-way fingerprint of the successful header.
                        *tunnel.cached_auth_fingerprint.lock().await = Some(auth_fingerprint);
                        true
                    } else {
                        false
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

    // Only authenticated public traffic keeps an idle tunnel alive.
    tunnel.touch();

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
    // captured after parts destructure

    // Hyper has already decoded the public request body (including chunked bodies). Read it
    // before serializing so the local service receives one unambiguous HTTP/1.1 framing mode.
    let (parts, body) = req.into_parts();
    let method_str_for_metrics: String = parts.method.to_string();

    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "Failed to read request body",
            ));
        }
    };

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

    // Build request line + headers. The raw tunnel is not an HTTP parser, so strip all
    // hop-by-hop fields and replace any incoming Transfer-Encoding/Content-Length with the
    // decoded body length. Connection tokens name additional hop-by-hop headers and are removed
    // as well (RFC 9110 section 7.6.1).
    let raw_request = serialize_http_request(
        &parts,
        body_bytes.len(),
        tunnel.options.host_header.as_deref(),
    );

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

    if !body_bytes.is_empty() && proxy_stream.write_all(&body_bytes).await.is_err() {
        return Ok(error_response(
            StatusCode::BAD_GATEWAY,
            "Failed to write body to tunnel",
        ));
    }

    // Parse exactly one response. Content-Length and chunked responses complete without waiting
    // for the local TCP connection to close; only a genuinely close-delimited response reads EOF.
    let parsed_response = match read_http_response(&mut proxy_stream, &parts.method).await {
        Ok(response) => response,
        Err(_) => {
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                "Invalid or incomplete response from tunnel",
            ));
        }
    };
    let status_code = parsed_response.status_code;
    let header_str = parsed_response.header_text;
    let body_data = parsed_response.body;
    let response_headers = parsed_response.headers;
    let response_no_body = response_has_no_body(&parts.method, status_code);

    let mut builder = Response::builder().status(status_code);

    // Forward end-to-end response fields only. The body was decoded above, so make the new
    // response's framing explicit rather than retaining Transfer-Encoding/chunk markers.
    let hop_by_hop = hop_by_hop_header_names(
        response_headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
    );
    let source_content_length = response_headers.iter().find_map(|(name, value)| {
        (name.eq_ignore_ascii_case("content-length")).then_some(value.as_str())
    });
    for (name, value) in &response_headers {
        if is_hop_by_hop(name, &hop_by_hop) || name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        builder = builder.header(name.as_str(), value.as_str());
    }
    if parts.method == Method::HEAD {
        if let Some(content_length) = source_content_length {
            builder = builder.header("Content-Length", content_length);
        }
    } else if response_no_body {
        builder = builder.header("Content-Length", "0");
    } else {
        builder = builder.header("Content-Length", body_data.len().to_string());
    }

    // Inject HSTS and any configured response headers
    builder = builder.header("Strict-Transport-Security", "max-age=31536000");
    for (name, value) in &tunnel.options.response_header {
        builder = builder.header(name.as_str(), value.as_str());
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
        .inc_by((raw_request.len() + body_bytes.len()) as u64);
    state.metrics.bytes_out_total.inc_by(body_data.len() as u64);

    let response = builder
        .body(Full::new(Bytes::from(body_data)))
        .unwrap_or_else(|_| {
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Response build error")
        });

    Ok(response)
}

#[derive(Debug)]
struct ParsedHttpResponse {
    status_code: u16,
    headers: Vec<(String, String)>,
    header_text: String,
    body: Vec<u8>,
}

/// Read and de-frame one HTTP/1.1 response from the raw local-service stream.
///
/// The public Hyper server cannot consume a response body until its framing is known. In
/// particular, a keep-alive local service must not force this function to wait for EOF after a
/// Content-Length or chunked response. The returned body is always decoded bytes.
async fn read_http_response<S>(
    stream: &mut S,
    request_method: &Method,
) -> anyhow::Result<ParsedHttpResponse>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buffered = Vec::with_capacity(READ_BUFFER_SIZE);
    let (status_code, headers, header_text) = loop {
        let header_end = read_header_section(stream, &mut buffered).await?;
        let header_bytes = buffered[..header_end].to_vec();
        let header_text = std::str::from_utf8(&header_bytes)?.to_string();
        let (status_code, headers) = parse_response_headers(&header_text)?;
        buffered.drain(..header_end);

        // Informational responses (for example, 100 Continue) do not terminate the response.
        // Keep parsing until the final response, while 101 Switching Protocols is terminal for
        // HTTP/1.1 framing and is treated as a no-body response below.
        if (100..200).contains(&status_code) && status_code != 101 {
            continue;
        }
        break (status_code, headers, header_text);
    };

    if response_has_no_body(request_method, status_code) {
        return Ok(ParsedHttpResponse {
            status_code,
            headers,
            header_text,
            body: Vec::new(),
        });
    }

    let transfer_encoding = header_values(&headers, "transfer-encoding");
    let chunked = transfer_encoding
        .iter()
        .flat_map(|value| value.split(','))
        .last()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("chunked"));

    let body = if chunked {
        read_chunked_body(stream, &mut buffered).await?
    } else if let Some(content_length) = parse_content_length(&headers)? {
        read_fixed_body(stream, &mut buffered, content_length).await?
    } else {
        read_close_delimited_body(stream, &mut buffered).await?
    };

    Ok(ParsedHttpResponse {
        status_code,
        headers,
        header_text,
        body,
    })
}

async fn read_header_section<S>(stream: &mut S, buffered: &mut Vec<u8>) -> anyhow::Result<usize>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut temp = [0u8; READ_BUFFER_SIZE];
    loop {
        if let Some(position) = buffered.windows(4).position(|window| window == b"\r\n\r\n") {
            return Ok(position + 4);
        }
        if buffered.len() >= MAX_RESPONSE_HEADERS {
            anyhow::bail!("response headers too large");
        }
        let n = stream.read(&mut temp).await?;
        if n == 0 {
            anyhow::bail!("response ended before headers");
        }
        buffered.extend_from_slice(&temp[..n]);
    }
}

fn parse_response_headers(header_text: &str) -> anyhow::Result<(u16, Vec<(String, String)>)> {
    let mut lines = header_text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing status line"))?;
    let mut status_parts = status_line.split_whitespace();
    let version = status_parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/") {
        anyhow::bail!("invalid HTTP status line");
    }
    let status_code = status_parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing response status"))?
        .parse::<u16>()?;

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("invalid response header"))?;
        if name.trim().is_empty() {
            anyhow::bail!("empty response header name");
        }
        headers.push((name.trim().to_string(), value.trim().to_string()));
    }
    Ok((status_code, headers))
}

fn header_values<'a>(headers: &'a [(String, String)], name: &str) -> Vec<&'a str> {
    headers
        .iter()
        .filter(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
        .collect()
}

fn parse_content_length(headers: &[(String, String)]) -> anyhow::Result<Option<usize>> {
    let mut parsed = None;
    for value in header_values(headers, "content-length") {
        for item in value.split(',') {
            let length = item.trim().parse::<usize>()?;
            if let Some(previous) = parsed {
                if previous != length {
                    anyhow::bail!("conflicting Content-Length values");
                }
            } else {
                parsed = Some(length);
            }
        }
    }
    Ok(parsed)
}

async fn ensure_buffered<S>(
    stream: &mut S,
    buffered: &mut Vec<u8>,
    required: usize,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut temp = [0u8; READ_BUFFER_SIZE];
    while buffered.len() < required {
        let n = stream.read(&mut temp).await?;
        if n == 0 {
            anyhow::bail!("response ended before body completed");
        }
        buffered.extend_from_slice(&temp[..n]);
    }
    Ok(())
}

fn take_buffered(buffered: &mut Vec<u8>, length: usize) -> Vec<u8> {
    let length = length.min(buffered.len());
    buffered.drain(..length).collect()
}

async fn read_fixed_body<S>(
    stream: &mut S,
    buffered: &mut Vec<u8>,
    content_length: usize,
) -> anyhow::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut body = Vec::with_capacity(content_length.min(READ_BUFFER_SIZE * 2));
    body.extend(take_buffered(buffered, content_length));
    while body.len() < content_length {
        let remaining = content_length - body.len();
        let mut temp = vec![0u8; remaining.min(READ_BUFFER_SIZE)];
        let n = stream.read(&mut temp).await?;
        if n == 0 {
            anyhow::bail!("response ended before Content-Length bytes were read");
        }
        body.extend_from_slice(&temp[..n]);
    }
    Ok(body)
}

async fn read_line_crlf<S>(stream: &mut S, buffered: &mut Vec<u8>) -> anyhow::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    loop {
        if let Some(position) = buffered.windows(2).position(|window| window == b"\r\n") {
            let line = buffered.drain(..position).collect::<Vec<_>>();
            buffered.drain(..2);
            return Ok(line);
        }
        if buffered.len() > MAX_RESPONSE_HEADERS {
            anyhow::bail!("response chunk line too large");
        }
        ensure_buffered(stream, buffered, buffered.len() + 1).await?;
    }
}

async fn read_chunked_body<S>(stream: &mut S, buffered: &mut Vec<u8>) -> anyhow::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut body = Vec::new();
    loop {
        let line = read_line_crlf(stream, buffered).await?;
        let size_text = line
            .split(|byte| *byte == b';')
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing chunk size"))?;
        let size_text = std::str::from_utf8(size_text)?.trim();
        let size = usize::from_str_radix(size_text, 16)?;
        if size == 0 {
            // Consume optional trailers. Their fields are hop-by-hop and are not exposed by the
            // current proxy response type, but they must be consumed to complete the framing.
            loop {
                if read_line_crlf(stream, buffered).await?.is_empty() {
                    break;
                }
            }
            return Ok(body);
        }

        ensure_buffered(stream, buffered, size).await?;
        body.extend(take_buffered(buffered, size));
        ensure_buffered(stream, buffered, 2).await?;
        if take_buffered(buffered, 2).as_slice() != b"\r\n" {
            anyhow::bail!("missing CRLF after response chunk");
        }
    }
}

async fn read_close_delimited_body<S>(
    stream: &mut S,
    buffered: &mut Vec<u8>,
) -> anyhow::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut body = std::mem::take(buffered);
    let mut temp = [0u8; READ_BUFFER_SIZE];
    loop {
        let n = stream.read(&mut temp).await?;
        if n == 0 {
            return Ok(body);
        }
        body.extend_from_slice(&temp[..n]);
    }
}

fn response_has_no_body(method: &Method, status_code: u16) -> bool {
    *method == Method::HEAD
        || (100..200).contains(&status_code)
        || status_code == StatusCode::NO_CONTENT.as_u16()
        || status_code == StatusCode::NOT_MODIFIED.as_u16()
}

fn hop_by_hop_header_names<'a>(
    headers: impl Iterator<Item = (&'a str, &'a str)>,
) -> std::collections::HashSet<String> {
    let mut names = HOP_BY_HOP_HEADERS
        .iter()
        .map(|name| (*name).to_string())
        .collect::<std::collections::HashSet<_>>();
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("connection") {
            names.extend(
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|token| !token.is_empty())
                    .map(str::to_ascii_lowercase),
            );
        }
    }
    names
}

fn serialize_http_request(
    parts: &http::request::Parts,
    body_length: usize,
    custom_host: Option<&str>,
) -> String {
    let mut raw_request = format!(
        "{} {} HTTP/1.1\r\n",
        parts.method,
        parts
            .uri
            .path_and_query()
            .map(|path| path.as_str())
            .unwrap_or("/")
    );

    let host_written = if let Some(custom_host) = custom_host {
        raw_request.push_str(&format!("Host: {custom_host}\r\n"));
        true
    } else {
        false
    };
    let hop_by_hop = hop_by_hop_header_names(
        parts
            .headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.to_str().unwrap_or(""))),
    );
    for (name, value) in &parts.headers {
        if host_written && name == HOST {
            continue;
        }
        if is_hop_by_hop(name.as_str(), &hop_by_hop) || name == http::header::CONTENT_LENGTH {
            continue;
        }
        if let Ok(value) = value.to_str() {
            raw_request.push_str(&format!("{name}: {value}\r\n"));
        }
    }
    raw_request.push_str(&format!("Content-Length: {body_length}\r\n\r\n"));
    raw_request
}

fn is_hop_by_hop(name: &str, hop_by_hop: &std::collections::HashSet<String>) -> bool {
    hop_by_hop.contains(&name.to_ascii_lowercase())
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

/// Request a proxy stream from the client via the tunnel's connection-scoped
/// pending-stream registry.
/// Returns the yamux stream (wrapped for tokio compat) once the client opens it, or None on timeout.
async fn request_proxy_stream(
    tunnel: &TunnelSession,
) -> Option<tokio_util::compat::Compat<yamux::Stream>> {
    let correlation_id = tunnel.next_correlation_id();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tunnel
        .stream_state
        .pending_streams
        .insert(correlation_id, tx);

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
        tunnel.stream_state.pending_streams.remove(&correlation_id);
        return None;
    }

    // Wait for the client to connect the proxy stream (with timeout)
    match tokio::time::timeout(Duration::from_secs(10), rx).await {
        Ok(Ok(stream)) => Some(stream.compat()),
        _ => {
            tunnel.stream_state.pending_streams.remove(&correlation_id);
            None
        }
    }
}

/// Serve TCP tunnels by binding dynamic ports — raw byte bridging (no HTTP parsing)
#[allow(dead_code)] // Compatibility entry point; production binds before registration.
pub async fn serve_tcp_tunnel(
    state: Arc<ServerState>,
    port: u16,
    tunnel: Arc<TunnelSession>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    serve_tcp_tunnel_on_listener(state, listener, tunnel).await
}

/// Serve a TCP tunnel using a listener that was bound before registration.
///
/// Keeping the listener outside this function lets control-plane registration
/// guarantee that a TunnelAck is only sent once the public port is live.
pub async fn serve_tcp_tunnel_on_listener(
    state: Arc<ServerState>,
    listener: TcpListener,
    tunnel: Arc<TunnelSession>,
) -> anyhow::Result<()> {
    let port = listener.local_addr()?.port();
    info!(port, "TCP tunnel listener started");

    loop {
        let (mut incoming, _peer_addr) = tokio::select! {
            result = listener.accept() => result?,
            _ = state.cancel.cancelled() => {
                info!(port, "TCP tunnel listener shutting down");
                return Ok(());
            }
            _ = tunnel.cancel.cancelled() => {
                info!(port, "TCP tunnel listener cancelled");
                return Ok(());
            }
            _ = tunnel.idle_cancel.cancelled() => {
                info!(port, "TCP tunnel closed after idle timeout");
                return Ok(());
            }
        };
        tunnel.touch();
        let tunnel = tunnel.clone();

        tokio::spawn(async move {
            tunnel.stream_started();
            tokio::select! {
                _ = tunnel.cancel.cancelled() => {}
                result = async {
                    let mut proxy_stream = match request_proxy_stream(&tunnel).await {
                        Some(s) => s,
                        None => return,
                    };

                    let _ = tokio::io::copy_bidirectional(&mut incoming, &mut proxy_stream).await;
                } => result,
            }
            tunnel.stream_finished();
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

    #[tokio::test]
    async fn content_length_response_finishes_on_keepalive() {
        let (mut stream, mut peer) = tokio::io::duplex(4096);
        peer.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nhello",
        )
        .await
        .unwrap();

        let response = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            read_http_response(&mut stream, &Method::GET),
        )
        .await
        .expect("Content-Length response should not wait for EOF")
        .unwrap();
        assert_eq!(response.status_code, 200);
        assert_eq!(response.body, b"hello");
    }

    #[tokio::test]
    async fn chunked_response_is_decoded_and_trailers_consumed() {
        let (mut stream, mut peer) = tokio::io::duplex(4096);
        peer.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".as_slice())
            .await
            .unwrap();
        peer.write_all(b"5\r\nhello\r\n6;note=yes\r\n world\r\n0\r\nX-Trailer: done\r\n\r\n")
            .await
            .unwrap();

        let response = read_http_response(&mut stream, &Method::GET).await.unwrap();
        assert_eq!(response.body, b"hello world");
        assert_eq!(
            response.headers[0],
            ("Transfer-Encoding".to_string(), "chunked".to_string())
        );
    }

    #[tokio::test]
    async fn informational_response_is_skipped_before_final_response() {
        let (mut stream, mut peer) = tokio::io::duplex(4096);
        peer.write_all(
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        )
        .await
        .unwrap();

        let response = read_http_response(&mut stream, &Method::POST)
            .await
            .unwrap();
        assert_eq!(response.status_code, 200);
        assert_eq!(response.body, b"ok");
    }

    #[tokio::test]
    async fn head_and_no_content_responses_have_no_body() {
        let (mut stream, mut peer) = tokio::io::duplex(4096);
        peer.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
            .await
            .unwrap();
        let response = read_http_response(&mut stream, &Method::HEAD)
            .await
            .unwrap();
        assert!(response.body.is_empty());

        let (mut stream, mut peer) = tokio::io::duplex(4096);
        peer.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        let response = read_http_response(&mut stream, &Method::GET).await.unwrap();
        assert!(response.body.is_empty());
    }

    #[test]
    fn connection_tokens_are_removed_with_standard_hop_by_hop_fields() {
        let headers = [
            ("Connection", "keep-alive, X-Local-Hop"),
            ("X-Local-Hop", "remove me"),
            ("X-End-To-End", "keep me"),
        ];
        let hop_by_hop = hop_by_hop_header_names(headers.into_iter());
        assert!(hop_by_hop.contains("connection"));
        assert!(hop_by_hop.contains("x-local-hop"));
        assert!(hop_by_hop.contains("transfer-encoding"));
        assert!(!hop_by_hop.contains("x-end-to-end"));
    }

    #[test]
    fn serialized_request_uses_decoded_content_length() {
        let request = Request::builder()
            .method(Method::POST)
            .uri("/submit")
            .header(HOST, "example.com")
            .header("Transfer-Encoding", "chunked")
            .header("Connection", "X-Local-Hop")
            .header("X-Local-Hop", "remove me")
            .body(())
            .unwrap();
        let (parts, ()) = request.into_parts();

        let serialized = serialize_http_request(&parts, 11, None);
        assert!(serialized.starts_with("POST /submit HTTP/1.1\r\n"));
        assert!(serialized.contains("Content-Length: 11\r\n"));
        assert!(!serialized.contains("Transfer-Encoding"));
        assert!(!serialized.contains("X-Local-Hop"));
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
