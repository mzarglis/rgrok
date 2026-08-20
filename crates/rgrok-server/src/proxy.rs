use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Uri};
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Incoming;
use hyper::header::{AUTHORIZATION, CONTENT_LENGTH, HOST};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::OwnedSemaphorePermit;
use tokio_rustls::TlsAcceptor;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tracing::{info, warn};

use rgrok_proto::messages::ServerMsg;

use crate::auth;
use crate::tunnel_manager::{ServerState, TunnelSession};

const MAX_RESPONSE_HEADERS: usize = 65_536;
const MAX_INFORMATIONAL_RESPONSES: usize = 16;
const READ_BUFFER_SIZE: usize = 8_192;
const CLOSE_DELIMITED_READ_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_INSPECTION_BODY: usize = 1_048_576;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyReadError {
    Read,
    TooLarge,
}

async fn collect_body_limited<B>(body: B, limit: usize) -> Result<Bytes, BodyReadError>
where
    B: http_body::Body<Data = Bytes>,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    match Limited::new(body, limit).collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(error) if error.downcast_ref::<LengthLimitError>().is_some() => {
            Err(BodyReadError::TooLarge)
        }
        Err(_) => Err(BodyReadError::Read),
    }
}

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

struct PreparedRequest {
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
    _body_guard: Option<BufferedRequestBody>,
}

struct BufferedRequestBody {
    _permit: OwnedSemaphorePermit,
    metrics: Arc<crate::metrics::Metrics>,
    bytes: i64,
}

impl Drop for BufferedRequestBody {
    fn drop(&mut self) {
        self.metrics.buffered_request_body_bytes.sub(self.bytes);
    }
}
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

    let max_request_body_bytes = state.config.server.max_request_body_bytes;
    if req
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length > max_request_body_bytes)
    {
        return Ok(error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Request body too large",
        ));
    }

    // Hyper has decoded the public framing. Bound collection before opening a
    // tunnel stream so a slow/oversized upload cannot occupy client capacity.
    let (parts, body) = req.into_parts();
    let body_permit = match state.request_body_slots.clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(_) => {
            return Ok(error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Server is shutting down",
            ));
        }
    };
    let body_bytes = match collect_body_limited(body, max_request_body_bytes).await {
        Ok(body_bytes) => body_bytes,
        Err(BodyReadError::TooLarge) => {
            return Ok(error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Request body too large",
            ));
        }
        Err(BodyReadError::Read) => {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "Failed to read request body",
            ));
        }
    };
    let buffered_bytes = i64::try_from(body_bytes.len()).unwrap_or(i64::MAX);
    state
        .metrics
        .buffered_request_body_bytes
        .add(buffered_bytes);
    let request = PreparedRequest {
        method: parts.method,
        uri: parts.uri,
        headers: parts.headers,
        body: body_bytes,
        _body_guard: Some(BufferedRequestBody {
            _permit: body_permit,
            metrics: state.metrics.clone(),
            bytes: buffered_bytes,
        }),
    };

    match proxy_request_to_tunnel(request, state, subdomain, tunnel, None).await {
        Ok(response) => Ok(response),
        Err(status) => Ok(error_response(status, "Tunnel proxy request failed")),
    }
}

/// Replay a captured request through an already-connected tunnel.
///
/// The request is routed directly by subdomain so inspection replay never depends on public DNS,
/// TLS certificates, or a second trip through the public proxy listener.
pub(crate) async fn replay_http_request(
    state: Arc<ServerState>,
    subdomain: &str,
    capture: &rgrok_proto::inspect::CapturedRequest,
    request_id: String,
) -> Result<Response<Full<Bytes>>, StatusCode> {
    let tunnel = state
        .tunnels
        .get(subdomain)
        .map(|entry| entry.clone())
        .ok_or(StatusCode::BAD_GATEWAY)?;

    if capture.req_body_truncated {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    let method =
        Method::from_bytes(capture.req_method.as_bytes()).map_err(|_| StatusCode::BAD_REQUEST)?;
    let uri = capture
        .req_url
        .parse::<Uri>()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let body = capture.req_body.clone().unwrap_or_default();
    let mut headers = HeaderMap::new();
    let mut had_content_length = false;
    for (name, value) in &capture.req_headers {
        if !is_safe_replay_header(name) {
            continue;
        }
        let header_name = name
            .parse::<http::header::HeaderName>()
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        let header_value = HeaderValue::from_str(value).map_err(|_| StatusCode::BAD_REQUEST)?;
        if header_name == CONTENT_LENGTH {
            had_content_length = true;
            continue;
        }
        headers.append(header_name, header_value);
    }
    // The captured request body may be bounded, so its wire length must match the replay body.
    // This also prevents a stale Content-Length from causing the local server to wait forever.
    if had_content_length || !body.is_empty() {
        headers.insert(
            CONTENT_LENGTH,
            HeaderValue::from_str(&body.len().to_string()).map_err(|_| StatusCode::BAD_REQUEST)?,
        );
    }

    let request = PreparedRequest {
        method,
        uri,
        headers,
        body,
        _body_guard: None,
    };

    proxy_request_to_tunnel(
        request,
        state,
        subdomain.to_string(),
        tunnel,
        Some(request_id),
    )
    .await
}

fn is_safe_replay_header(name: &str) -> bool {
    !matches!(
        name.to_ascii_lowercase().as_str(),
        "host"
            | "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "authorization"
            | "cookie"
            | "set-cookie"
            | "x-api-key"
            | "x-auth-token"
            | "x-access-token"
    )
}

async fn proxy_request_to_tunnel(
    request: PreparedRequest,
    state: Arc<ServerState>,
    subdomain: String,
    tunnel: Arc<TunnelSession>,
    capture_id: Option<String>,
) -> Result<Response<Full<Bytes>>, StatusCode> {
    let is_replay = capture_id.is_some();
    let mut proxy_stream = request_proxy_stream(&tunnel)
        .await
        .ok_or(StatusCode::GATEWAY_TIMEOUT)?;
    let start = std::time::Instant::now();
    let method_str_for_metrics = request.method.to_string();
    let inspect = tunnel.options.inspect || capture_id.is_some();

    let req_headers: Vec<(String, String)> = request
        .headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.to_string(), value.to_string()))
        })
        .collect();
    let req_body = if request.body.is_empty() {
        None
    } else {
        Some(Bytes::copy_from_slice(
            &request.body[..request.body.len().min(MAX_INSPECTION_BODY)],
        ))
    };
    let capture_id = if inspect {
        let id = capture_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        state
            .store_capture(
                &subdomain,
                rgrok_proto::inspect::CapturedRequest {
                    id: id.clone(),
                    captured_at: chrono::Utc::now(),
                    duration_ms: None,
                    tunnel_id: tunnel.id.clone(),
                    req_method: request.method.to_string(),
                    req_url: request
                        .uri
                        .path_and_query()
                        .map(|path| path.to_string())
                        .unwrap_or_else(|| "/".to_string()),
                    req_headers,
                    req_body,
                    req_body_truncated: request.body.len() > MAX_INSPECTION_BODY,
                    resp_status: None,
                    resp_headers: None,
                    resp_body: None,
                    resp_body_truncated: false,
                    remote_addr: if is_replay {
                        "replay".to_string()
                    } else {
                        String::new()
                    },
                    tls_version: None,
                },
            )
            .await;
        Some(id)
    } else {
        None
    };

    // Build request line + headers. The raw tunnel is not an HTTP parser, so strip all
    // hop-by-hop fields and replace any incoming Transfer-Encoding/Content-Length with the
    // decoded body length. Connection tokens name additional hop-by-hop headers and are removed
    // as well (RFC 9110 section 7.6.1).
    let host_header = tunnel
        .options
        .host_header
        .as_deref()
        .or_else(|| is_replay.then_some(tunnel.subdomain.as_str()));
    let raw_request = serialize_http_request(&request, request.body.len(), host_header);

    // Write headers into the proxy stream
    if proxy_stream
        .write_all(raw_request.as_bytes())
        .await
        .is_err()
    {
        return Err(StatusCode::BAD_GATEWAY);
    }

    if !request.body.is_empty() && proxy_stream.write_all(&request.body).await.is_err() {
        return Err(StatusCode::BAD_GATEWAY);
    }

    // Parse exactly one response. Content-Length and chunked responses complete without waiting
    // for the local TCP connection to close; only a genuinely close-delimited response reads EOF.
    let parsed_response = match read_http_response(
        &mut proxy_stream,
        &request.method,
        state.config.server.max_response_body_bytes,
    )
    .await
    {
        Ok(response) => response,
        Err(error) => {
            warn!(%error, "Failed to parse response from tunnel");
            return Err(StatusCode::BAD_GATEWAY);
        }
    };
    let status_code = parsed_response.status_code;
    let body_data = parsed_response.body;
    let response_headers = parsed_response.headers;
    let response_no_body = response_has_no_body(&request.method, status_code);

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
    if request.method == Method::HEAD {
        if let Some(content_length) = source_content_length {
            builder = builder.header("Content-Length", content_length);
        }
    } else if response_no_body {
        builder = builder.header("Content-Length", "0");
    } else {
        builder = builder.header("Content-Length", body_data.len().to_string());
    }
    builder = builder.header("Strict-Transport-Security", "max-age=31536000");
    for (name, value) in &tunnel.options.response_header {
        builder = builder.header(name.as_str(), value.as_str());
    }

    // Capture response metadata if inspection is enabled
    if let Some(cap_id) = capture_id {
        let duration_ms = start.elapsed().as_millis() as u64;
        let resp_headers = rgrok_proto::inspect::sanitize_headers(&response_headers);

        let body_truncated = body_data.len() > MAX_INSPECTION_BODY;
        let captured_body = if body_data.is_empty() {
            None
        } else {
            Some(Bytes::copy_from_slice(
                &body_data[..body_data.len().min(MAX_INSPECTION_BODY)],
            ))
        };

        let _ = state
            .inspect_tx
            .send(rgrok_proto::inspect::InspectEvent::RequestCompleted {
                id: cap_id.clone(),
                duration_ms,
                resp_status: status_code,
            });
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
        .inc_by(raw_request.len() as u64 + request.body.len() as u64);
    state.metrics.bytes_out_total.inc_by(body_data.len() as u64);

    builder
        .body(Full::new(Bytes::from(body_data)))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

#[derive(Debug)]
struct ParsedHttpResponse {
    status_code: u16,
    headers: Vec<(String, String)>,
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
    max_body_bytes: usize,
) -> anyhow::Result<ParsedHttpResponse>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buffered = Vec::with_capacity(READ_BUFFER_SIZE);
    let mut informational_responses = 0;
    let (status_code, headers) = loop {
        let header_end = read_header_section(stream, &mut buffered).await?;
        let header_bytes = buffered[..header_end].to_vec();
        let header_text = std::str::from_utf8(&header_bytes)?.to_string();
        let (status_code, headers) = parse_response_headers(&header_text)?;
        buffered.drain(..header_end);

        // Informational responses (for example, 100 Continue) do not terminate the response.
        // Keep parsing until the final response, while 101 Switching Protocols is terminal for
        // HTTP/1.1 framing and is treated as a no-body response below.
        if (100..200).contains(&status_code) && status_code != 101 {
            informational_responses += 1;
            if informational_responses > MAX_INFORMATIONAL_RESPONSES {
                anyhow::bail!("too many informational responses");
            }
            continue;
        }
        break (status_code, headers);
    };

    if response_has_no_body(request_method, status_code) {
        return Ok(ParsedHttpResponse {
            status_code,
            headers,
            body: Vec::new(),
        });
    }

    let transfer_codings = header_values(&headers, "transfer-encoding")
        .iter()
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if !transfer_codings.is_empty()
        && (transfer_codings.len() != 1 || !transfer_codings[0].eq_ignore_ascii_case("chunked"))
    {
        anyhow::bail!("unsupported Transfer-Encoding");
    }
    let chunked = !transfer_codings.is_empty();

    let body = if chunked {
        read_chunked_body(stream, &mut buffered, max_body_bytes).await?
    } else if let Some(content_length) = parse_content_length(&headers)? {
        read_fixed_body(stream, &mut buffered, content_length, max_body_bytes).await?
    } else {
        read_close_delimited_body(stream, &mut buffered, max_body_bytes).await?
    };

    Ok(ParsedHttpResponse {
        status_code,
        headers,
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
            if position + 4 > MAX_RESPONSE_HEADERS {
                anyhow::bail!("response headers too large");
            }
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
        if buffered.len() > MAX_RESPONSE_HEADERS
            && !buffered.windows(4).any(|window| window == b"\r\n\r\n")
        {
            anyhow::bail!("response headers too large");
        }
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
    max_body_bytes: usize,
) -> anyhow::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    if content_length > max_body_bytes {
        anyhow::bail!("response body exceeds configured limit");
    }
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

async fn read_chunked_body<S>(
    stream: &mut S,
    buffered: &mut Vec<u8>,
    max_body_bytes: usize,
) -> anyhow::Result<Vec<u8>>
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

        if size > max_body_bytes.saturating_sub(body.len()) {
            anyhow::bail!("response body exceeds configured limit");
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
    max_body_bytes: usize,
) -> anyhow::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut body = std::mem::take(buffered);
    if body.len() > max_body_bytes {
        anyhow::bail!("response body exceeds configured limit");
    }
    let mut temp = [0u8; READ_BUFFER_SIZE];
    loop {
        let n = tokio::time::timeout(CLOSE_DELIMITED_READ_TIMEOUT, stream.read(&mut temp))
            .await
            .map_err(|_| anyhow::anyhow!("close-delimited response timed out"))??;
        if n == 0 {
            return Ok(body);
        }
        if n > max_body_bytes.saturating_sub(body.len()) {
            anyhow::bail!("response body exceeds configured limit");
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
    parts: &PreparedRequest,
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
            read_http_response(&mut stream, &Method::GET, usize::MAX),
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

        let response = read_http_response(&mut stream, &Method::GET, usize::MAX)
            .await
            .unwrap();
        assert_eq!(response.body, b"hello world");
        assert_eq!(
            response.headers[0],
            ("Transfer-Encoding".to_string(), "chunked".to_string())
        );
    }

    #[tokio::test]
    async fn response_body_limit_rejects_fixed_and_chunked_bodies() {
        let (mut stream, mut peer) = tokio::io::duplex(4096);
        peer.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n123456")
            .await
            .unwrap();
        assert!(read_http_response(&mut stream, &Method::GET, 5)
            .await
            .is_err());

        let (mut stream, mut peer) = tokio::io::duplex(4096);
        peer.write_all(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n6\r\n123456\r\n0\r\n\r\n",
        )
        .await
        .unwrap();
        assert!(read_http_response(&mut stream, &Method::GET, 5)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn unsupported_transfer_coding_is_rejected() {
        let (mut stream, mut peer) = tokio::io::duplex(4096);
        peer.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n")
            .await
            .unwrap();
        assert!(read_http_response(&mut stream, &Method::GET, usize::MAX)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn informational_response_is_skipped_before_final_response() {
        let (mut stream, mut peer) = tokio::io::duplex(4096);
        peer.write_all(
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        )
        .await
        .unwrap();

        let response = read_http_response(&mut stream, &Method::POST, usize::MAX)
            .await
            .unwrap();
        assert_eq!(response.status_code, 200);
        assert_eq!(response.body, b"ok");
    }

    #[tokio::test]
    async fn excessive_informational_responses_are_rejected() {
        let (mut stream, mut peer) = tokio::io::duplex(4096);
        let response = "HTTP/1.1 100 Continue\r\n\r\n".repeat(MAX_INFORMATIONAL_RESPONSES + 1);
        peer.write_all(response.as_bytes()).await.unwrap();

        let error = read_http_response(&mut stream, &Method::POST, usize::MAX)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("too many informational"));
    }

    #[tokio::test]
    async fn close_delimited_response_reads_until_eof() {
        let (mut stream, mut peer) = tokio::io::duplex(4096);
        peer.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello")
            .await
            .unwrap();
        drop(peer);

        let response = read_http_response(&mut stream, &Method::GET, usize::MAX)
            .await
            .unwrap();
        assert_eq!(response.body, b"hello");
    }

    #[tokio::test]
    async fn conflicting_content_lengths_are_rejected() {
        let (mut stream, mut peer) = tokio::io::duplex(4096);
        peer.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\ntest")
            .await
            .unwrap();

        assert!(read_http_response(&mut stream, &Method::GET, usize::MAX)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn head_and_no_content_responses_have_no_body() {
        let (mut stream, mut peer) = tokio::io::duplex(4096);
        peer.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
            .await
            .unwrap();
        let response = read_http_response(&mut stream, &Method::HEAD, usize::MAX)
            .await
            .unwrap();
        assert!(response.body.is_empty());

        let (mut stream, mut peer) = tokio::io::duplex(4096);
        peer.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        let response = read_http_response(&mut stream, &Method::GET, usize::MAX)
            .await
            .unwrap();
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
        let request = PreparedRequest {
            method: parts.method,
            uri: parts.uri,
            headers: parts.headers,
            body: Bytes::new(),
            _body_guard: None,
        };

        let serialized = serialize_http_request(&request, 11, None);
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
