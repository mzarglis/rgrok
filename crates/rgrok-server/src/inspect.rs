use bytes::Bytes;
use chrono::Utc;

use rgrok_proto::inspect::CapturedRequest;

#[allow(dead_code)]
const MAX_BODY_CAPTURE: usize = 1_048_576; // 1 MB

/// Parse an HTTP request from raw bytes and create a CapturedRequest
#[allow(dead_code)]
pub fn capture_request_from_bytes(
    data: &[u8],
    tunnel_id: &str,
    remote_addr: &str,
) -> Option<CapturedRequest> {
    let request_str = String::from_utf8_lossy(data);
    let mut lines = request_str.lines();

    // Parse request line
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let url = parts.next()?.to_string();

    // Parse headers
    let mut headers = Vec::new();
    for line in &mut lines {
        if line.is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(": ") {
            headers.push((key.to_string(), value.to_string()));
        }
    }

    // Find body (after headers)
    let header_end = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4);

    let body = header_end.and_then(|pos| {
        if pos < data.len() {
            let body_bytes = &data[pos..];
            let capture_len = body_bytes.len().min(MAX_BODY_CAPTURE);
            Some(Bytes::copy_from_slice(&body_bytes[..capture_len]))
        } else {
            None
        }
    });

    Some(CapturedRequest {
        id: uuid::Uuid::new_v4().to_string(),
        captured_at: Utc::now(),
        duration_ms: None,
        tunnel_id: tunnel_id.to_string(),
        req_method: method,
        req_url: url,
        req_headers: headers,
        req_body: body,
        resp_status: None,
        resp_headers: None,
        resp_body: None,
        resp_body_truncated: false,
        remote_addr: remote_addr.to_string(),
        tls_version: None,
    })
}

/// Parse HTTP response status from raw bytes
#[allow(dead_code)]
pub fn parse_response_status(data: &[u8]) -> Option<u16> {
    let response_str = String::from_utf8_lossy(data);
    let first_line = response_str.lines().next()?;
    let mut parts = first_line.split_whitespace();
    parts.next()?; // HTTP/1.1
    parts.next()?.parse().ok()
}

/// Parse response headers from raw bytes
#[allow(dead_code)]
pub fn parse_response_headers(data: &[u8]) -> Vec<(String, String)> {
    let response_str = String::from_utf8_lossy(data);
    let mut headers = Vec::new();
    let mut lines = response_str.lines();
    lines.next(); // skip status line

    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(": ") {
            headers.push((key.to_string(), value.to_string()));
        }
    }

    headers
}
