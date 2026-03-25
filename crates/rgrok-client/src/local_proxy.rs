use std::sync::Arc;

use bytes::Bytes;
use chrono::Utc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use rgrok_proto::inspect::CapturedRequest;

use crate::inspect::InspectState;
use crate::output::TunnelStats;

/// Bridge two async streams bidirectionally, optionally capturing
/// request/response data for the inspection UI.
pub async fn bridge_streams<U, L>(
    upstream: &mut U,
    local: &mut L,
    inspect: Option<Arc<InspectState>>,
    stats: &TunnelStats,
) -> anyhow::Result<()>
where
    U: AsyncRead + AsyncWrite + Unpin,
    L: AsyncRead + AsyncWrite + Unpin,
{
    if inspect.is_some() {
        bridge_with_capture(upstream, local, inspect.unwrap(), stats).await
    } else {
        let (up, down) = tokio::io::copy_bidirectional(upstream, local).await?;
        stats.record_bytes_in(up);
        stats.record_bytes_out(down);
        Ok(())
    }
}

/// Bridge with request/response capture for the inspection UI.
/// We peek at the first chunk from the upstream (the HTTP request from the server)
/// and the first chunk from local (the HTTP response from the local service)
/// to capture metadata.
async fn bridge_with_capture<U, L>(
    upstream: &mut U,
    local: &mut L,
    inspect: Arc<InspectState>,
    stats: &TunnelStats,
) -> anyhow::Result<()>
where
    U: AsyncRead + AsyncWrite + Unpin,
    L: AsyncRead + AsyncWrite + Unpin,
{
    let start = std::time::Instant::now();

    // Read the initial request data from upstream
    let mut req_buf = vec![0u8; 8192];
    let req_n = upstream.read(&mut req_buf).await?;
    if req_n == 0 {
        return Ok(());
    }
    let req_data = &req_buf[..req_n];

    // Parse request for capture
    let capture = parse_request_for_capture(req_data);

    // Forward request data to local service
    local.write_all(req_data).await?;

    // Now bridge the rest bidirectionally, but also read the first response chunk
    // We'll capture it after the bridge completes or from the first response bytes.
    let mut resp_buf = vec![0u8; 8192];
    let resp_n = local.read(&mut resp_buf).await?;
    if resp_n == 0 {
        // Local service closed immediately
        if let Some(mut cap) = capture {
            cap.duration_ms = Some(start.elapsed().as_millis() as u64);
            inspect.store_capture(cap).await;
        }
        return Ok(());
    }
    let resp_data = &resp_buf[..resp_n];

    // Forward response to upstream
    upstream.write_all(resp_data).await?;

    // Parse response status and headers
    if let Some(mut cap) = capture {
        cap.resp_status = parse_response_status(resp_data);
        cap.resp_headers = Some(parse_response_headers(resp_data));
        let body_start = find_body_offset(resp_data);
        if let Some(offset) = body_start {
            if offset < resp_data.len() {
                let body_len = (resp_data.len() - offset).min(1_048_576);
                cap.resp_body = Some(Bytes::copy_from_slice(
                    &resp_data[offset..offset + body_len],
                ));
            }
        }
        cap.duration_ms = Some(start.elapsed().as_millis() as u64);
        inspect.store_capture(cap).await;
    }

    // Track initial bytes
    stats.record_bytes_in(req_n as u64);
    stats.record_bytes_out(resp_n as u64);

    // Continue bridging the rest
    let (up, down) = tokio::io::copy_bidirectional(upstream, local).await?;
    stats.record_bytes_in(up);
    stats.record_bytes_out(down);

    Ok(())
}

fn parse_request_for_capture(data: &[u8]) -> Option<CapturedRequest> {
    let request_str = String::from_utf8_lossy(data);
    let mut lines = request_str.lines();

    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let url = parts.next()?.to_string();

    let mut headers = Vec::new();
    for line in &mut lines {
        if line.is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(": ") {
            headers.push((key.to_string(), value.to_string()));
        }
    }

    let body_offset = find_body_offset(data);
    let body = body_offset.and_then(|pos| {
        if pos < data.len() {
            let body_bytes = &data[pos..];
            let capture_len = body_bytes.len().min(1_048_576);
            Some(Bytes::copy_from_slice(&body_bytes[..capture_len]))
        } else {
            None
        }
    });

    Some(CapturedRequest {
        id: uuid::Uuid::new_v4().to_string(),
        captured_at: Utc::now(),
        duration_ms: None,
        tunnel_id: String::new(),
        req_method: method,
        req_url: url,
        req_headers: headers,
        req_body: body,
        resp_status: None,
        resp_headers: None,
        resp_body: None,
        resp_body_truncated: false,
        remote_addr: String::new(),
        tls_version: None,
    })
}

fn parse_response_status(data: &[u8]) -> Option<u16> {
    let s = String::from_utf8_lossy(data);
    let first_line = s.lines().next()?;
    let mut parts = first_line.split_whitespace();
    parts.next()?; // HTTP/1.1
    parts.next()?.parse().ok()
}

fn parse_response_headers(data: &[u8]) -> Vec<(String, String)> {
    let s = String::from_utf8_lossy(data);
    let mut headers = Vec::new();
    let mut lines = s.lines();
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

fn find_body_offset(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_request_for_capture_valid_http() {
        let req = b"GET /api/test HTTP/1.1\r\nHost: example.com\r\nAccept: text/html\r\n\r\n";
        let cap = parse_request_for_capture(req).expect("should parse valid request");
        assert_eq!(cap.req_method, "GET");
        assert_eq!(cap.req_url, "/api/test");
        assert_eq!(cap.req_headers.len(), 2);
        assert_eq!(
            cap.req_headers[0],
            ("Host".to_string(), "example.com".to_string())
        );
        assert_eq!(
            cap.req_headers[1],
            ("Accept".to_string(), "text/html".to_string())
        );
        assert!(cap.req_body.is_none());
        assert!(cap.resp_status.is_none());
    }

    #[test]
    fn parse_request_for_capture_with_body() {
        let req = b"POST /submit HTTP/1.1\r\nContent-Length: 11\r\n\r\nhello world";
        let cap = parse_request_for_capture(req).expect("should parse POST request");
        assert_eq!(cap.req_method, "POST");
        assert_eq!(cap.req_url, "/submit");
        assert_eq!(cap.req_headers.len(), 1);
        let body = cap.req_body.expect("should have body");
        assert_eq!(&body[..], b"hello world");
    }

    #[test]
    fn parse_request_for_capture_empty_data_returns_none() {
        assert!(parse_request_for_capture(b"").is_none());
    }

    #[test]
    fn parse_request_for_capture_malformed_returns_none() {
        // A single word with no whitespace means parts.next() for url returns None
        assert!(parse_request_for_capture(b"GARBAGE\r\n\r\n").is_none());
    }

    #[test]
    fn parse_response_status_extracts_code() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n";
        assert_eq!(parse_response_status(resp), Some(200));
    }

    #[test]
    fn parse_response_status_404() {
        let resp = b"HTTP/1.1 404 Not Found\r\n\r\n";
        assert_eq!(parse_response_status(resp), Some(404));
    }

    #[test]
    fn parse_response_status_invalid_returns_none() {
        let resp = b"not an http response";
        assert_eq!(parse_response_status(resp), None);
    }

    #[test]
    fn parse_response_headers_extracts_headers() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Custom: value\r\n\r\n";
        let headers = parse_response_headers(resp);
        assert_eq!(headers.len(), 2);
        assert_eq!(
            headers[0],
            ("Content-Type".to_string(), "application/json".to_string())
        );
        assert_eq!(headers[1], ("X-Custom".to_string(), "value".to_string()));
    }

    #[test]
    fn parse_response_headers_empty_response() {
        let resp = b"HTTP/1.1 204 No Content\r\n\r\n";
        let headers = parse_response_headers(resp);
        assert!(headers.is_empty());
    }

    #[test]
    fn find_body_offset_finds_boundary() {
        let data = b"HTTP/1.1 200 OK\r\nFoo: bar\r\n\r\nbody here";
        let offset = find_body_offset(data).expect("should find boundary");
        assert_eq!(&data[offset..], b"body here");
    }

    #[test]
    fn find_body_offset_no_boundary() {
        let data = b"no boundary here";
        assert!(find_body_offset(data).is_none());
    }

    #[test]
    fn find_body_offset_boundary_at_end() {
        let data = b"HTTP/1.1 200 OK\r\n\r\n";
        let offset = find_body_offset(data).expect("should find boundary");
        assert_eq!(offset, data.len());
    }

    /// Local Forwarding: verify that connecting to a non-listening port fails with
    /// ConnectionRefused rather than hanging.
    #[tokio::test]
    async fn test_local_service_connection_refused() {
        let tmp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = tmp.local_addr().unwrap().port();
        drop(tmp); // stop listening

        let result = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)).await;
        assert!(result.is_err(), "Connection to closed port should fail");
    }

    /// Local Forwarding: bridge_streams handles clean EOF on both sides without panic.
    #[tokio::test]
    async fn test_bridge_streams_both_sides_eof() {
        let (mut upstream, upstream_peer) = tokio::io::duplex(1024);
        let (mut local, local_peer) = tokio::io::duplex(1024);

        // Both peers close immediately
        drop(upstream_peer);
        drop(local_peer);

        let stats = TunnelStats::new();
        let result = bridge_streams(&mut upstream, &mut local, None, &stats).await;
        assert!(result.is_ok(), "Should handle immediate EOF gracefully");
    }

    /// Local Forwarding: bridge_streams handles one-sided close (local crashes).
    #[tokio::test]
    async fn test_bridge_streams_local_crashes_mid_transfer() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let (mut upstream, mut upstream_peer) = tokio::io::duplex(1024);
        let (mut local, mut local_peer) = tokio::io::duplex(1024);

        // Upstream sends data then waits for response
        tokio::spawn(async move {
            upstream_peer
                .write_all(b"GET / HTTP/1.1\r\n\r\n")
                .await
                .unwrap();
            let mut buf = [0u8; 1024];
            let _ = upstream_peer.read(&mut buf).await;
        });

        // Local reads partial data then crashes
        tokio::spawn(async move {
            let mut buf = [0u8; 5];
            let _ = local_peer.read(&mut buf).await;
            drop(local_peer);
        });

        let stats = TunnelStats::new();
        // Should complete without hanging or panicking
        let _ = bridge_streams(&mut upstream, &mut local, None, &stats).await;
    }
}
