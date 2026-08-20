use std::sync::Arc;

use bytes::Bytes;
use chrono::Utc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use rgrok_proto::inspect::CapturedRequest;

use crate::inspect::InspectState;
use crate::output::TunnelStats;

const HEADER_CAPTURE_ALLOWANCE: usize = 64 * 1024;

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
    if let Some(inspect) = inspect {
        bridge_with_capture(upstream, local, inspect, stats).await
    } else {
        let (up, down) = tokio::io::copy_bidirectional(upstream, local).await?;
        stats.record_bytes_in(up);
        stats.record_bytes_out(down);
        Ok(())
    }
}

/// Bridge with request/response capture for the inspection UI.
///
/// Both directions must be pumped at the same time. In particular, a local HTTP
/// service may wait for the complete request body before sending any response;
/// reading an upstream chunk and then waiting for that response would deadlock
/// split request bodies.
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

    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);
    let (mut local_read, mut local_write) = tokio::io::split(local);
    let mut request_capture = CaptureBuffer::new(inspect.max_body_bytes);
    let mut response_capture = CaptureBuffer::new(inspect.max_body_bytes);

    // Keep these pumps concurrent so neither side's backpressure can prevent the
    // other direction from making progress. Each pump shuts down its destination
    // after observing EOF, matching copy_bidirectional's half-close behavior.
    let (bytes_in, bytes_out) = tokio::try_join!(
        forward_and_capture(&mut upstream_read, &mut local_write, &mut request_capture,),
        forward_and_capture(&mut local_read, &mut upstream_write, &mut response_capture,),
    )?;

    stats.record_bytes_in(bytes_in);
    stats.record_bytes_out(bytes_out);

    if let Some(mut cap) =
        parse_request_for_capture(request_capture.as_slice(), inspect.max_body_bytes)
    {
        cap.req_body_truncated = find_body_offset(request_capture.as_slice())
            .map(|offset| bytes_in.saturating_sub(offset as u64) > inspect.max_body_bytes as u64)
            .unwrap_or(false);
        let resp_data = response_capture.as_slice();
        if !resp_data.is_empty() {
            cap.resp_status = parse_response_status(resp_data);
            cap.resp_headers = Some(parse_response_headers(resp_data));
            let body_offset = find_body_offset(resp_data);
            if let Some(offset) = body_offset {
                if offset < resp_data.len() {
                    let body_len = (resp_data.len() - offset).min(inspect.max_body_bytes);
                    cap.resp_body = Some(Bytes::copy_from_slice(
                        &resp_data[offset..offset + body_len],
                    ));
                }
            }
            cap.resp_body_truncated = body_offset
                .map(|offset| {
                    bytes_out.saturating_sub(offset as u64) > inspect.max_body_bytes as u64
                })
                .unwrap_or(false);
        }
        cap.duration_ms = Some(start.elapsed().as_millis() as u64);
        inspect.store_capture(cap).await;
    }

    Ok(())
}

/// Bounded bytes collected for inspection while the complete stream is forwarded.
/// The extra prefix allowance keeps the complete one-megabyte body limit available
/// after typical HTTP headers while still bounding per-direction memory use.
struct CaptureBuffer {
    bytes: Vec<u8>,
    limit: usize,
}

impl CaptureBuffer {
    fn new(max_body_bytes: usize) -> Self {
        let limit = max_body_bytes.saturating_add(HEADER_CAPTURE_ALLOWANCE);
        Self {
            bytes: Vec::with_capacity(limit.min(128 * 1024)),
            limit,
        }
    }

    fn append(&mut self, data: &[u8]) {
        let remaining = self.limit.saturating_sub(self.bytes.len());
        let copied = data.len().min(remaining);
        self.bytes.extend_from_slice(&data[..copied]);
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

async fn forward_and_capture<R, W>(
    mut reader: R,
    mut writer: W,
    capture: &mut CaptureBuffer,
) -> anyhow::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut total = 0u64;
    let mut buffer = [0u8; 8192];
    loop {
        let n = reader.read(&mut buffer).await?;
        if n == 0 {
            writer.shutdown().await?;
            return Ok(total);
        }

        writer.write_all(&buffer[..n]).await?;
        capture.append(&buffer[..n]);
        total += n as u64;
    }
}

fn parse_request_for_capture(data: &[u8], max_body_bytes: usize) -> Option<CapturedRequest> {
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
            let capture_len = body_bytes.len().min(max_body_bytes);
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
        req_headers: rgrok_proto::inspect::sanitize_headers(&headers),
        req_body: body,
        req_body_truncated: false,
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
    rgrok_proto::inspect::sanitize_headers(&headers)
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
        let cap = parse_request_for_capture(req, 1_048_576).expect("should parse valid request");
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
        let cap = parse_request_for_capture(req, 1_048_576).expect("should parse POST request");
        assert_eq!(cap.req_method, "POST");
        assert_eq!(cap.req_url, "/submit");
        assert_eq!(cap.req_headers.len(), 1);
        let body = cap.req_body.expect("should have body");
        assert_eq!(&body[..], b"hello world");
    }

    #[test]
    fn parse_request_for_capture_empty_data_returns_none() {
        assert!(parse_request_for_capture(b"", 1_048_576).is_none());
    }

    #[test]
    fn parse_request_for_capture_malformed_returns_none() {
        // A single word with no whitespace means parts.next() for url returns None
        assert!(parse_request_for_capture(b"GARBAGE\r\n\r\n", 1_048_576).is_none());
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

    /// Inspection forwarding must continue reading the request while the local
    /// service waits for its complete body before producing a response.
    #[tokio::test]
    async fn test_inspection_forwards_split_headers_and_body_without_deadlock() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use tokio::sync::oneshot;
        use tokio::time::{timeout, Duration};

        let request_head_1 = b"POST /split HTTP/1.1\r\nHost: example.test\r\nContent-";
        let request_head_2 = b"Length: 11\r\n\r\n";
        let request_body = b"hello world";
        let response_head_1 = b"HTTP/1.1 201 Created\r\nContent-";
        let response_head_2 = b"Length: 4\r\nX-Test: split\r\n\r\n";
        let response_body = b"okay";
        let expected_request = [request_head_1.as_slice(), request_head_2, request_body].concat();
        let expected_response =
            [response_head_1.as_slice(), response_head_2, response_body].concat();
        let expected_response_len = expected_response.len();

        let (mut upstream, mut upstream_peer) = tokio::io::duplex(4096);
        let (mut local, mut local_peer) = tokio::io::duplex(4096);
        let (first_header_seen_tx, first_header_seen_rx) = oneshot::channel();
        let (header_seen_tx, header_seen_rx) = oneshot::channel();

        let local_task = tokio::spawn(async move {
            let mut first_head = vec![0u8; request_head_1.len()];
            local_peer.read_exact(&mut first_head).await.unwrap();
            assert_eq!(first_head, request_head_1);
            first_header_seen_tx.send(()).unwrap();

            let mut second_head = vec![0u8; request_head_2.len()];
            local_peer.read_exact(&mut second_head).await.unwrap();
            assert_eq!(second_head, request_head_2);
            header_seen_tx.send(()).unwrap();

            let mut body = vec![0u8; request_body.len()];
            local_peer.read_exact(&mut body).await.unwrap();
            assert_eq!(body, request_body);

            local_peer.write_all(response_head_1).await.unwrap();
            local_peer.write_all(response_head_2).await.unwrap();
            local_peer.write_all(response_body).await.unwrap();
        });

        let upstream_task = tokio::spawn(async move {
            upstream_peer.write_all(request_head_1).await.unwrap();
            first_header_seen_rx.await.unwrap();
            upstream_peer.write_all(request_head_2).await.unwrap();
            header_seen_rx.await.unwrap();
            upstream_peer.write_all(&request_body[..5]).await.unwrap();
            upstream_peer.write_all(&request_body[5..]).await.unwrap();

            let mut response = vec![0u8; expected_response.len()];
            upstream_peer.read_exact(&mut response).await.unwrap();
            assert_eq!(response, expected_response);
        });

        let inspect = Arc::new(InspectState::with_max_body_bytes(0, 1_048_576));
        let stats = TunnelStats::new();
        let result = timeout(
            Duration::from_secs(2),
            bridge_streams(&mut upstream, &mut local, Some(inspect.clone()), &stats),
        )
        .await;
        match result {
            Ok(result) => result.expect("inspection bridge should succeed"),
            Err(_) => {
                upstream_task.abort();
                local_task.abort();
                panic!("inspection bridge deadlocked on split request body");
            }
        }

        upstream_task.await.unwrap();
        local_task.await.unwrap();

        assert_eq!(
            stats.bytes_in.load(std::sync::atomic::Ordering::Relaxed),
            expected_request.len() as u64
        );
        assert_eq!(
            stats.bytes_out.load(std::sync::atomic::Ordering::Relaxed),
            expected_response_len as u64
        );

        let captures = inspect.captures.lock().await;
        assert_eq!(captures.len(), 1);
        let capture = captures.front().unwrap();
        assert_eq!(capture.req_method, "POST");
        assert_eq!(capture.req_url, "/split");
        assert_eq!(capture.req_body.as_deref(), Some(&request_body[..]));
        assert_eq!(capture.resp_status, Some(201));
        assert_eq!(capture.resp_body.as_deref(), Some(&response_body[..]));
        assert!(!capture.resp_body_truncated);
    }
}
