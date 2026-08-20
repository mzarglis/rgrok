use std::collections::VecDeque;
use std::sync::Arc;

use axum::extract::{Path, Request, State};
use axum::http::header::{self, HeaderMap, HeaderValue};
use axum::http::{Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::sse::{Event, Sse};
use axum::response::{Html, IntoResponse, Json, Response};
use axum::routing::{delete, get, post};
use axum::Router;
use futures::stream::Stream;
use tokio::sync::{broadcast, Mutex};
use tokio_stream::StreamExt;
use tracing::info;

use rgrok_proto::inspect::{CapturedRequest, InspectEvent};

const INDEX_HTML: &str = include_str!("../web/index.html");

/// Client-side inspection state
pub struct InspectState {
    pub captures: Mutex<VecDeque<CapturedRequest>>,
    pub inspect_tx: broadcast::Sender<InspectEvent>,
    pub local_port: u16,
    pub max_captures: usize,
    /// Maximum number of request/response body bytes retained per capture.
    pub max_body_bytes: usize,
    pub csrf_token: String,
}

impl InspectState {
    pub fn with_max_body_bytes(local_port: u16, max_body_bytes: usize) -> Self {
        let (inspect_tx, _) = broadcast::channel(256);
        Self {
            captures: Mutex::new(VecDeque::with_capacity(100)),
            inspect_tx,
            local_port,
            max_captures: 100,
            max_body_bytes,
            csrf_token: uuid::Uuid::new_v4().to_string(),
        }
    }

    /// Store a completed captured request
    pub async fn store_capture(&self, capture: CapturedRequest) {
        let mut capture = capture;
        capture.req_headers = rgrok_proto::inspect::sanitize_headers(&capture.req_headers);
        capture.resp_headers = capture
            .resp_headers
            .as_ref()
            .map(|headers| rgrok_proto::inspect::sanitize_headers(headers));
        let mut queue = self.captures.lock().await;
        if queue.len() >= self.max_captures {
            queue.pop_front();
        }
        let _ = self.inspect_tx.send(InspectEvent::NewRequest {
            request: Box::new(capture.clone()),
        });
        queue.push_back(capture);
    }
}

/// Serve the client-side inspection UI on the given port
pub async fn serve(state: Arc<InspectState>, port: u16) -> anyhow::Result<()> {
    let middleware_state = state.clone();
    let app = Router::new()
        .route("/", get(dashboard))
        .route("/api/requests", get(list_requests))
        .route("/api/requests", delete(clear_requests))
        .route("/api/requests/{id}", get(get_request))
        .route("/api/requests/{id}/replay", post(replay_request))
        .route("/api/stream", get(event_stream))
        .route("/api/status", get(tunnel_status))
        .with_state(state)
        .layer(middleware::from_fn(move |request: Request, next: Next| {
            let state = middleware_state.clone();
            async move { inspect_security(request, next, state).await }
        }));

    let bind_addr = format!("127.0.0.1:{}", port);
    info!("Inspection UI listening on http://{}", bind_addr);

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn inspect_security(request: Request, next: Next, state: Arc<InspectState>) -> Response {
    if is_mutating(request.method()) && !csrf_header_valid(request.headers(), &state.csrf_token) {
        return (StatusCode::FORBIDDEN, "missing or invalid CSRF token").into_response();
    }

    let has_csrf_cookie = request
        .headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(|value| cookie_value(value, "rgrok_csrf").is_some())
        .unwrap_or(false);
    let mut response = next.run(request).await;
    if !has_csrf_cookie {
        let cookie = format!("rgrok_csrf={}; Path=/; SameSite=Strict", state.csrf_token);
        if let Ok(value) = HeaderValue::from_str(&cookie) {
            response.headers_mut().insert(header::SET_COOKIE, value);
        }
    }
    response
}

fn is_mutating(method: &Method) -> bool {
    matches!(
        method,
        &Method::POST | &Method::PUT | &Method::PATCH | &Method::DELETE
    )
}

fn csrf_header_valid(headers: &HeaderMap, expected: &str) -> bool {
    headers
        .get("x-rgrok-csrf")
        .and_then(|value| value.to_str().ok())
        .map(|value| value == expected)
        .unwrap_or(false)
}

fn cookie_value<'a>(cookies: &'a str, name: &str) -> Option<&'a str> {
    cookies.split(';').find_map(|part| {
        let (key, value) = part.trim().split_once('=')?;
        (key == name).then_some(value)
    })
}

async fn dashboard() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn list_requests(State(state): State<Arc<InspectState>>) -> Json<Vec<CapturedRequest>> {
    let queue = state.captures.lock().await;
    let mut requests: Vec<CapturedRequest> = queue.iter().cloned().collect();
    requests.sort_by(|a, b| b.captured_at.cmp(&a.captured_at));
    Json(requests)
}

async fn get_request(
    State(state): State<Arc<InspectState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let queue = state.captures.lock().await;
    if let Some(req) = queue.iter().find(|r| r.id == id) {
        Ok(Json(req.clone()))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn clear_requests(State(state): State<Arc<InspectState>>) -> StatusCode {
    let mut queue = state.captures.lock().await;
    queue.clear();
    StatusCode::NO_CONTENT
}

async fn replay_request(
    State(state): State<Arc<InspectState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let queue = state.captures.lock().await;
    let cap = match queue.iter().find(|r| r.id == id) {
        Some(c) => c.clone(),
        None => return Err(StatusCode::NOT_FOUND),
    };
    drop(queue);

    // Re-issue the HTTP request to the local port
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}{}", state.local_port, cap.req_url);
    let method: reqwest::Method = cap.req_method.parse().unwrap_or(reqwest::Method::GET);
    let mut req = client.request(method, &url);

    for (k, v) in rgrok_proto::inspect::sanitize_headers(&cap.req_headers) {
        // Skip host header since we're replaying locally
        if !k.eq_ignore_ascii_case("host") {
            req = req.header(k, v);
        }
    }
    if let Some(body) = &cap.req_body {
        req = req.body(body.clone());
    }

    let start = std::time::Instant::now();
    match req.send().await {
        Ok(resp) => {
            let duration_ms = start.elapsed().as_millis() as u64;
            let resp_status = resp.status().as_u16();
            let resp_headers: Vec<(String, String)> = resp
                .headers()
                .iter()
                .filter_map(|(k, v)| v.to_str().ok().map(|vs| (k.to_string(), vs.to_string())))
                .collect();
            let resp_body_bytes = resp.bytes().await.ok();
            let (resp_body, resp_body_truncated) = resp_body_bytes
                .as_deref()
                .map(|body| capture_body(body, state.max_body_bytes))
                .unwrap_or((None, false));

            let new_id = uuid::Uuid::new_v4().to_string();
            let replay_capture = rgrok_proto::inspect::CapturedRequest {
                id: new_id.clone(),
                captured_at: chrono::Utc::now(),
                duration_ms: Some(duration_ms),
                tunnel_id: String::new(),
                req_method: cap.req_method.clone(),
                req_url: cap.req_url.clone(),
                req_headers: cap.req_headers.clone(),
                req_body: cap.req_body.clone(),
                resp_status: Some(resp_status),
                resp_headers: Some(resp_headers),
                resp_body,
                resp_body_truncated,
                remote_addr: "replay".to_string(),
                tls_version: None,
            };
            state.store_capture(replay_capture).await;

            Ok(Json(serde_json::json!({ "new_request_id": new_id })))
        }
        Err(e) => {
            tracing::warn!("Replay failed: {}", e);
            Err(StatusCode::BAD_GATEWAY)
        }
    }
}

fn capture_body(body: &[u8], max_body_bytes: usize) -> (Option<bytes::Bytes>, bool) {
    let truncated = body.len() > max_body_bytes;
    let captured = (!body.is_empty() && max_body_bytes > 0)
        .then(|| bytes::Bytes::copy_from_slice(&body[..body.len().min(max_body_bytes)]));
    (captured, truncated)
}

async fn event_stream(
    State(state): State<Arc<InspectState>>,
) -> Sse<impl Stream<Item = Result<Event, std::convert::Infallible>>> {
    let rx = state.inspect_tx.subscribe();
    let stream =
        tokio_stream::wrappers::BroadcastStream::new(rx).filter_map(|result| match result {
            Ok(event) => {
                let data = serde_json::to_string(&event).ok()?;
                Some(Ok(Event::default().data(data)))
            }
            Err(_) => None,
        });

    Sse::new(stream)
}

async fn tunnel_status(State(state): State<Arc<InspectState>>) -> Json<serde_json::Value> {
    let count = state.captures.lock().await.len();
    Json(serde_json::json!({
        "local_port": state.local_port,
        "captured_requests": count,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Replay Mechanism: replaying a captured request correctly re-issues it to the local
    /// port and stores the result as a new capture.
    #[tokio::test]
    async fn test_replay_reissues_request_to_local_service() {
        // Start a mock local service
        let mock_app = Router::new().route("/api/test", get(|| async { "replayed response" }));
        let mock_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mock_port = mock_listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(mock_listener, mock_app).await.unwrap();
        });

        // Create inspect state pointing to the mock service
        let state = Arc::new(InspectState::with_max_body_bytes(mock_port, 1_048_576));

        // Store a captured request to replay
        let capture = CapturedRequest {
            id: "cap-replay-1".to_string(),
            captured_at: chrono::Utc::now(),
            duration_ms: Some(50),
            tunnel_id: "tunnel-1".to_string(),
            req_method: "GET".to_string(),
            req_url: "/api/test".to_string(),
            req_headers: vec![("Accept".to_string(), "text/plain".to_string())],
            req_body: None,
            resp_status: Some(200),
            resp_headers: None,
            resp_body: None,
            resp_body_truncated: false,
            remote_addr: "1.2.3.4:5678".to_string(),
            tls_version: None,
        };
        state.store_capture(capture).await;

        // Start a minimal inspection server with just the replay route
        let inspect_app = Router::new()
            .route("/api/requests/{id}/replay", post(replay_request))
            .with_state(state.clone());
        let inspect_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let inspect_port = inspect_listener.local_addr().unwrap().port();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let _ = ready_tx.send(());
            axum::serve(inspect_listener, inspect_app).await.unwrap();
        });
        ready_rx.await.expect("inspect server failed to start");

        // Call the replay endpoint
        let client = reqwest::Client::new();
        let resp = client
            .post(format!(
                "http://127.0.0.1:{}/api/requests/cap-replay-1/replay",
                inspect_port
            ))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(
            body.get("new_request_id").is_some(),
            "Should return new request ID"
        );

        // Verify the replayed request was stored
        let captures = state.captures.lock().await;
        assert_eq!(captures.len(), 2, "Should have original + replayed request");
        let replayed = captures.back().unwrap();
        assert_eq!(replayed.req_method, "GET");
        assert_eq!(replayed.req_url, "/api/test");
        assert_eq!(replayed.remote_addr, "replay");
        assert!(replayed.resp_status.is_some());
    }

    #[tokio::test]
    async fn test_replay_nonexistent_request_returns_404() {
        let state = Arc::new(InspectState::with_max_body_bytes(9999, 1_048_576));

        let app = Router::new()
            .route("/api/requests/{id}/replay", post(replay_request))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let _ = ready_tx.send(());
            axum::serve(listener, app).await.unwrap();
        });
        ready_rx.await.expect("server failed to start");

        let client = reqwest::Client::new();
        let resp = client
            .post(format!(
                "http://127.0.0.1:{}/api/requests/nonexistent/replay",
                port
            ))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 404);
    }

    #[test]
    fn mutations_require_csrf_header() {
        let headers = HeaderMap::new();
        assert!(!csrf_header_valid(&headers, "csrf"));
        let mut headers = HeaderMap::new();
        headers.insert("x-rgrok-csrf", HeaderValue::from_static("csrf"));
        assert!(csrf_header_valid(&headers, "csrf"));
        assert!(is_mutating(&Method::DELETE));
        assert!(!is_mutating(&Method::GET));
    }

    #[test]
    fn dashboard_uses_dom_apis_instead_of_unsafe_interpolation() {
        assert!(!INDEX_HTML.contains("innerHTML"));
        assert!(!INDEX_HTML.contains("onclick="));
        assert!(INDEX_HTML.contains("textContent"));
    }
}
