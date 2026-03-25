use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, Sse};
use axum::response::{Html, IntoResponse, Json};
use axum::routing::{delete, get, post};
use axum::Router;
use futures::stream::Stream;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tracing::info;

use rgrok_proto::inspect::CapturedRequest;

use crate::tunnel_manager::ServerState;

/// Replay result returned to the client
#[derive(serde::Serialize)]
struct ReplayResult {
    new_request_id: String,
}

const INDEX_HTML: &str = include_str!("../web/index.html");

/// Serve the web inspection UI
pub async fn serve(state: Arc<ServerState>) -> anyhow::Result<()> {
    if state.config.inspect.ui_port == 0 {
        info!("Inspection UI disabled (ui_port = 0)");
        return Ok(());
    }

    let app = Router::new()
        .route("/", get(dashboard))
        .route("/api/requests", get(list_requests))
        .route("/api/requests", delete(clear_requests))
        .route("/api/requests/{id}", get(get_request))
        .route("/api/requests/{id}/replay", post(replay_request))
        .route("/api/stream", get(event_stream))
        .route("/api/status", get(server_status))
        .with_state(state.clone());

    let bind_addr = format!(
        "{}:{}",
        state.config.inspect.ui_bind, state.config.inspect.ui_port
    );
    info!("Inspection UI listening on {}", bind_addr);

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn dashboard() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn list_requests(State(state): State<Arc<ServerState>>) -> Json<Vec<CapturedRequest>> {
    let mut all_requests: Vec<CapturedRequest> = Vec::new();

    for entry in state.captures.iter() {
        let queue = entry.value().lock().await;
        all_requests.extend(queue.iter().cloned());
    }

    all_requests.sort_by(|a, b| b.captured_at.cmp(&a.captured_at));
    Json(all_requests)
}

async fn get_request(
    State(state): State<Arc<ServerState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    for entry in state.captures.iter() {
        let queue = entry.value().lock().await;
        if let Some(req) = queue.iter().find(|r| r.id == id) {
            return Ok(Json(req.clone()));
        }
    }
    Err(StatusCode::NOT_FOUND)
}

async fn clear_requests(State(state): State<Arc<ServerState>>) -> StatusCode {
    for entry in state.captures.iter() {
        let mut queue = entry.value().lock().await;
        queue.clear();
    }
    StatusCode::NO_CONTENT
}

async fn replay_request(
    State(state): State<Arc<ServerState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // Find the captured request across all tunnel captures
    let mut found: Option<CapturedRequest> = None;
    let mut tunnel_subdomain: Option<String> = None;

    for entry in state.captures.iter() {
        let queue = entry.value().lock().await;
        if let Some(req) = queue.iter().find(|r| r.id == id) {
            found = Some(req.clone());
            tunnel_subdomain = Some(entry.key().clone());
            break;
        }
    }

    let cap = match found {
        Some(c) => c,
        None => return Err(StatusCode::NOT_FOUND),
    };

    // Look up the tunnel session to find the local port target
    // For server-side replay, we forward through the tunnel to the client's local service
    let session = match tunnel_subdomain
        .as_deref()
        .and_then(|sub| state.tunnels.get(sub))
    {
        Some(s) => s.clone(),
        None => return Err(StatusCode::BAD_GATEWAY),
    };

    // Re-issue the HTTP request through the tunnel by sending a StreamOpen
    // For simplicity, we record the replay intent and return success
    // The actual replay goes through the normal proxy path
    let client = reqwest::Client::new();
    let url = format!(
        "https://{}.{}{}",
        session.subdomain, state.config.server.domain, cap.req_url
    );
    let method: reqwest::Method = cap.req_method.parse().unwrap_or(reqwest::Method::GET);
    let mut req = client.request(method, &url);

    for (k, v) in &cap.req_headers {
        if !k.eq_ignore_ascii_case("host") {
            req = req.header(k.as_str(), v.as_str());
        }
    }
    if let Some(body) = &cap.req_body {
        req = req.body(body.clone());
    }

    match req.send().await {
        Ok(_resp) => {
            let new_id = uuid::Uuid::new_v4().to_string();
            Ok(Json(ReplayResult {
                new_request_id: new_id,
            }))
        }
        Err(e) => {
            tracing::warn!("Replay failed: {}", e);
            Err(StatusCode::BAD_GATEWAY)
        }
    }
}

async fn event_stream(
    State(state): State<Arc<ServerState>>,
) -> Sse<impl Stream<Item = Result<Event, std::convert::Infallible>>> {
    let rx = state.inspect_tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|result| match result {
        Ok(event) => {
            let data = serde_json::to_string(&event).ok()?;
            Some(Ok(Event::default().data(data)))
        }
        Err(_) => None,
    });

    Sse::new(stream)
}

async fn server_status(State(state): State<Arc<ServerState>>) -> Json<serde_json::Value> {
    let active_tunnels = state.tunnels.len();
    let tcp_tunnels = state.tcp_tunnels.len();

    Json(serde_json::json!({
        "domain": state.config.server.domain,
        "active_tunnels": active_tunnels,
        "tcp_tunnels": tcp_tunnels,
        "max_tunnels": state.config.server.max_tunnels,
    }))
}
