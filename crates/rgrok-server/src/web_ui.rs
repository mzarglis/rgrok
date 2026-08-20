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
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tracing::info;

use rgrok_proto::inspect::CapturedRequest;

use crate::auth;
use crate::tunnel_manager::ServerState;

/// Replay result returned to the client
#[derive(serde::Serialize)]
struct ReplayResult {
    new_request_id: String,
}

const INDEX_HTML: &str = include_str!("../web/index.html");

#[derive(Clone)]
struct UiSecurity {
    auth_token: Option<String>,
    csrf_token: String,
}

impl UiSecurity {
    fn new(auth_token: Option<String>) -> Self {
        Self {
            auth_token: auth_token.filter(|token| !token.trim().is_empty()),
            csrf_token: uuid::Uuid::new_v4().to_string(),
        }
    }
}

/// Serve the web inspection UI
pub async fn serve(state: Arc<ServerState>) -> anyhow::Result<()> {
    if state.config.inspect.ui_port == 0 {
        info!("Inspection UI disabled (ui_port = 0)");
        return Ok(());
    }
    if !crate::config::is_loopback_bind(&state.config.inspect.ui_bind)
        && state
            .config
            .inspect
            .ui_auth_token
            .as_deref()
            .map(str::trim)
            .filter(|token| !token.is_empty())
            .is_none()
    {
        anyhow::bail!("refusing non-loopback inspection UI without inspect.ui_auth_token");
    }

    let security = Arc::new(UiSecurity::new(state.config.inspect.ui_auth_token.clone()));
    let middleware_security = security.clone();
    let app = Router::new()
        .route("/", get(dashboard))
        .route("/api/requests", get(list_requests))
        .route("/api/requests", delete(clear_requests))
        .route("/api/requests/{id}", get(get_request))
        .route("/api/requests/{id}/replay", post(replay_request))
        .route("/api/stream", get(event_stream))
        .route("/api/status", get(server_status))
        .with_state(state.clone())
        .layer(middleware::from_fn(move |request: Request, next: Next| {
            let security = middleware_security.clone();
            async move { inspect_security(request, next, security).await }
        }));

    let bind_addr = format!(
        "{}:{}",
        state.config.inspect.ui_bind, state.config.inspect.ui_port
    );
    info!("Inspection UI listening on {}", bind_addr);

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn inspect_security(request: Request, next: Next, security: Arc<UiSecurity>) -> Response {
    if let Some(token) = security.auth_token.as_deref() {
        let authorized = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(|value| authorized_header(value, token))
            .unwrap_or(false);
        if !authorized {
            return unauthorized_response();
        }
    }

    if is_mutating(request.method()) && !csrf_header_valid(request.headers(), &security.csrf_token)
    {
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
        let cookie = format!(
            "rgrok_csrf={}; Path=/; SameSite=Strict",
            security.csrf_token
        );
        if let Ok(value) = HeaderValue::from_str(&cookie) {
            response.headers_mut().insert(header::SET_COOKIE, value);
        }
    }
    response
}

fn authorized_header(value: &str, token: &str) -> bool {
    value
        .strip_prefix("Bearer ")
        .map(|candidate| candidate == token)
        .unwrap_or(false)
        || auth::parse_basic_auth_header(value)
            .map(|(user, password)| user == "rgrok" && password == token)
            .unwrap_or(false)
}

fn unauthorized_response() -> Response {
    let mut response = StatusCode::UNAUTHORIZED.into_response();
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"rgrok inspect\""),
    );
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

pub(crate) async fn replay_request(
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

    let subdomain = tunnel_subdomain.ok_or(StatusCode::BAD_GATEWAY)?;
    let new_id = uuid::Uuid::new_v4().to_string();

    // Route directly through the normal tunnel stream path. This avoids public DNS/TLS recursion
    // and stores the completed response under the exact ID returned to the UI.
    crate::proxy::replay_http_request(state, &subdomain, &cap, new_id.clone())
        .await
        .inspect_err(|&status| {
            tracing::warn!(%status, "Replay failed through tunnel");
        })?;

    Ok(Json(ReplayResult {
        new_request_id: new_id,
    }))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_ui_auth_accepts_bearer_and_basic_credentials() {
        let token = "ui-secret";
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer ui-secret"),
        );
        assert!(authorized_header(
            headers
                .get(header::AUTHORIZATION)
                .unwrap()
                .to_str()
                .unwrap(),
            token
        ));

        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode("rgrok:ui-secret");
        assert!(authorized_header(&format!("Basic {encoded}"), token));
        assert!(!authorized_header("Bearer wrong", token));
    }

    #[test]
    fn mutations_require_csrf_header() {
        let headers = HeaderMap::new();
        assert!(!csrf_header_valid(&headers, "csrf"));
        let mut headers = HeaderMap::new();
        headers.insert("x-rgrok-csrf", HeaderValue::from_static("csrf"));
        assert!(csrf_header_valid(&headers, "csrf"));
        assert!(is_mutating(&Method::POST));
        assert!(!is_mutating(&Method::GET));
    }

    #[test]
    fn dashboard_uses_dom_apis_instead_of_unsafe_interpolation() {
        assert!(!INDEX_HTML.contains("innerHTML"));
        assert!(!INDEX_HTML.contains("onclick="));
        assert!(INDEX_HTML.contains("textContent"));
    }
}
