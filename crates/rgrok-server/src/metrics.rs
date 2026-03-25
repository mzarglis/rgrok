use std::sync::Arc;

use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, Opts, Registry,
    TextEncoder,
};
use tracing::info;

/// Server-wide metrics collection
pub struct Metrics {
    pub registry: Registry,
    pub active_tunnels: IntGauge,
    pub requests_total: IntCounterVec,
    pub request_duration_ms: HistogramVec,
    pub bytes_in_total: IntCounter,
    pub bytes_out_total: IntCounter,
    pub ws_connections_active: IntGauge,
    pub tunnel_errors_total: IntCounterVec,
}

impl Metrics {
    pub fn new() -> Self {
        let registry = Registry::new();

        let active_tunnels = IntGauge::new("rgrok_active_tunnels", "Number of active tunnels")
            .expect("metric creation failed");
        registry.register(Box::new(active_tunnels.clone())).unwrap();

        let requests_total = IntCounterVec::new(
            Opts::new("rgrok_requests_total", "Total proxied requests by status"),
            &["status"],
        )
        .expect("metric creation failed");
        registry.register(Box::new(requests_total.clone())).unwrap();

        let request_duration_ms = HistogramVec::new(
            HistogramOpts::new("rgrok_request_duration_ms", "Request duration in milliseconds")
                .buckets(vec![5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0]),
            &["method"],
        )
        .expect("metric creation failed");
        registry
            .register(Box::new(request_duration_ms.clone()))
            .unwrap();

        let bytes_in_total =
            IntCounter::new("rgrok_bytes_in_total", "Total bytes received from clients")
                .expect("metric creation failed");
        registry.register(Box::new(bytes_in_total.clone())).unwrap();

        let bytes_out_total =
            IntCounter::new("rgrok_bytes_out_total", "Total bytes sent to clients")
                .expect("metric creation failed");
        registry
            .register(Box::new(bytes_out_total.clone()))
            .unwrap();

        let ws_connections_active = IntGauge::new(
            "rgrok_ws_connections_active",
            "Active WebSocket control connections",
        )
        .expect("metric creation failed");
        registry
            .register(Box::new(ws_connections_active.clone()))
            .unwrap();

        let tunnel_errors_total = IntCounterVec::new(
            Opts::new("rgrok_tunnel_errors_total", "Total tunnel errors by kind"),
            &["kind"],
        )
        .expect("metric creation failed");
        registry
            .register(Box::new(tunnel_errors_total.clone()))
            .unwrap();

        Self {
            registry,
            active_tunnels,
            requests_total,
            request_duration_ms,
            bytes_in_total,
            bytes_out_total,
            ws_connections_active,
            tunnel_errors_total,
        }
    }
}

/// Serve the /metrics endpoint on the given port
pub async fn serve(metrics: Arc<Metrics>, port: u16) -> anyhow::Result<()> {
    if port == 0 {
        info!("Metrics endpoint disabled (port = 0)");
        return Ok(());
    }

    let app = Router::new()
        .route("/metrics", get(metrics_handler))
        .with_state(metrics);

    let bind_addr = format!("127.0.0.1:{}", port);
    info!("Metrics endpoint listening on http://{}/metrics", bind_addr);

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn metrics_handler(
    axum::extract::State(metrics): axum::extract::State<Arc<Metrics>>,
) -> impl IntoResponse {
    let encoder = TextEncoder::new();
    let metric_families = metrics.registry.gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        buffer,
    )
}
