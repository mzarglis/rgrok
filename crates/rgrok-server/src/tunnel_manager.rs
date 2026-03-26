use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;
use tokio::sync::{broadcast, mpsc, oneshot, Mutex, RwLock};
use tokio_util::sync::CancellationToken;

use rgrok_proto::inspect::{CapturedRequest, InspectEvent};
use rgrok_proto::messages::{BasicAuthConfig, ServerMsg, TunnelOptions, TunnelType};

use crate::config::Config;

/// Shared server state accessible from all handlers
pub struct ServerState {
    pub config: Config,
    /// Map from subdomain -> active tunnel
    pub tunnels: DashMap<String, Arc<TunnelSession>>,
    /// Map from TCP port -> active tunnel
    pub tcp_tunnels: DashMap<u16, Arc<TunnelSession>>,
    /// Inspection capture ring-buffer per tunnel (last N requests)
    pub captures: DashMap<String, Arc<Mutex<VecDeque<CapturedRequest>>>>,
    /// Broadcast channel for web UI live updates
    pub inspect_tx: broadcast::Sender<InspectEvent>,
    /// Cancellation token for graceful shutdown
    pub cancel: CancellationToken,
    /// Blocklist of revoked JWT IDs (jti) — reloadable via SIGHUP
    pub revoked_jtis: RwLock<HashSet<String>>,
    /// Prometheus metrics
    pub metrics: Arc<crate::metrics::Metrics>,
    /// Hot-reloadable TLS config (watched by proxy listeners)
    pub tls_config: tokio::sync::watch::Sender<Option<Arc<rustls::ServerConfig>>>,
    #[allow(dead_code)]
    pub tls_config_rx: tokio::sync::watch::Receiver<Option<Arc<rustls::ServerConfig>>>,
    /// Notify when a tunnel is unregistered (useful for tests)
    pub cleanup_notify: Arc<tokio::sync::Notify>,
}

impl ServerState {
    pub fn new(config: Config) -> Self {
        let (inspect_tx, _) = broadcast::channel(256);
        let revoked: HashSet<String> = config.auth.revoked_jtis.iter().cloned().collect();
        let (tls_tx, tls_rx) = tokio::sync::watch::channel(None);
        Self {
            config,
            tunnels: DashMap::new(),
            tcp_tunnels: DashMap::new(),
            captures: DashMap::new(),
            inspect_tx,
            cancel: CancellationToken::new(),
            revoked_jtis: RwLock::new(revoked),
            metrics: Arc::new(crate::metrics::Metrics::new()),
            tls_config: tls_tx,
            tls_config_rx: tls_rx,
            cleanup_notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Check if a JWT ID has been revoked
    pub async fn is_jti_revoked(&self, jti: &str) -> bool {
        self.revoked_jtis.read().await.contains(jti)
    }

    /// Reload the jti blocklist from a new config
    #[allow(dead_code)]
    pub async fn reload_revoked_jtis(&self, jtis: &[String]) {
        let mut blocklist = self.revoked_jtis.write().await;
        blocklist.clear();
        blocklist.extend(jtis.iter().cloned());
    }

    /// Register a new tunnel, returning the assigned subdomain
    pub fn register_tunnel(
        &self,
        session: Arc<TunnelSession>,
    ) -> Result<(), rgrok_proto::TunnelError> {
        if self.tunnels.len() >= self.config.server.max_tunnels {
            return Err(rgrok_proto::TunnelError::SubdomainTaken {
                subdomain: "max tunnels reached".to_string(),
            });
        }

        let subdomain = session.subdomain.clone();
        if self.tunnels.contains_key(&subdomain) {
            return Err(rgrok_proto::TunnelError::SubdomainTaken { subdomain });
        }

        self.tunnels.insert(subdomain.clone(), session);
        self.metrics.active_tunnels.inc();
        self.captures.insert(
            subdomain,
            Arc::new(Mutex::new(VecDeque::with_capacity(
                self.config.inspect.buffer_size,
            ))),
        );
        Ok(())
    }

    /// Unregister a tunnel by subdomain
    pub fn unregister_tunnel(&self, subdomain: &str) {
        self.tunnels.remove(subdomain);
        self.captures.remove(subdomain);
        self.metrics.active_tunnels.dec();
        self.cleanup_notify.notify_waiters();
    }

    /// Allocate a TCP port from the configured range
    pub fn allocate_tcp_port(&self) -> Option<u16> {
        let [start, end] = self.config.server.tcp_port_range;
        (start..end).find(|&port| !self.tcp_tunnels.contains_key(&port))
    }

    /// Register a TCP tunnel on a specific port
    pub fn register_tcp_tunnel(&self, port: u16, session: Arc<TunnelSession>) {
        self.tcp_tunnels.insert(port, session);
    }

    /// Unregister a TCP tunnel
    pub fn unregister_tcp_tunnel(&self, port: u16) {
        self.tcp_tunnels.remove(&port);
        self.cleanup_notify.notify_waiters();
    }

    /// Store a captured request for inspection
    pub async fn store_capture(&self, subdomain: &str, capture: CapturedRequest) {
        if let Some(captures) = self.captures.get(subdomain) {
            let mut queue = captures.lock().await;
            if queue.len() >= self.config.inspect.buffer_size {
                queue.pop_front();
            }
            let _ = self.inspect_tx.send(InspectEvent::NewRequest {
                request: Box::new(capture.clone()),
            });
            queue.push_back(capture);
        }
    }
}

/// Represents an active tunnel session from a connected client
pub struct TunnelSession {
    pub id: String,
    #[allow(dead_code)]
    pub tunnel_type: TunnelType,
    pub subdomain: String,
    pub basic_auth: Option<BasicAuthConfig>,
    pub basic_auth_hash: Option<String>,
    pub options: TunnelOptions,
    #[allow(dead_code)]
    pub created_at: Instant,
    /// Sink to send messages to the connected client
    pub control_tx: mpsc::Sender<ServerMsg>,
    /// Next correlation ID (atomic counter)
    pub next_correlation_id: AtomicU32,
    /// Open yamux streams awaiting client: correlation_id -> oneshot sender for yamux::Stream
    pub pending_streams: DashMap<u32, oneshot::Sender<yamux::Stream>>,
    /// Cached last successful Authorization header value (fast-path to skip bcrypt)
    pub cached_auth_header: Mutex<Option<String>>,
}

impl TunnelSession {
    pub fn next_correlation_id(&self) -> u32 {
        self.next_correlation_id.fetch_add(1, Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use rgrok_proto::messages::TunnelType;

    fn make_test_config(buffer_size: usize) -> Config {
        let mut config = Config::default();
        config.inspect.buffer_size = buffer_size;
        config
    }

    fn make_captured_request(id: &str) -> CapturedRequest {
        CapturedRequest {
            id: id.to_string(),
            captured_at: Utc::now(),
            duration_ms: Some(10),
            tunnel_id: "test-tunnel".to_string(),
            req_method: "GET".to_string(),
            req_url: format!("http://example.com/{}", id),
            req_headers: vec![],
            req_body: None,
            resp_status: Some(200),
            resp_headers: None,
            resp_body: None,
            resp_body_truncated: false,
            remote_addr: "127.0.0.1:1234".to_string(),
            tls_version: None,
        }
    }

    fn make_tunnel_session(subdomain: &str) -> Arc<TunnelSession> {
        let (tx, _rx) = mpsc::channel(1);
        Arc::new(TunnelSession {
            id: "test-id".to_string(),
            tunnel_type: TunnelType::Http,
            subdomain: subdomain.to_string(),
            basic_auth: None,
            basic_auth_hash: None,
            options: TunnelOptions::default(),
            created_at: Instant::now(),
            control_tx: tx,
            next_correlation_id: AtomicU32::new(0),
            pending_streams: DashMap::new(),
            cached_auth_header: Mutex::new(None),
        })
    }

    #[tokio::test]
    async fn test_store_capture_enforces_max_buffer_size() {
        let buffer_size = 100;
        let state = ServerState::new(make_test_config(buffer_size));

        // Register a tunnel so captures map has an entry
        let session = make_tunnel_session("test-sub");
        state.register_tunnel(session).unwrap();

        // Insert buffer_size + 1 items
        for i in 0..=buffer_size {
            let capture = make_captured_request(&format!("req-{}", i));
            state.store_capture("test-sub", capture).await;
        }

        // Verify only buffer_size items remain
        let captures = state.captures.get("test-sub").unwrap();
        let queue = captures.lock().await;
        assert_eq!(
            queue.len(),
            buffer_size,
            "buffer should contain exactly {} items, got {}",
            buffer_size,
            queue.len()
        );

        // The oldest item (req-0) should have been evicted; first item should be req-1
        assert_eq!(queue.front().unwrap().id, "req-1");
        assert_eq!(queue.back().unwrap().id, format!("req-{}", buffer_size));
    }

    #[tokio::test]
    async fn test_store_capture_ignores_unknown_subdomain() {
        let state = ServerState::new(make_test_config(10));
        // No tunnel registered — store_capture should silently do nothing
        let capture = make_captured_request("orphan");
        state.store_capture("nonexistent", capture).await;
        assert!(state.captures.get("nonexistent").is_none());
    }

    /// Helper that creates a Config with a custom tcp_port_range and buffer_size.
    fn make_test_config_with_ports(buffer_size: usize, tcp_port_range: [u16; 2]) -> Config {
        let mut config = make_test_config(buffer_size);
        config.server.tcp_port_range = tcp_port_range;
        config
    }

    #[test]
    fn test_allocate_tcp_port_returns_first_available() {
        let state = ServerState::new(make_test_config_with_ports(10, [10000, 10003]));
        let port = state.allocate_tcp_port();
        assert_eq!(port, Some(10000));
    }

    #[test]
    fn test_allocate_tcp_port_skips_occupied() {
        let state = ServerState::new(make_test_config_with_ports(10, [10000, 10003]));
        // Occupy port 10000
        let session = make_tunnel_session("tcp-tunnel");
        state.register_tcp_tunnel(10000, session);
        let port = state.allocate_tcp_port();
        assert_eq!(port, Some(10001));
    }

    #[test]
    fn test_allocate_tcp_port_exhaustion() {
        let state = ServerState::new(make_test_config_with_ports(10, [10000, 10002]));
        // Occupy both ports in the range
        state.register_tcp_tunnel(10000, make_tunnel_session("tcp-a"));
        state.register_tcp_tunnel(10001, make_tunnel_session("tcp-b"));
        let port = state.allocate_tcp_port();
        assert_eq!(port, None);
    }

    #[test]
    fn test_unregister_tcp_tunnel_frees_port() {
        let state = ServerState::new(make_test_config_with_ports(10, [10000, 10003]));
        let session = make_tunnel_session("tcp-tunnel");
        state.register_tcp_tunnel(10000, session);
        // Port 10000 is occupied, so next allocation gives 10001
        assert_eq!(state.allocate_tcp_port(), Some(10001));
        // Free port 10000
        state.unregister_tcp_tunnel(10000);
        // Now 10000 should be available again
        assert_eq!(state.allocate_tcp_port(), Some(10000));
    }

    #[test]
    fn test_register_tunnel_max_tunnels() {
        let mut config = make_test_config(10);
        config.server.max_tunnels = 2;
        let state = ServerState::new(config);

        // Register 2 tunnels successfully
        state.register_tunnel(make_tunnel_session("sub-a")).unwrap();
        state.register_tunnel(make_tunnel_session("sub-b")).unwrap();

        // 3rd should fail
        let result = state.register_tunnel(make_tunnel_session("sub-c"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            rgrok_proto::TunnelError::SubdomainTaken { subdomain } => {
                assert_eq!(subdomain, "max tunnels reached");
            }
            other => panic!("expected SubdomainTaken error, got: {:?}", other),
        }
    }

    #[test]
    fn test_unregister_tunnel_decrements_metrics() {
        let state = ServerState::new(make_test_config(10));
        state
            .register_tunnel(make_tunnel_session("metrics-test"))
            .unwrap();
        assert_eq!(state.metrics.active_tunnels.get(), 1);
        state.unregister_tunnel("metrics-test");
        assert_eq!(state.metrics.active_tunnels.get(), 0);
    }
}
