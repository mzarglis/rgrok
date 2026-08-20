use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::sync::{broadcast, mpsc, oneshot, Mutex, RwLock, Semaphore};
use tokio_util::sync::CancellationToken;

use rgrok_proto::inspect::{CapturedRequest, InspectEvent};
use rgrok_proto::messages::{ServerMsg, TunnelOptions, TunnelType};

use crate::auth::BasicAuthVerifier;
use crate::config::Config;
use crate::dns::CloudflareClient;

#[derive(Debug, Hash, PartialEq, Eq)]
enum ReservationKey {
    Http(String),
    Tcp(u16),
}

fn max_tunnels_error(max: usize) -> rgrok_proto::TunnelError {
    rgrok_proto::TunnelError::CapacityExceeded { max }
}

/// Shared server state accessible from all handlers
pub struct ServerState {
    pub config: Config,
    /// Map from subdomain -> active tunnel
    pub tunnels: DashMap<String, Arc<TunnelSession>>,
    /// Map from TCP port -> active tunnel
    pub tcp_tunnels: DashMap<u16, Arc<TunnelSession>>,
    /// Registration reservations held while a tunnel is being prepared.
    ///
    /// This mutex covers both tunnel maps' capacity decisions. A reservation
    /// is made before any asynchronous preparation (for example, password
    /// hashing or TCP listener setup), so max_tunnels cannot be exceeded by
    /// concurrent requests.
    reservations: StdMutex<HashMap<ReservationKey, String>>,
    /// Inspection capture ring-buffer per tunnel (last N requests)
    pub captures: DashMap<String, Arc<Mutex<VecDeque<CapturedRequest>>>>,
    /// Broadcast channel for web UI live updates
    pub inspect_tx: broadcast::Sender<InspectEvent>,
    /// Cancellation token for graceful shutdown
    pub cancel: CancellationToken,
    /// Blocklist of revoked JWT IDs (jti) — reloadable via SIGHUP
    pub revoked_jtis: RwLock<HashSet<String>>,
    /// Monotonic generation incremented whenever the revocation list reloads.
    pub revocation_epoch: tokio::sync::watch::Sender<u64>,
    /// Prometheus metrics
    pub metrics: Arc<crate::metrics::Metrics>,
    /// Bounded bcrypt verifier shared by public HTTP handlers.
    pub basic_auth_verifier: BasicAuthVerifier,
    /// Limits how many public request bodies can be buffered concurrently.
    pub request_body_slots: Arc<Semaphore>,
    /// Hot-reloadable TLS config (watched by proxy listeners)
    pub tls_config: tokio::sync::watch::Sender<Option<Arc<rustls::ServerConfig>>>,
    #[allow(dead_code)]
    pub tls_config_rx: tokio::sync::watch::Receiver<Option<Arc<rustls::ServerConfig>>>,
    /// Notify when a tunnel is unregistered (useful for tests)
    pub cleanup_notify: Arc<tokio::sync::Notify>,
    /// Cloudflare client used for optional per-tunnel DNS records.
    pub dns_client: Option<Arc<CloudflareClient>>,
}

impl ServerState {
    pub fn new(config: Config) -> Self {
        let (inspect_tx, _) = broadcast::channel(256);
        let revoked: HashSet<String> = config.auth.revoked_jtis.iter().cloned().collect();
        let (tls_tx, tls_rx) = tokio::sync::watch::channel(None);
        let (revocation_epoch, _) = tokio::sync::watch::channel(0);
        let dns_client = config.cloudflare.per_tunnel_dns.then(|| {
            Arc::new(CloudflareClient::new(
                config.cloudflare.api_token.clone(),
                config.cloudflare.zone_id.clone(),
            ))
        });
        Self {
            config,
            tunnels: DashMap::new(),
            tcp_tunnels: DashMap::new(),
            reservations: StdMutex::new(HashMap::new()),
            captures: DashMap::new(),
            inspect_tx,
            cancel: CancellationToken::new(),
            revoked_jtis: RwLock::new(revoked),
            revocation_epoch,
            metrics: Arc::new(crate::metrics::Metrics::new()),
            basic_auth_verifier: BasicAuthVerifier::default(),
            request_body_slots: Arc::new(Semaphore::new(4)),
            tls_config: tls_tx,
            tls_config_rx: tls_rx,
            cleanup_notify: Arc::new(tokio::sync::Notify::new()),
            dns_client,
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
        self.revocation_epoch.send_modify(|epoch| *epoch += 1);
    }

    /// Register a new tunnel, returning the assigned subdomain
    pub fn register_tunnel(
        &self,
        session: Arc<TunnelSession>,
    ) -> Result<(), rgrok_proto::TunnelError> {
        let subdomain = session.subdomain.clone();
        let key = ReservationKey::Http(subdomain.clone());
        let mut reservations = self.lock_reservations();

        let owns_reservation = reservations
            .get(&key)
            .is_some_and(|owner| owner == &session.id);
        if reservations.contains_key(&key) && !owns_reservation {
            return Err(rgrok_proto::TunnelError::SubdomainTaken { subdomain });
        }
        if self.tunnels.contains_key(&subdomain) {
            return Err(rgrok_proto::TunnelError::SubdomainTaken { subdomain });
        }
        if !owns_reservation && self.at_capacity(&reservations) {
            return Err(max_tunnels_error(self.config.server.max_tunnels));
        }

        // Entry::Vacant makes this invariant explicit even if a future caller
        // bypasses the registration gate.
        use dashmap::mapref::entry::Entry;
        match self.tunnels.entry(subdomain.clone()) {
            Entry::Occupied(_) => Err(rgrok_proto::TunnelError::SubdomainTaken { subdomain }),
            Entry::Vacant(entry) => {
                entry.insert(session);
                if owns_reservation {
                    reservations.remove(&key);
                }
                self.metrics.active_tunnels.inc();
                self.captures.insert(
                    subdomain,
                    Arc::new(Mutex::new(VecDeque::with_capacity(
                        self.config.inspect.buffer_size,
                    ))),
                );
                Ok(())
            }
        }
    }

    /// Reserve an HTTP subdomain before doing asynchronous tunnel setup.
    pub fn reserve_http_tunnel(
        &self,
        subdomain: &str,
        owner: &str,
    ) -> Result<(), rgrok_proto::TunnelError> {
        let key = ReservationKey::Http(subdomain.to_string());
        let mut reservations = self.lock_reservations();
        if self.tunnels.contains_key(subdomain) || reservations.contains_key(&key) {
            return Err(rgrok_proto::TunnelError::SubdomainTaken {
                subdomain: subdomain.to_string(),
            });
        }
        if self.at_capacity(&reservations) {
            return Err(max_tunnels_error(self.config.server.max_tunnels));
        }
        reservations.insert(key, owner.to_string());
        Ok(())
    }

    /// Release an HTTP reservation after tunnel setup fails.
    pub fn release_http_tunnel(&self, subdomain: &str, owner: &str) {
        let mut reservations = self.lock_reservations();
        let key = ReservationKey::Http(subdomain.to_string());
        if reservations
            .get(&key)
            .is_some_and(|current| current == owner)
        {
            reservations.remove(&key);
        }
    }

    /// Unregister a tunnel by subdomain
    #[allow(dead_code)]
    pub fn unregister_tunnel(&self, subdomain: &str) -> Option<Arc<TunnelSession>> {
        self.remove_tunnel_if_owner(subdomain, None)
    }

    /// Unregister an HTTP tunnel only if it is still owned by `session`.
    ///
    /// A disconnected older session can otherwise remove a newer tunnel that
    /// has reused the same name after the old entry was removed.
    pub fn unregister_tunnel_if_owner(
        &self,
        subdomain: &str,
        session: &Arc<TunnelSession>,
    ) -> Option<Arc<TunnelSession>> {
        self.remove_tunnel_if_owner(subdomain, Some(session))
    }

    fn remove_tunnel_if_owner(
        &self,
        subdomain: &str,
        owner: Option<&Arc<TunnelSession>>,
    ) -> Option<Arc<TunnelSession>> {
        let _reservations = self.lock_reservations();
        let current = self
            .tunnels
            .get(subdomain)
            .map(|current| current.value().clone());
        let should_remove = current
            .as_ref()
            .is_some_and(|current| owner.is_none_or(|owner| Arc::ptr_eq(current, owner)));
        if !should_remove {
            return None;
        }
        let removed = self.tunnels.remove(subdomain).map(|(_, tunnel)| tunnel);
        if let Some(tunnel) = &removed {
            tunnel.idle_cancel.cancel();
            self.captures.remove(subdomain);
            self.metrics.active_tunnels.dec();
            self.cleanup_notify.notify_waiters();
        }
        removed
    }

    /// Allocate a TCP port from the configured range
    #[allow(dead_code)]
    pub fn allocate_tcp_port(&self) -> Option<u16> {
        let [start, end] = self.config.server.tcp_port_range;
        let reservations = self.lock_reservations();
        (start..end).find(|&port| {
            !self.tcp_tunnels.contains_key(&port)
                && !reservations.contains_key(&ReservationKey::Tcp(port))
        })
    }

    /// Reserve a TCP port and one slot in max_tunnels atomically.
    pub fn reserve_tcp_port(
        &self,
        requested: Option<u16>,
        owner: &str,
    ) -> Result<u16, rgrok_proto::TunnelError> {
        let [start, end] = self.config.server.tcp_port_range;
        let mut reservations = self.lock_reservations();
        let port = match requested {
            Some(port) if !(start..end).contains(&port) => {
                return Err(rgrok_proto::TunnelError::TcpPortOutOfRange { port, start, end });
            }
            Some(port) => port,
            None => (start..end)
                .find(|port| {
                    !self.tcp_tunnels.contains_key(port)
                        && !reservations.contains_key(&ReservationKey::Tcp(*port))
                })
                .ok_or(rgrok_proto::TunnelError::NoPortsAvailable { start, end })?,
        };
        let key = ReservationKey::Tcp(port);
        if self.tcp_tunnels.contains_key(&port) || reservations.contains_key(&key) {
            return Err(rgrok_proto::TunnelError::TcpPortTaken { port });
        }
        if self.at_capacity(&reservations) {
            return Err(max_tunnels_error(self.config.server.max_tunnels));
        }
        reservations.insert(key, owner.to_string());
        Ok(port)
    }

    /// Release a TCP port reservation after setup fails.
    pub fn release_tcp_port_reservation(&self, port: u16, owner: &str) {
        let mut reservations = self.lock_reservations();
        let key = ReservationKey::Tcp(port);
        if reservations
            .get(&key)
            .is_some_and(|current| current == owner)
        {
            reservations.remove(&key);
        }
    }

    /// Register a TCP tunnel on a specific port
    #[allow(dead_code)] // Kept for direct state/test callers; production binds before publish.
    pub fn register_tcp_tunnel(&self, port: u16, session: Arc<TunnelSession>) -> bool {
        self.try_register_tcp_tunnel(port, session).is_ok()
    }

    /// Publish a TCP tunnel, consuming its reservation when present.
    pub fn try_register_tcp_tunnel(
        &self,
        port: u16,
        session: Arc<TunnelSession>,
    ) -> Result<(), rgrok_proto::TunnelError> {
        let [start, end] = self.config.server.tcp_port_range;
        if !(start..end).contains(&port) {
            return Err(rgrok_proto::TunnelError::TcpPortOutOfRange { port, start, end });
        }
        let mut reservations = self.lock_reservations();
        let key = ReservationKey::Tcp(port);
        let owns_reservation = reservations
            .get(&key)
            .is_some_and(|owner| owner == &session.id);
        if reservations.contains_key(&key) && !owns_reservation {
            return Err(rgrok_proto::TunnelError::TcpPortTaken { port });
        }
        if self.tcp_tunnels.contains_key(&port) {
            return Err(rgrok_proto::TunnelError::TcpPortTaken { port });
        }
        if !owns_reservation && self.at_capacity(&reservations) {
            return Err(max_tunnels_error(self.config.server.max_tunnels));
        }
        use dashmap::mapref::entry::Entry;
        match self.tcp_tunnels.entry(port) {
            Entry::Occupied(_) => Err(rgrok_proto::TunnelError::TcpPortTaken { port }),
            Entry::Vacant(entry) => {
                entry.insert(session);
                if owns_reservation {
                    reservations.remove(&key);
                }
                self.metrics.active_tunnels.inc();
                Ok(())
            }
        }
    }

    /// Unregister a TCP tunnel
    #[allow(dead_code)]
    pub fn unregister_tcp_tunnel(&self, port: u16) {
        let _ = self.remove_tcp_tunnel(port);
    }

    /// Remove a TCP tunnel and return its session, if present.
    #[allow(dead_code)]
    pub fn remove_tcp_tunnel(&self, port: u16) -> Option<Arc<TunnelSession>> {
        let _reservations = self.lock_reservations();
        let removed = self.tcp_tunnels.remove(&port).map(|(_, tunnel)| tunnel);
        if let Some(tunnel) = &removed {
            tunnel.cancel.cancel();
            tunnel.idle_cancel.cancel();
            self.metrics.active_tunnels.dec();
            self.cleanup_notify.notify_waiters();
        }
        removed
    }

    /// Remove a TCP tunnel only if it is still owned by `session`.
    ///
    /// The port remains reserved while its listener shuts down. The cleanup
    /// caller releases that reservation only after observing listener
    /// completion, preventing a new registration from racing a still-bound
    /// socket.
    pub fn remove_tcp_tunnel_if_owner(
        &self,
        port: u16,
        session: &Arc<TunnelSession>,
    ) -> Option<Arc<TunnelSession>> {
        let mut reservations = self.lock_reservations();
        let current = self
            .tcp_tunnels
            .get(&port)
            .map(|current| current.value().clone());
        let should_remove = current
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, session));
        if !should_remove {
            return None;
        }
        if let Some((_, removed)) = self.tcp_tunnels.remove(&port) {
            reservations.insert(ReservationKey::Tcp(port), removed.id.clone());
            removed.cancel.cancel();
            removed.idle_cancel.cancel();
            self.metrics.active_tunnels.dec();
            self.cleanup_notify.notify_waiters();
            Some(removed)
        } else {
            None
        }
    }

    /// Remove an owned TCP tunnel, cancel its listener, and release the port
    /// reservation only after the listener confirms its socket was dropped.
    pub async fn shutdown_tcp_tunnel_if_owner(
        &self,
        port: u16,
        session: &Arc<TunnelSession>,
    ) -> Option<Arc<TunnelSession>> {
        let removed = self.remove_tcp_tunnel_if_owner(port, session)?;
        let listener_stopped = match removed.listener_stopped.lock().await.take() {
            Some(listener_stopped) => matches!(
                tokio::time::timeout(Duration::from_secs(5), listener_stopped).await,
                Ok(Ok(()))
            ),
            None => true,
        };
        if listener_stopped {
            self.release_tcp_port_reservation(port, &removed.id);
        } else {
            self.metrics.tcp_reservations_retained.inc();
            tracing::warn!(
                port,
                "TCP listener did not stop; retaining port reservation"
            );
        }
        Some(removed)
    }

    /// Create a DNS record for a newly reserved HTTP tunnel, when enabled.
    pub async fn create_dns_record(&self, subdomain: &str) -> anyhow::Result<Option<String>> {
        let Some(client) = &self.dns_client else {
            return Ok(None);
        };
        let public_ip = self.config.server.public_ip.as_deref().ok_or_else(|| {
            anyhow::anyhow!(
                "server.public_ip is required when cloudflare.per_tunnel_dns is enabled"
            )
        })?;
        let name = format!("{}.{}", subdomain, self.config.server.domain);
        client
            .create_record(&name, public_ip, self.config.cloudflare.dns_ttl)
            .await
            .map(Some)
            .map_err(|error| anyhow::anyhow!("failed to create DNS record for {name}: {error}"))
    }

    /// Delete a tunnel's owned DNS record. Cleanup is best-effort after the
    /// routing entry has already been removed.
    pub async fn delete_dns_record(&self, session: &TunnelSession) {
        let (Some(client), Some(record_id)) = (&self.dns_client, &session.dns_record_id) else {
            return;
        };
        if let Err(error) = client.delete_record(record_id).await {
            tracing::warn!(record_id = %record_id, "Failed to delete tunnel DNS record: {error}");
        }
    }

    /// Remove tunnels with no public traffic or active streams for the
    /// configured idle period.
    pub async fn reap_idle_tunnels(&self, now: Instant) {
        let timeout = Duration::from_secs(self.config.server.tunnel_idle_timeout_secs);

        let http_candidates: Vec<(String, Arc<TunnelSession>)> = self
            .tunnels
            .iter()
            .filter_map(|entry| {
                let session = entry.value().clone();
                session
                    .is_idle(now, timeout)
                    .then(|| (entry.key().clone(), session))
            })
            .collect();
        for (subdomain, session) in http_candidates {
            if let Some(removed) = self.unregister_tunnel_if_owner(&subdomain, &session) {
                let _ = removed.control_tx.try_send(ServerMsg::Error {
                    code: 408,
                    message: "tunnel closed after idle timeout".to_string(),
                });
                self.delete_dns_record(&removed).await;
                tracing::info!(subdomain = %subdomain, "Closed idle tunnel");
            }
        }

        let tcp_candidates: Vec<(u16, Arc<TunnelSession>)> = self
            .tcp_tunnels
            .iter()
            .filter_map(|entry| {
                let session = entry.value().clone();
                session
                    .is_idle(now, timeout)
                    .then(|| (*entry.key(), session))
            })
            .collect();
        for (port, session) in tcp_candidates {
            if let Some(removed) = self.shutdown_tcp_tunnel_if_owner(port, &session).await {
                let _ = removed.control_tx.try_send(ServerMsg::Error {
                    code: 408,
                    message: "tunnel closed after idle timeout".to_string(),
                });
                self.delete_dns_record(&removed).await;
                tracing::info!(port, "Closed idle TCP tunnel");
            }
        }
    }

    fn lock_reservations(&self) -> std::sync::MutexGuard<'_, HashMap<ReservationKey, String>> {
        self.reservations
            .lock()
            .expect("tunnel registration mutex poisoned")
    }

    fn at_capacity(&self, reservations: &HashMap<ReservationKey, String>) -> bool {
        self.tunnels.len() + self.tcp_tunnels.len() + reservations.len()
            >= self.config.server.max_tunnels
    }

    /// Store a captured request for inspection
    pub async fn store_capture(&self, subdomain: &str, mut capture: CapturedRequest) {
        capture.req_headers = rgrok_proto::inspect::sanitize_headers(&capture.req_headers);
        capture.resp_headers = capture
            .resp_headers
            .as_ref()
            .map(|headers| rgrok_proto::inspect::sanitize_headers(headers));
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

/// Stream correlation state shared by every tunnel created over one
/// authenticated control connection.
pub struct ConnectionStreamState {
    pub next_correlation_id: AtomicU32,
    pub pending_streams: DashMap<u32, oneshot::Sender<yamux::Stream>>,
}

impl ConnectionStreamState {
    pub fn new() -> Self {
        Self {
            next_correlation_id: AtomicU32::new(1),
            pending_streams: DashMap::new(),
        }
    }

    pub fn next_correlation_id(&self) -> u32 {
        self.next_correlation_id.fetch_add(1, Ordering::Relaxed)
    }
}

impl Default for ConnectionStreamState {
    fn default() -> Self {
        Self::new()
    }
}

/// Represents an active tunnel session from a connected client.
pub struct TunnelSession {
    pub id: String,
    #[allow(dead_code)]
    pub tunnel_type: TunnelType,
    pub subdomain: String,
    /// Username for basic auth; the plaintext password is never retained.
    pub basic_auth_username: Option<String>,
    pub basic_auth_hash: Option<String>,
    pub options: TunnelOptions,
    #[allow(dead_code)]
    pub created_at: Instant,
    /// Last time this tunnel handled public traffic.
    pub last_activity: StdMutex<Instant>,
    /// Number of currently active proxied streams.
    pub active_streams: AtomicUsize,
    /// Cloudflare record created for this tunnel, if enabled.
    pub dns_record_id: Option<String>,
    /// Cancellation signal used by idle cleanup and session teardown.
    pub idle_cancel: CancellationToken,
    /// Sink to send messages to the connected client
    pub control_tx: mpsc::Sender<ServerMsg>,
    /// Connection-scoped stream IDs and pending data streams.
    pub stream_state: Arc<ConnectionStreamState>,
    /// Cancels the TCP listener owned by this tunnel.
    pub cancel: CancellationToken,
    /// Signals that the TCP listener has dropped its bound socket.
    pub listener_stopped: Mutex<Option<oneshot::Receiver<()>>>,
    /// Cached fingerprint of the last successful Authorization header
    /// (fast-path to skip bcrypt without retaining reversible credentials).
    pub cached_auth_fingerprint: Mutex<Option<[u8; 32]>>,
}

impl TunnelSession {
    pub fn next_correlation_id(&self) -> u32 {
        self.stream_state.next_correlation_id()
    }

    pub fn touch(&self) {
        if let Ok(mut last_activity) = self.last_activity.lock() {
            *last_activity = Instant::now();
        }
    }

    pub fn stream_started(&self) {
        self.active_streams.fetch_add(1, Ordering::Relaxed);
        self.touch();
    }

    pub fn stream_finished(&self) {
        self.active_streams.fetch_sub(1, Ordering::Relaxed);
        self.touch();
    }

    pub fn is_idle(&self, now: Instant, timeout: Duration) -> bool {
        if self.active_streams.load(Ordering::Relaxed) != 0 {
            return false;
        }
        self.last_activity
            .lock()
            .map(|last_activity| now.duration_since(*last_activity) >= timeout)
            .unwrap_or(false)
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
            req_body_truncated: false,
            resp_status: Some(200),
            resp_headers: None,
            resp_body: None,
            resp_body_truncated: false,
            remote_addr: "127.0.0.1:1234".to_string(),
            tls_version: None,
        }
    }

    fn make_tunnel_session(subdomain: &str) -> Arc<TunnelSession> {
        make_test_session(subdomain, "test-id")
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
        assert!(matches!(
            err,
            rgrok_proto::TunnelError::CapacityExceeded { max: 2 }
        ));
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

    #[tokio::test]
    async fn test_concurrent_duplicate_http_registration_has_one_winner() {
        let state = Arc::new(ServerState::new(make_test_config(32)));
        let contenders = 32;
        let barrier = Arc::new(tokio::sync::Barrier::new(contenders));
        let mut tasks = Vec::with_capacity(contenders);

        for i in 0..contenders {
            let state = state.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                let id = format!("winner-{i}");
                state
                    .register_tunnel(make_test_session("same-name", &id))
                    .is_ok()
                    .then_some(id)
            }));
        }

        let mut winners = Vec::new();
        for task in tasks {
            if let Some(id) = task.await.unwrap() {
                winners.push(id);
            }
        }
        assert_eq!(winners.len(), 1);
        assert_eq!(state.tunnels.len(), 1);
        assert_eq!(state.tunnels.get("same-name").unwrap().id, winners[0]);
        assert_eq!(state.metrics.active_tunnels.get(), 1);

        state.unregister_tunnel("same-name");
        assert_eq!(state.metrics.active_tunnels.get(), 0);
    }

    #[tokio::test]
    async fn test_capacity_reservations_are_atomic_across_http_and_tcp() {
        let mut config = make_test_config(10);
        config.server.max_tunnels = 2;
        config.server.tcp_port_range = [10000, 10020];
        let state = Arc::new(ServerState::new(config));
        let contenders = 16;
        let reserve_barrier = Arc::new(tokio::sync::Barrier::new(contenders));
        let commit_barrier = Arc::new(tokio::sync::Barrier::new(contenders));
        let mut tasks = Vec::with_capacity(contenders);

        for i in 0..contenders {
            let state = state.clone();
            let reserve_barrier = reserve_barrier.clone();
            let commit_barrier = commit_barrier.clone();
            tasks.push(tokio::spawn(async move {
                let owner = format!("reservation-{i}");
                reserve_barrier.wait().await;
                let reservation = if i % 2 == 0 {
                    state
                        .reserve_http_tunnel(&format!("http-{i}"), &owner)
                        .map(|_| None)
                } else {
                    state
                        .reserve_tcp_port(Some(10000 + i as u16), &owner)
                        .map(Some)
                };
                let Ok(tcp_port) = reservation else {
                    commit_barrier.wait().await;
                    return false;
                };

                // Keep all successful reservations in flight until every
                // contender has attempted its reservation.
                commit_barrier.wait().await;
                if let Some(port) = tcp_port {
                    state.register_tcp_tunnel(port, make_test_session(&format!("tcp-{i}"), &owner))
                } else {
                    state
                        .register_tunnel(make_test_session(&format!("http-{i}"), &owner))
                        .is_ok()
                }
            }));
        }

        let mut committed = 0;
        for task in tasks {
            committed += usize::from(task.await.unwrap());
        }
        assert_eq!(committed, 2);
        assert_eq!(state.tunnels.len() + state.tcp_tunnels.len(), 2);
        assert_eq!(state.metrics.active_tunnels.get(), 2);
    }

    #[test]
    fn test_old_owner_cleanup_cannot_remove_replacement() {
        let state = ServerState::new(make_test_config(10));
        let old = make_test_session("replacement", "old");
        state.register_tunnel(old.clone()).unwrap();

        // The old session disconnects, freeing the name. A replacement then
        // registers before a delayed cleanup callback from the old session.
        state.unregister_tunnel_if_owner("replacement", &old);
        let replacement = make_test_session("replacement", "new");
        state.register_tunnel(replacement.clone()).unwrap();
        state.unregister_tunnel_if_owner("replacement", &old);

        {
            let current = state.tunnels.get("replacement").unwrap();
            assert!(Arc::ptr_eq(current.value(), &replacement));
        }
        assert_eq!(state.metrics.active_tunnels.get(), 1);
        state.unregister_tunnel_if_owner("replacement", &replacement);
        assert_eq!(state.metrics.active_tunnels.get(), 0);
    }

    fn make_test_session(subdomain: &str, id: &str) -> Arc<TunnelSession> {
        let (tx, _rx) = mpsc::channel(1);
        Arc::new(TunnelSession {
            id: id.to_string(),
            tunnel_type: TunnelType::Http,
            subdomain: subdomain.to_string(),
            basic_auth_username: None,
            basic_auth_hash: None,
            options: TunnelOptions::default(),
            created_at: Instant::now(),
            last_activity: StdMutex::new(Instant::now()),
            active_streams: AtomicUsize::new(0),
            dns_record_id: None,
            idle_cancel: CancellationToken::new(),
            control_tx: tx,
            stream_state: Arc::new(ConnectionStreamState::new()),
            cached_auth_fingerprint: Mutex::new(None),
            cancel: CancellationToken::new(),
            listener_stopped: Mutex::new(None),
        })
    }
}
