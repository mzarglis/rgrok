/// Typed errors for the rgrok tunnel system
#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    #[error("authentication failed: {reason}")]
    AuthFailed { reason: String },

    #[error("subdomain '{subdomain}' is already in use")]
    SubdomainTaken { subdomain: String },

    #[error("no TCP ports available in range {start}-{end}")]
    NoPortsAvailable { start: u16, end: u16 },

    #[error("connection to local port {port} refused")]
    LocalPortRefused { port: u16 },

    #[error("tunnel session expired")]
    SessionExpired,

    #[error("protocol version mismatch: client={client}, server={server}")]
    VersionMismatch { client: String, server: String },

    #[error("invalid subdomain: {reason}")]
    InvalidSubdomain { reason: String },

    #[error("tunnel not found: {id}")]
    TunnelNotFound { id: String },

    #[error("stream timeout: correlation {correlation_id} not acknowledged within deadline")]
    StreamTimeout { correlation_id: u32 },

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("transport error: {0}")]
    Transport(#[from] std::io::Error),
}
