pub mod errors;
pub mod inspect;
pub mod messages;
pub mod subdomain;
pub mod transport;

/// Version of the control protocol exchanged during authentication.
///
/// This is intentionally separate from the wire message's field name (which
/// historically carries the client package version) so the server can reject
/// incompatible peers before creating a tunnel.
pub const CONTROL_PROTOCOL_VERSION: &str = env!("CARGO_PKG_VERSION");

pub use errors::TunnelError;
pub use inspect::{CapturedRequest, InspectEvent};
pub use messages::*;
pub use subdomain::{generate_subdomain, validate_subdomain};
pub use transport::{
    read_msg_from_stream, spawn_yamux_driver, write_msg_to_stream, yamux_config, TunnelStream,
    TunnelTransport, WsCompat, YamuxControl, YamuxTransport,
};
