use serde::{Deserialize, Serialize};

/// Client -> Server messages
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMsg {
    /// Authenticate and request a tunnel
    Auth { token: String, version: String },
    /// Request a new tunnel
    TunnelRequest {
        id: String,
        tunnel_type: TunnelType,
        subdomain: Option<String>,
        basic_auth: Option<BasicAuthConfig>,
        options: TunnelOptions,
    },
    /// Heartbeat
    Ping { seq: u64 },
    /// Acknowledge a proxy stream open
    StreamAck { correlation_id: u32 },
}

/// Server -> Client messages
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMsg {
    /// Auth accepted
    AuthOk { session_id: String },
    /// Auth rejected
    AuthErr { reason: String },
    /// Tunnel is live
    TunnelAck {
        id: String,
        public_url: String,
        tunnel_type: TunnelType,
    },
    /// Server asking client to open a new proxy stream for an incoming request
    StreamOpen {
        correlation_id: u32,
        tunnel_id: String,
    },
    /// Heartbeat response
    Pong { seq: u64 },
    /// Server-initiated error
    Error { code: u32, message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TunnelType {
    Http,
    Https,
    Tcp { remote_port: Option<u16> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicAuthConfig {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TunnelOptions {
    pub host_header: Option<String>,
    pub inspect: bool,
    pub response_header: Vec<(String, String)>,
}

/// Encode a message to MessagePack bytes
pub fn encode_msg<T: Serialize>(msg: &T) -> Result<Vec<u8>, rmp_serde::encode::Error> {
    rmp_serde::to_vec_named(msg)
}

/// Decode a message from MessagePack bytes
pub fn decode_msg<'a, T: Deserialize<'a>>(data: &'a [u8]) -> Result<T, rmp_serde::decode::Error> {
    rmp_serde::from_slice(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_msg_roundtrip() {
        let msg = ClientMsg::Auth {
            token: "test-token".to_string(),
            version: "0.1.0".to_string(),
        };
        let encoded = encode_msg(&msg).unwrap();
        let decoded: ClientMsg = decode_msg(&encoded).unwrap();
        match decoded {
            ClientMsg::Auth { token, version } => {
                assert_eq!(token, "test-token");
                assert_eq!(version, "0.1.0");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_server_msg_roundtrip() {
        let msg = ServerMsg::TunnelAck {
            id: "t1".to_string(),
            public_url: "https://test.tunnel.example.com".to_string(),
            tunnel_type: TunnelType::Http,
        };
        let encoded = encode_msg(&msg).unwrap();
        let decoded: ServerMsg = decode_msg(&encoded).unwrap();
        match decoded {
            ServerMsg::TunnelAck {
                id,
                public_url,
                tunnel_type,
            } => {
                assert_eq!(id, "t1");
                assert_eq!(public_url, "https://test.tunnel.example.com");
                assert_eq!(tunnel_type, TunnelType::Http);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_tunnel_request_roundtrip() {
        let msg = ClientMsg::TunnelRequest {
            id: "req-1".to_string(),
            tunnel_type: TunnelType::Tcp {
                remote_port: Some(15432),
            },
            subdomain: Some("myapp".to_string()),
            basic_auth: Some(BasicAuthConfig {
                username: "admin".to_string(),
                password: "secret".to_string(),
            }),
            options: TunnelOptions {
                host_header: Some("localhost".to_string()),
                inspect: true,
                response_header: vec![("X-Custom".to_string(), "value".to_string())],
            },
        };
        let encoded = encode_msg(&msg).unwrap();
        let decoded: ClientMsg = decode_msg(&encoded).unwrap();
        match decoded {
            ClientMsg::TunnelRequest {
                id, tunnel_type, ..
            } => {
                assert_eq!(id, "req-1");
                assert_eq!(
                    tunnel_type,
                    TunnelType::Tcp {
                        remote_port: Some(15432)
                    }
                );
            }
            _ => panic!("wrong variant"),
        }
    }
}
