use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A captured HTTP request/response pair for the inspection UI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedRequest {
    pub id: String,
    pub captured_at: DateTime<Utc>,
    pub duration_ms: Option<u64>,
    pub tunnel_id: String,

    // Request
    pub req_method: String,
    pub req_url: String,
    pub req_headers: Vec<(String, String)>,
    #[serde(
        serialize_with = "serialize_opt_bytes",
        deserialize_with = "deserialize_opt_bytes"
    )]
    pub req_body: Option<Bytes>,

    // Response (filled in when stream closes)
    pub resp_status: Option<u16>,
    pub resp_headers: Option<Vec<(String, String)>>,
    #[serde(
        serialize_with = "serialize_opt_bytes",
        deserialize_with = "deserialize_opt_bytes"
    )]
    pub resp_body: Option<Bytes>,
    pub resp_body_truncated: bool,

    // Metadata
    pub remote_addr: String,
    pub tls_version: Option<String>,
}

/// Event sent via SSE for live inspection updates
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum InspectEvent {
    NewRequest {
        request: Box<CapturedRequest>,
    },
    RequestCompleted {
        id: String,
        duration_ms: u64,
        resp_status: u16,
    },
}

fn serialize_opt_bytes<S>(val: &Option<Bytes>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use base64::Engine;
    match val {
        Some(b) => {
            let encoded = base64::engine::general_purpose::STANDARD.encode(b);
            serializer.serialize_some(&encoded)
        }
        None => serializer.serialize_none(),
    }
}

fn deserialize_opt_bytes<'de, D>(deserializer: D) -> Result<Option<Bytes>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use base64::Engine;
    let opt: Option<String> = Option::deserialize(deserializer)?;
    match opt {
        Some(s) => {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(&s)
                .map_err(serde::de::Error::custom)?;
            Ok(Some(Bytes::from(decoded)))
        }
        None => Ok(None),
    }
}
