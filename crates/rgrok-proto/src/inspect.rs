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
    #[serde(
        serialize_with = "serialize_headers",
        deserialize_with = "deserialize_headers"
    )]
    pub req_headers: Vec<(String, String)>,
    #[serde(
        serialize_with = "serialize_opt_bytes",
        deserialize_with = "deserialize_opt_bytes"
    )]
    pub req_body: Option<Bytes>,
    /// True when the original request body exceeded the configured capture limit.
    #[serde(default)]
    pub req_body_truncated: bool,

    // Response (filled in when stream closes)
    pub resp_status: Option<u16>,
    #[serde(
        serialize_with = "serialize_opt_headers",
        deserialize_with = "deserialize_opt_headers"
    )]
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

/// Header names whose values commonly contain credentials or other bearer
/// secrets. These are omitted from captures, JSON, SSE, and replay requests.
pub fn is_sensitive_header(name: &str) -> bool {
    let name = name.trim().to_ascii_lowercase();
    matches!(
        name.as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "x-api-key"
            | "api-key"
            | "x-auth-token"
            | "x-csrf-token"
            | "sec-websocket-key"
    ) || name.contains("api-key")
        || name.contains("apikey")
        || name.contains("token")
        || name.contains("secret")
        || name.contains("password")
        || name.contains("credential")
}

/// Remove security-sensitive headers before a capture is retained or replayed.
pub fn sanitize_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(name, _)| !is_sensitive_header(name))
        .cloned()
        .collect()
}

/// Validate an HTTP Host authority for a service that is intentionally bound
/// only to loopback. Ports are optional, but malformed suffixes are rejected.
pub fn is_loopback_authority(authority: &str) -> bool {
    let host = if let Some(bracketed) = authority.strip_prefix('[') {
        let Some((host, suffix)) = bracketed.split_once(']') else {
            return false;
        };
        if !suffix.is_empty()
            && suffix
                .strip_prefix(':')
                .is_none_or(|port| port.parse::<u16>().is_err())
        {
            return false;
        }
        host
    } else if let Some((host, port)) = authority.split_once(':') {
        if port.parse::<u16>().is_err() {
            return false;
        }
        host
    } else {
        authority
    };

    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn serialize_headers<S>(headers: &[(String, String)], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    sanitize_headers(headers).serialize(serializer)
}

fn deserialize_headers<'de, D>(deserializer: D) -> Result<Vec<(String, String)>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let headers = Vec::<(String, String)>::deserialize(deserializer)?;
    Ok(sanitize_headers(&headers))
}

fn serialize_opt_headers<S>(
    headers: &Option<Vec<(String, String)>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    headers
        .as_ref()
        .map(|headers| sanitize_headers(headers))
        .serialize(serializer)
}

fn deserialize_opt_headers<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<(String, String)>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let headers = Option::<Vec<(String, String)>>::deserialize(deserializer)?;
    Ok(headers.map(|headers| sanitize_headers(&headers)))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_headers_are_removed_from_captures_and_json() {
        let headers = vec![
            ("Authorization".to_string(), "Bearer secret".to_string()),
            ("Cookie".to_string(), "session=secret".to_string()),
            ("X-Api-Key".to_string(), "secret".to_string()),
            ("Accept".to_string(), "text/plain".to_string()),
        ];
        assert_eq!(
            sanitize_headers(&headers),
            vec![("Accept".into(), "text/plain".into())]
        );

        let capture = CapturedRequest {
            id: "id".into(),
            captured_at: Utc::now(),
            duration_ms: None,
            tunnel_id: "tunnel".into(),
            req_method: "GET".into(),
            req_url: "/".into(),
            req_headers: headers,
            req_body: None,
            req_body_truncated: false,
            resp_status: Some(200),
            resp_headers: Some(vec![("Set-Cookie".into(), "secret".into())]),
            resp_body: None,
            resp_body_truncated: false,
            remote_addr: "".into(),
            tls_version: None,
        };
        let json = serde_json::to_string(&capture).unwrap();
        assert!(!json.contains("Bearer secret"));
        assert!(!json.contains("Set-Cookie"));
        assert!(json.contains("Accept"));
    }

    #[test]
    fn loopback_authority_rejects_malformed_and_rebinding_hosts() {
        for authority in [
            "localhost",
            "localhost:4040",
            "127.0.0.1:4040",
            "[::1]:4040",
        ] {
            assert!(is_loopback_authority(authority));
        }
        for authority in [
            "attacker.example:4040",
            "localhost:4040:evil",
            "[::1].attacker.example",
            "[::1]:not-a-port",
        ] {
            assert!(!is_loopback_authority(authority));
        }
    }
}
