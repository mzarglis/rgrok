use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub auth: AuthConfig,
    pub tls: TlsConfig,
    pub cloudflare: CloudflareConfig,
    pub inspect: InspectConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub domain: String,
    /// Public IPv4 address used for per-tunnel Cloudflare A records.
    #[serde(default)]
    pub public_ip: Option<String>,
    #[serde(default = "default_control_port")]
    pub control_port: u16,
    #[serde(default = "default_https_port")]
    pub https_port: u16,
    #[serde(default = "default_http_port")]
    pub http_port: u16,
    #[serde(default = "default_tcp_port_range")]
    pub tcp_port_range: [u16; 2],
    #[serde(default = "default_max_tunnels")]
    pub max_tunnels: usize,
    #[serde(default = "default_tunnel_idle_timeout")]
    pub tunnel_idle_timeout_secs: u64,
    #[serde(default = "default_metrics_port")]
    pub metrics_port: u16,
    /// Maximum HTTP request body accepted by the public proxy.
    #[serde(default = "default_max_request_body_bytes")]
    pub max_request_body_bytes: usize,
    /// Maximum HTTP response body read from a tunnel by the public proxy.
    #[serde(default = "default_max_response_body_bytes")]
    pub max_response_body_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub secret: String,
    #[serde(default)]
    pub tokens: Vec<String>,
    /// List of revoked JWT IDs (jti values) — tokens with these IDs will be rejected
    #[serde(default)]
    pub revoked_jtis: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    #[serde(default = "default_acme_env")]
    pub acme_env: String,
    #[serde(default)]
    pub acme_email: String,
    #[serde(default = "default_cert_dir")]
    pub cert_dir: String,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudflareConfig {
    #[serde(default)]
    pub api_token: String,
    #[serde(default)]
    pub zone_id: String,
    #[serde(default = "default_dns_ttl")]
    pub dns_ttl: u32,
    #[serde(default)]
    pub per_tunnel_dns: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectConfig {
    #[serde(default)]
    pub ui_port: u16,
    #[serde(default = "default_ui_bind")]
    pub ui_bind: String,
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,
    /// Optional HTTP Basic/Bearer token for the inspection UI. A token is
    /// mandatory when `ui_bind` is not a loopback address.
    #[serde(default)]
    pub ui_auth_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_format")]
    pub format: String,
}

fn default_control_port() -> u16 {
    7835
}
fn default_https_port() -> u16 {
    443
}
fn default_http_port() -> u16 {
    80
}
fn default_tcp_port_range() -> [u16; 2] {
    [10000, 20000]
}
fn default_max_tunnels() -> usize {
    100
}
fn default_tunnel_idle_timeout() -> u64 {
    300
}
fn default_metrics_port() -> u16 {
    9090
}
fn default_max_request_body_bytes() -> usize {
    16 * 1024 * 1024
}
fn default_max_response_body_bytes() -> usize {
    16 * 1024 * 1024
}
fn default_acme_env() -> String {
    "production".to_string()
}
fn default_cert_dir() -> String {
    "/var/lib/rgrok/certs".to_string()
}
fn default_dns_ttl() -> u32 {
    1
}
fn default_ui_bind() -> String {
    "127.0.0.1".to_string()
}
fn default_buffer_size() -> usize {
    100
}

pub(crate) fn is_loopback_bind(bind: &str) -> bool {
    let bind = bind.trim();
    bind.parse::<std::net::IpAddr>()
        .is_ok_and(|address| address.is_loopback())
        || rgrok_proto::inspect::is_loopback_authority(bind)
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_log_format() -> String {
    "json".to_string()
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.auth.secret.len() < 32 {
            anyhow::bail!("auth.secret must be at least 32 characters");
        }
        if is_placeholder_secret(&self.auth.secret) {
            anyhow::bail!(
                "auth.secret must not be a placeholder; replace it with a randomly generated secret (for example, `openssl rand -hex 32`)"
            );
        }
        if self.server.domain.is_empty() {
            anyhow::bail!("server.domain must be set");
        }
        if self.server.tcp_port_range[0] >= self.server.tcp_port_range[1] {
            anyhow::bail!("server.tcp_port_range start must be less than end");
        }
        if self.server.tunnel_idle_timeout_secs == 0 {
            anyhow::bail!("server.tunnel_idle_timeout_secs must be greater than zero");
        }
        if self.cloudflare.per_tunnel_dns {
            if self.cloudflare.api_token.is_empty() || self.cloudflare.zone_id.is_empty() {
                anyhow::bail!(
                    "cloudflare.api_token and cloudflare.zone_id are required when per_tunnel_dns is enabled"
                );
            }
            let public_ip = self.server.public_ip.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "server.public_ip is required when cloudflare.per_tunnel_dns is enabled"
                )
            })?;
            if public_ip.parse::<std::net::Ipv4Addr>().is_err() {
                anyhow::bail!("server.public_ip must be a valid IPv4 address");
            }
        }
        if self.server.max_request_body_bytes == 0 {
            anyhow::bail!("server.max_request_body_bytes must be greater than zero");
        }
        if self.server.max_response_body_bytes == 0 {
            anyhow::bail!("server.max_response_body_bytes must be greater than zero");
        }
        if self.inspect.ui_port != 0 && !is_loopback_bind(&self.inspect.ui_bind) {
            let token = self
                .inspect
                .ui_auth_token
                .as_deref()
                .map(str::trim)
                .filter(|token| !token.is_empty())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                    "inspect.ui_auth_token must be configured when inspect.ui_bind is non-loopback"
                )
                })?;
            if is_placeholder_secret(token) {
                anyhow::bail!(
                    "inspect.ui_auth_token must not be a placeholder when inspect.ui_bind is non-loopback"
                );
            }
        }
        Ok(())
    }
}

/// Return whether a secret is one of the placeholder forms shipped in examples
/// or commonly copied into a deployment. Matching markers rather than a single
/// literal keeps validation effective when the explanatory suffix changes.
fn is_placeholder_secret(secret: &str) -> bool {
    let normalized = secret.trim().to_ascii_lowercase();
    [
        "changeme",
        "change_me",
        "change-me",
        "change-this-to",
        "generate_with",
        "replace_with",
        "your-secret",
        "your_secret",
        "<your",
        "placeholder",
        "example.com",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                domain: "tunnel.example.com".to_string(),
                public_ip: None,
                control_port: default_control_port(),
                https_port: default_https_port(),
                http_port: default_http_port(),
                tcp_port_range: default_tcp_port_range(),
                max_tunnels: default_max_tunnels(),
                tunnel_idle_timeout_secs: default_tunnel_idle_timeout(),
                metrics_port: default_metrics_port(),
                max_request_body_bytes: default_max_request_body_bytes(),
                max_response_body_bytes: default_max_response_body_bytes(),
            },
            auth: AuthConfig {
                secret: "a".repeat(32),
                tokens: vec![],
                revoked_jtis: vec![],
            },
            tls: TlsConfig {
                acme_env: default_acme_env(),
                acme_email: String::new(),
                cert_dir: default_cert_dir(),
                cert_file: None,
                key_file: None,
            },
            cloudflare: CloudflareConfig {
                api_token: String::new(),
                zone_id: String::new(),
                dns_ttl: default_dns_ttl(),
                per_tunnel_dns: false,
            },
            inspect: InspectConfig {
                ui_port: 0,
                ui_bind: default_ui_bind(),
                buffer_size: default_buffer_size(),
                ui_auth_token: None,
            },
            logging: LoggingConfig {
                level: default_log_level(),
                format: default_log_format(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_toml() -> &'static str {
        r#"
[server]
domain = "tunnel.example.com"

[auth]
secret = "abcdefghijklmnopqrstuvwxyz123456"

[tls]
acme_email = "test@example.com"

[cloudflare]

[inspect]

[logging]
"#
    }

    #[test]
    fn test_valid_config_parses() {
        let config: Config = toml::from_str(valid_toml()).unwrap();
        config.validate().unwrap();
        assert_eq!(config.server.domain, "tunnel.example.com");
        assert_eq!(config.auth.secret, "abcdefghijklmnopqrstuvwxyz123456");
    }

    #[test]
    fn test_default_values_are_correct() {
        let config: Config = toml::from_str(valid_toml()).unwrap();
        assert_eq!(config.server.control_port, 7835);
        assert_eq!(config.server.https_port, 443);
        assert_eq!(config.server.http_port, 80);
        assert_eq!(config.server.tcp_port_range, [10000, 20000]);
        assert_eq!(config.server.max_tunnels, 100);
        assert_eq!(config.server.tunnel_idle_timeout_secs, 300);
        assert_eq!(config.server.metrics_port, 9090);
        assert_eq!(config.server.max_request_body_bytes, 16 * 1024 * 1024);
        assert_eq!(config.server.max_response_body_bytes, 16 * 1024 * 1024);
        assert_eq!(config.tls.acme_env, "production");
        assert_eq!(config.tls.cert_dir, "/var/lib/rgrok/certs");
        assert_eq!(config.cloudflare.dns_ttl, 1);
        assert!(!config.cloudflare.per_tunnel_dns);
        assert_eq!(config.inspect.ui_bind, "127.0.0.1");
        assert_eq!(config.inspect.buffer_size, 100);
        assert!(config.inspect.ui_auth_token.is_none());
        assert_eq!(config.logging.level, "info");
        assert_eq!(config.logging.format, "json");
    }

    #[test]
    fn test_short_secret_rejected() {
        let toml_str = r#"
[server]
domain = "tunnel.example.com"

[auth]
secret = "tooshort"

[tls]
[cloudflare]
[inspect]
[logging]
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains("at least 32 characters"),
            "expected secret length error, got: {}",
            err
        );
    }

    #[test]
    fn test_placeholder_secret_rejected() {
        let toml_str = r#"
[server]
domain = "tunnel.example.com"

[auth]
secret = "CHANGEME_generate_with_openssl_rand_hex_32"

[tls]
[cloudflare]
[inspect]
[logging]
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains("must not be a placeholder"),
            "expected placeholder secret error, got: {}",
            err
        );
    }

    #[test]
    fn test_placeholder_detection_is_not_literal_only() {
        assert!(is_placeholder_secret(
            "CHANGEME_replace_with_a_secret_generated_for_this_host"
        ));
        assert!(!is_placeholder_secret("7d2c6b9e4f1a8c0e3b5d9f2a6c8e1b4d"));
        assert!(!is_placeholder_secret("a-legitimate-example-passphrase"));
    }

    #[test]
    fn test_empty_domain_rejected() {
        let toml_str = r#"
[server]
domain = ""

[auth]
secret = "abcdefghijklmnopqrstuvwxyz123456"

[tls]
[cloudflare]
[inspect]
[logging]
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains("domain must be set"),
            "expected domain error, got: {}",
            err
        );
    }

    #[test]
    fn test_invalid_tcp_port_range_start_equals_end() {
        let toml_str = r#"
[server]
domain = "tunnel.example.com"
tcp_port_range = [5000, 5000]

[auth]
secret = "abcdefghijklmnopqrstuvwxyz123456"

[tls]
[cloudflare]
[inspect]
[logging]
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains("start must be less than end"),
            "expected port range error, got: {}",
            err
        );
    }

    #[test]
    fn test_invalid_tcp_port_range_start_greater_than_end() {
        let toml_str = r#"
[server]
domain = "tunnel.example.com"
tcp_port_range = [20000, 10000]

[auth]
secret = "abcdefghijklmnopqrstuvwxyz123456"

[tls]
[cloudflare]
[inspect]
[logging]
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains("start must be less than end"),
            "expected port range error, got: {}",
            err
        );
    }

    #[test]
    fn test_default_impl_validates() {
        let config = Config::default();
        config.validate().unwrap();
    }

    #[test]
    fn test_per_tunnel_dns_requires_public_ip_and_credentials() {
        let mut config = Config::default();
        config.cloudflare.per_tunnel_dns = true;
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("api_token and cloudflare.zone_id"));

        config.cloudflare.api_token = "token".to_string();
        config.cloudflare.zone_id = "zone".to_string();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("server.public_ip is required"));

        config.server.public_ip = Some("not-an-ip".to_string());
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("valid IPv4"));

        config.server.public_ip = Some("203.0.113.10".to_string());
        config.validate().unwrap();
    }

    #[test]
    fn non_loopback_inspection_requires_authentication() {
        let mut config: Config = toml::from_str(valid_toml()).unwrap();
        config.inspect.ui_port = 4040;
        config.inspect.ui_bind = "0.0.0.0".to_string();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("ui_auth_token"));

        config.inspect.ui_auth_token = Some("ui-secret".to_string());
        config.validate().unwrap();
    }

    #[test]
    fn non_loopback_inspection_rejects_placeholder_authentication() {
        let mut config: Config = toml::from_str(valid_toml()).unwrap();
        config.inspect.ui_port = 4040;
        config.inspect.ui_bind = "0.0.0.0".to_string();
        config.inspect.ui_auth_token = Some("change-this-to-a-long-random-value".to_string());

        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("must not be a placeholder"));
    }

    #[test]
    fn test_zero_idle_timeout_rejected() {
        let mut config = Config::default();
        config.server.tunnel_idle_timeout_secs = 0;
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("tunnel_idle_timeout_secs"));
    }

    #[test]
    fn test_zero_http_body_limit_rejected() {
        let mut config = Config::default();
        config.server.max_request_body_bytes = 0;
        let err = config.validate().unwrap_err();
        assert!(err
            .to_string()
            .contains("max_request_body_bytes must be greater than zero"));

        config.server.max_request_body_bytes = 1;
        config.server.max_response_body_bytes = 0;
        let err = config.validate().unwrap_err();
        assert!(err
            .to_string()
            .contains("max_response_body_bytes must be greater than zero"));
    }

    #[test]
    fn loopback_inspection_keeps_developer_default() {
        let mut config: Config = toml::from_str(valid_toml()).unwrap();
        config.inspect.ui_port = 4040;
        config.inspect.ui_bind = "127.0.0.1".to_string();
        config.validate().unwrap();
        config.inspect.ui_bind = "::1".to_string();
        config.validate().unwrap();
    }
}
