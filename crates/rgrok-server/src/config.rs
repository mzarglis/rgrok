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
        if self.server.domain.is_empty() {
            anyhow::bail!("server.domain must be set");
        }
        if self.server.tcp_port_range[0] >= self.server.tcp_port_range[1] {
            anyhow::bail!("server.tcp_port_range start must be less than end");
        }
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                domain: "tunnel.example.com".to_string(),
                control_port: default_control_port(),
                https_port: default_https_port(),
                http_port: default_http_port(),
                tcp_port_range: default_tcp_port_range(),
                max_tunnels: default_max_tunnels(),
                tunnel_idle_timeout_secs: default_tunnel_idle_timeout(),
                metrics_port: default_metrics_port(),
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
        assert_eq!(config.tls.acme_env, "production");
        assert_eq!(config.tls.cert_dir, "/var/lib/rgrok/certs");
        assert_eq!(config.cloudflare.dns_ttl, 1);
        assert!(!config.cloudflare.per_tunnel_dns);
        assert_eq!(config.inspect.ui_bind, "127.0.0.1");
        assert_eq!(config.inspect.buffer_size, 100);
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
}
