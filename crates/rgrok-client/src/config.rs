use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub server: ServerSection,
    pub auth: AuthSection,
    #[serde(default)]
    pub defaults: DefaultsSection,
    #[serde(default)]
    pub logging: LoggingSection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSection {
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSection {
    #[serde(default)]
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DefaultsSection {
    #[serde(default = "default_inspect_port")]
    pub inspect_port: u16,
    #[serde(default = "default_inspect")]
    pub inspect: bool,
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingSection {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_format")]
    pub format: String,
}

impl Default for LoggingSection {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

fn default_port() -> u16 {
    7835
}
fn default_inspect_port() -> u16 {
    4040
}
fn default_inspect() -> bool {
    true
}
fn default_max_body_bytes() -> usize {
    1_048_576
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_log_format() -> String {
    "pretty".to_string()
}

impl ClientConfig {
    /// Load config from a file path, expanding ~ to home dir
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let expanded = expand_tilde(path);
        if !expanded.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(&expanded)?;
        let config: ClientConfig = toml::from_str(&content)?;
        Ok(config)
    }

    /// Save config to file, creating parent directories
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let expanded = expand_tilde(path);
        if let Some(parent) = expanded.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = toml::to_string_pretty(self)?;
        std::fs::write(&expanded, content)?;

        // Set restrictive permissions on config file
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&expanded, std::fs::Permissions::from_mode(0o600))?;
        }

        Ok(())
    }

    /// Get the default config path
    pub fn default_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("rgrok")
            .join("config.toml")
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server: ServerSection {
                host: "tunnel.example.com".to_string(),
                port: default_port(),
            },
            auth: AuthSection {
                token: String::new(),
            },
            defaults: DefaultsSection::default(),
            logging: LoggingSection::default(),
        }
    }
}

fn expand_tilde(path: &Path) -> PathBuf {
    let path_str = path.to_string_lossy();
    if path_str.starts_with("~/") || path_str.starts_with("~\\") {
        if let Some(home) = dirs::home_dir() {
            return home.join(&path_str[2..]);
        }
    }
    path.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_values() {
        let config = ClientConfig::default();

        assert_eq!(config.server.host, "tunnel.example.com");
        assert_eq!(config.server.port, 7835);
        assert_eq!(config.auth.token, "");
        // DefaultsSection derives Default, so Rust defaults (0/false) apply,
        // not the serde default functions. The serde defaults only kick in
        // when deserializing from TOML with missing fields.
        assert_eq!(config.defaults.inspect_port, 0);
        assert_eq!(config.defaults.inspect, false);
        assert_eq!(config.defaults.max_body_bytes, 0);
        assert_eq!(config.logging.level, "info");
        assert_eq!(config.logging.format, "pretty");
    }

    #[test]
    fn test_config_roundtrip_toml() {
        let config = ClientConfig {
            server: ServerSection {
                host: "my.server.io".to_string(),
                port: 9999,
            },
            auth: AuthSection {
                token: "tok_abc123".to_string(),
            },
            defaults: DefaultsSection {
                inspect_port: 5050,
                inspect: false,
                max_body_bytes: 2_097_152,
            },
            logging: LoggingSection {
                level: "debug".to_string(),
                format: "json".to_string(),
            },
        };

        let toml_str = toml::to_string_pretty(&config).expect("serialize");
        let deserialized: ClientConfig = toml::from_str(&toml_str).expect("deserialize");

        assert_eq!(deserialized.server.host, "my.server.io");
        assert_eq!(deserialized.server.port, 9999);
        assert_eq!(deserialized.auth.token, "tok_abc123");
        assert_eq!(deserialized.defaults.inspect_port, 5050);
        assert_eq!(deserialized.defaults.inspect, false);
        assert_eq!(deserialized.defaults.max_body_bytes, 2_097_152);
        assert_eq!(deserialized.logging.level, "debug");
        assert_eq!(deserialized.logging.format, "json");
    }

    #[test]
    fn test_config_partial_toml() {
        let toml_str = r#"
[server]
host = "partial.example.com"

[auth]
token = ""
"#;
        let config: ClientConfig = toml::from_str(toml_str).expect("deserialize partial");

        assert_eq!(config.server.host, "partial.example.com");
        // port should fall back to default
        assert_eq!(config.server.port, 7835);
        // defaults section is missing from TOML, so serde uses
        // DefaultsSection's derive(Default) (Rust Default: 0/false),
        // NOT the per-field serde default functions.
        assert_eq!(config.defaults.inspect_port, 0);
        assert_eq!(config.defaults.inspect, false);
        assert_eq!(config.defaults.max_body_bytes, 0);
        // logging section should be fully defaulted
        assert_eq!(config.logging.level, "info");
        assert_eq!(config.logging.format, "pretty");
    }

    #[test]
    fn test_config_custom_values() {
        let toml_str = r#"
[server]
host = "custom.host.dev"
port = 1234

[auth]
token = "secret-token"

[defaults]
inspect_port = 8080
inspect = false
max_body_bytes = 512

[logging]
level = "trace"
format = "compact"
"#;
        let config: ClientConfig = toml::from_str(toml_str).expect("deserialize custom");

        assert_eq!(config.server.host, "custom.host.dev");
        assert_eq!(config.server.port, 1234);
        assert_eq!(config.auth.token, "secret-token");
        assert_eq!(config.defaults.inspect_port, 8080);
        assert_eq!(config.defaults.inspect, false);
        assert_eq!(config.defaults.max_body_bytes, 512);
        assert_eq!(config.logging.level, "trace");
        assert_eq!(config.logging.format, "compact");
    }

    // Auth parsing tests — replicate the logic from main.rs's parse_auth_arg
    // since that function is not public/importable from here.
    fn parse_auth(auth: &str) -> Option<(String, String)> {
        let (user, pass) = auth.split_once(':')?;
        Some((user.to_string(), pass.to_string()))
    }

    #[test]
    fn test_parse_auth_valid() {
        let result = parse_auth("user:pass");
        assert_eq!(result, Some(("user".to_string(), "pass".to_string())));
    }

    #[test]
    fn test_parse_auth_no_colon() {
        let result = parse_auth("nocolon");
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_auth_empty_password() {
        let result = parse_auth("user:");
        assert_eq!(result, Some(("user".to_string(), "".to_string())));
    }

    #[test]
    fn test_parse_auth_multiple_colons() {
        let result = parse_auth("user:pass:extra");
        assert_eq!(
            result,
            Some(("user".to_string(), "pass:extra".to_string()))
        );
    }
}
