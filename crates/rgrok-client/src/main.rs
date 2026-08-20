mod cli;
mod config;
mod inspect;
mod local_proxy;
mod output;
mod tunnel;

use clap::Parser;

use crate::cli::{Cli, Command};
use crate::config::ClientConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Load config
    let mut config = ClientConfig::load(&cli.config)?;

    // Apply server override from CLI
    if let Some(server) = &cli.server {
        apply_server_override(&mut config, server)?;
    }
    if cli.insecure {
        config.server.insecure = true;
    }

    match cli.command {
        Command::Http {
            port,
            subdomain,
            auth,
            no_inspect,
            host_header,
            inspect_port,
        } => {
            init_tracing(&config);
            let options = rgrok_proto::TunnelOptions {
                host_header,
                inspect: !no_inspect && config.defaults.inspect,
                response_header: vec![],
            };
            let tunnel_cfg = tunnel::TunnelConfig {
                local_port: port,
                tunnel_type: rgrok_proto::TunnelType::Http,
                subdomain,
                basic_auth: auth,
                options,
                inspect_port: if no_inspect { 0 } else { inspect_port },
            };
            tunnel::run(config, tunnel_cfg).await?;
        }
        Command::Https {
            port,
            subdomain,
            auth,
        } => {
            init_tracing(&config);
            let options = rgrok_proto::TunnelOptions {
                host_header: None,
                inspect: config.defaults.inspect,
                response_header: vec![],
            };
            let tunnel_cfg = tunnel::TunnelConfig {
                local_port: port,
                tunnel_type: rgrok_proto::TunnelType::Https,
                subdomain,
                basic_auth: auth,
                options,
                inspect_port: config.defaults.inspect_port,
            };
            tunnel::run(config, tunnel_cfg).await?;
        }
        Command::Tcp { port, remote_port } => {
            init_tracing(&config);
            let options = rgrok_proto::TunnelOptions::default();
            let tunnel_cfg = tunnel::TunnelConfig {
                local_port: port,
                tunnel_type: rgrok_proto::TunnelType::Tcp { remote_port },
                subdomain: None,
                basic_auth: None,
                options,
                inspect_port: 0,
            };
            tunnel::run(config, tunnel_cfg).await?;
        }
        Command::Config => {
            println!("{}", toml::to_string_pretty(&config)?);
        }
        Command::Authtoken { token } => {
            config.auth.token = token;
            let path = cli.config;
            config.save(&path)?;
            println!("Auth token saved to {}", path.display());
        }
    }

    Ok(())
}

/// Apply a one-off server address override.
///
/// An override may be a hostname, `host:port`, or an explicitly scheme-qualified
/// `ws://`/`wss://` address. A `ws://` scheme is itself an explicit opt-in to the
/// insecure development transport; an unqualified address keeps the configured
/// transport mode.
fn apply_server_override(config: &mut ClientConfig, server: &str) -> anyhow::Result<()> {
    let (scheme, authority) = match server.split_once("://") {
        Some((scheme, authority)) => {
            let scheme = scheme.to_ascii_lowercase();
            if scheme != "ws" && scheme != "wss" {
                anyhow::bail!(
                    "Unsupported server URL scheme '{}'; use ws:// or wss://",
                    scheme
                );
            }
            (Some(scheme), authority)
        }
        None => (None, server),
    };

    if authority.is_empty()
        || authority.contains('/')
        || authority.contains('?')
        || authority.contains('#')
    {
        anyhow::bail!(
            "Invalid server address '{}'; expected host[:port] or ws[s]://host[:port]",
            server
        );
    }

    let (host, port) = if let Some(bracketed_host) = authority.strip_prefix('[') {
        let closing = bracketed_host.find(']').ok_or_else(|| {
            anyhow::anyhow!("Invalid IPv6 server address '{}': missing ']'", server)
        })?;
        let host = &bracketed_host[..closing];
        if host.is_empty() {
            anyhow::bail!("Invalid server address '{}': host is empty", server);
        }
        let remainder = &bracketed_host[closing + 1..];
        let port = if remainder.is_empty() {
            None
        } else if let Some(port) = remainder.strip_prefix(':') {
            Some(parse_server_port(port, server)?)
        } else {
            anyhow::bail!(
                "Invalid server address '{}': unexpected text after IPv6 host",
                server
            );
        };
        (host, port)
    } else if authority.matches(':').count() > 1 {
        anyhow::bail!(
            "Invalid server address '{}': IPv6 addresses must be enclosed in '[' and ']'",
            server
        );
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        if host.is_empty() {
            anyhow::bail!("Invalid server address '{}': host is empty", server);
        }
        (host, Some(parse_server_port(port, server)?))
    } else {
        (authority, None)
    };

    config.server.host = host.to_string();
    if let Some(port) = port {
        config.server.port = port;
    }
    if let Some(scheme) = scheme {
        config.server.insecure = scheme == "ws";
    }
    Ok(())
}

fn parse_server_port(port: &str, server: &str) -> anyhow::Result<u16> {
    if port.is_empty() {
        anyhow::bail!("Invalid server address '{}': port is empty", server);
    }
    port.parse::<u16>().map_err(|_| {
        anyhow::anyhow!(
            "Invalid server port '{}' in '{}': expected 1-65535",
            port,
            server
        )
    })
}

fn init_tracing(config: &ClientConfig) {
    use tracing_subscriber::EnvFilter;

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.logging.level));

    tracing_subscriber::fmt().with_env_filter(filter).init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_override_preserves_secure_default() {
        let mut config = ClientConfig::default();

        apply_server_override(&mut config, "relay.example.com:9443").unwrap();

        assert_eq!(config.server.host, "relay.example.com");
        assert_eq!(config.server.port, 9443);
        assert!(!config.server.insecure);
    }

    #[test]
    fn server_override_scheme_selects_transport() {
        let mut config = ClientConfig::default();

        apply_server_override(&mut config, "ws://127.0.0.1:7835").unwrap();
        assert_eq!(config.server.host, "127.0.0.1");
        assert!(config.server.insecure);

        apply_server_override(&mut config, "wss://relay.example.com:9443").unwrap();
        assert_eq!(config.server.host, "relay.example.com");
        assert_eq!(config.server.port, 9443);
        assert!(!config.server.insecure);
    }

    #[test]
    fn server_override_accepts_bracketed_ipv6() {
        let mut config = ClientConfig::default();

        apply_server_override(&mut config, "wss://[::1]:7835").unwrap();

        assert_eq!(config.server.host, "::1");
        assert_eq!(config.server.port, 7835);
        assert!(!config.server.insecure);
    }

    #[test]
    fn server_override_rejects_unsupported_scheme() {
        let mut config = ClientConfig::default();

        let error = apply_server_override(&mut config, "https://relay.example.com")
            .expect_err("https is not a control WebSocket scheme");

        assert!(error.to_string().contains("use ws:// or wss://"));
    }
}
