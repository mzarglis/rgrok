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
        if let Some((host, port)) = server.rsplit_once(':') {
            config.server.host = host.to_string();
            if let Ok(p) = port.parse::<u16>() {
                config.server.port = p;
            }
        } else {
            config.server.host = server.clone();
        }
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
            let basic_auth = auth.as_ref().and_then(parse_auth_arg);
            let options = rgrok_proto::TunnelOptions {
                host_header,
                inspect: !no_inspect && config.defaults.inspect,
                response_header: vec![],
            };
            let tunnel_cfg = tunnel::TunnelConfig {
                local_port: port,
                tunnel_type: rgrok_proto::TunnelType::Http,
                subdomain,
                basic_auth,
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
            let basic_auth = auth.as_ref().and_then(parse_auth_arg);
            let options = rgrok_proto::TunnelOptions {
                host_header: None,
                inspect: config.defaults.inspect,
                response_header: vec![],
            };
            let tunnel_cfg = tunnel::TunnelConfig {
                local_port: port,
                tunnel_type: rgrok_proto::TunnelType::Https,
                subdomain,
                basic_auth,
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

fn parse_auth_arg(auth: &String) -> Option<rgrok_proto::BasicAuthConfig> {
    let (user, pass) = auth.split_once(':')?;
    Some(rgrok_proto::BasicAuthConfig {
        username: user.to_string(),
        password: pass.to_string(),
    })
}

fn init_tracing(config: &ClientConfig) {
    use tracing_subscriber::EnvFilter;

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.logging.level));

    tracing_subscriber::fmt().with_env_filter(filter).init();
}
