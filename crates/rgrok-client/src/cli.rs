use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "rgrok", version, about = "Secure tunnels to localhost")]
pub struct Cli {
    /// Path to config file
    #[arg(short, long, default_value = "~/.config/rgrok/config.toml")]
    pub config: PathBuf,

    /// Server address override
    #[arg(long)]
    pub server: Option<String>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Forward HTTP traffic
    Http {
        /// Local port to expose
        port: u16,
        /// Request a specific subdomain
        #[arg(long)]
        subdomain: Option<String>,
        /// Protect with basic auth (user:pass)
        #[arg(long)]
        auth: Option<String>,
        /// Disable request inspection
        #[arg(long)]
        no_inspect: bool,
        /// Rewrite Host header sent to local server
        #[arg(long)]
        host_header: Option<String>,
        /// Inspection UI port
        #[arg(long, default_value = "4040")]
        inspect_port: u16,
    },
    /// Forward HTTPS traffic (terminates TLS, forwards plain HTTP locally)
    Https {
        /// Local port to expose
        port: u16,
        /// Request a specific subdomain
        #[arg(long)]
        subdomain: Option<String>,
        /// Protect with basic auth (user:pass)
        #[arg(long)]
        auth: Option<String>,
    },
    /// Expose a raw TCP port
    Tcp {
        /// Local port to expose
        port: u16,
        /// Request a specific remote port
        #[arg(long)]
        remote_port: Option<u16>,
    },
    /// Print current config
    Config,
    /// Save auth token to config
    Authtoken {
        /// Auth token from server operator
        token: String,
    },
}
