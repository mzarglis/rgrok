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

    /// Use an unencrypted ws:// control connection (development only)
    #[arg(long, global = true)]
    pub insecure: bool,

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
        /// Protect with basic auth (USER:PASSWORD; PASSWORD may contain ':')
        #[arg(long, value_name = "USER:PASSWORD", value_parser = parse_basic_auth)]
        auth: Option<rgrok_proto::BasicAuthConfig>,
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
        /// Protect with basic auth (USER:PASSWORD; PASSWORD may contain ':')
        #[arg(long, value_name = "USER:PASSWORD", value_parser = parse_basic_auth)]
        auth: Option<rgrok_proto::BasicAuthConfig>,
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

fn parse_basic_auth(value: &str) -> Result<rgrok_proto::BasicAuthConfig, String> {
    let (username, password) = value.split_once(':').ok_or_else(|| {
        "basic auth must use USER:PASSWORD format (password may contain ':')".to_string()
    })?;

    if username.is_empty() {
        return Err("basic auth username must not be empty".to_string());
    }
    if password.is_empty() {
        return Err("basic auth password must not be empty".to_string());
    }

    Ok(rgrok_proto::BasicAuthConfig {
        username: username.to_string(),
        password: password.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_auth_valid() {
        let auth = parse_basic_auth("user:pass").expect("valid basic auth");
        assert_eq!(auth.username, "user");
        assert_eq!(auth.password, "pass");
    }

    #[test]
    fn parse_basic_auth_requires_colon() {
        let error = parse_basic_auth("user").expect_err("missing colon must fail");
        assert!(error.contains("USER:PASSWORD"));
    }

    #[test]
    fn parse_basic_auth_rejects_empty_username() {
        let error = parse_basic_auth(":pass").expect_err("empty username must fail");
        assert!(error.contains("username must not be empty"));
    }

    #[test]
    fn parse_basic_auth_rejects_empty_password() {
        let error = parse_basic_auth("user:").expect_err("empty password must fail");
        assert!(error.contains("password must not be empty"));
    }

    #[test]
    fn parse_basic_auth_preserves_colons_in_password() {
        let auth = parse_basic_auth("user:pass:extra").expect("valid basic auth");
        assert_eq!(auth.username, "user");
        assert_eq!(auth.password, "pass:extra");
    }

    #[test]
    fn cli_rejects_malformed_basic_auth() {
        let result = Cli::try_parse_from(["rgrok", "http", "3000", "--auth", "malformed"]);
        assert!(result.is_err());
        let error = result.err().expect("malformed auth must fail").to_string();
        assert!(error.contains("USER:PASSWORD"));
    }
}
