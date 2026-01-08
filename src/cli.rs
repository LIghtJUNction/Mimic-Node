use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "mimictl")]
#[command(about = "Mimic-Node control tool", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Generate reality keypair and apply to config
    #[command(visible_aliases = ["gen", "keys"])]
    GenKeys,

    /// Add a new user (supports batch)
    Add {
        /// Email addresses
        #[arg(required = true)]
        emails: Vec<String>,

        /// User level
        #[arg(short, long, default_value = "0")]
        level: u32,
    },

    /// Remove a user by email or pattern (supports batch)
    #[command(visible_aliases = ["rm", "delete", "remove"])]
    Del {
        /// Emails or glob patterns (e.g., "*@example.com")
        #[arg(required = true)]
        targets: Vec<String>,
    },

    /// Reset UUID and SID for a specific user
    ResetUser {
        /// Email of the user
        email: String,
    },

    /// Reset global config to defaults
    Reset {
        /// Users to preserve (can be specified multiple times)
        #[arg(long = "keep-user")]
        keep_users: Vec<String>,
    },

    /// Set or auto-detect best Reality SNI server
    Sni {
        /// Target domain (optional, auto-detects if missing)
        domain: Option<String>,
    },

    /// Generate VLESS share links
    Link {
        /// Email of the user
        email: String,

        /// Explicit addresses to use
        addresses: Vec<String>,

        /// Prefer IPv4 for auto-detection
        #[arg(short = '4', long = "v4")]
        v4: bool,

        /// Prefer IPv6 for auto-detection
        #[arg(short = '6', long = "v6")]
        v6: bool,
    },

    /// List users
    #[command(visible_aliases = ["ls"])]
    List {
        /// Filter by name substring
        filter: Option<String>,
    },

    /// Show details for a specific user
    Info { email: String },

    /// Show current config and PUBKEY
    Show,

    /// Apply staged config to running system
    Apply,

    /// Check system status (service, mounts, config)
    Check,
}
