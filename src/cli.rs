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

        /// Show what would be changed, do not write staging
        #[arg(short = 'n', long = "dry-run")]
        dry_run: bool,

        /// Apply staged changes immediately
        #[arg(long = "apply")]
        apply: bool,
    },

    /// Update user attributes (supports batch). Example: `mimictl update '*@example.com' --level 1`
    #[command(visible_aliases = ["mod", "chg", "set"])]
    Update {
        /// Emails, UUIDs or glob patterns to match users
        #[arg(required = true)]
        targets: Vec<String>,

        /// Set the user's level for all matched users
        #[arg(short, long)]
        level: Option<u32>,

        /// Rename the user's email. Only allowed when exactly one user is matched.
        #[arg(short = 'e', long = "email")]
        email: Option<String>,

        /// Replace email substrings: provide FROM and TO (e.g. --email-replace FROM TO)
        #[arg(long = "email-replace", value_names = ["FROM", "TO"], num_args = 2)]
        email_replace: Option<Vec<String>>,

        /// Treat the FROM pattern as a regular expression (used with --email-replace)
        #[arg(long = "regex")]
        regex: bool,

        /// Replace only the first match in the email part (default behavior replaces all matches)
        #[arg(long = "replace-first")]
        replace_first: bool,

        /// Show what would be changed, do not write staging
        #[arg(short = 'n', long = "dry-run")]
        dry_run: bool,

        /// Apply staged changes immediately
        #[arg(long = "apply")]
        apply: bool,
    },

    /// Reset UUID and SID for user(s) (supports batch and patterns)
    ResetUser {
        /// Emails or glob patterns to match users (e.g., "alice@example.com", "*@example.com")
        #[arg(required = true)]
        targets: Vec<String>,

        /// Show what would be changed, do not write staging
        #[arg(short = 'n', long = "dry-run")]
        dry_run: bool,

        /// Apply staged changes immediately
        #[arg(long = "apply")]
        apply: bool,
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

        /// Path to SNI list file (optional, defaults to /usr/share/mimic-node/sni.txt)
        #[arg(short = 'f', long = "file", value_name = "PATH")]
        file: Option<std::path::PathBuf>,
    },

    /// Discard staged changes (remove `config.new` / `PUBKEY.new` in staging)
    ///
    /// If no `--item` is provided, both staging files will be removed.
    Discard {
        /// Items to discard: 'config' and/or 'pubkey'. Repeatable.
        #[arg(short = 'i', long = "item", value_name = "ITEM")]
        items: Vec<String>,

        /// Force discard without interactive confirmation
        #[arg(short = 'f', long = "force")]
        force: bool,
    },

    /// Generate and install shell completions for current shell
    Completions {
        /// Shell to generate completions for (auto-detected if omitted)
        #[arg(short = 's', long = "shell")]
        shell: Option<String>,

        /// Apply/install the completion to current user's shell configuration
        #[arg(short = 'a', long = "apply")]
        apply: bool,
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

        /// Output as JSON array (compact) for scripts
        #[arg(long = "json")]
        json: bool,
    },

    /// Show details for specific user(s) (supports batch and patterns)
    Info {
        /// Emails or glob patterns to match users
        #[arg(required = true)]
        targets: Vec<String>,

        /// Output as JSON array (compact) for scripts
        #[arg(long = "json")]
        json: bool,
    },

    /// Show current config and PUBKEY
    Show,

    /// Apply staged config to running system
    Apply,

    /// Check system status (service, mounts, config)
    Check,

    /// Verify configuration integrity (keys, sids, uuids)
    Verify {
        /// Enable verbose output
        #[arg(short, long)]
        verbose: bool,

        /// Custom config file path
        #[arg(short, long, value_name = "FILE")]
        config: Option<std::path::PathBuf>,

        /// Verify a specific VLESS link details
        #[arg(short, long, value_name = "LINK")]
        link: Option<String>,
    },
}
