use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "mimictl")]
#[command(about = "Mimic-Node control tool", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Hysteria2Commands {
    /// Setup Hysteria2 inbound with given port and optional parameters
    Setup {
        /// Listen port for Hysteria2
        #[arg(short = 'p', long, default_value = "443")]
        port: u16,

        /// Password for authentication (auto-generated if not provided)
        #[arg(short = 'P', long)]
        password: Option<String>,

        /// Masquerade domain or URL (default: https://microsoft.com)
        #[arg(short = 'm', long = "masquerade")]
        masquerade: Option<String>,

        /// Domain for certbot to generate certificate
        #[arg(short = 'd', long = "domain")]
        domain: Option<String>,

        /// Upload speed limit in Mbps
        #[arg(long = "up")]
        up_mbps: Option<u32>,

        /// Download speed limit in Mbps
        #[arg(long = "down")]
        down_mbps: Option<u32>,

        /// Enable salamander obfs
        #[arg(long = "obfs")]
        obfs: bool,

        /// HTTP2 idle timeout (golang Duration format, e.g. "60s")
        #[arg(long = "http2-idle-timeout")]
        http2_idle_timeout: Option<String>,

        /// HTTP2 keep-alive period
        #[arg(long = "http2-keep-alive-period")]
        http2_keep_alive_period: Option<String>,

        /// HTTP2 max concurrent streams
        #[arg(long = "http2-max-concurrent-streams")]
        http2_max_concurrent_streams: Option<u32>,

        /// QUIC initial packet size
        #[arg(long = "quic-initial-packet-size")]
        quic_initial_packet_size: Option<u32>,

        /// Disable QUIC path MTU discovery
        #[arg(long = "quic-disable-path-mtu-discovery")]
        quic_disable_path_mtu_discovery: bool,

        /// Path to TLS certificate
        #[arg(long = "cert")]
        cert_path: Option<String>,

        /// Path to TLS private key
        #[arg(long = "key")]
        key_path: Option<String>,

        /// Show what would be changed, do not write staging
        #[arg(short = 'n', long = "dry-run")]
        dry_run: bool,
    },

    /// Add a new user to existing Hysteria2 inbound
    AddUser {
        /// User name
        #[arg(short = 'u', long = "name")]
        name: Option<String>,

        /// Password for the new user (auto-generated if not provided)
        #[arg(short = 'P', long)]
        password: Option<String>,

        /// Show what would be changed, do not write staging
        #[arg(short = 'n', long = "dry-run")]
        dry_run: bool,
    },

    /// Generate share link for Hysteria2
    Link {
        /// User name (defaults to first user)
        #[arg(short = 'u', long = "name")]
        name: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum DnsCommands {
    /// Setup DoH3 (DNS over HTTP3) with Google DNS
    SetupDoH3 {
        /// Show what would be changed, do not write staging
        #[arg(short = 'n', long = "dry-run")]
        dry_run: bool,
    },

    /// Add a DNS server
    AddServer {
        /// Server tag/name
        #[arg(short, long)]
        tag: String,

        /// Server address (domain or IP)
        #[arg(short = 's', long = "server")]
        server: String,

        /// Server type (h3, tls, udp, https)
        #[arg(long = "type", default_value = "h3")]
        server_type: String,

        /// Server port
        #[arg(short = 'p', long = "port")]
        port: Option<u16>,

        /// Path (for DoH/DoH3)
        #[arg(long = "path")]
        path: Option<String>,

        /// Show what would be changed, do not write staging
        #[arg(short = 'n', long = "dry-run")]
        dry_run: bool,
    },
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

    /// Configure Hysteria2 protocol
    Hysteria2 {
        #[command(subcommand)]
        command: Hysteria2Commands,
    },

    /// Configure DNS servers with DoH3 (DNS over HTTP3)
    Dns {
        #[command(subcommand)]
        command: DnsCommands,
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

    /// Upgrade config to latest default with new features (merge new defaults, keep user data)
    Upgrade {
        /// Auto merge new defaults without prompting
        #[arg(short, long)]
        auto: bool,

        /// Show what would be changed, do not write staging
        #[arg(short = 'n', long = "dry-run")]
        dry_run: bool,
    },

    /// Interactive setup wizard for node configuration
    Setup,

    /// Diagnose node issues and check system status
    Diagnose {
        /// Enable verbose output
        #[arg(short, long)]
        verbose: bool,
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

        /// Network interface to use for auto-detection (e.g. 'eth0')
        /// When provided, mimictl will attempt to use addresses assigned to this
        /// interface for link generation instead of relying on external IP services.
        #[arg(short = 'i', long = "interface", value_name = "IFACE")]
        interface: Option<String>,

        /// When enabled, generate addresses by assigning within the interface's IPv6 prefix (e.g. /64).
        /// Useful when the interface has a /64 and you want multiple sibling addresses within that range.
        #[arg(long = "assign")]
        assign: bool,

        /// When enabled, attempt (experimental) IPv4 address assignment within the interface's IPv4 subnet.
        /// Requires root and a suitable IPv4 subnet on the interface. Use with caution.
        #[arg(long = "assign-v4")]
        assign_v4: bool,

        /// When set, treat failures to detect/assign addresses as fatal errors (strict mode).
        /// Without this flag, the command will WARN and try to continue (best-effort).
        #[arg(long = "strict")]
        strict: bool,

        /// Number of addresses/links to generate when auto-detecting (default: 1)
        #[arg(long = "num", value_name = "N", default_value = "1")]
        num: usize,
    },

    /// Generate sing-box client config(s) from VLESS link(s) read from stdin or provided via arguments.
    ///
    /// Example:
    ///   mimictl link alice@example.com | mimictl from-link -o client.json --socks
    FromLink {
        /// Path to output file. If omitted, prints to stdout.
        #[arg(short = 'o', long = "out", value_name = "FILE")]
        out: Option<std::path::PathBuf>,

        /// Add a local SOCKS5 inbound (default).
        #[arg(short = 's', long = "socks")]
        socks: bool,

        /// Add a TUN inbound instead of SOCKS (mutually exclusive).
        #[arg(short = 't', long = "tun")]
        tun: bool,

        /// Tag name for selector outbound when multiple links are present
        #[arg(long = "selector-tag", default_value = "proxy")]
        selector_tag: String,
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

    /// Show diff between current and default config, apply changes interactively
    Diff,

    /// Apply staged config to running system
    Apply,

    /// Check system status (service, mounts, config)
    Check,

    /// Protect or unprotect important files with immutable attribute
    Protect {
        /// Unprotect files (allows modification, use before manual editing)
        #[arg(short = 'u', long = "unprotect")]
        unprotect: bool,
    },

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

    /// Install or uninstall Claude Code skill for Mimic-Node
    Skill {
        #[command(subcommand)]
        command: SkillCommands,
    },
}

#[derive(Subcommand)]
pub enum SkillCommands {
    /// Install the Mimic-Node skill for Claude Code
    Install {
        /// Install to project .claude/skills/ instead of ~/.claude/skills/
        #[arg(short, long)]
        project: bool,

        /// Force reinstall even if already installed
        #[arg(short, long)]
        force: bool,
    },

    /// Uninstall the Mimic-Node skill from Claude Code
    Uninstall {
        /// Uninstall from project .claude/skills/ instead of ~/.claude/skills/
        #[arg(short, long)]
        project: bool,
    },

    /// Check if the Mimic-Node skill is installed
    Status,
}
