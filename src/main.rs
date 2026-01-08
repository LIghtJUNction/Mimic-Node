mod config;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use colored::*;
use config::SingBoxConfig;
use rand::Rng;
use regex::Regex;
use std::fs;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};
use std::process::Command;
use tokio::time::Duration;

// --- Constants ---
const FLOW_TYPE: &str = "xtls-rprx-vision";

// --- CLI Definitions ---
#[derive(Parser)]
#[command(name = "mimictl")]
#[command(about = "Mimic-Node control tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
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

    /// Apply staged changes
    Apply,

    /// Validate configuration (sing-box check + internal consistency)
    Check,
}

// --- Globals/Paths ---
struct Paths {
    root: PathBuf,
    config: PathBuf,
    staging: PathBuf,
    pubkey: PathBuf,
    staging_pubkey: PathBuf,
    sni_list: PathBuf,
    default_config: PathBuf,
}

impl Paths {
    fn new() -> Self {
        let root_str = std::env::var("MIMIC_NODE_ROOT").unwrap_or_else(|_| "/".to_string());
        let root = PathBuf::from(root_str);

        let etc_singbox = root.join("etc/sing-box");
        let usr_share = root.join("usr/share/mimic-node");

        Self {
            config: etc_singbox.join("config.json"),
            staging: etc_singbox.join("config.new"),
            pubkey: etc_singbox.join("PUBKEY"),
            staging_pubkey: etc_singbox.join("PUBKEY.new"),
            sni_list: usr_share.join("sni.txt"),
            default_config: usr_share.join("default/config.json"),
            root,
        }
    }

    fn get_input_config_path(&self) -> &PathBuf {
        if self.staging.exists() {
            &self.staging
        } else {
            &self.config
        }
    }
}

// --- Main ---

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let paths = Paths::new();

    // Overlay Integrity Check (skip for simple read ops if strictness allows, but script enforces it generally)
    // The script skips check for 'help'. Clap handles help before we get here.
    // Script checks if mountpoint exists.
    check_overlay(&paths)?;

    match cli.command {
        Commands::GenKeys => cmd_gen_keys(&paths)?,
        Commands::Add { emails, level } => cmd_add(&paths, emails, level)?,
        Commands::Del { targets } => cmd_del(&paths, targets)?,
        Commands::ResetUser { email } => cmd_reset_user(&paths, email)?,
        Commands::Reset { keep_users } => cmd_reset_global(&paths, keep_users)?,
        Commands::Sni { domain } => cmd_sni(&paths, domain).await?,
        Commands::Link {
            email,
            addresses,
            v4,
            v6,
        } => cmd_link(&paths, email, addresses, v4, v6).await?,
        Commands::List { filter } => cmd_list(&paths, filter)?,
        Commands::Info { email } => cmd_info(&paths, email)?,
        Commands::Show => cmd_show(&paths)?,
        Commands::Apply => apply_staging(&paths)?,
        Commands::Check => cmd_check(&paths)?,
    }

    Ok(())
}

// --- Helpers ---

fn check_overlay(paths: &Paths) -> Result<()> {
    if paths.root == Path::new("/") {
        // We are operating on the system root
        let mount_target = "/etc/sing-box";

        // Check if mounted
        let is_mounted = Command::new("mountpoint")
            .arg("-q")
            .arg(mount_target)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        if !is_mounted {
            eprintln!("{}", "[WARN] OverlayFS is NOT mounted.".yellow());
            eprintln!("{}", "[INFO] Attempting to auto-mount...".green());

            // Try systemctl
            let _ = Command::new("systemctl")
                .args(["start", "mimic-node-mount.service"])
                .status();

            // Try direct script
            if !check_mountpoint(mount_target) {
                let _ = Command::new("/usr/bin/mimic-mount").arg("start").status();
            }

            if !check_mountpoint(mount_target) {
                return Err(anyhow!("CRITICAL: Failed to mount OverlayFS at {}. Please run 'sudo systemctl start mimic-node-mount'.", mount_target));
            }
            eprintln!("{}", "[INFO] OverlayFS mounted successfully.".green());
        }
    }
    Ok(())
}

fn check_mountpoint(path: &str) -> bool {
    Command::new("mountpoint")
        .arg("-q")
        .arg(path)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn load_config(path: &Path) -> Result<SingBoxConfig> {
    let content =
        fs::read_to_string(path).with_context(|| format!("Failed to read config: {:?}", path))?;
    let config: SingBoxConfig =
        serde_json::from_str(&content).context("Failed to parse config JSON")?;
    Ok(config)
}

fn save_config(path: &Path, config: &SingBoxConfig) -> Result<()> {
    let content = serde_json::to_string_pretty(config)?;
    fs::write(path, content)?;
    Ok(())
}

fn generate_keypair() -> Result<(String, String)> {
    // Try sing-box first
    if let Ok(output) = Command::new("sing-box")
        .args(["generate", "reality-keypair"])
        .output()
    {
        if output.status.success() {
            let out_str = String::from_utf8(output.stdout)?;
            // Output format:
            // PrivateKey: ...
            // PublicKey: ...
            let mut priv_key = String::new();
            let mut pub_key = String::new();

            for line in out_str.lines() {
                if let Some(val) = line.strip_prefix("PrivateKey: ") {
                    priv_key = val.trim().to_string();
                } else if let Some(val) = line.strip_prefix("PublicKey: ") {
                    pub_key = val.trim().to_string();
                }
            }
            if !priv_key.is_empty() && !pub_key.is_empty() {
                return Ok((priv_key, pub_key));
            }
        }
    }

    // Fallback: openssl (Warning)
    eprintln!(
        "{}",
        "[WARN] sing-box not available/failed; generating pseudo keypair with openssl.".yellow()
    );

    let gen_key = |bytes: usize| -> Result<String> {
        let output = Command::new("openssl")
            .args(["rand", "-base64", &bytes.to_string()])
            .output()?;
        let s = String::from_utf8(output.stdout)?;
        Ok(s.trim().to_string())
    };

    Ok((gen_key(32)?, gen_key(32)?))
}

fn generate_uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn generate_sid() -> String {
    let mut rng = rand::rng();
    let rand_bytes: [u8; 8] = rng.random();
    hex::encode(rand_bytes)
}

fn apply_staging(paths: &Paths) -> Result<()> {
    if paths.staging.exists() {
        // Validate JSON structure
        let _ = load_config(&paths.staging)?;

        // Validate using sing-box check
        eprintln!("{} Validating staged configuration...", "[INFO]".green());
        let check_status = Command::new("sing-box")
            .args(["check", "-c", paths.staging.to_str().unwrap()])
            .status();

        match check_status {
            Ok(status) if status.success() => {
                eprintln!("{} Configuration valid.", "[INFO]".green());
            }
            _ => {
                return Err(anyhow!(
                    "Staged configuration is invalid. 'sing-box check' failed. Aborting apply."
                ));
            }
        }

        fs::rename(&paths.staging, &paths.config)?;
        eprintln!(
            "{} Applied staged config -> {:?}",
            "[INFO]".green(),
            paths.config
        );
    }

    if paths.staging_pubkey.exists() {
        fs::rename(&paths.staging_pubkey, &paths.pubkey)?;
        eprintln!(
            "{} Applied staged PUBKEY -> {:?}",
            "[INFO]".green(),
            paths.pubkey
        );
    }

    // Reload sing-box
    let _ = Command::new("systemctl")
        .args(["try-reload-or-restart", "sing-box"])
        .status();

    Ok(())
}

// --- Commands Implementation ---

fn cmd_gen_keys(paths: &Paths) -> Result<()> {
    eprintln!("{} Generating reality keypair...", "[INFO]".green());
    let (priv_key, pub_key) = generate_keypair()?;

    let input_path = paths.get_input_config_path();
    let mut config = load_config(input_path)?;

    if let Some(inbound) = config.inbounds.first_mut() {
        if let Some(tls) = inbound.tls.as_mut() {
            if let Some(reality) = tls.reality.as_mut() {
                reality.private_key = priv_key;
            }
        }
    }

    save_config(&paths.staging, &config)?;
    fs::write(&paths.staging_pubkey, &pub_key)?;

    eprintln!(
        "{} Keypair staged. Run 'mimictl apply' to activate.",
        "[INFO]".green()
    );
    println!("{}", pub_key);

    Ok(())
}

fn cmd_add(paths: &Paths, emails: Vec<String>, level: u32) -> Result<()> {
    // Check for private key first
    let input_path = paths.get_input_config_path();
    let mut config = load_config(input_path)?;

    // Quick check if private key is present in loaded config
    let has_key = config
        .inbounds
        .first()
        .and_then(|i| i.tls.as_ref())
        .and_then(|t| t.reality.as_ref())
        .map(|r| !r.private_key.is_empty())
        .unwrap_or(false);

    if !has_key {
        eprintln!(
            "{}",
            "[WARN] No private key found; generating one now.".yellow()
        );
        // Generate keys in place into `config` object
        let (priv_key, pub_key) = generate_keypair()?;
        if let Some(inbound) = config.inbounds.first_mut() {
            if inbound.tls.is_none() {
                // Initialize structure if completely missing (unlikely given default)
                // Keeping it simple: assuming structure exists from default config
                return Err(anyhow!("Config structure invalid: missing tls"));
            }
            if let Some(tls) = inbound.tls.as_mut() {
                if tls.reality.is_none() {
                    // Init reality...
                    return Err(anyhow!("Config structure invalid: missing reality"));
                }
                if let Some(reality) = tls.reality.as_mut() {
                    reality.private_key = priv_key;
                }
            }
        }
        // Save pubkey immediately to staging path if we are generating it
        fs::write(&paths.staging_pubkey, &pub_key)?;
    }

    for email in emails {
        let uuid = generate_uuid();
        let sid = generate_sid();
        let name = format!("{}:{}:{}", email, sid, level);

        let user = config::User {
            name: name.clone(),
            uuid: uuid.clone(),
            flow: FLOW_TYPE.to_string(),
        };

        if let Some(inbound) = config.inbounds.first_mut() {
            inbound.users.push(user);
            if let Some(tls) = inbound.tls.as_mut() {
                if let Some(reality) = tls.reality.as_mut() {
                    reality.short_id.push(sid.clone());
                    // Deduplicate short_ids (simple approach)
                    reality.short_id.sort();
                    reality.short_id.dedup();
                }
            }
        }

        eprintln!(
            "{} Prepared user: {} (uuid: {})",
            "[INFO]".green(),
            name,
            uuid
        );
        println!("uuid: {}\nsid: {}", uuid, sid);
    }

    save_config(&paths.staging, &config)?;

    eprintln!(
        "{} Users staged. Run 'mimictl apply' to activate.",
        "[INFO]".green()
    );

    Ok(())
}

fn cmd_del(paths: &Paths, targets: Vec<String>) -> Result<()> {
    let input_path = paths.get_input_config_path();
    let mut config = load_config(input_path)?;

    for target in targets {
        // Handle wildcards: convert glob to regex
        let is_glob = target.contains('*') || target.contains('?');
        let regex_str: String = if is_glob {
            let escaped = regex::escape(&target)
                .replace("\\*", ".*")
                .replace("\\?", ".");
            format!("^{}:", escaped)
        } else {
            format!("^{}:", regex::escape(&target))
        };

        let re = Regex::new(&regex_str)?;

        if let Some(inbound) = config.inbounds.first_mut() {
            inbound.users.retain(|u| !re.is_match(&u.name));
        }

        eprintln!("{} Processed deletion for: {}", "[INFO]".green(), target);
    }

    save_config(&paths.staging, &config)?;

    eprintln!(
        "{} Deletion(s) staged. Run 'mimictl apply' to activate.",
        "[INFO]".green()
    );

    Ok(())
}

fn cmd_reset_user(paths: &Paths, email: String) -> Result<()> {
    let input_path = paths.get_input_config_path();
    let mut config = load_config(input_path)?;

    let mut found = false;
    let mut old_sid = String::new();
    let mut new_sid = String::new();
    let mut new_uuid = String::new();

    if let Some(inbound) = config.inbounds.first_mut() {
        if let Some(user) = inbound
            .users
            .iter_mut()
            .find(|u| u.name.starts_with(&format!("{}:", email)))
        {
            found = true;
            // Parse name: email:sid:level
            let parts: Vec<&str> = user.name.split(':').collect();
            let level = parts.last().unwrap_or(&"0");
            old_sid = parts.get(parts.len() - 2).unwrap_or(&"").to_string();

            new_sid = generate_sid();
            new_uuid = generate_uuid();
            let new_name = format!("{}:{}:{}", email, new_sid, level);

            eprintln!(
                "{} Resetting user {} (Level: {})",
                "[INFO]".green(),
                email,
                level
            );
            eprintln!(
                "{} Old SID: {} -> New SID: {}",
                "[INFO]".green(),
                old_sid,
                new_sid
            );

            user.name = new_name;
            user.uuid = new_uuid.clone();
        }

        if found {
            // Update short_id list
            if let Some(tls) = inbound.tls.as_mut() {
                if let Some(reality) = tls.reality.as_mut() {
                    if let Some(pos) = reality.short_id.iter().position(|x| x == &old_sid) {
                        reality.short_id.remove(pos);
                    }
                    reality.short_id.push(new_sid.clone());
                }
            }
        }
    }

    if !found {
        return Err(anyhow!("User not found: {}", email));
    }

    save_config(&paths.staging, &config)?;
    println!("uuid: {}\nsid: {}", new_uuid, new_sid);

    eprintln!(
        "{} Staged reset for: {}. Run 'mimictl apply' to activate.",
        "[INFO]".green(),
        email
    );

    Ok(())
}

fn cmd_reset_global(paths: &Paths, keep_users_emails: Vec<String>) -> Result<()> {
    eprintln!(
        "{} Resetting configuration to defaults...",
        "[INFO]".green()
    );

    // Load default config
    let default_config = load_config(&paths.default_config)?;
    let mut new_config = default_config.clone();

    // Preserve users
    if !keep_users_emails.is_empty() {
        let current_config = load_config(paths.get_input_config_path())?;

        for email in keep_users_emails {
            eprintln!("{} Preserving user: {}", "[INFO]".green(), email);

            // Find in current
            let user_opt = current_config.inbounds.first().and_then(|i| {
                i.users
                    .iter()
                    .find(|u| u.name.starts_with(&format!("{}:", email)))
            });

            if let Some(user) = user_opt {
                // Get SID
                let parts: Vec<&str> = user.name.split(':').collect();
                let sid = parts.get(parts.len() - 2).unwrap_or(&"").to_string();

                // Add to new config
                if let Some(inbound) = new_config.inbounds.first_mut() {
                    inbound.users.push(user.clone());
                    if let Some(tls) = inbound.tls.as_mut() {
                        if let Some(reality) = tls.reality.as_mut() {
                            reality.short_id.push(sid);
                            reality.short_id.sort();
                            reality.short_id.dedup();
                        }
                    }
                }
            } else {
                eprintln!(
                    "{} User '{}' not found in current config, skipping.",
                    "[WARN]".yellow(),
                    email
                );
            }
        }
    }

    save_config(&paths.staging, &new_config)?;

    eprintln!(
        "{} Staged global reset. Run 'mimictl apply' to activate.",
        "[INFO]".green()
    );

    Ok(())
}

async fn cmd_sni(paths: &Paths, target_sni: Option<String>) -> Result<()> {
    let sni_to_set: String;

    if let Some(sni) = target_sni {
        sni_to_set = sni;
        eprintln!("{} Setting custom SNI: {}", "[INFO]".green(), sni_to_set);
    } else {
        // Auto-detect
        if !paths.sni_list.exists() {
            return Err(anyhow!("SNI list file not found: {:?}", paths.sni_list));
        }
        eprintln!(
            "{} Auto-detecting best SNI from {:?}...",
            "[INFO]".green(),
            paths.sni_list
        );

        let file = fs::File::open(&paths.sni_list)?;
        let reader = io::BufReader::new(file);

        let mut candidates = Vec::new();
        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            candidates.push(trimmed.to_string());
        }

        let mut best_fallback = None;
        let mut found_perfect = None;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .http2_prior_knowledge() // For H2 checking
            .build()?;

        // Sequential scan for now to mimic shell script logic and progress bar
        let mut count = 0;
        for cand in candidates {
            count += 1;
            if count % 5 == 0 {
                eprint!(".");
            }

            let url = format!("https://{}", cand);

            // 1. Connectivity Check (IPv4 preferred)
            // Reqwest uses system resolver. To force IPv4, we'd need a custom connector.
            // For simplicity, we just try HEAD.
            let resp = client.head(&url).send().await;

            if resp.is_err() {
                continue;
            }

            // 2. Reality check using sing-box
            // Check if sing-box exists
            let sing_box_check = Command::new("sing-box")
                .args(["check", "reality-dest", &format!("{}:443", cand)])
                .output();

            if let Ok(output) = sing_box_check {
                if output.status.success() {
                    eprintln!("\n{} Found perfect match: {}", "[INFO]".green(), cand);
                    found_perfect = Some(cand);
                    break;
                }
            }

            // 3. Fallback H2 check
            // Since we configured client with http2_prior_knowledge/support, we can check version?
            // Actually, for a real H2 check on HTTPS, we need ALPN. reqwest supports it by default.
            if best_fallback.is_none() {
                if let Ok(response) = resp {
                    if response.version() == reqwest::Version::HTTP_2 {
                        best_fallback = Some(cand.clone());
                        // If no sing-box available, stop here
                        if Command::new("sing-box").arg("version").output().is_err() {
                            eprintln!(
                                "\n{} Selected SNI (H2 supported): {}",
                                "[INFO]".green(),
                                cand
                            );
                            found_perfect = Some(cand);
                            break;
                        }
                    }
                }
            }
        }
        eprintln!(); // Newline after dots

        if let Some(p) = found_perfect {
            sni_to_set = p;
        } else if let Some(f) = best_fallback {
            eprintln!(
                "{} No perfect Reality match found. Using fallback (H2 supported): {}",
                "[WARN]".yellow(),
                f
            );
            sni_to_set = f;
        } else {
            return Err(anyhow!("No reachable SNI found in candidates list."));
        }
    }

    // Apply
    let input_path = paths.get_input_config_path();
    let mut config = load_config(input_path)?;

    if let Some(inbound) = config.inbounds.first_mut() {
        if let Some(tls) = inbound.tls.as_mut() {
            tls.server_name = sni_to_set.clone();
            if let Some(reality) = tls.reality.as_mut() {
                reality.handshake.server = sni_to_set.clone();
            }
        }
    }

    save_config(&paths.staging, &config)?;
    eprintln!(
        "{} SNI staged as: {}. Run 'mimictl apply' to activate.",
        "[INFO]".green(),
        sni_to_set
    );

    Ok(())
}

async fn cmd_link(
    paths: &Paths,
    email: String,
    mut addresses: Vec<String>,
    v4: bool,
    v6: bool,
) -> Result<()> {
    let input_path = paths.get_input_config_path();
    let config = load_config(input_path)?;

    let user = config
        .inbounds
        .first()
        .and_then(|i| {
            i.users
                .iter()
                .find(|u| u.name.starts_with(&format!("{}:", email)))
        })
        .ok_or_else(|| anyhow!("User '{}' not found", email))?;

    let parts: Vec<&str> = user.name.split(':').collect();
    let sid = parts.get(parts.len() - 2).unwrap_or(&"").to_string();

    let inbound = config.inbounds.first().unwrap();
    let port = inbound.listen_port;
    let sni = inbound
        .tls
        .as_ref()
        .map(|t| t.server_name.clone())
        .unwrap_or_default();

    let pbk = if paths.pubkey.exists() {
        fs::read_to_string(&paths.pubkey)?.trim().to_string()
    } else {
        return Err(anyhow!("PUBKEY file not found."));
    };

    // Auto-detect IPs
    if addresses.is_empty() {
        let mut detect_v4 = v4;
        let mut detect_v6 = v6;
        if !v4 && !v6 {
            detect_v4 = true;
            detect_v6 = true;
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .build()?;

        if detect_v4 {
            if let Ok(ip) = client.get("https://api.ipify.org").send().await {
                if let Ok(text) = ip.text().await {
                    addresses.push(text);
                }
            }
        }
        if detect_v6 {
            if let Ok(ip) = client.get("https://api6.ipify.org").send().await {
                if let Ok(text) = ip.text().await {
                    addresses.push(text);
                }
            }
        }
        if addresses.is_empty() {
            eprintln!(
                "{} Could not detect public IP. Using placeholder.",
                "[WARN]".yellow()
            );
            addresses.push("<YOUR_SERVER_IP>".to_string());
        }
    }

    let mut links = Vec::new();

    for addr in addresses {
        let host = if addr.contains(':') && !addr.contains('[') {
            format!("[{}]", addr)
        } else {
            addr
        };

        let link = format!(
            "vless://{}@{}:{}?security=reality&encryption=none&pbk={}&fp=chrome&type=tcp&sni={}&sid={}&flow={}#{}",
            user.uuid, host, port, pbk, sni, sid, user.flow, user.name
        );
        links.push(link);
    }

    println!("{}", serde_json::to_string_pretty(&links)?);

    Ok(())
}

fn cmd_list(paths: &Paths, filter: Option<String>) -> Result<()> {
    let input_path = paths.get_input_config_path();
    let config = load_config(input_path)?;

    if let Some(inbound) = config.inbounds.first() {
        for user in &inbound.users {
            if let Some(f) = &filter {
                if !user.name.contains(f) {
                    continue;
                }
            }
            println!("{}\t{}\t{}", user.name, user.uuid, user.flow);
        }
    }
    Ok(())
}

fn cmd_info(paths: &Paths, email: String) -> Result<()> {
    let input_path = paths.get_input_config_path();
    let config = load_config(input_path)?;

    if let Some(inbound) = config.inbounds.first() {
        if let Some(user) = inbound
            .users
            .iter()
            .find(|u| u.name.starts_with(&format!("{}:", email)))
        {
            println!("{}", serde_json::to_string_pretty(user)?);
            return Ok(());
        }
    }
    Err(anyhow!("User not found: {}", email))
}

fn cmd_show(paths: &Paths) -> Result<()> {
    eprintln!("Config ({:?}):", paths.config);
    if paths.config.exists() {
        let content = fs::read_to_string(&paths.config)?;
        println!("{}", content);
    }
    eprintln!("\nPUBKEY ({:?}):", paths.pubkey);
    if paths.pubkey.exists() {
        let content = fs::read_to_string(&paths.pubkey)?;
        println!("{}", content);
    }
    Ok(())
}

fn cmd_check(paths: &Paths) -> Result<()> {
    let input_path = paths.get_input_config_path();
    eprintln!(
        "{} Checking configuration at {:?}...",
        "[INFO]".green(),
        input_path
    );

    // 1. sing-box native check
    eprintln!("{} Running 'sing-box check'...", "[INFO]".green());
    let check_status = Command::new("sing-box")
        .args(["check", "-c", input_path.to_str().unwrap()])
        .status();

    match check_status {
        Ok(status) if status.success() => {
            eprintln!("{} 'sing-box check' passed.", "[INFO]".green());
        }
        _ => {
            return Err(anyhow!(
                "'sing-box check' failed. Invalid configuration syntax."
            ));
        }
    }

    // 2. Internal Consistency Checks
    eprintln!(
        "{} Running internal consistency checks...",
        "[INFO]".green()
    );
    let config = load_config(input_path)?;
    let mut warnings = 0;

    if let Some(inbound) = config.inbounds.first() {
        // Collect ShortIDs
        let mut valid_sids = Vec::new();
        if let Some(tls) = &inbound.tls {
            if let Some(reality) = &tls.reality {
                valid_sids = reality.short_id.clone();
            } else {
                eprintln!(
                    "{} Missing Reality configuration in first inbound.",
                    "[WARN]".yellow()
                );
                warnings += 1;
            }
        } else {
            eprintln!(
                "{} Missing TLS configuration in first inbound.",
                "[WARN]".yellow()
            );
            warnings += 1;
        }

        // Check Users
        for user in &inbound.users {
            let parts: Vec<&str> = user.name.split(':').collect();

            // Expected format: email:sid:level
            if parts.len() < 3 {
                eprintln!(
                    "{} User '{}' has invalid name format (expected email:sid:level).",
                    "[WARN]".yellow(),
                    user.name
                );
                warnings += 1;
                continue;
            }

            // Extract SID (second to last element)
            let sid = parts[parts.len() - 2];

            if !valid_sids.contains(&sid.to_string()) {
                eprintln!(
                    "{} User '{}' uses ShortID '{}' which is missing from reality.short_id list.",
                    "[WARN]".yellow(),
                    user.name,
                    sid
                );
                warnings += 1;
            }

            // Check UUID format
            if uuid::Uuid::parse_str(&user.uuid).is_err() {
                eprintln!(
                    "{} User '{}' has invalid UUID: {}",
                    "[WARN]".yellow(),
                    user.name,
                    user.uuid
                );
                warnings += 1;
            }
        }
    } else {
        eprintln!("{} No inbounds defined.", "[WARN]".yellow());
        warnings += 1;
    }

    if warnings == 0 {
        eprintln!("{} Internal consistency check passed.", "[INFO]".green());
    } else {
        eprintln!(
            "{} Consistency check finished with {} warning(s).",
            "[WARN]".yellow(),
            warnings
        );
    }

    Ok(())
}
