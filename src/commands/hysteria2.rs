use anyhow::Result;
use colored::*;
use serde_json::Value;
use std::process::Command;

use crate::paths::Paths;

fn generate_password(length: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    (0..length)
        .map(|_| {
            let idx = (rand::random::<f64>() * CHARSET.len() as f64) as usize % CHARSET.len();
            CHARSET[idx] as char
        })
        .collect()
}

fn generate_obfs_password() -> String {
    generate_password(16)
}

fn check_certbot() -> bool {
    Command::new("certbot")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn run_certbot(domain: &str, cert_path: &str, key_path: &str) -> Result<()> {
    eprintln!("{} Running certbot for domain: {}", "[INFO]".green(), domain);

    let output = Command::new("certbot")
        .args([
            "certonly",
            "--standalone",
            "-d",
            domain,
            "--non-interactive",
            "--agree-tos",
            "-m",
            "admin@localhost",
            "--http-01-port",
            "80",
        ])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("certbot failed: {}", stderr));
    }

    // Certbot stores certificates in /etc/letsencrypt/live/{domain}/
    let live_path = format!("/etc/letsencrypt/live/{}/fullchain.pem", domain);
    let key_path_live = format!("/etc/letsencrypt/live/{}/privkey.pem", domain);

    // Copy or symlink to target paths
    std::fs::copy(&live_path, cert_path)?;
    std::fs::copy(&key_path_live, key_path)?;

    eprintln!("{} Certificate generated successfully", "[INFO]".green());
    Ok(())
}

pub fn setup(
    paths: &Paths,
    port: u16,
    password: Option<String>,
    masquerade: Option<String>,
    domain: Option<String>,
    cert_path: Option<String>,
    key_path: Option<String>,
    up_mbps: Option<u32>,
    down_mbps: Option<u32>,
    obfs: bool,
    http2_idle_timeout: Option<String>,
    http2_keep_alive_period: Option<String>,
    http2_max_concurrent_streams: Option<u32>,
    quic_initial_packet_size: Option<u32>,
    quic_disable_path_mtu_discovery: bool,
    dry_run: bool,
) -> Result<()> {
    let input_path = paths.get_input_config_path();
    let config_str = std::fs::read_to_string(input_path)?;
    let mut config_json: Value = serde_json::from_str(&config_str)?;

    let pwd = password.clone().unwrap_or_else(|| generate_password(32));
    let obfs_pwd = if obfs { Some(generate_obfs_password()) } else { None };

    let cert = cert_path.clone().unwrap_or_else(|| "/path/to/cert.crt".to_string());
    let key = key_path.clone().unwrap_or_else(|| "/path/to/cert.key".to_string());

    // If domain is provided, try certbot
    if let Some(ref dom) = domain {
        if check_certbot() {
            run_certbot(dom, &cert, &key)?;
        } else {
            eprintln!("{} certbot not found, skipping certificate generation", "[WARN]".yellow());
        }
    }

    eprintln!("{} Setting up Hysteria2 inbound...", "[INFO]".green());
    eprintln!("  {}: {}", "Port".cyan(), port);
    eprintln!(
        "{}: {}",
        "Password".cyan(),
        if password.is_some() {
            "(provided)".to_string()
        } else {
            "(auto-generated)".to_string()
        }
    );
    eprintln!(
        "{}: {}",
        "Masquerade".cyan(),
        masquerade.as_deref().unwrap_or("https://microsoft.com")
    );
    if let Some(ref m) = masquerade {
        eprintln!("  {}: {}", "Masquerade".cyan(), m);
    }
    if let Some(ref d) = domain {
        eprintln!("  {}: {}", "Domain".cyan(), d);
    }
    if let (Some(up), Some(down)) = (up_mbps, down_mbps) {
        eprintln!("  {}: {} Mbps  {}: {} Mbps", "up_mbps".cyan(), up, "down_mbps".cyan(), down);
    }
    if obfs_pwd.is_some() {
        eprintln!("  {}: enabled (salamander)", "Obfs".cyan());
    }

    let masquerade_val = masquerade.unwrap_or_else(|| "https://microsoft.com".to_string());

    // Build the new hy2 inbound JSON with standard structure
    let mut hy2_json = serde_json::json!({
        "type": "hysteria2",
        "tag": "hy2-in",
        "listen": "::",
        "listen_port": port,
        "up_mbps": up_mbps.unwrap_or(100),
        "down_mbps": down_mbps.unwrap_or(100),
        "users": [
            {
                "name": "admin",
                "password": pwd
            }
        ],
        "ignore_client_bandwidth": false,
        "tls": {
            "enabled": true,
            "alpn": ["h3"],
            "cert_path": cert,
            "key_path": key
        },
        "masquerade": masquerade_val,
    });

    // Add QUIC fields if provided
    if let Some(initial_size) = quic_initial_packet_size {
        hy2_json["initial_packet_size"] = serde_json::json!(initial_size);
    }
    if quic_disable_path_mtu_discovery {
        hy2_json["disable_path_mtu_discovery"] = serde_json::json!(true);
    }

    // Add HTTP2 fields if provided
    if let (Some(idle), Some(keepalive), Some(streams)) = (http2_idle_timeout, http2_keep_alive_period, http2_max_concurrent_streams) {
        hy2_json["tls"]["http2_idle_timeout"] = serde_json::json!(idle);
        hy2_json["tls"]["http2_keep_alive_period"] = serde_json::json!(keepalive);
        hy2_json["tls"]["http2_max_concurrent_streams"] = serde_json::json!(streams);
    }

    // Add obfs if enabled
    if let Some(ref obfs_pass) = obfs_pwd {
        hy2_json["obfs"] = serde_json::json!({
            "type": "salamander",
            "password": obfs_pass
        });
    }

    // Get inbounds array, remove existing hy2 if present, insert at correct position
    if let Some(inbounds) = config_json.get_mut("inbounds").and_then(|i| i.as_array_mut()) {
        // Remove existing hy2 inbound (by tag)
        inbounds.retain(|i| {
            i.get("tag")
                .and_then(|t| t.as_str())
                .map(|t| t != "hy2-in")
                .unwrap_or(true)
        });

        // Find VLESS inbound index to insert after it
        let insert_idx = inbounds
            .iter()
            .position(|i| {
                i.get("type")
                    .and_then(|t| t.as_str())
                    .map(|t| t == "vless")
                    .unwrap_or(false)
            })
            .map(|i| i + 1)
            .unwrap_or(inbounds.len());

        inbounds.insert(insert_idx, hy2_json);
    }

    if dry_run {
        eprintln!("{} [DRY RUN] Changes staged (not written)", "[WARN]".yellow());
        println!("{}", serde_json::to_string_pretty(&config_json)?);
    } else {
        std::fs::write(&paths.staging, serde_json::to_string_pretty(&config_json)?)?;
        eprintln!(
            "{} Hysteria2 config staged. Run 'mimictl apply' to activate.",
            "[INFO]".green()
        );
    }

    Ok(())
}

pub fn add_user(
    paths: &Paths,
    name: Option<String>,
    password: Option<String>,
    dry_run: bool,
) -> Result<()> {
    let input_path = paths.get_input_config_path();
    let config_str = std::fs::read_to_string(input_path)?;
    let mut config_json: Value = serde_json::from_str(&config_str)?;

    let user_name = name.unwrap_or_else(|| "admin".to_string());
    let pwd = password.clone().unwrap_or_else(|| generate_password(32));

    // Find and update hy2 inbound
    if let Some(inbounds) = config_json.get_mut("inbounds").and_then(|i| i.as_array_mut()) {
        let hy2_idx = inbounds.iter().position(|i| {
            i.get("tag")
                .and_then(|t| t.as_str())
                .map(|t| t == "hy2-in")
                .unwrap_or(false)
        });

        if let Some(idx) = hy2_idx {
            if let Some(users) = inbounds[idx]
                .get_mut("users")
                .and_then(|u| u.as_array_mut())
            {
                users.push(serde_json::json!({
                    "name": user_name,
                    "password": pwd.clone()
                }));
            }
        } else {
            return Err(anyhow::anyhow!(
                "Hysteria2 inbound 'hy2-in' not found. Run 'mimictl hysteria2 setup' first."
            ));
        }
    }

    if dry_run {
        eprintln!("{} [DRY RUN] Changes staged (not written)", "[WARN]".yellow());
        println!("{}", serde_json::to_string_pretty(&config_json)?);
    } else {
        std::fs::write(&paths.staging, serde_json::to_string_pretty(&config_json)?)?;
        eprintln!(
            "{} New Hysteria2 user added. Run 'mimictl apply' to activate.",
            "[INFO]".green()
        );
    }

    Ok(())
}
