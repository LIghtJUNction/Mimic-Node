use anyhow::{anyhow, Result};
use colored::*;
use std::fs;
use std::io::{self, BufRead};
use std::process::Command;
use tokio::time::Duration;

use crate::paths::Paths;
use crate::utils::{load_config, save_config};

pub async fn sni(paths: &Paths, target_sni: Option<String>) -> Result<()> {
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

pub async fn link(
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
