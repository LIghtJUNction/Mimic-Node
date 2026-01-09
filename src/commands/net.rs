use anyhow::{Result, anyhow};
use colored::*;
use std::fs;
use std::io::{self, BufRead};
use std::process::Command;
use tokio::time::Duration;

use crate::paths::Paths;
use crate::utils::{load_config, save_config};

pub async fn sni(
    paths: &Paths,
    target_sni: Option<String>,
    file: Option<std::path::PathBuf>,
) -> Result<()> {
    let sni_to_set: String;

    if let Some(sni) = target_sni {
        sni_to_set = sni;
        eprintln!("{} Setting custom SNI: {}", "[INFO]".green(), sni_to_set);
    } else {
        // Auto-detect: choose SNI list file (CLI flag takes precedence)
        let sni_path = if let Some(p) = file {
            p
        } else {
            paths.sni_list.clone()
        };

        if !sni_path.exists() {
            return Err(anyhow!("SNI list file not found: {:?}", sni_path));
        }
        eprintln!(
            "{} Auto-detecting best SNI from {:?}...",
            "[INFO]".green(),
            sni_path
        );

        let f = fs::File::open(&sni_path)?;
        let reader = io::BufReader::new(f);

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

            if let Ok(output) = sing_box_check
                && output.status.success()
            {
                eprintln!("\n{} Found perfect match: {}", "[INFO]".green(), cand);
                found_perfect = Some(cand);
                break;
            }

            // 3. Fallback H2 check
            // Since we configured client with http2_prior_knowledge/support, we can check version?
            // Actually, for a real H2 check on HTTPS, we need ALPN. reqwest supports it by default.
            if best_fallback.is_none()
                && let Ok(response) = resp
                && response.version() == reqwest::Version::HTTP_2
            {
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

    if let Some(inbound) = config.inbounds.first_mut()
        && let Some(tls) = inbound.tls.as_mut()
    {
        tls.server_name = sni_to_set.clone();
        if let Some(reality) = tls.reality.as_mut() {
            reality.handshake.server = sni_to_set.clone();
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

        if detect_v4
            && let Ok(ip) = client.get("https://api.ipify.org").send().await
            && let Ok(text) = ip.text().await
        {
            addresses.push(text);
        }
        if detect_v6
            && let Ok(ip) = client.get("https://api6.ipify.org").send().await
            && let Ok(text) = ip.text().await
        {
            addresses.push(text);
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

        // Use a safe fragment label derived from SID (first 4 chars) to avoid special characters in `user.name`
        let label = sid_label(&sid);
        let link = format!(
            "vless://{}@{}:{}?security=reality&encryption=none&pbk={}&fp=chrome&type=tcp&sni={}&sid={}&flow={}#{}",
            user.uuid, host, port, pbk, sni, sid, user.flow, label
        );
        links.push(link);
    }

    println!("{}", serde_json::to_string_pretty(&links)?);

    Ok(())
}

// Helper: derive a safe label from SID (first 4 chars)
fn sid_label(sid: &str) -> String {
    sid.get(0..4)
        .map(|s| s.to_string())
        .unwrap_or_else(|| sid.to_string())
}

// tests moved to end of file

#[cfg(feature = "completions")]
use clap::CommandFactory;
#[cfg(feature = "completions")]
use clap_complete::{
    generate_to,
    shells::{Bash, Elvish, Fish, PowerShell, Zsh},
};

#[cfg(feature = "completions")]
pub fn completions(shell: Option<String>, apply: bool) -> Result<()> {
    use std::io::Write;
    use std::path::PathBuf;

    let shell_name = if let Some(s) = shell {
        s
    } else {
        std::env::var("SHELL")
            .unwrap_or_else(|_| "bash".to_string())
            .split('/')
            .next_back()
            .unwrap()
            .to_string()
    };

    let mut cmd = crate::cli::Cli::command();

    let out_dir = std::env::var("XDG_CACHE_HOME")
        .map(|p| PathBuf::from(p).join("mimic-node-completions"))
        .unwrap_or_else(|_| {
            PathBuf::from(std::env::var("HOME").unwrap()).join(".cache/mimic-node-completions")
        });

    std::fs::create_dir_all(&out_dir)?;

    let generated_path = match shell_name.as_str() {
        "bash" => generate_to(Bash, &mut cmd, "mimictl", &out_dir)?,
        "zsh" => generate_to(Zsh, &mut cmd, "mimictl", &out_dir)?,
        "fish" => generate_to(Fish, &mut cmd, "mimictl", &out_dir)?,
        "pwsh" | "powershell" => generate_to(PowerShell, &mut cmd, "mimictl", &out_dir)?,
        "elvish" => generate_to(Elvish, &mut cmd, "mimictl", &out_dir)?,
        other => return Err(anyhow!("Unsupported shell: {}", other)),
    };

    println!(
        "{} Generated completion at {:?}",
        "[INFO]".green(),
        generated_path
    );

    if apply {
        let home =
            std::env::var("HOME").map_err(|_| anyhow!("HOME environment variable not set"))?;
        match shell_name.as_str() {
            "bash" => {
                let rc = PathBuf::from(home).join(".bashrc");
                let source_line = format!(
                    "\n# mimictl completions\nsource \"{}\"\n",
                    generated_path.display()
                );
                if rc.exists() {
                    let content = std::fs::read_to_string(&rc)?;
                    if !content.contains(&source_line) {
                        let mut f = std::fs::OpenOptions::new().append(true).open(&rc)?;
                        f.write_all(source_line.as_bytes())?;
                        println!("{} Appended source line to {:?}", "[INFO]".green(), rc);
                    } else {
                        println!(
                            "{} Source line already present in {:?}",
                            "[INFO]".green(),
                            rc
                        );
                    }
                } else {
                    std::fs::write(&rc, source_line)?;
                    println!("{} Created {:?} with source line", "[INFO]".green(), rc);
                }
            }
            "zsh" => {
                let rc = PathBuf::from(home).join(".zshrc");
                let source_line = format!(
                    "\n# mimictl completions\nsource \"{}\"\n",
                    generated_path.display()
                );
                if rc.exists() {
                    let content = std::fs::read_to_string(&rc)?;
                    if !content.contains(&source_line) {
                        let mut f = std::fs::OpenOptions::new().append(true).open(&rc)?;
                        f.write_all(source_line.as_bytes())?;
                        println!("{} Appended source line to {:?}", "[INFO]".green(), rc);
                    } else {
                        println!(
                            "{} Source line already present in {:?}",
                            "[INFO]".green(),
                            rc
                        );
                    }
                } else {
                    std::fs::write(&rc, source_line)?;
                    println!("{} Created {:?} with source line", "[INFO]".green(), rc);
                }
            }
            "fish" => {
                let comp_dir = PathBuf::from(home).join(".config/fish/completions");
                std::fs::create_dir_all(&comp_dir)?;
                let dest = comp_dir.join("mimictl.fish");
                std::fs::copy(&generated_path, &dest)?;
                println!(
                    "{} Installed fish completion to {:?}",
                    "[INFO]".green(),
                    dest
                );
            }
            other => {
                eprintln!(
                    "{} Automatic apply for shell '{}' is not implemented; you can source the file manually: {:?}",
                    "[WARN]".yellow(),
                    other,
                    generated_path
                );
            }
        }
    }

    Ok(())
}

#[cfg(not(feature = "completions"))]
pub fn completions(_shell: Option<String>, _apply: bool) -> Result<()> {
    Err(anyhow!(
        "Completions feature not enabled at compile time. Rebuild with --features completions"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sid_label_truncates() {
        assert_eq!(sid_label("abcd1234"), "abcd");
    }

    #[test]
    fn test_sid_label_shorter() {
        assert_eq!(sid_label("ab"), "ab");
    }

    #[test]
    fn test_link_fragment_uses_sid_label() {
        let uuid = "uuid";
        let host = "1.2.3.4";
        let port = 443;
        let pbk = "pbk";
        let sni = "sni.example";
        let sid = "abcd1234";
        let flow = "flow";
        let label = sid_label(sid);
        let link = format!(
            "vless://{}@{}:{}?security=reality&encryption=none&pbk={}&fp=chrome&type=tcp&sni={}&sid={}&flow={}#{}",
            uuid, host, port, pbk, sni, sid, flow, label
        );
        assert!(link.ends_with("#abcd"));
    }
}
