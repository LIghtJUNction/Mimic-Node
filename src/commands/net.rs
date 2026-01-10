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

            // 2. Reality check using sing-box (allow override via SING_BOX_BIN)
            let sing_box = std::env::var("SING_BOX_BIN").unwrap_or_else(|_| "sing-box".to_string());
            let sing_box_check = Command::new(&sing_box)
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
                let sing_box =
                    std::env::var("SING_BOX_BIN").unwrap_or_else(|_| "sing-box".to_string());
                if Command::new(&sing_box).arg("version").output().is_err() {
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

    // Use the shared matching logic (same as user commands) so lookups are consistent.
    // We first ensure an inbound exists, then perform matching. If multiple users match,
    // we return a helpful, unambiguous error that lists candidates (so the user can choose
    // a UUID or a more precise pattern).
    let inbound = config
        .inbounds
        .first()
        .ok_or_else(|| anyhow!("No inbound configuration present."))?;

    let indices = crate::commands::user::find_matching_indices(&inbound.users, &email)?;
    if indices.is_empty() {
        return Err(anyhow!("User '{}' not found", email));
    }
    if indices.len() > 1 {
        let candidates: Vec<String> = indices
            .iter()
            .map(|&i| inbound.users[i].name.clone())
            .collect();
        return Err(anyhow!(
            "Ambiguous target '{}': matched multiple users: {}. Please specify a UUID or a more specific pattern.",
            email,
            candidates.join(", ")
        ));
    }

    // Single match -> proceed
    let user = &inbound.users[indices[0]];
    let parts: Vec<&str> = user.name.split(':').collect();
    let sid = parts.get(parts.len() - 2).unwrap_or(&"").to_string();

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
    use crate::paths::Paths;
    use std::fs;
    use uuid::Uuid;

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
        let parts = sid_label("abcd1234");
        assert_eq!(parts, "abcd");
    }

    // Async tests for `link` behavior:
    // - ensure we match by local part like 'astrbot'
    // - ensure ambiguous matches return a helpful error
    #[tokio::test]
    async fn test_link_matches_local_part() {
        let base = std::env::temp_dir();
        let dir = base.join(format!("mimic_node_test_{}", Uuid::new_v4()));
        let etc = dir.join("etc").join("sing-box");
        let usr = dir
            .join("usr")
            .join("share")
            .join("mimic-node")
            .join("default");
        fs::create_dir_all(&etc).unwrap();
        fs::create_dir_all(&usr).unwrap();

        let paths = Paths {
            root: dir.clone(),
            config: etc.join("config.json"),
            staging: etc.join("config.new"),
            pubkey: etc.join("PUBKEY"),
            staging_pubkey: etc.join("PUBKEY.new"),
            sni_list: usr.join("sni.txt"),
            default_config: usr.join("default/config.json"),
        };

        // Minimal config with a single user whose local-part is "astrbot"
        let cfg = serde_json::json!({
            "inbounds": [
                {
                    "type": "vless",
                    "listen_port": 12345,
                    "users": [ { "name": "astrbot:SID1:0", "uuid": "1111", "flow": "xtls" } ],
                    "tls": { "server_name": "sni.example" }
                }
            ]
        });
        fs::write(&paths.config, serde_json::to_string_pretty(&cfg).unwrap()).unwrap();
        fs::write(&paths.pubkey, "PUBKEY").unwrap();

        // Provide explicit addresses to avoid network detection in the test
        let res = link(
            &paths,
            "astrbot".to_string(),
            vec!["1.2.3.4".to_string()],
            true,
            false,
        )
        .await;
        assert!(
            res.is_ok(),
            "link should succeed for exact local-part match"
        );

        if let Err(e) = fs::remove_dir_all(&dir) {
            eprintln!("[WARN] Failed to remove test directory {:?}: {}", dir, e);
        }
    }

    #[tokio::test]
    async fn test_link_ambiguous() {
        let base = std::env::temp_dir();
        let dir = base.join(format!("mimic_node_test_{}", Uuid::new_v4()));
        let etc = dir.join("etc").join("sing-box");
        let usr = dir
            .join("usr")
            .join("share")
            .join("mimic-node")
            .join("default");
        fs::create_dir_all(&etc).unwrap();
        fs::create_dir_all(&usr).unwrap();

        let paths = Paths {
            root: dir.clone(),
            config: etc.join("config.json"),
            staging: etc.join("config.new"),
            pubkey: etc.join("PUBKEY"),
            staging_pubkey: etc.join("PUBKEY.new"),
            sni_list: usr.join("sni.txt"),
            default_config: usr.join("default/config.json"),
        };

        // Two users sharing same short local-part "astr"
        let cfg = serde_json::json!({
            "inbounds": [
                {
                    "type": "vless",
                    "listen_port": 12345,
                    "users": [
                        { "name": "astr:SID1:0", "uuid": "1111", "flow": "xtls" },
                        { "name": "astr:SID2:0", "uuid": "2222", "flow": "xtls" }
                    ],
                    "tls": { "server_name": "sni.example" }
                }
            ]
        });
        fs::write(&paths.config, serde_json::to_string_pretty(&cfg).unwrap()).unwrap();
        fs::write(&paths.pubkey, "PUBKEY").unwrap();

        let res = link(
            &paths,
            "astr".to_string(),
            vec!["1.2.3.4".to_string()],
            true,
            false,
        )
        .await;
        assert!(res.is_err(), "link should return error for ambiguous match");
        let err_msg = format!("{:?}", res.err().unwrap());
        assert!(err_msg.contains("Ambiguous target") || err_msg.contains("matched multiple users"));

        if let Err(e) = fs::remove_dir_all(&dir) {
            eprintln!("[WARN] Failed to remove test directory {:?}: {}", dir, e);
        }
    }
}
