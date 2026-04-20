use anyhow::{Context, Result};
use std::process::Command;

const GIST_CONFIG_PATH: &str = "/etc/mimic-node/gist-id.conf";

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct GistConfig {
    pub gist_id: String,
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remark: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub convert_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cron: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct GistInfo {
    pub gist_id: String,
    pub remark: Option<String>,
    pub username: String,
    pub node_name: Option<String>,
    pub convert_type: Option<String>,
    pub cron: Option<String>,
}

impl GistConfig {
    pub fn load() -> Result<Self> {
        let content = std::fs::read_to_string(GIST_CONFIG_PATH)
            .with_context(|| format!("Failed to read {}", GIST_CONFIG_PATH))?;
        let config: GistConfig = toml::from_str(&content)
            .with_context(|| "Failed to parse gist config")?;
        Ok(config)
    }

    pub fn save(&self) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .context("Failed to serialize gist config")?;
        std::fs::write(GIST_CONFIG_PATH, content)
            .with_context(|| format!("Failed to write {}", GIST_CONFIG_PATH))?;
        Ok(())
    }
}

pub fn setup(gist_id: Option<&str>, username: &str, remark: Option<&str>, node_name: Option<&str>, convert_type: Option<&str>, cron: Option<&str>) -> Result<()> {
    let gist_id = if let Some(id) = gist_id {
        id.to_string()
    } else {
        // Create a new gist automatically with placeholder
        let placeholder = "/tmp/mimic-gist-placeholder.txt";
        std::fs::write(placeholder, "Mimic-Node subscription\n")?;
        let output = Command::new("gh")
            .args(["gist", "create", "-f", "placeholder.txt", placeholder, "-d", "Mimic-Node"])
            .output()
            .context("Failed to create gist")
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        let _ = std::fs::remove_file(placeholder);

        if !output.status.success() {
            anyhow::bail!("Failed to create gist: {}", String::from_utf8_lossy(&output.stderr));
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        let created_gist_id = output_str
            .trim()
            .split('/')
            .last()
            .unwrap_or_default()
            .to_string();

        if created_gist_id.is_empty() {
            anyhow::bail!("Failed to parse created gist ID");
        }

        println!("Created new gist: {}", created_gist_id);
        created_gist_id
    };

    let config = GistConfig {
        gist_id,
        username: username.to_string(),
        remark: remark.map(|s| s.to_string()),
        node_name: node_name.map(|s| s.to_string()),
        convert_type: convert_type.map(|s| s.to_string()),
        cron: cron.map(|s| s.to_string()),
    };
    config.save()?;
    println!("Gist config saved to {}", GIST_CONFIG_PATH);
    println!("Username: {}", username);
    if let Some(ref r) = config.remark {
        println!("Remark: {}", r);
    }
    let display_name = config.node_name.as_ref().map(|s| s.as_str()).unwrap_or("mimic-node");
    println!("Node name prefix: {}", display_name);
    let ct = convert_type.unwrap_or("v2ray");
    println!("Convert type: {}", ct);
    if let Some(ref c) = config.cron {
        println!("Cron: {}", c);
    }
    Ok(())
}

pub fn revoke(gist_id: Option<&str>) -> Result<()> {
    let old_gist_id = if let Some(id) = gist_id {
        id.to_string()
    } else {
        let config = GistConfig::load()?;
        config.gist_id
    };

    // Load existing config to get settings for new gist
    let existing_config = GistConfig::load().ok();

    let output = Command::new("gh")
        .args(["gist", "delete", &old_gist_id])
        .output()
        .context("Failed to execute gh gist delete")?;

    if !output.status.success() {
        anyhow::bail!("Failed to delete gist: {}", String::from_utf8_lossy(&output.stderr));
    }

    println!("Gist {} deleted", old_gist_id);

    // Create a new gist with same settings
    let placeholder = "/tmp/mimic-gist-placeholder.txt";
    std::fs::write(placeholder, "Mimic-Node subscription\n")?;

    let output = Command::new("gh")
        .args(["gist", "create", "-f", "placeholder.txt", placeholder, "-d", "Mimic-Node"])
        .output()
        .context("Failed to create new gist")?;
    let _ = std::fs::remove_file(placeholder);

    if !output.status.success() {
        anyhow::bail!("Failed to create new gist: {}", String::from_utf8_lossy(&output.stderr));
    }

    let output_str = String::from_utf8_lossy(&output.stdout);
    let new_gist_id = output_str
        .trim()
        .split('/')
        .last()
        .unwrap_or_default()
        .to_string();

    if new_gist_id.is_empty() {
        anyhow::bail!("Failed to parse new gist ID");
    }

    println!("Created new gist: {}", new_gist_id);

    // Save new config
    let config = GistConfig {
        gist_id: new_gist_id.clone(),
        username: existing_config.as_ref().map(|c| c.username.as_str()).unwrap_or("root").to_string(),
        remark: existing_config.as_ref().and_then(|c| c.remark.clone()),
        node_name: existing_config.as_ref().and_then(|c| c.node_name.clone()),
        convert_type: existing_config.as_ref().and_then(|c| c.convert_type.clone()),
        cron: existing_config.as_ref().and_then(|c| c.cron.clone()),
    };
    config.save()?;

    println!("Config updated with new gist ID");
    Ok(())
}

pub fn rm(gist_id: Option<&str>) -> Result<()> {
    let gist_id = if let Some(id) = gist_id {
        id.to_string()
    } else {
        let config = GistConfig::load()?;
        config.gist_id
    };

    let output = Command::new("gh")
        .args(["gist", "delete", &gist_id])
        .output()
        .context("Failed to execute gh gist delete")?;

    if !output.status.success() {
        anyhow::bail!("Failed to delete gist: {}", String::from_utf8_lossy(&output.stderr));
    }

    std::fs::remove_file(GIST_CONFIG_PATH)
        .with_context(|| format!("Failed to remove {}", GIST_CONFIG_PATH))?;

    println!("Gist {} deleted and config removed", gist_id);
    Ok(())
}

pub fn list() -> Result<()> {
    // First show local config if exists
    if let Ok(config) = GistConfig::load() {
        println!("=== Local Gist Config ===");
        println!("Gist ID: {}", config.gist_id);
        println!("Username: {}", config.username);
        if let Some(ref remark) = config.remark {
            println!("Remark: {}", remark);
        }
        if let Some(ref node_name) = config.node_name {
            println!("Node name: {}", node_name);
        }
        if let Some(ref convert_type) = config.convert_type {
            println!("Convert type: {}", convert_type);
        }
        if let Some(ref cron) = config.cron {
            println!("Cron: {}", cron);
        }

        // Get GitHub username for raw URL
        let gh_user = Command::new("gh")
            .args(["api", "user", "-q", ".login"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|_| "LIghtJUNction".to_string());

        println!("\nRaw URL: https://gist.githubusercontent.com/{}/{}/raw/subscription.txt", gh_user, config.gist_id);
        println!();
    }

    // List all gists from GitHub
    println!("=== GitHub Gists ===");
    let output = Command::new("gh")
        .args(["gist", "list", "--limit", "30"])
        .output()
        .context("Failed to list gists")?;

    if output.status.success() {
        let gists = String::from_utf8_lossy(&output.stdout);
        if gists.trim().is_empty() {
            println!("No gists found");
        } else {
            // Parse and display each gist
            // Format: gist_id\tdescription\n
            for line in gists.lines() {
                if let Some((id, desc)) = line.split_once('\t') {
                    println!("{}  {}", id, desc);
                } else {
                    println!("{}", line);
                }
            }
        }
    } else {
        eprintln!("Failed to list gists: {}", String::from_utf8_lossy(&output.stderr));
    }

    Ok(())
}

pub fn sync(include_hy2: bool) -> Result<()> {
    let config = GistConfig::load()?;

    use base64::Engine;

    // Get VLESS links
    let output = Command::new("mimictl")
        .args(["link", &config.username])
        .output()
        .context("Failed to run mimictl link")?;

    if !output.status.success() {
        anyhow::bail!("mimictl link failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    let link_output = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if link_output.is_empty() {
        anyhow::bail!("mimictl link returned empty output");
    }

    println!("Got VLESS link for {}", config.username);

    // Parse JSON array output from mimictl link
    let vless_links: Vec<String> = serde_json::from_str(&link_output)
        .unwrap_or_else(|_| vec![link_output.clone()]);

    // Get Hysteria2 link if requested
    let mut all_links = vless_links;
    if include_hy2 {
        let hy2_output = Command::new("mimictl")
            .args(["hysteria2", "link"])
            .output()
            .context("Failed to run hysteria2 link")?;

        if hy2_output.status.success() {
            let hy2_link = String::from_utf8_lossy(&hy2_output.stdout).trim().to_string();
            if !hy2_link.is_empty() {
                println!("Got Hysteria2 link");
                all_links.push(hy2_link);
            }
        }
    }

    // Use node_name from config, or "mimic-node" as fallback
    let base_name = config.node_name.clone().unwrap_or_else(|| "mimic-node".to_string());

    // Categorize links by type and assign names
    let mut ipv4_count = 0;
    let mut ipv6_count = 0;
    let mut hy2_count = 0;

    let encoded_lines: Vec<String> = all_links.iter().filter_map(|link| {
        if let Some(pos) = link.find("://") {
            let proto = &link[..pos + 3]; // includes ://
            let rest = &link[pos + 3..];

            // Split content and old fragment
            let (content, _old_fragment) = rest.split_once('#').unwrap_or((rest, ""));

            // Base64 encode the content (without the old fragment)
            let encoded_content = base64::engine::general_purpose::STANDARD.encode(content.as_bytes());

            // Assign node name based on link type
            let node_name = if link.starts_with("vless://") {
                if link.contains("[") {
                    // IPv6 address
                    ipv6_count += 1;
                    format!("{}-VLESS-IPv6-{}", base_name, ipv6_count)
                } else {
                    // IPv4 address
                    ipv4_count += 1;
                    format!("{}-VLESS-IPv4-{}", base_name, ipv4_count)
                }
            } else if link.starts_with("hysteria2://") || link.starts_with("hy2://") {
                hy2_count += 1;
                format!("{}-HY2-{}", base_name, hy2_count)
            } else {
                base_name.clone()
            };

            // Result: vless://base64(content)#nodename
            Some(format!("{}{}#{}", proto, encoded_content, node_name))
        } else {
            None
        }
    }).collect();

    if encoded_lines.is_empty() {
        anyhow::bail!("No valid links found");
    }

    // Join lines and final base64 encode
    let lines_str = encoded_lines.join("\n");
    let final_encoded = base64::engine::general_purpose::STANDARD.encode(lines_str.as_bytes());

    let filename = "subscription.txt";
    let temp_file = format!("/tmp/{}", filename);
    std::fs::write(&temp_file, &final_encoded)
        .context("Failed to write temp file")?;

    // Create JSON input for gh api
    let json_input = serde_json::json!({
        "files": {
            "subscription.txt": {
                "content": final_encoded
            }
        }
    });
    let json_file = format!("{}.json", temp_file);
    std::fs::write(&json_file, &json_input.to_string())
        .context("Failed to write json input file")?;

    // Use gh api with --input to read JSON from file
    let output = Command::new("gh")
        .args(["api", &format!("gists/{}", config.gist_id), "--method", "PATCH", "--input", &json_file])
        .output()
        .context("Failed to update gist via API")?;

    let _ = std::fs::remove_file(&temp_file);
    let _ = std::fs::remove_file(&json_file);

    if !output.status.success() {
        // Fallback: delete and recreate
        let _ = Command::new("gh")
            .args(["gist", "delete", &config.gist_id])
            .output();

        let output = Command::new("gh")
            .args(["gist", "create", "-d", "Mimic-Node", "-f", filename, &temp_file])
            .output()
            .context("Failed to create gist")?;

        if !output.status.success() {
            anyhow::bail!("Failed to sync gist: {}", String::from_utf8_lossy(&output.stderr));
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        let new_gist_id = output_str.trim().split('/').last().unwrap_or_default().to_string();

        let config = GistConfig {
            gist_id: new_gist_id.clone(),
            username: config.username.clone(),
            remark: config.remark.clone(),
            node_name: config.node_name.clone(),
            convert_type: config.convert_type.clone(),
            cron: config.cron.clone(),
        };
        config.save()?;
        println!("Subscription synced to new gist {}", new_gist_id);
    } else {
        println!("Subscription synced to gist {}", config.gist_id);
    }

    // Get GitHub username for raw URL
    let gh_user = Command::new("gh")
        .args(["api", "user", "-q", ".login"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "LIghtJUNction".to_string());

    println!("Raw URL: https://gist.githubusercontent.com/{}/{}/raw/subscription.txt", gh_user, config.gist_id);
    Ok(())
}
