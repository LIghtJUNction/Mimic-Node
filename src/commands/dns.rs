use anyhow::Result;
use colored::*;
use serde_json::Value;

use crate::paths::Paths;

pub fn setup(
    paths: &Paths,
    dry_run: bool,
) -> Result<()> {
    let input_path = paths.get_input_config_path();
    let config_str = std::fs::read_to_string(input_path)?;
    let mut config_json: Value = serde_json::from_str(&config_str)?;

    eprintln!("{} Configuring DNS with DoH3 (DNS over HTTP3)...", "[INFO]".green());

    // Update DNS servers to use DoH3
    let dns_servers = serde_json::json!([
        {
            "tag": "google",
            "type": "h3",
            "server": "dns.google",
            "server_port": 443,
            "path": "/dns-query"
        },
        {
            "tag": "alidns",
            "type": "udp",
            "server": "223.5.5.5"
        }
    ]);

    if let Some(dns) = config_json.get_mut("dns") {
        dns["servers"] = dns_servers;
    }

    if dry_run {
        eprintln!("{} [DRY RUN] Changes staged (not written)", "[WARN]".yellow());
        println!("{}", serde_json::to_string_pretty(&config_json)?);
    } else {
        std::fs::write(&paths.staging, serde_json::to_string_pretty(&config_json)?)?;
        eprintln!(
            "{} DNS config staged. Run 'mimictl apply' to activate.",
            "[INFO]".green()
        );
    }

    Ok(())
}

pub fn add_server(
    paths: &Paths,
    tag: String,
    server: String,
    server_type: String,
    port: Option<u16>,
    path: Option<String>,
    dry_run: bool,
) -> Result<()> {
    let input_path = paths.get_input_config_path();
    let config_str = std::fs::read_to_string(input_path)?;
    let mut config_json: Value = serde_json::from_str(&config_str)?;

    eprintln!("{} Adding DNS server '{}'...", "[INFO]".green(), tag);

    let mut new_server = serde_json::json!({
        "tag": tag,
        "type": server_type,
        "server": server
    });

    if let Some(p) = port {
        new_server["server_port"] = serde_json::json!(p);
    }

    if let Some(ref p) = path {
        new_server["path"] = serde_json::json!(p);
    }

    if let Some(dns) = config_json.get_mut("dns").and_then(|d| d.get_mut("servers")).and_then(|s| s.as_array_mut()) {
        dns.push(new_server);
    }

    if dry_run {
        eprintln!("{} [DRY RUN] Changes staged (not written)", "[WARN]".yellow());
        println!("{}", serde_json::to_string_pretty(&config_json)?);
    } else {
        std::fs::write(&paths.staging, serde_json::to_string_pretty(&config_json)?)?;
        eprintln!(
            "{} DNS server added. Run 'mimictl apply' to activate.",
            "[INFO]".green()
        );
    }

    Ok(())
}
