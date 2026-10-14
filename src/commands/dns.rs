use anyhow::{Context, Result, bail};
use colored::*;
use serde_json::{Value, json};
use std::net::IpAddr;

use crate::paths::Paths;

fn servers(config: &mut Value) -> Result<&mut Vec<Value>> {
    let root = config
        .as_object_mut()
        .context("Configuration must be a JSON object")?;
    let dns = root.entry("dns").or_insert_with(|| json!({}));
    let dns = dns.as_object_mut().context("dns must be a JSON object")?;
    dns.entry("servers")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .context("dns.servers must be an array")
}

pub(super) fn ensure_default_resolver(config: &mut Value) -> Result<()> {
    let route = config
        .as_object_mut()
        .context("Configuration must be a JSON object")?
        .entry("route")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .context("route must be a JSON object")?;
    if route.contains_key("default_domain_resolver") {
        return Ok(());
    }
    let preferred = config["dns"]["final"].as_str().map(str::to_owned);
    let servers = servers(config)?;
    let selected = preferred
        .filter(|tag| servers.iter().any(|s| s["tag"].as_str() == Some(tag)))
        .or_else(|| {
            servers.iter().find_map(|s| {
                s["tag"]
                    .as_str()
                    .filter(|tag| !tag.is_empty())
                    .map(str::to_owned)
            })
        })
        .unwrap_or_else(|| {
            servers.push(json!({"type": "local", "tag": "mimic-bootstrap"}));
            "mimic-bootstrap".to_string()
        });
    config["route"]["default_domain_resolver"] = json!(selected);
    Ok(())
}

fn configure_doh3(config: &mut Value) -> Result<()> {
    let servers = servers(config)?;
    // Keep other servers: existing DNS rules may still refer to their tags.
    for server in [
        json!({
            "tag": "google", "type": "h3", "server": "dns.google",
            "server_port": 443, "path": "/dns-query", "domain_resolver": "alidns"
        }),
        json!({"tag": "alidns", "type": "udp", "server": "223.5.5.5"}),
    ] {
        if let Some(existing) = servers.iter_mut().find(|s| s["tag"] == server["tag"]) {
            *existing = server;
        } else {
            servers.push(server);
        }
    }
    config["dns"]["final"] = json!("google");
    ensure_default_resolver(config)
}

fn add_dns_server(
    config: &mut Value,
    tag: &str,
    server: &str,
    server_type: &str,
    port: Option<u16>,
    path: Option<&str>,
) -> Result<()> {
    if tag.trim().is_empty() {
        bail!("DNS server tag must not be empty");
    }
    if !matches!(server_type, "h3" | "https" | "tls" | "quic" | "tcp" | "udp") {
        bail!("Unsupported DNS server type '{server_type}'; use h3, https, tls, quic, tcp or udp");
    }
    if port == Some(0) {
        bail!("DNS server port must be between 1 and 65535");
    }
    if let Some(path) = path {
        if !matches!(server_type, "h3" | "https") {
            bail!("--path is only supported for h3 and https DNS servers");
        }
        if !path.starts_with('/') {
            bail!("DNS request path must start with '/'");
        }
    }
    let server = server.trim_matches(['[', ']']);
    if server.is_empty() {
        bail!("DNS server address must not be empty");
    }
    // The address is a host, not a URL. Host parsing also rejects spaces and '/'.
    let host = if let Ok(ip) = server.parse::<IpAddr>() {
        ip.to_string()
    } else {
        url::Host::parse(server)
            .context("Invalid DNS server hostname")?
            .to_string()
    };
    let servers = servers(config)?;
    if servers.iter().any(|s| s["tag"].as_str() == Some(tag)) {
        bail!("DNS server tag '{tag}' already exists");
    }
    let mut new_server = json!({"tag": tag, "type": server_type, "server": host});
    if let Some(port) = port {
        new_server["server_port"] = json!(port);
    }
    if let Some(path) = path {
        new_server["path"] = json!(path);
    }
    if host.parse::<IpAddr>().is_err() {
        // A hostname needs an independent bootstrap resolver to avoid recursion.
        let bootstrap = servers
            .iter()
            .find_map(|s| {
                let tag = s["tag"].as_str().filter(|t| !t.is_empty())?;
                let local = s["type"].as_str() == Some("local");
                let ip = s["server"].as_str().and_then(|s| s.parse::<IpAddr>().ok());
                let plain_ip = matches!(s["type"].as_str(), Some("udp" | "tcp")) && ip.is_some();
                (local || plain_ip).then(|| tag.to_string())
            })
            .unwrap_or_else(|| {
                let mut bootstrap = "mimic-bootstrap".to_string();
                while bootstrap == tag
                    || servers
                        .iter()
                        .any(|s| s["tag"].as_str() == Some(&bootstrap))
                {
                    bootstrap.push('-');
                }
                servers.push(json!({"tag": bootstrap, "type": "local"}));
                bootstrap
            });
        new_server["domain_resolver"] = json!(bootstrap);
    }
    servers.push(new_server);
    if config["dns"].get("final").is_none() {
        config["dns"]["final"] = json!(tag);
    }
    ensure_default_resolver(config)
}

fn finish(paths: &Paths, config: &Value, dry_run: bool) -> Result<()> {
    let contents = serde_json::to_string_pretty(config)?;
    if dry_run {
        eprintln!(
            "{} [DRY RUN] Changes previewed (not written)",
            "[WARN]".yellow()
        );
        println!("{contents}");
    } else {
        crate::utils::write_private_file(&paths.staging, contents.as_bytes())?;
        eprintln!(
            "{} DNS config staged. Run 'mimictl apply' to activate.",
            "[INFO]".green()
        );
    }
    Ok(())
}

pub fn setup(paths: &Paths, dry_run: bool) -> Result<()> {
    let config_str = std::fs::read_to_string(paths.get_input_config_path())?;
    let mut config: Value = serde_json::from_str(&config_str)?;
    configure_doh3(&mut config)?;
    finish(paths, &config, dry_run)
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
    let config_str = std::fs::read_to_string(paths.get_input_config_path())?;
    let mut config: Value = serde_json::from_str(&config_str)?;
    add_dns_server(
        &mut config,
        &tag,
        &server,
        &server_type,
        port,
        path.as_deref(),
    )?;
    finish(paths, &config, dry_run)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doh3_creates_missing_dns_and_has_independent_bootstrap() {
        let mut config = json!({});
        configure_doh3(&mut config).unwrap();
        assert_eq!(config["dns"]["servers"][0]["domain_resolver"], "alidns");
        assert_eq!(config["dns"]["final"], "google");
        assert_eq!(config["route"]["default_domain_resolver"], "google");
        configure_doh3(&mut config).unwrap();
        assert_eq!(config["dns"]["servers"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn doh3_keeps_servers_referenced_by_existing_rules() {
        let mut config = json!({"dns": {"servers": [{"tag": "custom", "type": "local"}],
            "rules": [{"domain": "example.com", "server": "custom"}]}});
        configure_doh3(&mut config).unwrap();
        assert_eq!(config["dns"]["servers"][0]["tag"], "custom");
        assert_eq!(config["dns"]["rules"][0]["server"], "custom");
    }

    #[test]
    fn default_resolver_bootstraps_empty_config_and_preserves_explicit_route() {
        let mut config = json!({});
        ensure_default_resolver(&mut config).unwrap();
        assert_eq!(config["dns"]["servers"][0]["type"], "local");
        assert_eq!(
            config["route"]["default_domain_resolver"],
            "mimic-bootstrap"
        );
        configure_doh3(&mut config).unwrap();
        assert_eq!(
            config["route"]["default_domain_resolver"],
            "mimic-bootstrap"
        );
    }

    #[test]
    fn hostname_dns_gets_local_bootstrap_and_duplicate_tags_fail() {
        let mut config = json!({});
        add_dns_server(
            &mut config,
            "custom",
            "dns.example.com",
            "https",
            None,
            None,
        )
        .unwrap();
        assert_eq!(config["dns"]["servers"][0]["type"], "local");
        assert_eq!(
            config["dns"]["servers"][1]["domain_resolver"],
            "mimic-bootstrap"
        );
        assert_eq!(config["dns"]["final"], "custom");
        assert!(add_dns_server(&mut config, "custom", "1.1.1.1", "udp", None, None).is_err());
    }

    #[test]
    fn ipv6_dns_does_not_need_bootstrap() {
        let mut config = json!({});
        add_dns_server(
            &mut config,
            "v6",
            "[2606:4700:4700::1111]",
            "udp",
            Some(53),
            None,
        )
        .unwrap();
        assert_eq!(
            config["dns"]["servers"][0]["server"],
            "2606:4700:4700::1111"
        );
        assert!(config["dns"]["servers"][0].get("domain_resolver").is_none());
    }

    #[test]
    fn malformed_dns_and_invalid_transport_options_fail() {
        assert!(configure_doh3(&mut json!({"dns": []})).is_err());
        assert!(configure_doh3(&mut json!({"dns": {"servers": {}}})).is_err());
        assert!(
            add_dns_server(
                &mut json!({}),
                "bad",
                "1.1.1.1",
                "udp",
                None,
                Some("/dns-query")
            )
            .is_err()
        );
        assert!(
            add_dns_server(
                &mut json!({}),
                "bad",
                "https://dns.google",
                "h3",
                None,
                None
            )
            .is_err()
        );
    }
}
