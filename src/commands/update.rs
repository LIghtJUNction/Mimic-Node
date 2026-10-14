use anyhow::{Result, anyhow};
use colored::*;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::fs;

use crate::paths::Paths;

pub fn upgrade(paths: &Paths, auto: bool, dry_run: bool) -> Result<()> {
    let current: Value = serde_json::from_str(&fs::read_to_string(paths.get_input_config_path())?)?;
    let upgraded = migrate_config(&current)?;
    if upgraded == current {
        eprintln!(
            "{} No supported legacy fields need migration.",
            "[INFO]".green()
        );
        return Ok(());
    }
    if dry_run {
        println!("{}", serde_json::to_string_pretty(&upgraded)?);
    } else if auto {
        crate::utils::save_config(&paths.staging, &serde_json::from_value(upgraded)?)?;
        eprintln!(
            "{} Compatibility changes staged. Run 'mimictl apply' to validate and activate.",
            "[INFO]".green()
        );
    } else {
        eprintln!(
            "{} Legacy configuration found. Use --dry-run to review, then --auto to stage the migration.",
            "[INFO]".green()
        );
    }
    Ok(())
}

// Only transform fields with direct equivalents. Never merge arbitrary defaults
// into user routing, credentials, or protocol-specific inbound objects.
fn migrate_config(current: &Value) -> Result<Value> {
    if !current.is_object() {
        return Err(anyhow!("Configuration must be an object"));
    }
    let mut config = current.clone();
    let mut blocked_tags = HashSet::new();
    if let Some(outbounds) = config.get("outbounds").and_then(Value::as_array) {
        for outbound in outbounds {
            if outbound["type"] == "block" {
                blocked_tags.insert(outbound["tag"].as_str().unwrap_or_default().to_owned());
            }
        }
        for outbound in outbounds {
            if outbound
                .get("outbounds")
                .and_then(Value::as_array)
                .is_some_and(|tags| {
                    tags.iter()
                        .any(|tag| blocked_tags.contains(tag.as_str().unwrap_or_default()))
                })
            {
                return Err(anyhow!(
                    "A selector references a block outbound; replace that choice with explicit reject routing before upgrading"
                ));
            }
        }
    }
    if config
        .get("route")
        .and_then(|r| r.get("final"))
        .and_then(Value::as_str)
        .is_some_and(|tag| blocked_tags.contains(tag))
    {
        return Err(anyhow!(
            "route.final references a block outbound; configure explicit reject routing before upgrading"
        ));
    }
    if let Some(rules) = config.get_mut("route").and_then(|r| r.get_mut("rules")) {
        migrate_route_rules(rules, &blocked_tags);
    }
    if let Some(outbounds) = config.get_mut("outbounds").and_then(Value::as_array_mut) {
        outbounds.retain(|o| o["type"] != "block");
    }

    let mut sniff_rules = Vec::new();
    if let Some(inbounds) = config.get_mut("inbounds").and_then(Value::as_array_mut) {
        for inbound in inbounds {
            let object = inbound
                .as_object_mut()
                .ok_or_else(|| anyhow!("Inbound must be an object"))?;
            let sniff = object
                .remove("sniff")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            object.remove("sniff_override_destination");
            let timeout = object.remove("sniff_timeout");
            if sniff {
                let tag = object
                    .get("tag")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| anyhow!("Give sniff-enabled inbound a tag before upgrading"))?;
                let mut rule = json!({"inbound": tag, "action": "sniff"});
                if let Some(timeout) = timeout {
                    rule["timeout"] = timeout;
                }
                sniff_rules.push(rule);
            }
            if let Some(tls) = object.get_mut("tls").and_then(Value::as_object_mut) {
                if let Some(cert) = tls.remove("cert_path") {
                    tls.entry("certificate_path").or_insert(cert);
                }
                if let Some(handshake) = tls.get_mut("reality").and_then(|r| r.get_mut("handshake"))
                    && let Some(server) = handshake.get("server").and_then(Value::as_str)
                    && server.contains("://")
                {
                    let url = url::Url::parse(server)?;
                    let host = url
                        .host_str()
                        .ok_or_else(|| anyhow!("Reality handshake URL has no host"))?
                        .to_owned();
                    let port = url.port();
                    handshake["server"] = json!(host);
                    if let Some(port) = port {
                        handshake["server_port"] = json!(port);
                    }
                }
            }
        }
    }
    if !sniff_rules.is_empty() {
        if config.get("route").is_none() {
            config["route"] = json!({});
        }
        if config["route"].get("rules").is_none() {
            config["route"]["rules"] = json!([]);
        }
        let rules = config["route"]["rules"]
            .as_array_mut()
            .ok_or_else(|| anyhow!("route.rules must be an array"))?;
        sniff_rules.append(rules);
        *rules = sniff_rules;
    }

    if let Some(servers) = config
        .get_mut("dns")
        .and_then(|d| d.get_mut("servers"))
        .and_then(Value::as_array_mut)
    {
        let mut needs_bootstrap = false;
        let local_tag = (0..)
            .map(|i| format!("mimic-bootstrap-{i}"))
            .find(|tag| !servers.iter().any(|s| s["tag"].as_str() == Some(tag)))
            .unwrap();
        for server in servers.iter_mut() {
            let object = server
                .as_object_mut()
                .ok_or_else(|| anyhow!("DNS server must be an object"))?;
            if let Some(address) = object.remove("address") {
                let address = address
                    .as_str()
                    .ok_or_else(|| anyhow!("DNS address must be a string"))?;
                if address == "local" {
                    object.insert("type".into(), json!("local"));
                } else {
                    let address = if address.contains("://") {
                        address.to_owned()
                    } else {
                        format!("udp://{address}")
                    };
                    let url = url::Url::parse(&address)?;
                    if !matches!(
                        url.scheme(),
                        "udp" | "tcp" | "tls" | "https" | "h3" | "quic"
                    ) {
                        return Err(anyhow!(
                            "DNS address scheme '{}' needs manual migration",
                            url.scheme()
                        ));
                    }
                    let host = url
                        .host_str()
                        .ok_or_else(|| anyhow!("DNS address has no host"))?
                        .trim_matches(['[', ']']);
                    object.insert("type".into(), json!(url.scheme()));
                    object.insert("server".into(), json!(host));
                    if let Some(port) = url.port() {
                        object.insert("server_port".into(), json!(port));
                    }
                    if matches!(url.scheme(), "https" | "h3") && !url.path().is_empty() {
                        object.insert("path".into(), json!(url.path()));
                    }
                }
                if let Some(resolver) = object.remove("address_resolver") {
                    object.entry("domain_resolver").or_insert(resolver);
                }
                if object.get("detour").and_then(Value::as_str) == Some("direct") {
                    object.remove("detour");
                }
            }
            if object
                .get("server")
                .and_then(Value::as_str)
                .is_some_and(|host| host.parse::<std::net::IpAddr>().is_err())
                && !object.contains_key("domain_resolver")
            {
                object.insert("domain_resolver".into(), json!(local_tag));
                needs_bootstrap = true;
            }
        }
        if needs_bootstrap {
            servers.push(json!({"tag": local_tag, "type": "local"}));
        }
    }
    crate::commands::dns::ensure_default_resolver(&mut config)?;
    Ok(config)
}

fn migrate_route_rules(rules: &mut Value, blocked_tags: &HashSet<String>) {
    if let Some(rules) = rules.as_array_mut() {
        for rule in rules {
            if let Some(children) = rule.get_mut("rules") {
                migrate_route_rules(children, blocked_tags);
            }
            if rule
                .get("outbound")
                .and_then(Value::as_str)
                .is_some_and(|tag| blocked_tags.contains(tag))
            {
                rule.as_object_mut().unwrap().remove("outbound");
                rule["action"] = json!("reject");
            } else if rule["action"] == "direct" {
                rule["action"] = json!("route");
                rule["outbound"] = json!("direct");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_preserves_credentials_routing_and_unknown_fields() {
        let before = json!({
            "inbounds": [{"type": "vless", "tag": "vless-in", "sniff": true,
                "users": [{"uuid": "keep", "name": "user"}],
                "tls": {"reality": {"private_key": "secret", "handshake": {"server": "https://example.com", "server_port": 443}}}}],
            "outbounds": [{"type": "direct", "tag": "direct"}, {"type": "block", "tag": "blocked"}],
            "route": {"rules": [{"domain": "bad.example", "outbound": "blocked"}], "final": "direct"},
            "dns": {"servers": [{"tag": "google", "address": "h3://dns.google/dns-query"}]},
            "custom": {"preserve": true}
        });
        let after = migrate_config(&before).unwrap();
        assert_eq!(
            after["inbounds"][0]["users"],
            before["inbounds"][0]["users"]
        );
        assert_eq!(
            after["inbounds"][0]["tls"]["reality"]["private_key"],
            "secret"
        );
        assert_eq!(
            after["inbounds"][0]["tls"]["reality"]["handshake"]["server"],
            "example.com"
        );
        assert_eq!(after["route"]["rules"][0]["action"], "sniff");
        assert_eq!(
            after["route"]["rules"][1],
            json!({"domain": "bad.example", "action": "reject"})
        );
        assert_eq!(after["custom"], before["custom"]);
        assert_eq!(
            after["dns"]["servers"][0]["domain_resolver"],
            "mimic-bootstrap-0"
        );
        assert_eq!(migrate_config(&after).unwrap(), after);
    }

    #[test]
    fn ambiguous_block_selector_fails_without_mutating_input() {
        let before = json!({"outbounds": [{"type": "block", "tag": "block"}, {"type": "selector", "tag": "proxy", "outbounds": ["block"]}]});
        assert!(migrate_config(&before).is_err());
        assert_eq!(before["outbounds"][0]["type"], "block");
    }
}
