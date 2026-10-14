use serde_json::Value;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

fn default_config() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("overlay/usr/share/mimic-node/default/config.json");
    let content = fs::read_to_string(path).expect("packaged default configuration exists");
    serde_json::from_str(&content).expect("packaged default configuration is valid JSON")
}

#[test]
fn default_is_a_vless_reality_template_without_shared_credentials() {
    let config = default_config();
    let inbound = &config["inbounds"][0];
    assert_eq!(inbound["type"], "vless");
    assert_eq!(inbound["tag"], "vless-in");
    assert!(
        inbound["listen_port"]
            .as_u64()
            .is_some_and(|p| p > 0 && p <= 65535)
    );
    assert_eq!(inbound["users"], serde_json::json!([]));
    assert_eq!(inbound["tls"]["enabled"], true);
    let reality = &inbound["tls"]["reality"];
    assert_eq!(reality["enabled"], true);
    assert_eq!(reality["private_key"], "");
    assert_eq!(reality["short_id"], serde_json::json!([]));
    let server = reality["handshake"]["server"].as_str().unwrap();
    assert!(!server.is_empty());
    assert!(
        !server.contains("://"),
        "handshake server must be a hostname"
    );
    assert_eq!(reality["handshake"]["server_port"], 443);
}

#[test]
fn default_routing_references_existing_tags() {
    let config = default_config();
    let inbounds = config["inbounds"].as_array().unwrap();
    let outbounds = config["outbounds"].as_array().unwrap();
    let inbound_tags: HashSet<_> = inbounds
        .iter()
        .map(|i| i["tag"].as_str().unwrap())
        .collect();
    let outbound_tags: HashSet<_> = outbounds
        .iter()
        .map(|o| o["tag"].as_str().unwrap())
        .collect();
    assert_eq!(inbound_tags.len(), inbounds.len(), "duplicate inbound tag");
    assert_eq!(
        outbound_tags.len(),
        outbounds.len(),
        "duplicate outbound tag"
    );
    assert!(outbound_tags.contains(config["route"]["final"].as_str().unwrap()));
    assert!(outbounds.iter().any(|o| o["type"] == "direct"));
    for rule in config["route"]["rules"].as_array().unwrap() {
        if let Some(tag) = rule["inbound"].as_str() {
            assert!(inbound_tags.contains(tag), "unknown inbound {tag}");
        }
        if let Some(tag) = rule["outbound"].as_str() {
            assert!(outbound_tags.contains(tag), "unknown outbound {tag}");
        }
    }
}

#[test]
fn default_uses_route_actions_instead_of_removed_fields() {
    let config = default_config();
    for inbound in config["inbounds"].as_array().unwrap() {
        for removed in [
            "sniff",
            "sniff_override_destination",
            "domain_strategy",
            "gso",
        ] {
            assert!(
                inbound.get(removed).is_none(),
                "removed inbound field {removed}"
            );
        }
    }
    for outbound in config["outbounds"].as_array().unwrap() {
        assert_ne!(outbound["type"], "block", "use a reject route action");
        assert_ne!(outbound["type"], "dns", "use a hijack-dns route action");
    }
    assert!(
        config["route"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["action"] == "sniff")
    );
}

#[test]
fn default_logging_has_a_supported_level() {
    let config = default_config();
    assert!(config["log"].is_object());
    assert!(
        ["trace", "debug", "info", "warn", "error", "fatal", "panic"]
            .contains(&config["log"]["level"].as_str().unwrap())
    );
    assert!(config["log"]["timestamp"].is_boolean());
}
