use std::fs;
use std::path::PathBuf;

fn get_default_config_path() -> PathBuf {
    PathBuf::from("/home/lightjunction/GITHUB/Mimic-Node/overlay/usr/share/mimic-node/default/config.json")
}

#[test]
fn test_default_config_exists() {
    let path = get_default_config_path();
    assert!(path.exists(), "Default config should exist at {:?}", path);
}

#[test]
fn test_default_config_valid_json() {
    let path = get_default_config_path();
    let content = fs::read_to_string(&path)
        .expect("Failed to read default config");

    let result = serde_json::from_str::<serde_json::Value>(&content);
    assert!(result.is_ok(), "Default config should be valid JSON: {:?}", result.err());
}

#[test]
fn test_default_config_has_log() {
    let path = get_default_config_path();
    let content = fs::read_to_string(&path).unwrap();
    let config: serde_json::Value = serde_json::from_str(&content).unwrap();

    assert!(config.get("log").is_some(), "Config should have 'log' section");
    let log = config.get("log").unwrap();

    // Check required log fields per sing-box docs
    assert!(log.get("disabled").is_some(), "log should have 'disabled' field");
    assert!(log.get("level").is_some(), "log should have 'level' field");
    assert!(log.get("timestamp").is_some(), "log should have 'timestamp' field");
}

#[test]
fn test_default_config_has_dns() {
    let path = get_default_config_path();
    let content = fs::read_to_string(&path).unwrap();
    let config: serde_json::Value = serde_json::from_str(&content).unwrap();

    assert!(config.get("dns").is_some(), "Config should have 'dns' section");
}

#[test]
fn test_default_config_has_inbounds() {
    let path = get_default_config_path();
    let content = fs::read_to_string(&path).unwrap();
    let config: serde_json::Value = serde_json::from_str(&content).unwrap();

    assert!(config.get("inbounds").is_some(), "Config should have 'inbounds' section");
    let inbounds = config.get("inbounds").unwrap().as_array().unwrap();
    assert!(!inbounds.is_empty(), "Inbounds should not be empty");
}

#[test]
fn test_default_config_has_outbounds() {
    let path = get_default_config_path();
    let content = fs::read_to_string(&path).unwrap();
    let config: serde_json::Value = serde_json::from_str(&content).unwrap();

    assert!(config.get("outbounds").is_some(), "Config should have 'outbounds' section");
    let outbounds = config.get("outbounds").unwrap().as_array().unwrap();
    assert!(!outbounds.is_empty(), "Outbounds should not be empty");
}

#[test]
fn test_default_config_has_route() {
    let path = get_default_config_path();
    let content = fs::read_to_string(&path).unwrap();
    let config: serde_json::Value = serde_json::from_str(&content).unwrap();

    assert!(config.get("route").is_some(), "Config should have 'route' section");
}

#[test]
fn test_vless_inbound_has_reality() {
    let path = get_default_config_path();
    let content = fs::read_to_string(&path).unwrap();
    let config: serde_json::Value = serde_json::from_str(&content).unwrap();

    let inbounds = config.get("inbounds").unwrap().as_array().unwrap();
    let vless = inbounds.iter().find(|i| {
        i.get("type") == Some(&serde_json::Value::String("vless".to_string()))
    });

    assert!(vless.is_some(), "Should have VLESS inbound");
    let vless = vless.unwrap();

    // Check reality config per sing-box docs
    let tls = vless.get("tls").unwrap();
    assert!(tls.get("reality").is_some(), "VLESS should have reality config");

    let reality = tls.get("reality").unwrap();
    assert!(reality.get("enabled").is_some(), "reality should have 'enabled'");
    assert!(reality.get("private_key").is_some(), "reality should have 'private_key'");
    assert!(reality.get("handshake").is_some(), "reality should have 'handshake'");
}

#[test]
fn test_vless_inbound_has_multiplex() {
    let path = get_default_config_path();
    let content = fs::read_to_string(&path).unwrap();
    let config: serde_json::Value = serde_json::from_str(&content).unwrap();

    let inbounds = config.get("inbounds").unwrap().as_array().unwrap();
    let vless = inbounds.iter().find(|i| {
        i.get("tag") == Some(&serde_json::Value::String("vless-in".to_string()))
    });

    assert!(vless.is_some(), "Should have vless-in");

    // VLESS should have multiplex
    let multiplex = vless.unwrap().get("multiplex");
    assert!(multiplex.is_some(), "VLESS should have multiplex config");

    let multiplex = multiplex.unwrap();
    assert!(multiplex.get("enabled").is_some(), "multiplex should have 'enabled'");
}

#[test]
fn test_hysteria2_inbound_structure() {
    let path = get_default_config_path();
    let content = fs::read_to_string(&path).unwrap();
    let config: serde_json::Value = serde_json::from_str(&content).unwrap();

    let inbounds = config.get("inbounds").unwrap().as_array().unwrap();
    let hy2 = inbounds.iter().find(|i| {
        i.get("type") == Some(&serde_json::Value::String("hysteria2".to_string()))
    });

    assert!(hy2.is_some(), "Should have Hysteria2 inbound");
    let hy2 = hy2.unwrap();

    // Check required fields per sing-box docs
    assert!(hy2.get("listen_port").is_some(), "Hysteria2 should have listen_port");
    assert!(hy2.get("users").is_some(), "Hysteria2 should have users");
    assert!(hy2.get("tls").is_some(), "Hysteria2 should have tls");

    // Check TLS structure
    let tls = hy2.get("tls").unwrap();
    assert!(tls.get("enabled").is_some(), "tls should have 'enabled'");
    assert!(tls.get("certificate_path").is_some() || tls.get("cert_path").is_some(),
            "tls should have certificate_path");
}

#[test]
fn test_ssh_inbound_structure() {
    let path = get_default_config_path();
    let content = fs::read_to_string(&path).unwrap();
    let config: serde_json::Value = serde_json::from_str(&content).unwrap();

    let inbounds = config.get("inbounds").unwrap().as_array().unwrap();
    let ssh = inbounds.iter().find(|i| {
        i.get("type") == Some(&serde_json::Value::String("ssh".to_string()))
    });

    assert!(ssh.is_some(), "Should have SSH inbound");
    let ssh = ssh.unwrap();

    assert!(ssh.get("listen_port").is_some(), "SSH should have listen_port");
    assert!(ssh.get("users").is_some(), "SSH should have users");
}

#[test]
fn test_direct_outbound_has_required_fields() {
    let path = get_default_config_path();
    let content = fs::read_to_string(&path).unwrap();
    let config: serde_json::Value = serde_json::from_str(&content).unwrap();

    let outbounds = config.get("outbounds").unwrap().as_array().unwrap();
    let direct = outbounds.iter().find(|o| {
        o.get("type") == Some(&serde_json::Value::String("direct".to_string()))
    });

    assert!(direct.is_some(), "Should have direct outbound");
    let direct = direct.unwrap();

    // Check dial fields per sing-box docs
    assert!(direct.get("bind_interface").is_some() || direct.get("detour").is_some(),
            "direct should have bind_interface or detour");
}

#[test]
fn test_route_has_final() {
    let path = get_default_config_path();
    let content = fs::read_to_string(&path).unwrap();
    let config: serde_json::Value = serde_json::from_str(&content).unwrap();

    let route = config.get("route").unwrap();
    assert!(route.get("final").is_some(), "route should have 'final'");
}

#[test]
fn test_route_rules_sniff_action() {
    let path = get_default_config_path();
    let content = fs::read_to_string(&path).unwrap();
    let config: serde_json::Value = serde_json::from_str(&content).unwrap();

    let route = config.get("route").unwrap();
    let rules = route.get("rules").unwrap().as_array().unwrap();

    // Check that sniff actions are in rules (not deprecated in inbound)
    let sniff_rules: Vec<_> = rules.iter().filter(|r| {
        r.get("action") == Some(&serde_json::Value::String("sniff".to_string()))
    }).collect();

    assert!(!sniff_rules.is_empty(), "Should have sniff actions in route rules");
}

#[test]
fn test_dns_has_servers() {
    let path = get_default_config_path();
    let content = fs::read_to_string(&path).unwrap();
    let config: serde_json::Value = serde_json::from_str(&content).unwrap();

    let dns = config.get("dns").unwrap();
    assert!(dns.get("servers").is_some(), "dns should have 'servers'");

    let servers = dns.get("servers").unwrap().as_array().unwrap();
    assert!(!servers.is_empty(), "dns servers should not be empty");
}

#[test]
fn test_dns_final_valid() {
    let path = get_default_config_path();
    let content = fs::read_to_string(&path).unwrap();
    let config: serde_json::Value = serde_json::from_str(&content).unwrap();

    let dns = config.get("dns").unwrap();
    let final_dns = dns.get("final").unwrap().as_str().unwrap();

    let servers = dns.get("servers").unwrap().as_array().unwrap();
    let server_tags: Vec<_> = servers.iter().filter_map(|s| s.get("tag").and_then(|t| t.as_str())).collect();

    assert!(server_tags.contains(&final_dns), "final DNS '{}' should be in servers list", final_dns);
}

#[test]
fn test_no_deprecated_download_detour() {
    let path = get_default_config_path();
    let content = fs::read_to_string(&path).unwrap();
    let config: serde_json::Value = serde_json::from_str(&content).unwrap();

    // download_detour is deprecated in 1.14.0, should use http_client instead
    let route = config.get("route").unwrap();

    if let Some(rule_sets) = route.get("rule_set") {
        let rule_sets = rule_sets.as_array().unwrap();
        for rs in rule_sets {
            assert!(rs.get("download_detour").is_none(),
                    "rule_set should not use deprecated 'download_detour', use 'http_client' instead");
        }
    }
}

#[test]
fn test_no_deprecated_independent_cache() {
    let path = get_default_config_path();
    let content = fs::read_to_string(&path).unwrap();
    let config: serde_json::Value = serde_json::from_str(&content).unwrap();

    // independent_cache is deprecated in 1.14.0
    let dns = config.get("dns").unwrap();
    assert!(dns.get("independent_cache").is_none(),
            "dns should not use deprecated 'independent_cache'");
}

#[test]
fn test_no_deprecated_sniff_in_inbound() {
    let path = get_default_config_path();
    let content = fs::read_to_string(&path).unwrap();
    let config: serde_json::Value = serde_json::from_str(&content).unwrap();

    // sniff in inbound is deprecated since 1.11.0, should be in route rules
    let inbounds = config.get("inbounds").unwrap().as_array().unwrap();

    for inbound in inbounds {
        assert!(inbound.get("sniff").is_none(),
                "inbound should not use deprecated 'sniff', use route rules instead");
        assert!(inbound.get("sniff_override_destination").is_none(),
                "inbound should not use deprecated 'sniff_override_destination', use route rules instead");
    }
}

#[test]
fn test_http_clients_for_rule_sets() {
    let path = get_default_config_path();
    let content = fs::read_to_string(&path).unwrap();
    let config: serde_json::Value = serde_json::from_str(&content).unwrap();

    let route = config.get("route").unwrap();

    // If rule_sets exist, http_clients should exist (new in 1.14.0)
    if route.get("rule_set").is_some() {
        assert!(route.get("http_clients").is_some() || route.get("default_http_client").is_some(),
                "If using rule_sets, should have http_clients or default_http_client");
    }
}

#[test]
fn test_experimental_clash_api_structure() {
    let path = get_default_config_path();
    let content = fs::read_to_string(&path).unwrap();
    let config: serde_json::Value = serde_json::from_str(&content).unwrap();

    if let Some(experimental) = config.get("experimental") {
        if let Some(clash_api) = experimental.get("clash_api") {
            // Required field
            assert!(clash_api.get("external_controller").is_some(),
                    "clash_api should have 'external_controller'");

            // New fields in 1.10.0+
            assert!(clash_api.get("access_control_allow_origin").is_some(),
                    "clash_api should have 'access_control_allow_origin'");

            // Deprecated fields should not exist
            assert!(clash_api.get("cache_file").is_none(),
                    "clash_api should not have deprecated 'cache_file'");
            assert!(clash_api.get("cache_id").is_none(),
                    "clash_api should not have deprecated 'cache_id'");
        }
    }
}

#[test]
fn test_cache_file_separated() {
    let path = get_default_config_path();
    let content = fs::read_to_string(&path).unwrap();
    let config: serde_json::Value = serde_json::from_str(&content).unwrap();

    // cache_file should be in experimental, not in clash_api (separated in 1.8.0)
    if let Some(experimental) = config.get("experimental") {
        if let Some(cache_file) = experimental.get("cache_file") {
            assert!(cache_file.get("enabled").is_some(),
                    "cache_file should have 'enabled'");
            // store_fakeip and store_selected are now at top level of cache_file
            assert!(cache_file.get("store_fakeip").is_some() || cache_file.get("store_selected").is_some(),
                    "cache_file should have store options");
        }
    }
}

#[test]
fn test_clash_api_no_deprecated_store_mode() {
    let path = get_default_config_path();
    let content = fs::read_to_string(&path).unwrap();
    let config: serde_json::Value = serde_json::from_str(&content).unwrap();

    if let Some(experimental) = config.get("experimental") {
        if let Some(clash_api) = experimental.get("clash_api") {
            // store_mode is deprecated since 1.8.0
            assert!(clash_api.get("store_mode").is_none(),
                    "clash_api should not have deprecated 'store_mode'");
        }
    }
}

#[test]
fn test_tailscale_endpoint_structure() {
    let path = get_default_config_path();
    let content = fs::read_to_string(&path).unwrap();
    let config: serde_json::Value = serde_json::from_str(&content).unwrap();

    if let Some(endpoints) = config.get("endpoints") {
        let endpoints = endpoints.as_array().unwrap();
        let tailscale = endpoints.iter().find(|e| {
            e.get("type") == Some(&serde_json::Value::String("tailscale".to_string()))
        });

        if let Some(ts) = tailscale {
            // New in 1.14.0 - dial fields deprecated
            assert!(ts.get("control_http_client").is_some() || ts.get("control_url").is_some(),
                    "tailscale endpoint should have control_http_client or control_url");

            // Should not have old dial fields
            assert!(ts.get("server").is_none(),
                    "tailscale endpoint should not have deprecated 'server' field");
        }
    }
}

#[test]
fn test_inbounds_no_gso() {
    let path = get_default_config_path();
    let content = fs::read_to_string(&path).unwrap();
    let config: serde_json::Value = serde_json::from_str(&content).unwrap();

    // GSO is deprecated since 1.13.0
    let inbounds = config.get("inbounds").unwrap().as_array().unwrap();

    for inbound in inbounds {
        if inbound.get("type") == Some(&serde_json::Value::String("tun".to_string())) {
            assert!(inbound.get("gso").is_none(),
                    "TUN should not use deprecated 'gso'");
        }
    }
}

#[test]
fn test_services_has_stats_api() {
    let path = get_default_config_path();
    let content = fs::read_to_string(&path).unwrap();
    let config: serde_json::Value = serde_json::from_str(&content).unwrap();

    if let Some(services) = config.get("services") {
        let services = services.as_array().unwrap();
        let stats = services.iter().find(|s| {
            s.get("type") == Some(&serde_json::Value::String("stats".to_string()))
        });

        if let Some(stats) = stats {
            assert!(stats.get("listen").is_some(), "stats should have 'listen'");
            assert!(stats.get("stats").is_some(), "stats should have 'stats' config");

            let stats_config = stats.get("stats").unwrap();
            assert!(stats_config.get("enabled").is_some(),
                    "stats.config should have 'enabled'");
        }
    }
}

#[test]
fn test_certificate_providers_structure() {
    let path = get_default_config_path();
    let content = fs::read_to_string(&path).unwrap();
    let config: serde_json::Value = serde_json::from_str(&content).unwrap();

    // ACME structure per sing-box 1.14.0 docs
    if let Some(providers) = config.get("certificate_providers") {
        if let Some(acme) = providers.get("acme") {
            assert!(acme.get("tag").is_some(), "acme should have 'tag'");

            // key_type should be valid per docs
            if let Some(key_type) = acme.get("key_type").and_then(|k| k.as_str()) {
                assert!(["ed25519", "p256", "p384", "rsa2048", "rsa4096"].contains(&key_type),
                        "key_type should be valid value, got: {}", key_type);
            }
        }
    }
}

#[test]
fn test_udp_over_tcp_version() {
    let path = get_default_config_path();
    let content = fs::read_to_string(&path).unwrap();
    let config: serde_json::Value = serde_json::from_str(&content).unwrap();

    let inbounds = config.get("inbounds").unwrap().as_array().unwrap();
    let vless = inbounds.iter().find(|i| {
        i.get("tag") == Some(&serde_json::Value::String("vless-in".to_string()))
    });

    if let Some(vless) = vless {
        if let Some(uot) = vless.get("udp_over_tcp") {
            if let Some(version) = uot.get("version").and_then(|v| v.as_i64()) {
                assert!(version == 1 || version == 2,
                        "udp_over_tcp version should be 1 or 2, got: {}", version);
            }
        }
    }
}

#[test]
fn test_dns_strategy_valid() {
    let path = get_default_config_path();
    let content = fs::read_to_string(&path).unwrap();
    let config: serde_json::Value = serde_json::from_str(&content).unwrap();

    let dns = config.get("dns").unwrap();
    if let Some(strategy) = dns.get("strategy").and_then(|s| s.as_str()) {
        assert!(["prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only"].contains(&strategy),
                "DNS strategy should be valid value, got: {}", strategy);
    }
}

#[test]
fn test_clash_api_default_mode_valid() {
    let path = get_default_config_path();
    let content = fs::read_to_string(&path).unwrap();
    let config: serde_json::Value = serde_json::from_str(&content).unwrap();

    if let Some(experimental) = config.get("experimental") {
        if let Some(clash_api) = experimental.get("clash_api") {
            if let Some(mode) = clash_api.get("default_mode").and_then(|m| m.as_str()) {
                assert!(["Rule", "Proxy", "Global"].contains(&mode),
                        "default_mode should be valid value, got: {}", mode);
            }
        }
    }
}
