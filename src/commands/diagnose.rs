use anyhow::Result;
use colored::*;
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::paths::Paths;

pub fn run(paths: &Paths, verbose: bool) -> Result<()> {
    println!(r#"
  ███╗   ███╗██╗██████╗ ███████╗██╗    ██╗ █████╗ ██╗   ██╗
  ████╗ ████║██║██╔══██╗██╔════╝██║    ██║██╔══██╗╚██╗ ██╔╝
  ██╔████╔██║██║██████╔╝█████╗  ██║ █╗ ██║███████║ ╚████╔╝
  ██║╚██╔╝██║██║██╔═══╝ ██╔══╝ ██║███╗██║██╔══██║  ╚██╔╝
  ██║ ╚═╝ ██║██║██║     ███████╗╚███╔███╔╝██║  ██║   ██║
  ╚═╝     ╚═╝╚═╝╚═╝     ╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝
"#);

    println!("{} System Health Check\n", "  Mimic-Node Diagnostic".cyan().bold());
    println!("  ───────────────────────────────────────\n");

    let mut warnings = 0;

    // System Checks
    println!("  {}", "System".cyan().bold());
    if check_overlay_mount(paths, verbose) {
        println!("    {} OverlayFS mounted", "●".green());
    } else {
        println!("    {} OverlayFS not mounted", "○".yellow());
        warnings += 1;
    }
    if check_config_exists(paths, verbose) {
        println!("    {} Config files present", "●".green());
    } else {
        println!("    {} Config files missing", "○".red());
        warnings += 1;
    }
    if check_sing_box_installed(verbose) {
        // Already printed in function
    }
    println!();

    // Network Checks
    println!("  {}", "Network".cyan().bold());
    if check_port_listening(443, verbose) {
        println!("    {} Port 443 listening", "●".green());
    } else {
        println!("    {} Port 443 not listening", "○".yellow());
        warnings += 1;
    }
    if check_firewall_rules(verbose) {
        println!("    {} Firewall rules OK", "●".green());
    } else {
        warnings += 1;
    }
    if check_protocol_sniffing(paths, verbose) {
        println!("    {} Protocol sniffing enabled", "●".green());
    } else {
        println!("    {} Protocol sniffing disabled", "○".yellow());
        warnings += 1;
    }
    if check_hysteria2(paths, verbose) {
        // Already printed in function
    } else {
        warnings += 1;
    }
    println!();

    // TLS & Security
    println!("  {}", "Security".cyan().bold());
    if check_tls_certificate(paths, verbose) {
        println!("    {} TLS certificates OK", "●".green());
    } else {
        println!("    {} TLS certificates missing", "○".yellow());
        warnings += 1;
    }
    if check_reality_keys(paths, verbose) {
        println!("    {} Reality keys configured", "●".green());
    } else {
        println!("    {} Reality keys missing", "○".yellow());
        warnings += 1;
    }
    if check_permission_settings(paths, verbose) {
        println!("    {} File permissions OK", "●".green());
    } else {
        println!("    {} File permissions issue", "○".yellow());
        warnings += 1;
    }
    println!();

    // Performance
    println!("  {}", "Performance".cyan().bold());
    if check_kernel_tls_support(verbose) {
        println!("    {} Kernel TLS support", "●".green());
    }
    if check_bbr_enabled(verbose) {
        println!("    {} BBR congestion control", "●".green());
    }
    if check_dns_configuration(paths, verbose) {
        println!("    {} DNS configuration OK", "●".green());
    } else {
        println!("    {} DNS configuration issue", "○".yellow());
        warnings += 1;
    }
    println!();

    // Deprecations
    let deprecation_issues = check_deprecated_features(paths, verbose);
    if !deprecation_issues {
        println!("    {} No deprecated features", "●".green());
    } else {
        warnings += 1;
    }
    println!();

    // Summary
    println!("  ───────────────────────────────────────");
    if warnings == 0 {
        println!("  {} All checks passed!", "●".green());
    } else {
        println!("  {} {} warning(s)", "○".yellow(), warnings);
        println!("  {} Run with --verbose for details", "Tip:".dimmed());
    }
    println!();

    Ok(())
}

fn check_overlay_mount(paths: &Paths, verbose: bool) -> bool {
    print!("  Checking OverlayFS mount... ");
    if paths.root == Path::new("/") {
        let mount_target = "/etc/sing-box";
        let is_mounted = Command::new("mountpoint")
            .arg("-q")
            .arg(mount_target)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        if is_mounted {
            println!("{}", "[OK]".green());
            if verbose {
                println!("      {} Mounted at {}", "[*]".cyan(), mount_target);
            }
            true
        } else {
            println!("{}", "[WARN]".yellow());
            if verbose {
                println!("      {} OverlayFS not mounted at {}", "[!]".yellow(), mount_target);
                println!("      {} Run: sudo systemctl start mimic-node-mount", "[>]".cyan());
            }
            false
        }
    } else {
        println!("{}", "[SKIP]".dimmed());
        println!("      {} Running in non-system mode", "[*]".cyan());
        true
    }
}

fn check_config_exists(paths: &Paths, verbose: bool) -> bool {
    print!("  Checking config files... ");
    let config_exists = paths.config.exists() || paths.staging.exists();
    let default_exists = paths.default_config.exists();

    if config_exists && default_exists {
        println!("{}", "[OK]".green());
        if let Some(p) = paths.get_input_config_path().to_str()
            && verbose {
                println!("      {} Config: {}", "[*]".cyan(), p);
            }
        true
    } else {
        println!("{}", "[ERROR]".red());
        println!("      {} Config exists: {}", "[!]".red(), config_exists);
        println!("      {} Default config exists: {}", "[!]".red(), default_exists);
        false
    }
}

fn check_sing_box_installed(verbose: bool) -> bool {
    print!("  Checking sing-box installation... ");
    let output = Command::new("sing-box")
        .args(["version"])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            let version = String::from_utf8_lossy(&o.stdout);
            let first_line = version.lines().next().unwrap_or("unknown");
            println!("{}", "[OK]".green());
            if verbose {
                println!("      {} {}", "[*]".cyan(), first_line);
            }
            true
        }
        _ => {
            println!("{}", "[ERROR]".red());
            if verbose {
                println!("      {} sing-box not found or failed to run", "[!]".red());
                println!("      {} Install: sudo systemctl enable sing-box", "[>]".cyan());
            }
            false
        }
    }
}

fn check_port_listening(port: u16, verbose: bool) -> bool {
    print!("  Checking port {} listening... ", port);
    let output = Command::new("ss")
        .args(["-tlnp"])
        .output();

    match output {
        Ok(o) => {
            let listening = String::from_utf8_lossy(&o.stdout);
            let found = listening.lines().any(|line| {
                line.contains(&format!(":{}", port)) && line.contains("LISTEN")
            });

            if found {
                println!("{}", "[OK]".green());
                true
            } else {
                println!("{}", "[WARN]".yellow());
                if verbose {
                    println!("      {} Port {} not listening", "[!]".yellow(), port);
                }
                false
            }
        }
        _ => {
            // Try netstat as fallback
            print!("  (trying netstat) ");
            let output = Command::new("netstat")
                .args(["-tlnp"])
                .output();

            match output {
                Ok(o) => {
                    let listening = String::from_utf8_lossy(&o.stdout);
                    let found = listening.lines().any(|line| {
                        line.contains(&format!(":{}", port)) && line.contains("LISTEN")
                    });

                    if found {
                        println!("{}", "[OK]".green());
                        true
                    } else {
                        println!("{}", "[WARN]".yellow());
                        false
                    }
                }
                _ => {
                    println!("{}", "[SKIP]".dimmed());
                    false
                }
            }
        }
    }
}

fn check_firewall_rules(verbose: bool) -> bool {
    print!("  Checking firewall rules... ");

    // Check iptables for sing-box rules
    let output = Command::new("iptables")
        .args(["-L", "-n"])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            let rules = String::from_utf8_lossy(&o.stdout);
            let has_singbox_rules = rules.contains("sing-box") || rules.contains("mimic");

            if has_singbox_rules {
                println!("{}", "[OK]".green());
                if verbose {
                    println!("      {} sing-box firewall rules found", "[*]".cyan());
                }
            } else {
                println!("{}", "[INFO]".cyan());
                if verbose {
                    println!("      {} No sing-box specific rules (may be using auto_redirect)", "[*]".cyan());
                }
            }
            true
        }
        _ => {
            println!("{}", "[SKIP]".dimmed());
            if verbose {
                println!("      {} Cannot read iptables (may need root)", "[*]".cyan());
            }
            true // Not critical
        }
    }
}

fn check_tls_certificate(paths: &Paths, verbose: bool) -> bool {
    print!("  Checking TLS certificates... ");

    if let Ok(config_str) = fs::read_to_string(paths.get_input_config_path()) {
        if let Ok(config) = serde_json::from_str::<serde_json::Value>(&config_str) {
            // Check for cert paths in inbounds
            let mut cert_found = false;
            let mut key_found = false;

            if let Some(inbounds) = config.get("inbounds").and_then(|i| i.as_array()) {
                for inbound in inbounds {
                    if let Some(tls) = inbound.get("tls") {
                        if let Some(cert) = tls.get("cert_path").or(tls.get("certificate_path"))
                            && let Some(path) = cert.as_str()
                                && !path.is_empty() && path != "/path/to/cert.crt" {
                                    cert_found = true;
                                    if verbose {
                                        println!("\n      {} Cert: {}", "[*]".cyan(), path);
                                    }
                                }
                        if let Some(key) = tls.get("key_path").or(tls.get("private_key_path"))
                            && let Some(path) = key.as_str()
                                && !path.is_empty() && path != "/path/to/cert.key" {
                                    key_found = true;
                                    if verbose {
                                        println!("      {} Key: {}", "[*]".cyan(), path);
                                    }
                                }
                    }
                }
            }

            if cert_found && key_found {
                println!("{}", "[OK]".green());
                true
            } else if !cert_found {
                println!("{}", "[WARN]".yellow());
                if verbose {
                    println!("\n      {} TLS certificates not configured or using defaults", "[!]".yellow());
                }
                false
            } else {
                println!("{}", "[WARN]".yellow());
                false
            }
        } else {
            println!("{}", "[ERROR]".red());
            if verbose {
                println!("      {} Failed to parse config", "[!]".red());
            }
            false
        }
    } else {
        println!("{}", "[SKIP]".dimmed());
        false
    }
}

fn check_reality_keys(paths: &Paths, verbose: bool) -> bool {
    print!("  Checking Reality keys... ");

    if let Ok(config_str) = fs::read_to_string(paths.get_input_config_path()) {
        if let Ok(config) = serde_json::from_str::<serde_json::Value>(&config_str) {
            let mut has_private_key = false;

            if let Some(inbounds) = config.get("inbounds").and_then(|i| i.as_array()) {
                for inbound in inbounds {
                    if inbound.get("type") == Some(&serde_json::Value::String("vless".to_string()))
                        && let Some(tls) = inbound.get("tls")
                            && let Some(reality) = tls.get("reality")
                                && let Some(pk) = reality.get("private_key")
                                    && let Some(key) = pk.as_str()
                                        && !key.is_empty() {
                                            has_private_key = true;
                                            if verbose {
                                                let masked = if key.len() > 8 {
                                                    format!("{}...{}", &key[..4], &key[key.len()-4..])
                                                } else {
                                                    "****".to_string()
                                                };
                                                println!("\n      {} Private key: {}", "[*]".cyan(), masked);
                                            }
                                        }
                }
            }

            if has_private_key {
                println!("{}", "[OK]".green());
                true
            } else {
                println!("{}", "[WARN]".yellow());
                if verbose {
                    println!("\n      {} Reality private key not configured", "[!]".yellow());
                    println!("      {} Run: mimictl gen-keys", "[>]".cyan());
                }
                false
            }
        } else {
            println!("{}", "[SKIP]".dimmed());
            true
        }
    } else {
        println!("{}", "[SKIP]".dimmed());
        true
    }
}

fn check_dns_configuration(paths: &Paths, verbose: bool) -> bool {
    print!("  Checking DNS configuration... ");

    if let Ok(config_str) = fs::read_to_string(paths.get_input_config_path())
        && let Ok(config) = serde_json::from_str::<serde_json::Value>(&config_str)
            && let Some(dns) = config.get("dns")
                && let Some(servers) = dns.get("servers").and_then(|s| s.as_array()) {
                    let server_types: Vec<_> = servers
                        .iter()
                        .filter_map(|s| s.get("type").and_then(|t| t.as_str()))
                        .collect();

                    if verbose {
                        println!("\n      {} DNS servers: {:?}", "[*]".cyan(), server_types);
                    }

                    let has_encrypted = server_types.iter().any(|t| {
                        matches!(*t, "tls" | "h3" | "https" | "dnsjson" | "dnsseg")
                    });

                    if has_encrypted {
                        println!("{}", "[OK]".green());
                        return true;
                    } else {
                        println!("{}", "[WARN]".yellow());
                        if verbose {
                            println!("      {} No encrypted DNS (consider adding DoH3)", "[!]".yellow());
                        }
                        return false;
                    }
                }

    println!("{}", "[SKIP]".dimmed());
    true
}

fn check_permission_settings(paths: &Paths, verbose: bool) -> bool {
    print!("  Checking file permissions... ");

    let config_path = paths.config.to_str().unwrap_or("");

    if config_path.is_empty() || config_path == "/etc/sing-box/config.json" {
        // Check if running as root or proper user
        let output = Command::new("id")
            .args(["-u"])
            .output();

        if let Ok(o) = output {
            let uid = String::from_utf8_lossy(&o.stdout);
            if uid.trim() == "0" {
                println!("{}", "[WARN]".yellow());
                if verbose {
                    println!("\n      {} Running as root is not recommended", "[!]".yellow());
                }
                return false;
            }
        }
    }

    println!("{}", "[OK]".green());
    true
}

fn check_recent_commits(verbose: bool) -> bool {
    if !verbose {
        return true;
    }

    print!("  Checking recent git commits... ");

    let output = Command::new("git")
        .args(["log", "--oneline", "-5"])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            let commits = String::from_utf8_lossy(&o.stdout);
            println!("{}", "[OK]".green());
            println!("\n      {} Recent commits:", "[*]".cyan());
            for line in commits.lines().take(5) {
                println!("      {} {}", "[>]".dimmed(), line);
            }
            true
        }
        _ => {
            println!("{}", "[SKIP]".dimmed());
            true
        }
    }
}

fn check_kernel_tls_support(verbose: bool) -> bool {
    print!("  Checking kernel TLS support... ");

    // Check Linux kernel version for kTLS support (5.1+)
    let output = Command::new("uname")
        .args(["-r"])
        .output();

    match output {
        Ok(o) => {
            let version = String::from_utf8_lossy(&o.stdout);
            let version_str = version.trim();

            // Parse kernel version
            let parts: Vec<&str> = version_str.split('.').collect();
            if parts.len() >= 2 {
                let major: u32 = parts[0].parse().unwrap_or(0);
                let minor: u32 = parts[1].parse().unwrap_or(0);

                if major > 5 || (major == 5 && minor >= 1) {
                    println!("{}", "[OK]".green());
                    if verbose {
                        println!("\n      {} Kernel {} supports kTLS", "[*]".cyan(), version_str);
                    }
                    return true;
                }
            }

            println!("{}", "[INFO]".cyan());
            if verbose {
                println!("\n      {} Kernel {} may not support kTLS (need 5.1+)", "[*]".cyan(), version_str);
            }
            true // Not critical
        }
        _ => {
            println!("{}", "[SKIP]".dimmed());
            true
        }
    }
}

fn check_bbr_enabled(verbose: bool) -> bool {
    print!("  Checking BBR congestion control... ");

    let output = Command::new("sysctl")
        .args(["net.ipv4.tcp_congestion_control"])
        .output();

    match output {
        Ok(o) => {
            let value = String::from_utf8_lossy(&o.stdout);
            let has_bbr = value.contains("bbr");

            if has_bbr {
                println!("{}", "[OK]".green());
                if verbose {
                    println!("\n      {} BBR enabled", "[*]".cyan());
                }
                true
            } else {
                println!("{}", "[INFO]".cyan());
                if verbose {
                    println!("\n      {} BBR not enabled (consider enabling for better performance)", "[*]".cyan());
                    println!("      {} Run: sudo sysctl -w net.ipv4.tcp_congestion_control=bbr", "[>]".cyan());
                }
                true // Not critical
            }
        }
        _ => {
            println!("{}", "[SKIP]".dimmed());
            true
        }
    }
}

fn check_protocol_sniffing(paths: &Paths, verbose: bool) -> bool {
    print!("  Checking protocol sniffing... ");

    if let Ok(config_str) = fs::read_to_string(paths.get_input_config_path()) {
        if let Ok(config) = serde_json::from_str::<serde_json::Value>(&config_str) {
            let mut sniffing_enabled = false;
            let mut sniff_rules_count = 0;
            let supported_protocols = vec![
                "HTTP (http)",
                "TLS (tls)",
                "QUIC (quic)",
                "STUN (stun)",
                "DNS (dns)",
                "BitTorrent (bittorrent)",
                "DTLS (dtls)",
                "SSH (ssh)",
                "RDP (rdp)",
                "NTP (ntp)",
            ];

            if let Some(route) = config.get("route")
                && let Some(rules) = route.get("rules").and_then(|r| r.as_array()) {
                    for rule in rules {
                        if rule.get("action") == Some(&serde_json::Value::String("sniff".to_string())) {
                            sniff_rules_count += 1;
                            sniffing_enabled = true;
                        }
                    }
                }

            if sniffing_enabled {
                println!("{}", "[OK]".green());
                if verbose {
                    println!("      {} Protocol sniffing: {} rules configured", "[*]".cyan(), sniff_rules_count);
                    println!("      {} Supported protocols:", "[*]".cyan());
                    for proto in supported_protocols.iter().take(6) {
                        println!("        {} {}", "[>]".dimmed(), proto);
                    }
                    println!("        {} ... and more", "[>]".dimmed());
                }
                true
            } else {
                println!("{}", "[WARN]".yellow());
                if verbose {
                    println!("      {} No sniff rules found in route configuration", "[!]".yellow());
                    println!("      {} Recommended: Add {{\"action\": \"sniff\"}} to route rules", "[*]".cyan());
                }
                false
            }
        } else {
            println!("{}", "[SKIP]".dimmed());
            true
        }
    } else {
        println!("{}", "[SKIP]".dimmed());
        true
    }
}

fn check_deprecated_features(paths: &Paths, verbose: bool) -> bool {
    print!("  Checking for deprecated features... ");

    if let Ok(config_str) = fs::read_to_string(paths.get_input_config_path()) {
        if let Ok(config) = serde_json::from_str::<serde_json::Value>(&config_str) {
            let mut issues = Vec::new();

            issues.append(&mut check_deprecated_114(&config, verbose));
            issues.append(&mut check_deprecated_113(&config, verbose));
            issues.append(&mut check_deprecated_112(&config, verbose));
            issues.append(&mut check_deprecated_111(&config, verbose));
            issues.append(&mut check_deprecated_110(&config, verbose));
            issues.append(&mut check_deprecated_18(&config, verbose));

            if issues.is_empty() {
                println!("{}", "[OK]".green());
                true
            } else {
                println!("{}", "[WARN]".yellow());
                if verbose {
                    for issue in &issues {
                        println!("      {} {}", "[!]".yellow(), issue);
                    }
                }
                false
            }
        } else {
            println!("{}", "[SKIP]".dimmed());
            true
        }
    } else {
        println!("{}", "[SKIP]".dimmed());
        true
    }
}

fn check_deprecated_114(config: &serde_json::Value, verbose: bool) -> Vec<String> {
    let mut issues = Vec::new();

    if let Some(experimental) = config.get("experimental") {
        if experimental.get("download_detour").is_some() {
            issues.push("download_detour (1.14.0+: removed, use routing rules)".to_string());
        }
        if experimental.get("independent_cache").is_some() {
            issues.push("independent_cache (1.14.0+: removed, use experimental.cache_file)".to_string());
        }
    }

    if let Some(cert_providers) = config.get("certificate_providers")
        && cert_providers.get("acme").is_some() {
            issues.push("certificate_providers.acme (1.14.0+: moved to experimental.ACME)".to_string());
        }

    if let Some(endpoints) = config.get("endpoints").and_then(|e| e.as_array()) {
        for endpoint in endpoints {
            if endpoint.get("type") == Some(&serde_json::Value::String("tailscale".to_string()))
                && endpoint.get("control_url").is_some() {
                    issues.push("endpoints.tailscale.control_url (1.14.0+: removed)".to_string());
                }
        }
    }

    if let Some(route) = config.get("route")
        && route.get("store_rdrc").is_some() {
            issues.push("route.store_rdrc (1.14.0+: removed)".to_string());
        }

    if verbose && !issues.is_empty() {
        println!("\n      {} sing-box 1.14.0 deprecations:", "[*]".cyan());
    }
    issues
}

fn check_deprecated_113(config: &serde_json::Value, verbose: bool) -> Vec<String> {
    let mut issues = Vec::new();

    if let Some(inbounds) = config.get("inbounds").and_then(|i| i.as_array()) {
        for inbound in inbounds {
            if inbound.get("sniff").is_some() || inbound.get("sniff_override_destination").is_some() {
                issues.push("inbound sniff/sniff_override_destination (1.13.0+: use route.sniff)".to_string());
            }
            if inbound.get("type") == Some(&serde_json::Value::String("tun".to_string()))
                && inbound.get("gsgo").is_some() {
                    issues.push("inbound.tun.gsgo (1.13.0+: renamed to kernel_gso)".to_string());
                }
        }
    }

    if let Some(outbounds) = config.get("outbounds").and_then(|o| o.as_array()) {
        for outbound in outbounds {
            if outbound.get("type") == Some(&serde_json::Value::String("wireguard".to_string())) {
                issues.push("outbound.wireguard (1.13.0+: use endpoint + selector)".to_string());
            }
            if (outbound.get("type") == Some(&serde_json::Value::String("block".to_string()))
                || outbound.get("type") == Some(&serde_json::Value::String("dns".to_string())))
                && outbound.get("outbound").is_some() {
                    issues.push("outbound.block/dns with outbound field (1.13.0+: removed)".to_string());
                }
        }
    }

    if verbose && !issues.is_empty() {
        println!("\n      {} sing-box 1.13.0 deprecations:", "[*]".cyan());
    }
    issues
}

fn check_deprecated_112(config: &serde_json::Value, verbose: bool) -> Vec<String> {
    let mut issues = Vec::new();

    if let Some(dns) = config.get("dns").and_then(|d| d.as_object())
        && let Some(servers) = dns.get("servers").and_then(|s| s.as_array()) {
            for server in servers {
                if let Some(srv_type) = server.get("type").and_then(|t| t.as_str())
                    && srv_type == "dns" {
                        issues.push("dns.servers[].type=dns (1.12.0+: use udp or tls)".to_string());
                    }
                if server.get("ip_version").is_some() {
                    issues.push("dns.servers[].ip_version (1.12.0+: removed)".to_string());
                }
                if server.get("bounds").is_some() {
                    issues.push("dns.servers[].bounds (1.12.0+: removed)".to_string());
                }
            }
        }

    if let Some(tls) = config.get("tls").and_then(|t| t.as_object())
        && tls.get("ech").is_some() {
            issues.push("tls.ech (1.12.0+: use TLS inbounds with ECH)".to_string());
        }

    if verbose && !issues.is_empty() {
        println!("\n      {} sing-box 1.12.0 deprecations:", "[*]".cyan());
    }
    issues
}

fn check_deprecated_111(config: &serde_json::Value, verbose: bool) -> Vec<String> {
    let mut issues = Vec::new();

    if let Some(outbounds) = config.get("outbounds").and_then(|o| o.as_array()) {
        for outbound in outbounds {
            if outbound.get("type") == Some(&serde_json::Value::String("direct".to_string())) {
                if outbound.get("override_address").is_some() {
                    issues.push("outbound.direct.override_address (1.11.0+: removed)".to_string());
                }
                if outbound.get("override_port").is_some() {
                    issues.push("outbound.direct.override_port (1.11.0+: removed)".to_string());
                }
            }
        }
    }

    if verbose && !issues.is_empty() {
        println!("\n      {} sing-box 1.11.0 deprecations:", "[*]".cyan());
    }
    issues
}

fn check_deprecated_110(config: &serde_json::Value, verbose: bool) -> Vec<String> {
    let mut issues = Vec::new();

    if let Some(inbounds) = config.get("inbounds").and_then(|i| i.as_array()) {
        for inbound in inbounds {
            if inbound.get("inet4_address").is_some() {
                issues.push("inbound.inet4_address (1.10.0+: use address)".to_string());
            }
            if inbound.get("inet6_address").is_some() {
                issues.push("inbound.inet6_address (1.10.0+: use address)".to_string());
            }
        }
    }

    if verbose && !issues.is_empty() {
        println!("\n      {} sing-box 1.10.0 deprecations:", "[*]".cyan());
    }
    issues
}

fn check_deprecated_18(config: &serde_json::Value, verbose: bool) -> Vec<String> {
    let mut issues = Vec::new();

    if let Some(rule_sets) = config.get("route").and_then(|r| r.get("rule_set")).and_then(|rs| rs.as_array()) {
        for rule_set in rule_sets {
            if let Some(rs_type) = rule_set.get("type").and_then(|t| t.as_str())
                && (rs_type == "geoip" || rs_type == "geosite") {
                    issues.push(format!("rule_set.type={} (1.8.0+: use remote format)", rs_type));
                }
        }
    }

    if let Some(experimental) = config.get("experimental") {
        if experimental.get("clash_api").and_then(|c| c.get("cache_file")).is_some() {
            issues.push("experimental.clash_api.cache_file (1.8.0+: use experimental.cache_file)".to_string());
        }
        if experimental.get("clash_api").and_then(|c| c.get("store_mode")).is_some() {
            issues.push("experimental.clash_api.store_mode (1.8.0+: removed)".to_string());
        }
    }

    if verbose && !issues.is_empty() {
        println!("\n      {} sing-box 1.8.0 deprecations:", "[*]".cyan());
    }
    issues
}

fn check_hysteria2(paths: &Paths, verbose: bool) -> bool {
    print!("  Checking Hysteria2 configuration... ");

    if let Ok(config_str) = fs::read_to_string(paths.get_input_config_path()) {
        if let Ok(config) = serde_json::from_str::<serde_json::Value>(&config_str) {
            if let Some(inbounds) = config.get("inbounds").and_then(|i| i.as_array()) {
                if let Some(hy2) = inbounds.iter().find(|i| {
                    i.get("type") == Some(&serde_json::Value::String("hysteria2".to_string()))
                }) {
                    let port = hy2.get("listen_port").and_then(|p| p.as_u64()).unwrap_or(8443);
                    let has_obfs = hy2.get("obfs").is_some();
                    let has_limits = hy2.get("up_mbps").is_some() || hy2.get("down_mbps").is_some();
                    let has_server_name = hy2.get("tls")
                        .and_then(|t| t.get("server_name"))
                        .and_then(|s| s.as_str())
                        .filter(|s| !s.is_empty())
                        .is_some();

                    println!("{}", "[OK]".green());
                    if verbose {
                        println!("      {} Port: {}", "[*]".cyan(), port);
                        println!("      {} Obfuscation: {}", "[*]".cyan(), if has_obfs { "enabled" } else { "disabled" });
                        println!("      {} Speed Limits: {}", "[*]".cyan(), if has_limits { "set" } else { "unlimited" });
                        println!("      {} Domain: {}", "[*]".cyan(), if has_server_name {
                            hy2.get("tls").and_then(|t| t.get("server_name")).and_then(|s| s.as_str()).unwrap_or("N/A")
                        } else { "using IP" });
                    }
                    return true;
                }
            }
        }
    }
    println!("{}", "[INFO]".cyan());
    if verbose {
        println!("      {} No Hysteria2 inbound configured", "[*]".cyan());
    }
    true // Not critical
}
