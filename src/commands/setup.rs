use anyhow::Result;
use colored::*;
use std::io::{self, Write};
use std::path::Path;
use std::process::Command;

use crate::paths::Paths;

pub fn interactive(paths: &Paths) -> Result<()> {
    clear_screen();
    println!(r#"
    ███╗   ███╗██╗██████╗ ███████╗██╗    ██╗ █████╗ ██╗   ██╗
    ████╗ ████║██║██╔══██╗██╔════╝██║    ██║██╔══██╗╚██╗ ██╔╝
    ██╔████╔██║██║██████╔╝█████╗  ██║ █╗ ██║███████║ ╚████╔╝
    ██║╚██╔╝██║██║██╔═══╝ ██╔══╝ ██║███╗██║██╔══██║  ╚██╔╝
    ██║ ╚═╝ ██║██║██║     ███████╗╚███╔███╔╝██║  ██║   ██║
    ╚═╝     ╚═╝╚═╝╚═╝     ╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝
    "#);
    println!("{}", "  Mimic-Node Setup Wizard v1.0\n".white());

    println!("{}", "  Welcome to Mimic-Node Interactive Setup!\n".white());
    println!("{}", "  This wizard will guide you through node configuration.\n".dimmed());

    loop {
        clear_screen();
        show_main_menu();

        let choice = prompt_menu("Select an option", &["Start Setup", "User Management", "View Current Config", "Interactive Config Editor", "Generate Keys", "Exit"])?;

        match choice {
            0 => {
                if let Err(e) = run_setup_wizard(paths) {
                    eprintln!("{} Setup error: {}", "[ERROR]".red(), e);
                    prompt_enter()?;
                }
            }
            1 => {
                if let Err(e) = user_management(paths) {
                    eprintln!("{} User management error: {}", "[ERROR]".red(), e);
                    prompt_enter()?;
                }
            }
            2 => {
                view_current_config(paths)?;
            }
            3 => {
                if let Err(e) = interactive_config_editor(paths) {
                    eprintln!("{} Config editor error: {}", "[ERROR]".red(), e);
                    prompt_enter()?;
                }
            }
            4 => {
                generateRealityKeys(paths)?;
            }
            5 => {
                println!("\n{}", "  Goodbye!".green());
                break;
            }
            _ => {}
        }
    }

    Ok(())
}

fn show_main_menu() {
    println!(r#"
╭─────────────────────────────────────────────────╮
│              Mimic-Node Main Menu              │
├─────────────────────────────────────────────────┤
│  [1] ● Start Setup          Configure new node  │
│  [2] ● User Management      Add/Remove/List    │
│  [3] ● View Current Config  Show configuration  │
│  [4] ● Interactive Editor   Edit with hints     │
│  [5] ● Generate Keys        Reality keypair      │
│  [0] ○ Exit                 Quit setup           │
╰─────────────────────────────────────────────────╯
"#);
}

fn run_setup_wizard(_paths: &Paths) -> Result<()> {
    clear_screen();
    println!(r#"
╭─────────────────────────────────────────────────╮
│              Node Setup Wizard                  │
╰─────────────────────────────────────────────────╯
"#);

    println!("{}", "  Welcome! This wizard will help you configure your node.\n".white());
    println!("{}", "  Let's start with the basics.\n".dimmed());

    // Step 1: Protocol Selection
    println!("{}", "\n  [Step 1/5] Protocol Selection\n".cyan().bold());
    println!("{}", "  Which protocols would you like to enable?\n".dimmed());

    let protocol_options = [
        "VLESS + Reality (Recommended - Best for GFW evasion)",
        "Hysteria2 (High speed QUIC protocol)",
        "TUN Mode (System VPN - Route all traffic)",
        "SSH (Secure Shell)",
        "Select All",
    ];

    let proto_choice = prompt_menu("Select primary protocol", &protocol_options)?;

    let enable_vless = proto_choice != 1;
    let enable_hy2 = proto_choice == 1 || proto_choice == 4;
    let enable_tun = proto_choice == 2 || proto_choice == 4;
    let enable_ssh = proto_choice == 3 || proto_choice == 4;

    // Step 2: Network Settings
    println!("\n{}", "  [Step 2/5] Network Settings\n".cyan().bold());

    let port: u16 = prompt_input("  Listen port (default: 443)", Some("443".to_string()))?
        .parse()
        .unwrap_or(443);

    let sni_domain = prompt_input("  SNI Domain for TLS (e.g., microsoft.com)", Some("microsoft.com".to_string()))?;

    let enable_ipv6 = prompt_yes_no("  Enable IPv6 support?", false)?;

    // Step 3: Performance Settings
    println!("\n{}", "  [Step 3/5] Performance Settings\n".cyan().bold());

    let enable_bbr = prompt_yes_no("  Enable BBR congestion control?", true)?;
    let enable_tfo = prompt_yes_no("  Enable TCP Fast Open?", true)?;
    let enable_multiplex = prompt_yes_no("  Enable Multiplex (better throughput)?", true)?;

    let up_mbps: u32 = prompt_input("  Upload limit (Mbps, 0 = unlimited)", Some("100".to_string()))?
        .parse()
        .unwrap_or(100);
    let down_mbps: u32 = prompt_input("  Download limit (Mbps, 0 = unlimited)", Some("200".to_string()))?
        .parse()
        .unwrap_or(200);

    // Step 4: DNS Settings
    println!("\n{}", "  [Step 4/5] DNS Settings\n".cyan().bold());

    let dns_options = [
        "Google DNS (8.8.8.8) - Recommended",
        "Cloudflare DNS (1.1.1.1) - Fast & Private",
        "Custom DNS",
    ];

    let dns_choice = prompt_menu("Select DNS provider", &dns_options)?;

    let dns_strategy = prompt_menu("DNS Strategy", &["prefer_ipv4 (Recommended)", "prefer_ipv6", "ipv4_only", "ipv6_only"])?;

    // Step 5: User Configuration
    println!("\n{}", "  [Step 5/5] User Configuration\n".cyan().bold());
    let add_users = prompt_yes_no("  Would you like to add users now?", true)?;

    let mut users = Vec::new();
    if add_users {
        println!("\n  Enter user details (email format recommended):");
        loop {
            let email = prompt_input("  User email (or Enter to finish adding users)", None)?;
            if email.is_empty() {
                break;
            }
            let level: u32 = prompt_input("  User level (0=normal, 100=admin)", Some("0".to_string()))?
                .parse()
                .unwrap_or(0);
            users.push((email.clone(), level));
            println!("{}", format!("  {} Added: {} (level: {})", "[OK]".green(), email, level));
        }
    }

    // Generate Reality keys if VLESS is enabled
    let mut generate_keys = false;
    if enable_vless {
        println!("\n{}", "  Generating Reality keys for VLESS...".cyan());
        generate_keys = prompt_yes_no("  Generate new Reality keypair?", true)?;
    }

    // Summary and Confirmation
    clear_screen();
    println!(r#"
╭─────────────────────────────────────────────────╮
│            Configuration Summary                 │
╰─────────────────────────────────────────────────╯
"#);

    println!("\n  Protocols:");
    if enable_vless { println!("  {} VLESS + Reality", "[+]".green()); }
    if enable_hy2 { println!("  {} Hysteria2", "[+]".green()); }
    if enable_tun { println!("  {} TUN (System VPN)", "[+]".green()); }
    if enable_ssh { println!("  {} SSH", "[+]".green()); }

    println!("\n  Network:");
    println!("  {} Listen Port: {}", "[*]".cyan(), port);
    println!("  {} SNI Domain: {}", "[*]".cyan(), sni_domain);
    println!("  {} IPv6: {}", "[*]".cyan(), if enable_ipv6 { "Enabled" } else { "Disabled" });

    println!("\n  Performance:");
    println!("  {} BBR: {}", "[*]".cyan(), if enable_bbr { "Enabled" } else { "Disabled" });
    println!("  {} TCP Fast Open: {}", "[*]".cyan(), if enable_tfo { "Enabled" } else { "Disabled" });
    println!("  {} Multiplex: {}", "[*]".cyan(), if enable_multiplex { "Enabled" } else { "Disabled" });
    println!("  {} Bandwidth: up={}Mbps, down={}Mbps", "[*]".cyan(), up_mbps, down_mbps);

    println!("\n  DNS:");
    match dns_choice {
        0 => println!("  {} Google DNS (8.8.8.8)", "[*]".cyan()),
        1 => println!("  {} Cloudflare DNS (1.1.1.1)", "[*]".cyan()),
        _ => println!("  {} Custom DNS", "[*]".cyan()),
    }
    let strategies = ["prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only"];
    println!("  {} Strategy: {}", "[*]".cyan(), strategies[dns_strategy]);

    if !users.is_empty() {
        println!("\n  Users ({} total):", users.len());
        for (email, level) in &users {
            println!("  {} {} (level: {})", "[*]".cyan(), email, level);
        }
    } else {
        println!("\n  {} No users added (you can add later with 'mimictl add')", "[*]".dimmed());
    }

    if enable_vless && generate_keys {
        println!("\n  {} Reality keys will be generated", "[*]".cyan());
    }

    println!(r#"

╭─────────────────────────────────────────────────╮
│  This will create a staging config at:          │
│  /var/lib/mimic-node/staging/config.json        │
│                                                  │
│  After setup, run 'mimictl apply' to activate.  │
╰─────────────────────────────────────────────────╯
"#);

    let confirm = prompt_yes_no("\n  Create this configuration?", true)?;

    if confirm {
        // Build the configuration
        let mut config = serde_json::json!({
            "log": {
                "level": "warn",
                "timestamp": true
            },
            "dns": {
                "servers": [
                    {"tag": "google", "type": "h3", "server": "dns.google", "server_port": 443, "path": "/dns-query"},
                    {"tag": "alidns", "type": "udp", "server": "223.5.5.5"}
                ],
                "rules": [
                    {"rule_set": ["geosite-cn"], "server": "alidns"},
                    {"protocol": "dns", "outbound": "direct"}
                ],
                "final": "google",
                "strategy": strategies[dns_strategy]
            },
            "inbounds": [],
            "outbounds": [
                {"type": "direct", "tag": "direct"},
                {"type": "block", "tag": "block"}
            ],
            "route": {
                "rules": [
                    {"protocol": "dns", "outbound": "direct"},
                    {"rule_set": ["geosite-cn", "geoip-cn"], "outbound": "block"}
                ],
                "rule_set": [
                    {"tag": "geosite-cn", "type": "remote", "format": "binary", "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs"},
                    {"tag": "geoip-cn", "type": "remote", "format": "binary", "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs"}
                ],
                "final": "direct"
            },
            "services": [
                {"type": "ssm-api", "tag": "ssm-api", "listen": "127.0.0.1", "listen_port": 9090}
            ]
        });

        // Add inbounds based on selection
        let inbounds = config.as_object_mut().unwrap().get_mut("inbounds").unwrap().as_array_mut().unwrap();

        if enable_vless {
            let vless_inbound = serde_json::json!({
                "type": "vless",
                "tag": "vless-in",
                "listen": "::",
                "listen_port": port,
                "tcp_fast_open": enable_tfo,
                "tcp_keep_alive": "5m",
                "udp_timeout": "5m",
                "multiplex": {
                    "enabled": enable_multiplex,
                    "padding": false,
                    "brutal": {
                        "enabled": enable_multiplex,
                        "up_mbps": up_mbps,
                        "down_mbps": down_mbps
                    }
                },
                "users": users.iter().filter(|(_email, _)| true).map(|(email, level)| {
                    serde_json::json!({"name": email, "level": level})
                }).collect::<Vec<_>>(),
                "tls": {
                    "enabled": true,
                    "server_name": sni_domain,
                    "handshake_timeout": "15s",
                    "kernel_tx": true,
                    "reality": {
                        "enabled": true,
                        "handshake": {"server": format!("https://{}", sni_domain), "server_port": 443},
                        "private_key": "",
                        "short_id": []
                    }
                }
            });
            inbounds.push(vless_inbound);
        }

        if enable_hy2 {
            let hy2_password = uuid::Uuid::new_v4().to_string().split('-').next().unwrap_or("password").to_string();
            let hy2_inbound = serde_json::json!({
                "type": "hysteria2",
                "tag": "hy2-in",
                "listen": "::",
                "listen_port": if enable_vless { port + 1 } else { port },
                "tcp_fast_open": enable_tfo,
                "up_mbps": up_mbps,
                "down_mbps": down_mbps,
                "users": [{"name": "admin", "password": hy2_password}],
                "tls": {
                    "enabled": true,
                    "alpn": ["h3"],
                    "cert_path": "/path/to/cert.pem",
                    "key_path": "/path/to/key.pem"
                },
                "masquerade": format!("https://{}", sni_domain),
                "bbr_profile": if enable_bbr { "bbr" } else { "" }
            });
            inbounds.push(hy2_inbound);
        }

        if enable_tun {
            let tun_inbound = serde_json::json!({
                "type": "tun",
                "tag": "tun-in",
                "interface_name": "tun0",
                "address": if enable_ipv6 {
                    serde_json::json!(["172.18.0.1/30", "fdfe:dcba:9876::1/126"])
                } else {
                    serde_json::json!(["172.18.0.1/30"])
                },
                "mtu": 9000,
                "auto_route": true,
                "strict_route": true,
                "endpoint_independent_nat": false,
                "udp_timeout": "5m",
                "stack": "system"
            });
            inbounds.push(tun_inbound);
        }

        if enable_ssh {
            let ssh_inbound = serde_json::json!({
                "type": "ssh",
                "tag": "ssh-in",
                "listen": "::",
                "listen_port": 22,
                "tcp_fast_open": enable_tfo,
                "users": [{"name": "root", "password": ""}]
            });
            inbounds.push(ssh_inbound);
        }

        // Write staging config
        let staging_dir = Path::new("/var/lib/mimic-node/staging");
        std::fs::create_dir_all(staging_dir)?;

        let config_path = staging_dir.join("config.json");
        let config_str = serde_json::to_string_pretty(&config)?;
        std::fs::write(&config_path, &config_str)?;

        println!("\n{}", format!("  {} Configuration created at: {}", "[OK]".green(), config_path.display()));
        println!("\n{}", "  Next steps:".cyan().bold());
        println!("  {} 1. Review: mimictl show", "[>]".dimmed());
        println!("  {} 2. Apply: mimictl apply", "[>]".dimmed());
        if enable_vless && generate_keys {
            println!("  {} 3. Generate keys: mimictl gen-keys", "[>]".dimmed());
            println!("  {} 4. Then apply again: mimictl apply", "[>]".dimmed());
        }
    } else {
        println!("\n{}", "  Setup cancelled. No changes made.".yellow());
    }

    prompt_enter()?;
    Ok(())
}

fn user_management(paths: &Paths) -> Result<()> {
    loop {
        clear_screen();
        println!(r#"
╭─────────────────────────────────────────────────╮
│              User Management                    │
╰─────────────────────────────────────────────────╯
"#);

        let options = [
            "List All Users",
            "Add New User",
            "Remove User",
            "Reset User UUID/SID",
            "Back to Main Menu",
        ];

        let choice = prompt_menu("Select action", &options)?;

        match choice {
            0 => {
                list_users(paths)?;
            }
            1 => {
                add_new_user(paths)?;
            }
            2 => {
                remove_user(paths)?;
            }
            3 => {
                reset_user(paths)?;
            }
            4 => {
                break;
            }
            _ => {}
        }
    }
    Ok(())
}

fn list_users(paths: &Paths) -> Result<()> {
    clear_screen();
    println!(r#"
╭─────────────────────────────────────────────────╮
│              User List                          │
╰─────────────────────────────────────────────────╯
"#);

    // Use existing user list command
    let config_str = std::fs::read_to_string(paths.get_input_config_path())?;
    let config: serde_json::Value = serde_json::from_str(&config_str)?;

    if let Some(inbounds) = config.get("inbounds").and_then(|i| i.as_array()) {
        for inbound in inbounds {
            if inbound.get("type").and_then(|t| t.as_str()) == Some("vless")
                && let Some(users) = inbound.get("users").and_then(|u| u.as_array()) {
                    println!("\n  VLESS Users:\n");
                    println!("  {:<40} {:<10} {:<20}", "Email", "Level", "UUID");
                    println!("  {}", "-".repeat(70));
                    for user in users {
                        let name = user.get("name").and_then(|n| n.as_str()).unwrap_or("-");
                        let uuid = user.get("uuid").and_then(|u| u.as_str()).unwrap_or("-");
                        let flow = user.get("flow").and_then(|f| f.as_str()).unwrap_or("-");
                        println!("  {:<40} {:<10} {:<36}", name, flow, uuid);
                    }
                }
        }
    }

    prompt_enter()?;
    Ok(())
}

fn add_new_user(_paths: &Paths) -> Result<()> {
    clear_screen();
    println!(r#"
╭─────────────────────────────────────────────────╮
│              Add New User                       │
╰─────────────────────────────────────────────────╯
"#);

    let email = prompt_input("  User email", None)?;
    if email.is_empty() {
        println!("{}", "  Cancelled".yellow());
        prompt_enter()?;
        return Ok(());
    }

    let level_str = prompt_input("  User level (default: 0)", Some("0".to_string()))?;
    let level: u32 = level_str.parse().unwrap_or(0);

    // Use mimictl add command
    let output = Command::new("mimictl")
        .args(["add", &email, "--level", &level.to_string()])
        .output()?;

    if output.status.success() {
        println!("\n{}", format!("  {} User '{}' added successfully!", "[OK]".green(), email));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("\n{}", format!("  {} Error: {}", "[ERROR]".red(), stderr));
    }

    prompt_enter()?;
    Ok(())
}

fn remove_user(_paths: &Paths) -> Result<()> {
    clear_screen();
    println!(r#"
╭─────────────────────────────────────────────────╮
│              Remove User                        │
╰─────────────────────────────────────────────────╯
"#);

    let target = prompt_input("  User email or pattern (e.g., *@example.com)", None)?;
    if target.is_empty() {
        println!("{}", "  Cancelled".yellow());
        prompt_enter()?;
        return Ok(());
    }

    let output = Command::new("mimictl")
        .args(["del", &target])
        .output()?;

    if output.status.success() {
        println!("\n{}", format!("  {} User(s) removed", "[OK]".green()));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("\n{}", format!("  {} Error: {}", "[ERROR]".red(), stderr));
    }

    prompt_enter()?;
    Ok(())
}

fn reset_user(_paths: &Paths) -> Result<()> {
    clear_screen();
    println!(r#"
╭─────────────────────────────────────────────────╮
│            Reset User UUID/SID                   │
╰─────────────────────────────────────────────────╯
"#);

    let target = prompt_input("  User email or pattern", None)?;
    if target.is_empty() {
        println!("{}", "  Cancelled".yellow());
        prompt_enter()?;
        return Ok(());
    }

    let output = Command::new("mimictl")
        .args(["reset-user", &target])
        .output()?;

    if output.status.success() {
        println!("\n{}", format!("  {} User(s) reset", "[OK]".green()));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("\n{}", format!("  {} Error: {}", "[ERROR]".red(), stderr));
    }

    prompt_enter()?;
    Ok(())
}

fn view_current_config(paths: &Paths) -> Result<()> {
    clear_screen();
    println!(r#"
╭─────────────────────────────────────────────────╮
│          Current Configuration                   │
╰─────────────────────────────────────────────────╯
"#);

    let config_str = std::fs::read_to_string(paths.get_input_config_path())?;
    let config: serde_json::Value = serde_json::from_str(&config_str)?;

    println!("{}", serde_json::to_string_pretty(&config).unwrap().cyan());

    prompt_enter()?;
    Ok(())
}

fn generateRealityKeys(_paths: &Paths) -> Result<()> {
    clear_screen();
    println!(r#"
╭─────────────────────────────────────────────────╮
│           Generate Reality Keys                  │
╰─────────────────────────────────────────────────╯
"#);

    let output = Command::new("mimictl")
        .args(["gen-keys"])
        .output()?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        println!("\n{}", stdout);
        println!("\n{}", "  Keys generated and staged! Run 'mimictl apply' to activate.".green());
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("\n{}", format!("  {} Error: {}", "[ERROR]".red(), stderr));
    }

    prompt_enter()?;
    Ok(())
}

fn interactive_config_editor(paths: &Paths) -> Result<()> {
    loop {
        clear_screen();
        println!(r#"
╭─────────────────────────────────────────────────╮
│         Interactive Config Editor                │
╰─────────────────────────────────────────────────╯
"#);

        let config_str = std::fs::read_to_string(paths.get_input_config_path())?;
        let config: serde_json::Value = serde_json::from_str(&config_str)?;

        let sections = [
            "DNS Settings",
            "VLESS Inbound",
            "Hysteria2 Inbound",
            "TUN Inbound",
            "SSH Inbound",
            "Outbound Direct",
            "Route Rules",
            "Services & API",
            "Experimental (Clash API)",
            "Back to Main Menu",
        ];

        let choice = prompt_menu("Select section to edit", &sections)?;

        match choice {
            0 => edit_dns_settings(&config, paths)?,
            1 => edit_vless_inbound(&config, paths)?,
            2 => edit_hysteria2_inbound(&config, paths)?,
            3 => edit_tun_inbound(&config, paths)?,
            4 => edit_ssh_inbound(&config, paths)?,
            5 => edit_outbound_direct(&config, paths)?,
            6 => edit_route_rules(&config, paths)?,
            7 => edit_services(&config, paths)?,
            8 => edit_experimental(&config, paths)?,
            9 => break,
            _ => {}
        }
    }
    Ok(())
}

fn edit_dns_settings(config: &serde_json::Value, _paths: &Paths) -> Result<()> {
    clear_screen();
    println!(r#"
╭─────────────────────────────────────────────────╮
│              DNS Settings                        │
╰─────────────────────────────────────────────────╯
"#);

    if let Some(dns) = config.get("dns") {
        println!("{}", "  Current DNS Configuration:".cyan().bold());
        println!();

        // Final DNS
        let final_dns = dns.get("final").and_then(|v| v.as_str()).unwrap_or("not set");
        println!("  {} final DNS: {}", "[*]".cyan(), final_dns);

        // Strategy
        let strategy = dns.get("strategy").and_then(|v| v.as_str()).unwrap_or("not set");
        println!("  {} strategy: {}", "[*]".cyan(), strategy);

        // Servers
        if let Some(servers) = dns.get("servers").and_then(|s| s.as_array()) {
            println!("\n  {} DNS Servers:", "[>]".yellow());
            for server in servers {
                let tag = server.get("tag").and_then(|v| v.as_str()).unwrap_or("-");
                let stype = server.get("type").and_then(|v| v.as_str()).unwrap_or("-");
                let srv = server.get("server").and_then(|v| v.as_str()).unwrap_or("-");
                println!("    {} {} ({}:{})", tag.green(), stype.dimmed(), srv, server.get("server_port").and_then(|v| v.as_u64()).unwrap_or(443));
            }
        }

        println!(r#"
╭─────────────────────────────────────────────────╮
│              Recommendations                       │
╰─────────────────────────────────────────────────╯

  [1] ● Enable DNS over H3 (DoH3)    Encrypt DNS queries
  [2] ● Add encrypted DNS servers    Use DoT/DoQ for privacy
  [3] ● Optimize DNS strategy        Set prefer_ipv4 routing
  [0] ○ Back
"#);

        let choice = prompt_input("  Select action", Some("0".to_string()))?;
        match choice.as_str() {
            "1" => {
                println!("\n  {} Run: mimictl dns setup-doh3", "[>]".cyan());
                println!("  {} This will add Google DNS over H3", "[*]".dimmed());
            }
            "2" => {
                println!("\n  {} Run: mimictl dns add-server", "[>]".cyan());
                println!("  {} Add TLS/DoQ servers like cloudflare", "[*]".dimmed());
            }
            "3" => {
                println!("\n  {} Current strategy: {}", "[*]".cyan(), strategy);
                println!("  {} Recommended: prefer_ipv4 for IPv4-first routing", "[*]".dimmed());
            }
            _ => {}
        }
    }

    prompt_enter()?;
    Ok(())
}

fn edit_vless_inbound(config: &serde_json::Value, _paths: &Paths) -> Result<()> {
    clear_screen();
    println!(r#"
╭─────────────────────────────────────────────────╮
│           VLESS + Reality Inbound                 │
╰─────────────────────────────────────────────────╯
"#);

    if let Some(inbounds) = config.get("inbounds").and_then(|i| i.as_array())
        && let Some(vless) = inbounds.iter().find(|i| i.get("type") == Some(&serde_json::Value::String("vless".to_string()))) {
            println!("{}", "  Current VLESS Configuration:".cyan().bold());
            println!();

            // Listen
            let listen = vless.get("listen").and_then(|v| v.as_str()).unwrap_or("::");
            let port = vless.get("listen_port").and_then(|v| v.as_u64()).unwrap_or(443);
            println!("  {} listen: {}:{}", "[*]".cyan(), listen, port);

            // Sniff
            let sniff = vless.get("sniff").and_then(|v| v.as_bool()).unwrap_or(false);
            let sniff_override = vless.get("sniff_override_destination").and_then(|v| v.as_bool()).unwrap_or(false);
            println!("  {} sniff: {}, override: {}", "[*]".cyan(), sniff, sniff_override);

            // Multiplex
            if let Some(mux) = vless.get("multiplex") {
                let mux_enabled = mux.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
                let mux_padding = mux.get("padding").and_then(|v| v.as_bool()).unwrap_or(false);
                println!("  {} multiplex: enabled={}, padding={}", "[*]".cyan(), mux_enabled, mux_padding);

                if let Some(brutal) = mux.get("brutal") {
                    let brutal_enabled = brutal.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
                    let up = brutal.get("up_mbps").and_then(|v| v.as_u64()).unwrap_or(0);
                    let down = brutal.get("down_mbps").and_then(|v| v.as_u64()).unwrap_or(0);
                    println!("  {} brutal: enabled={}, up={}, down={}", "[*]".cyan(), brutal_enabled, up, down);
                }
            }

            // TLS & Reality
            if let Some(tls) = vless.get("tls") {
                let reality_enabled = tls.get("reality").and_then(|r| r.get("enabled").and_then(|v| v.as_bool())).unwrap_or(false);
                let server_name = tls.get("server_name").and_then(|v| v.as_str()).unwrap_or("");
                println!("  {} TLS: enabled={}, server_name={}", "[*]".cyan(), tls.get("enabled").unwrap_or(&serde_json::Value::Bool(false)), server_name);
                println!("  {} Reality: enabled={}", "[*]".cyan(), reality_enabled);
            }

            // Users
            if let Some(users) = vless.get("users").and_then(|u| u.as_array()) {
                println!("\n  {} Users: {} registered", "[>]".yellow(), users.len());
            }
        }

    println!(r#"
╭─────────────────────────────────────────────────╮
│              Recommendations                       │
╰─────────────────────────────────────────────────╯

  [1] ● Generate Reality Keys     Required for VLESS
  [2] ● Add User                  Add new VLESS user
  [3] ● Enable Multiplex Brute     Better throughput
  [4] ● Optimize TCP Settings     TFO, keep-alive
  [0] ○ Back
"#);

    let choice = prompt_input("  Select action", Some("0".to_string()))?;
    match choice.as_str() {
        "1" => {
            println!("\n  {} Run: mimictl gen-keys", "[>]".cyan());
            println!("  {} Generates new Reality keypair", "[*]".dimmed());
        }
        "2" => {
            println!("\n  {} Run: mimictl add user@example.com", "[>]".cyan());
            println!("  {} Add VLESS user with email format", "[*]".dimmed());
        }
        "3" => {
            println!("\n  {} Multiplex Brute provides 2-3x throughput via compression", "[*]".cyan());
            println!("  {} Recommended: up=100, down=200 Mbps for most networks", "[*]".dimmed());
        }
        "4" => {
            println!("\n  {} Recommended TCP settings:", "[*]".cyan());
            println!("  {}   tcp_fast_open: true", "[*]".dimmed());
            println!("  {}   tcp_keep_alive: 5m", "[*]".dimmed());
            println!("  {}   tcp_keep_alive_interval: 75s", "[*]".dimmed());
        }
        _ => {}
    }

    prompt_enter()?;
    Ok(())
}

fn edit_hysteria2_inbound(config: &serde_json::Value, _paths: &Paths) -> Result<()> {
    clear_screen();
    println!(r#"
╭─────────────────────────────────────────────────╮
│              Hysteria2 Inbound                     │
╰─────────────────────────────────────────────────╯
"#);

    if let Some(inbounds) = config.get("inbounds").and_then(|i| i.as_array())
        && let Some(hy2) = inbounds.iter().find(|i| i.get("type") == Some(&serde_json::Value::String("hysteria2".to_string()))) {
            println!("{}", "  Current Hysteria2 Configuration:".cyan().bold());
            println!();

            let listen = hy2.get("listen").and_then(|v| v.as_str()).unwrap_or("::");
            let port = hy2.get("listen_port").and_then(|v| v.as_u64()).unwrap_or(443);
            println!("  {} listen: {}:{}", "[*]".cyan(), listen, port);

            let up = hy2.get("up_mbps").and_then(|v| v.as_u64()).unwrap_or(100);
            let down = hy2.get("down_mbps").and_then(|v| v.as_u64()).unwrap_or(100);
            println!("  {} bandwidth: up={}, down={} Mbps", "[*]".cyan(), up, down);

            let masquerade = hy2.get("masquerade").and_then(|v| v.as_str()).unwrap_or("");
            println!("  {} masquerade: {}", "[*]".cyan(), masquerade);

            let bbr = hy2.get("bbr_profile").and_then(|v| v.as_str()).unwrap_or("disabled");
            println!("  {} BBR: {}", "[*]".cyan(), bbr);

            if let Some(tls) = hy2.get("tls") {
                let alpn = tls.get("alpn").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(", ")).unwrap_or_default();
                println!("  {} ALPN: {}", "[*]".cyan(), alpn);
            }

            if let Some(users) = hy2.get("users").and_then(|u| u.as_array()) {
                println!("\n  {} Users: {} registered", "[>]".yellow(), users.len());
                for user in users {
                    let name = user.get("name").and_then(|v| v.as_str()).unwrap_or("-");
                    println!("    {} {}", "[*]".dimmed(), name);
                }
            }
        }

    println!(r#"
╭─────────────────────────────────────────────────╮
│              Recommendations                       │
╰─────────────────────────────────────────────────╯

  [1] ● Setup Hysteria2            Configure port, password
  [2] ● Add User                   Add new Hysteria2 user
  [3] ● Enable BBR                 Better congestion control
  [4] ● Optimize Bandwidth         Adjust up/down Mbps
  [0] ○ Back
"#);

    let choice = prompt_input("  Select action", Some("0".to_string()))?;
    match choice.as_str() {
        "1" => {
            println!("\n  {} Run: mimictl hysteria2 setup -p 443 -P password -d example.com", "[>]".cyan());
        }
        "2" => {
            println!("\n  {} Run: mimictl hysteria2 add-user -u username -P password", "[>]".cyan());
        }
        "3" => {
            println!("\n  {} BBR (Bottleneck Bandwidth and RTT) improves throughput", "[*]".cyan());
            println!("  {} Recommended for high-latency or congested networks", "[*]".dimmed());
        }
        "4" => {
            println!("\n  {} For 1Gbps network: up=500, down=1000 Mbps", "[*]".cyan());
            println!("  {} Adjust based on your actual bandwidth", "[*]".dimmed());
        }
        _ => {}
    }

    prompt_enter()?;
    Ok(())
}

fn edit_tun_inbound(config: &serde_json::Value, _paths: &Paths) -> Result<()> {
    clear_screen();
    println!(r#"
╭─────────────────────────────────────────────────╮
│           TUN (System VPN) Inbound                │
╰─────────────────────────────────────────────────╯
"#);

    if let Some(inbounds) = config.get("inbounds").and_then(|i| i.as_array())
        && let Some(tun) = inbounds.iter().find(|i| i.get("type") == Some(&serde_json::Value::String("tun".to_string()))) {
            println!("{}", "  Current TUN Configuration:".cyan().bold());
            println!();

            let iface = tun.get("interface_name").and_then(|v| v.as_str()).unwrap_or("tun0");
            println!("  {} interface: {}", "[*]".cyan(), iface);

            let mtu = tun.get("mtu").and_then(|v| v.as_u64()).unwrap_or(9000);
            println!("  {} MTU: {}", "[*]".cyan(), mtu);

            let auto_route = tun.get("auto_route").and_then(|v| v.as_bool()).unwrap_or(false);
            let strict_route = tun.get("strict_route").and_then(|v| v.as_bool()).unwrap_or(false);
            println!("  {} auto_route: {}, strict_route: {}", "[*]".cyan(), auto_route, strict_route);

            let stack = tun.get("stack").and_then(|v| v.as_str()).unwrap_or("system");
            println!("  {} stack: {}", "[*]".cyan(), stack);

            let sniff = tun.get("sniff").and_then(|v| v.as_bool()).unwrap_or(false);
            println!("  {} sniff: {}", "[*]".cyan(), sniff);

            if let Some(addr) = tun.get("address").and_then(|v| v.as_array()) {
                println!("  {} addresses: {:?}", "[*]".cyan(), addr);
            }
        }

    println!(r#"
╭─────────────────────────────────────────────────╮
│              Recommendations                       │
╰─────────────────────────────────────────────────╯

  [1] ● Enable System Proxy        Route all traffic VPN
  [2] ● Optimize MTU              Default 9000 optimal
  [3] ● Enable Strict Route        Prevent leaks
  [4] ● Configure DNS              Set custom DNS for TUN
  [5] ● TunnelVision Advisory      CVE-2024-3661 notice
  [0] ○ Back
"#);

    let choice = prompt_input("  Select action", Some("0".to_string()))?;
    match choice.as_str() {
        "1" => {
            let auto_route_val = config.get("inbounds")
                .and_then(|i| i.as_array())
                .and_then(|inbounds| inbounds.iter().find(|i| i.get("type") == Some(&serde_json::Value::String("tun".to_string()))))
                .and_then(|t| t.get("auto_route").and_then(|v| v.as_bool()))
                .unwrap_or(false);
            println!("\n  {} auto_route is currently: {}", "[*]".cyan(), auto_route_val);
            println!("  {} When enabled, all device traffic routes through VPN", "[*]".dimmed());
        }
        "2" => {
            println!("\n  {} Recommended MTU settings:", "[*]".cyan());
            println!("  {}   9000 - Jumbo frames (recommended for local network)", "[*]".dimmed());
            println!("  {}   1500 - Standard Ethernet", "[*]".dimmed());
        }
        "3" => {
            println!("\n  {} strict_route prevents routing leaks", "[*]".cyan());
            println!("  {} Recommended to keep enabled", "[*]".dimmed());
        }
        "4" => {
            println!("\n  {} Configure DNS in the DNS section", "[*]".cyan());
            println!("  {} Recommended: Use DoH3 (Google or Cloudflare)", "[*]".dimmed());
        }
        "5" => {
            println!(r#"
  {} TunnelVision Security Advisory (CVE-2024-3661)
  {} ================================================

  TunnelVision is an attack that uses DHCP option 121 to
  set higher priority routes, causing VPN traffic to bypass
  the VPN tunnel.

  {} Platform Status:
    Android  : NOT AFFECTED (doesn't handle DHCP 121)
    Apple    : Use sing-box 1.9.0-rc.16+ with includeAllNetworks
    Linux    : Use sing-box 1.9.0-rc.16+ (auto-route rules safe)
    Windows  : NO SOLUTION YET

  {} Workarounds:
    - Don't connect to untrusted networks
    - Relay untrusted network through another device
    - Use Linux or Android for sensitive connections
"#,
                "[!]".yellow().bold(),
                "=".yellow(),
                "[*]".cyan(),
                "[>]".green());
        }
        _ => {}
    }

    prompt_enter()?;
    Ok(())
}

fn edit_ssh_inbound(config: &serde_json::Value, _paths: &Paths) -> Result<()> {
    clear_screen();
    println!(r#"
╭─────────────────────────────────────────────────╮
│              SSH Inbound                          │
╰─────────────────────────────────────────────────╯
"#);

    if let Some(inbounds) = config.get("inbounds").and_then(|i| i.as_array())
        && let Some(ssh) = inbounds.iter().find(|i| i.get("type") == Some(&serde_json::Value::String("ssh".to_string()))) {
            println!("{}", "  Current SSH Configuration:".cyan().bold());
            println!();

            let listen = ssh.get("listen").and_then(|v| v.as_str()).unwrap_or("::");
            let port = ssh.get("listen_port").and_then(|v| v.as_u64()).unwrap_or(22);
            println!("  {} listen: {}:{}", "[*]".cyan(), listen, port);

            let sniff = ssh.get("sniff").and_then(|v| v.as_bool()).unwrap_or(false);
            println!("  {} sniff: {}", "[*]".cyan(), sniff);

            if let Some(users) = ssh.get("users").and_then(|u| u.as_array()) {
                println!("\n  {} Users: {} registered", "[>]".yellow(), users.len());
                for user in users {
                    let name = user.get("name").and_then(|v| v.as_str()).unwrap_or("-");
                    println!("    {} {}", "[*]".dimmed(), name);
                }
            }
        }

    println!(r#"
╭─────────────────────────────────────────────────╮
│              Recommendations                       │
╰─────────────────────────────────────────────────╯

  [1] ● Change Default Port        Port 22 targeted often
  [2] ● Add SSH User               Add new SSH user
  [3] ● Enable Strict Auth         Key-based authentication
  [0] ○ Back
"#);

    let choice = prompt_input("  Select action", Some("0".to_string()))?;
    match choice.as_str() {
        "1" => {
            println!("\n  {} Recommended: Use a high port (e.g., 2222)", "[*]".cyan());
            println!("  {} Change in config: listen_port", "[*]".dimmed());
        }
        "2" => {
            println!("\n  {} SSH users can be added via setup wizard", "[*]".cyan());
        }
        "3" => {
            println!("\n  {} Use key-based auth instead of passwords", "[*]".cyan());
            println!("  {} Edit users[].auth_method in config", "[*]".dimmed());
        }
        _ => {}
    }

    prompt_enter()?;
    Ok(())
}

fn edit_outbound_direct(config: &serde_json::Value, _paths: &Paths) -> Result<()> {
    clear_screen();
    println!(r#"
╭─────────────────────────────────────────────────╮
│              Outbound Direct                      │
╰─────────────────────────────────────────────────╯
"#);

    if let Some(outbounds) = config.get("outbounds").and_then(|o| o.as_array())
        && let Some(direct) = outbounds.iter().find(|o| o.get("type") == Some(&serde_json::Value::String("direct".to_string()))) {
            println!("{}", "  Current Direct Outbound:".cyan().bold());
            println!();

            let bind_iface = direct.get("bind_interface").and_then(|v| v.as_str()).unwrap_or("");
            println!("  {} bind_interface: {}", "[*]".cyan(), if bind_iface.is_empty() { "(auto)".dimmed().to_string() } else { bind_iface.to_string() });

            let routing_mark = direct.get("routing_mark").and_then(|v| v.as_u64()).unwrap_or(0);
            println!("  {} routing_mark: {}", "[*]".cyan(), routing_mark);

            let tfo = direct.get("tcp_fast_open").and_then(|v| v.as_bool()).unwrap_or(false);
            println!("  {} tcp_fast_open: {}", "[*]".cyan(), tfo);

            let domain_matcher = direct.get("domain_matcher").and_then(|v| v.as_str()).unwrap_or("mph");
            println!("  {} domain_matcher: {}", "[*]".cyan(), domain_matcher);

            let fallback_delay = direct.get("fallback_delay").and_then(|v| v.as_str()).unwrap_or("300ms");
            println!("  {} fallback_delay: {}", "[*]".cyan(), fallback_delay);
        }

    println!(r#"
╭─────────────────────────────────────────────────╮
│              Recommendations                       │
╰─────────────────────────────────────────────────╯

  [1] ● Enable BBR                Better congestion control
  [2] ● Optimize TFO              TCP Fast Open reduces latency
  [3] ● Set Domain Strategy        prefer_ipv4 routing
  [4] ● Bind Interface             Force traffic through NIC
  [0] ○ Back
"#);

    let choice = prompt_input("  Select action", Some("0".to_string()))?;
    match choice.as_str() {
        "1" => {
            println!("\n  {} Run: sudo sysctl -w net.ipv4.tcp_congestion_control=bbr", "[>]".cyan());
            println!("  {} Enable BBR for better throughput on high-latency links", "[*]".dimmed());
        }
        "2" => {
            println!("\n  {} TFO is already enabled if true", "[*]".cyan());
            println!("  {} Reduces connection latency by 1-2 RTT", "[*]".dimmed());
        }
        "3" => {
            println!("\n  {} Recommended: Set domain_strategy to prefer_ipv4", "[*]".cyan());
            println!("  {} IPv4 routing is more reliable and has better NAT support", "[*]".dimmed());
        }
        "4" => {
            println!("\n  {} Useful for multi-NIC setups", "[*]".cyan());
            println!("  {} Example: eth0, wlan0, etc.", "[*]".dimmed());
        }
        _ => {}
    }

    prompt_enter()?;
    Ok(())
}

fn edit_route_rules(config: &serde_json::Value, _paths: &Paths) -> Result<()> {
    clear_screen();
    println!(r#"
╭─────────────────────────────────────────────────╮
│              Route Rules                          │
╰─────────────────────────────────────────────────╯
"#);

    println!("{}", "  Current Route Configuration:".cyan().bold());
    println!();

    if let Some(route) = config.get("route") {
        let final_outbound = route.get("final").and_then(|v| v.as_str()).unwrap_or("direct");
        println!("  {} final outbound: {}", "[*]".cyan(), final_outbound);

        let auto_detect = route.get("auto_detect_interface").and_then(|v| v.as_bool()).unwrap_or(false);
        println!("  {} auto_detect_interface: {}", "[*]".cyan(), auto_detect);

        if let Some(rules) = route.get("rules").and_then(|r| r.as_array()) {
            println!("\n  {} Rules: {} configured", "[>]".yellow(), rules.len());
            for (i, rule) in rules.iter().enumerate().take(5) {
                if let Some(action) = rule.get("action").and_then(|v| v.as_str()) {
                    println!("    {} rule {}: action={}", "[*]".dimmed(), i+1, action);
                } else if let Some(outbound) = rule.get("outbound").and_then(|v| v.as_str()) {
                    println!("    {} rule {}: outbound={}", "[*]".dimmed(), i+1, outbound);
                }
            }
        }

        if let Some(rule_sets) = route.get("rule_set").and_then(|rs| rs.as_array()) {
            println!("\n  {} Rule Sets: {} configured", "[>]".yellow(), rule_sets.len());
            for rs in rule_sets {
                let tag = rs.get("tag").and_then(|v| v.as_str()).unwrap_or("-");
                let rs_type = rs.get("type").and_then(|v| v.as_str()).unwrap_or("-");
                println!("    {} {} ({})", "[*]".dimmed(), tag, rs_type);
            }
        }
    }

    println!(r#"
╭─────────────────────────────────────────────────╮
│              Recommendations                       │
╰─────────────────────────────────────────────────╯

  [1] ● Update Rule Sets          Download latest geo data
  [2] ● Add Custom Rule           Block/allow domains
  [3] ● Enable IPv6 Routing       Route IPv6 through proxy
  [4] ● Configure Domain Strategy Set DNS strategy
  [0] ○ Back
"#);

    let choice = prompt_input("  Select action", Some("0".to_string()))?;
    match choice.as_str() {
        "1" => {
            println!("\n  {} Rule sets are auto-downloaded", "[*]".cyan());
            println!("  {} geosite-cn and geoip-cn are used for China routing", "[*]".dimmed());
        }
        "2" => {
            println!("\n  {} Rules format:", "[*]".cyan());
            println!(r#"    {{"rule_set": "geosite-cn", "outbound": "block"}}"#);
        }
        "3" => {
            println!("\n  {} IPv6 routing can be enabled via domain_strategy", "[*]".cyan());
            println!("  {} Example: Set to prefer_ipv6 for IPv6-first routing", "[*]".dimmed());
        }
        "4" => {
            println!("\n  {} Strategies:", "[*]".cyan());
            println!("  {}   prefer_ipv4 - IPv4 first (recommended)", "[*]".dimmed());
            println!("  {}   prefer_ipv6 - IPv6 first", "[*]".dimmed());
            println!("  {}   ipv4_only  - IPv4 only", "[*]".dimmed());
            println!("  {}   ipv6_only  - IPv6 only", "[*]".dimmed());
        }
        _ => {}
    }

    prompt_enter()?;
    Ok(())
}

fn edit_services(config: &serde_json::Value, _paths: &Paths) -> Result<()> {
    clear_screen();
    println!(r#"
╭─────────────────────────────────────────────────╮
│              Services & API                       │
╰─────────────────────────────────────────────────╯
"#);

    println!("{}", "  Current Services:".cyan().bold());
    println!();

    if let Some(services) = config.get("services").and_then(|s| s.as_array()) {
        for service in services {
            let stype = service.get("type").and_then(|v| v.as_str()).unwrap_or("-");
            let tag = service.get("tag").and_then(|v| v.as_str()).unwrap_or("-");
            let listen = service.get("listen").and_then(|v| v.as_str()).unwrap_or("::");
            let port = service.get("listen_port").and_then(|v| v.as_u64()).unwrap_or(0);
            println!("  {} {} ({}:{})", "[*]".cyan(), tag.green(), listen, port);

            if stype == "ssm-api" {
                println!("    {} Service: Sing-Box Service Manager API", "[*]".dimmed());
            } else if stype == "resolved" {
                println!("    {} Service: Local DNS Resolver", "[*]".dimmed());
            }
        }
    } else {
        println!("  {} No services configured", "[*]".dimmed());
    }

    println!(r#"
╭─────────────────────────────────────────────────╮
│              Recommendations                       │
╰─────────────────────────────────────────────────╯

  [1] ● Enable SSM API           Required for management
  [2] ● Configure Local DNS       Setup DoH3 resolver
  [3] ● Change API Port           Non-standard for security
  [0] ○ Back
"#);

    let choice = prompt_input("  Select action", Some("0".to_string()))?;
    match choice.as_str() {
        "1" => {
            println!("\n  {} SSM API is required for:", "[*]".cyan());
            println!("  {}   - User management via mimictl", "[*]".dimmed());
            println!("  {}   - Dynamic config updates", "[*]".dimmed());
        }
        "2" => {
            println!("\n  {} Run: mimictl dns setup-doh3", "[>]".cyan());
        }
        "3" => {
            println!("\n  {} Default port is 9090", "[*]".cyan());
            println!("  {} Change in services[].listen_port", "[*]".dimmed());
        }
        _ => {}
    }

    prompt_enter()?;
    Ok(())
}

fn edit_experimental(config: &serde_json::Value, _paths: &Paths) -> Result<()> {
    clear_screen();
    println!(r#"
╭─────────────────────────────────────────────────╮
│           Experimental (Clash API)                │
╰─────────────────────────────────────────────────╯
"#);

    println!("{}", "  Current Experimental Configuration:".cyan().bold());
    println!();

    if let Some(exp) = config.get("experimental") {
        if let Some(clash) = exp.get("clash_api") {
            let enabled = clash.get("external_controller").is_some();
            println!("  {} Clash API: {}", "[*]".cyan(), if enabled { "enabled".green() } else { "disabled".red() });

            if let Some(controller) = clash.get("external_controller").and_then(|v| v.as_str()) {
                println!("  {} external_controller: {}", "[*]".cyan(), controller);
            }

            if let Some(secret) = clash.get("secret").and_then(|v| v.as_str()) {
                let masked = if secret.len() > 4 { format!("{}...", &secret[..4]) } else { "****".to_string() };
                println!("  {} secret: {}", "[*]".cyan(), masked);
            }

            if let Some(mode) = clash.get("default_mode").and_then(|v| v.as_str()) {
                println!("  {} default_mode: {}", "[*]".cyan(), mode);
            }
        }
    } else {
        println!("  {} No experimental features configured", "[*]".dimmed());
    }

    println!(r#"
╭─────────────────────────────────────────────────╮
│              Recommendations                       │
╰─────────────────────────────────────────────────╯

  [1] ● Enable Clash API          For Clash dashboard
  [2] ● Change Secret             Use strong random secret
  [3] ● Configure Default Mode     Rule/Proxy/Global
  [4] ● Enable Store Selected      Remember last proxy
  [0] ○ Back
"#);

    let choice = prompt_input("  Select action", Some("0".to_string()))?;
    match choice.as_str() {
        "1" => {
            println!("\n  {} Clash API enables:", "[*]".cyan());
            println!("  {}   - Clash dashboard (Stash, Meta)", "[*]".dimmed());
            println!("  {}   - External controller integration", "[*]".dimmed());
        }
        "2" => {
            println!("\n  {} Generate strong secret:", "[*]".cyan());
            println!("  {}   openssl rand -base64 32", "[>]".dimmed());
        }
        "3" => {
            println!("\n  {} Modes:", "[*]".cyan());
            println!("  {}   Rule  - Route by rules (recommended)", "[*]".dimmed());
            println!("  {}   Proxy - Route through specific proxy", "[*]".dimmed());
            println!("  {}   Global - Route everything through proxy", "[*]".dimmed());
        }
        "4" => {
            println!("\n  {} store_selected remembers your last proxy choice", "[*]".cyan());
            println!("  {} Recommended to keep enabled", "[*]".dimmed());
        }
        _ => {}
    }

    prompt_enter()?;
    Ok(())
}

// Helper functions

fn prompt_menu<T: AsRef<str>>(prompt: &str, options: &[T]) -> Result<usize> {
    println!("\n  {}:", prompt.yellow());
    for (i, opt) in options.iter().enumerate() {
        println!("    {:>2}. {}", i, opt.as_ref());
    }
    print!("\n  Enter choice: ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let choice: usize = input.trim().parse().unwrap_or(999);

    Ok(choice)
}

fn prompt_input(prompt: &str, default: Option<String>) -> Result<String> {
    let default_str = default.unwrap_or_default();
    let prompt_str = if default_str.is_empty() {
        format!("\n  {}: ", prompt.yellow())
    } else {
        format!("\n  {} [{}]: ", prompt.yellow(), default_str.dimmed())
    };

    print!("{}", prompt_str);
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim().to_string();

    Ok(if input.is_empty() { default_str } else { input })
}

fn prompt_yes_no(prompt: &str, default: bool) -> Result<bool> {
    let default_str = if default { "[Y/n]" } else { "[y/N]" };
    print!("\n  {} {}: ", prompt.yellow(), default_str.dimmed());
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim().to_lowercase();

    Ok(match input.as_str() {
        "y" | "yes" => true,
        "n" | "no" => false,
        _ => default,
    })
}

fn prompt_enter() -> Result<()> {
    print!("\n  Press Enter to continue...");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(())
}

fn clear_screen() {
    print!("\x1B[2J\x1B[1;1H");
    let _ = io::stdout().flush();
}
