use anyhow::{Result, anyhow};
use colored::*;
use if_addrs::get_if_addrs;

use std::fs;
use std::io::{self, BufRead, Read};
use std::path::PathBuf;
use std::process::Command;
use tokio::time::Duration;

use serde_json::{Value, json};
use url::Url;

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

// Choose a sensible IPv6 address from a list of candidate IpAddrs.
// Preference order:
// 1) global unicast (first one encountered)
// 2) unique-local addresses (fc00::/7) if no global unicast found
fn choose_ipv6_candidate<I>(ips: I) -> Option<std::net::Ipv6Addr>
where
    I: IntoIterator<Item = std::net::IpAddr>,
{
    let mut ula: Option<std::net::Ipv6Addr> = None;
    for ip in ips {
        if let std::net::IpAddr::V6(v6) = ip {
            if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                continue;
            }

            // Skip link-local fe80::/10: check top 10 bits via first hextet mask
            let first_hextet = v6.segments()[0];
            if (first_hextet & 0xffc0) == 0xfe80 {
                continue;
            }

            // Unique local addresses fc00::/7 (first byte 0xfc or 0xfd)
            let first_byte = v6.octets()[0];
            if first_byte == 0xfc || first_byte == 0xfd {
                if ula.is_none() {
                    ula = Some(v6);
                }
                continue;
            }

            // Otherwise treat as global unicast candidate
            return Some(v6);
        }
    }

    // fallback to ULA if no global unicast found
    ula
}

// Collect up to `max` IPv6 candidates from an iterator of IpAddrs.
// Preference order: global unicast first, then unique-local (ULA).
fn collect_ipv6_candidates<I>(ips: I, max: usize) -> Vec<std::net::Ipv6Addr>
where
    I: IntoIterator<Item = std::net::IpAddr>,
{
    let mut globals: Vec<std::net::Ipv6Addr> = Vec::new();
    let mut ulas: Vec<std::net::Ipv6Addr> = Vec::new();

    for ip in ips {
        if let std::net::IpAddr::V6(v6) = ip {
            if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                continue;
            }
            // Skip link-local
            let first_hextet = v6.segments()[0];
            if (first_hextet & 0xffc0) == 0xfe80 {
                continue;
            }
            let first_byte = v6.octets()[0];
            if first_byte == 0xfc || first_byte == 0xfd {
                ulas.push(v6);
            } else {
                globals.push(v6);
            }
        }
    }

    let mut out: Vec<std::net::Ipv6Addr> = Vec::new();
    for g in globals.into_iter() {
        if out.len() >= max {
            break;
        }
        out.push(g);
    }
    for u in ulas.into_iter() {
        if out.len() >= max {
            break;
        }
        out.push(u);
    }
    out
}

pub async fn link(
    paths: &Paths,
    email: String,
    mut addresses: Vec<String>,
    v4: bool,
    v6: bool,
    interface: Option<String>,
    num: usize,
    assign: bool,
    assign_v4: bool,
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

        // If user specified an interface, prefer addresses from that interface
        if let Some(iface_name) = interface.as_ref() {
            if let Ok(ifaces) = get_if_addrs() {
                let iface_ips: Vec<std::net::IpAddr> = ifaces
                    .into_iter()
                    .filter(|ifa| ifa.name == *iface_name)
                    .map(|ifa| ifa.addr.ip())
                    .collect();

                if iface_ips.is_empty() {
                    return Err(anyhow!("No addresses found on interface: {}", iface_name));
                }

                // If user wants IPv6 and specified a number, collect up to `num` IPv6 addresses from this interface.
                if detect_v6 {
                    let v6_candidates = collect_ipv6_candidates(iface_ips.clone().into_iter(), num);
                    if !v6_candidates.is_empty() {
                        for v in v6_candidates {
                            addresses.push(v.to_string());
                        }
                    } else if let Some(v4) = iface_ips.iter().find_map(|ip| match ip {
                        std::net::IpAddr::V4(v4) => Some(*v4),
                        _ => None,
                    }) {
                        // no IPv6 candidates; fall back to IPv4 if available
                        addresses.push(v4.to_string());
                    }
                } else {
                    // prefer IPv4
                    if let Some(v4) = iface_ips.iter().find_map(|ip| match ip {
                        std::net::IpAddr::V4(v4) => Some(*v4),
                        _ => None,
                    }) {
                        addresses.push(v4.to_string());
                    } else {
                        // fallback: choose IPv6 candidates if no IPv4 found
                        let v6_candidate = choose_ipv6_candidate(iface_ips.into_iter());
                        if let Some(v6) = v6_candidate {
                            addresses.push(v6.to_string());
                        }
                    }
                }
            } else {
                return Err(anyhow!("Failed to enumerate network interfaces"));
            }

            // If caller asked for assignment, or if we are running as root and still need more
            // addresses to satisfy `num`, perform address generation & assignment in the interface's prefix.
            let need_more = addresses.len() < num;
            // Determine if we are root by calling `id -u` (portable-ish check).
            let is_root = match Command::new("id").arg("-u").output() {
                Ok(o) => String::from_utf8_lossy(&o.stdout).trim() == "0",
                Err(_) => false,
            };

            if assign || (need_more && is_root) {
                if need_more && is_root && !assign {
                    eprintln!(
                        "{} Running as root and not enough addresses available; auto-assigning to reach --num.",
                        "[INFO]".green()
                    );
                }

                // Attempt IPv6 auto-assignment (best-effort). On any failure we WARN and continue
                let out = Command::new("ip")
                    .args(["-6", "-o", "addr", "show", "dev", iface_name])
                    .output();
                if let Err(e) = out {
                    eprintln!(
                        "{} Failed to run 'ip' to inspect interface {} for IPv6: {}. Skipping IPv6 auto-assign.",
                        "[WARN]".yellow(),
                        iface_name,
                        e
                    );
                } else {
                    let out = out.unwrap();
                    if !out.status.success() {
                        eprintln!(
                            "{} 'ip' returned non-zero when inspecting interface {} for IPv6. Skipping IPv6 auto-assign.",
                            "[WARN]".yellow(),
                            iface_name
                        );
                    } else {
                        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                        // Find first token like 2605:.../64
                        let mut found_prefix: Option<(std::net::Ipv6Addr, usize)> = None;
                        for line in stdout.lines() {
                            for token in line.split_whitespace() {
                                if token.contains(':') && token.contains('/') {
                                    if let Some((addr_str, plen_str)) = token.split_once('/') {
                                        if let Ok(plen) = plen_str.parse::<usize>() {
                                            if let Ok(ipv6) = addr_str.parse::<std::net::Ipv6Addr>()
                                            {
                                                found_prefix = Some((ipv6, plen));
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                            if found_prefix.is_some() {
                                break;
                            }
                        }

                        if let Some((base_ip, prefix_len)) = found_prefix {
                            if prefix_len % 16 != 0 {
                                eprintln!(
                                    "{} Unsupported IPv6 prefix length {} on interface {}. Only prefixes divisible by 16 are supported for automatic assignment. Skipping IPv6 auto-assign.",
                                    "[WARN]".yellow(),
                                    prefix_len,
                                    iface_name
                                );
                            } else {
                                let prefix_hextets = prefix_len / 16;
                                let mut base_segs = base_ip.segments();
                                for i in prefix_hextets..8 {
                                    base_segs[i] = 0;
                                }

                                // Compute how many addresses still needed
                                let mut need = if num > addresses.len() {
                                    num - addresses.len()
                                } else {
                                    0
                                };
                                // RNG initialization not required; using rand::random() directly
                                let mut seen = std::collections::HashSet::<String>::new();
                                for a in &addresses {
                                    seen.insert(a.clone());
                                }

                                let mut attempts = 0usize;
                                while need > 0 && attempts < (need * 8 + 32) {
                                    attempts += 1;
                                    // Randomize last 64 bits (4 hextets)
                                    let r1: u16 = rand::random::<u16>();
                                    let r2: u16 = rand::random::<u16>();
                                    let r3: u16 = rand::random::<u16>();
                                    let r4: u16 = rand::random::<u16>();
                                    let mut segs = base_segs;
                                    // Fill tail of the address with random hextets starting at prefix boundary
                                    let tail_index = prefix_hextets;
                                    if tail_index <= 4 {
                                        segs[tail_index + 0] = r1;
                                        segs[tail_index + 1] = r2;
                                        segs[tail_index + 2] = r3;
                                        segs[tail_index + 3] = r4;
                                    } else {
                                        // fallback: put randomness into last 4 hextets
                                        segs[4] = r1;
                                        segs[5] = r2;
                                        segs[6] = r3;
                                        segs[7] = r4;
                                    }
                                    let candidate = std::net::Ipv6Addr::from(segs);
                                    let s = candidate.to_string();
                                    if seen.contains(&s) {
                                        continue;
                                    }

                                    let assign_target = format!("{}/{}", s, prefix_len);
                                    let status_res = Command::new("ip")
                                        .args([
                                            "-6",
                                            "addr",
                                            "add",
                                            &assign_target,
                                            "dev",
                                            iface_name,
                                        ])
                                        .status();

                                    match status_res {
                                        Ok(status) if status.success() => {
                                            eprintln!(
                                                "{} Assigned IPv6 {} on {}",
                                                "[INFO]".green(),
                                                s,
                                                iface_name
                                            );
                                            addresses.push(s.clone());
                                            seen.insert(s);
                                            need -= 1;
                                        }
                                        Ok(_) => {
                                            eprintln!(
                                                "{} 'ip addr add' returned non-zero for {} on {}. Continuing attempts.",
                                                "[WARN]".yellow(),
                                                assign_target,
                                                iface_name
                                            );
                                        }
                                        Err(e) => {
                                            eprintln!(
                                                "{} Failed to execute 'ip' for IPv6 assignment: {}. Continuing attempts.",
                                                "[WARN]".yellow(),
                                                e
                                            );
                                        }
                                    }
                                }

                                if need > 0 {
                                    eprintln!(
                                        "{} Could not assign sufficient IPv6 addresses to reach requested --num on interface {} (got {}).",
                                        "[WARN]".yellow(),
                                        iface_name,
                                        num - need
                                    );
                                }
                            }
                        } else {
                            eprintln!(
                                "{} No global IPv6 prefix found on interface {}; skipping IPv6 auto-assign.",
                                "[WARN]".yellow(),
                                iface_name
                            );
                        }
                    }
                }

                // Experimental: Try IPv4 automatic assignment if requested (best-effort; WARN on failure)
                if assign_v4 && addresses.len() < num {
                    let out4_res = Command::new("ip")
                        .args(["-4", "-o", "addr", "show", "dev", iface_name])
                        .output();
                    if let Err(e) = out4_res {
                        eprintln!(
                            "{} Failed to run 'ip' to inspect interface {} for IPv4: {}. Skipping IPv4 auto-assign.",
                            "[WARN]".yellow(),
                            iface_name,
                            e
                        );
                    } else {
                        let out4 = out4_res.unwrap();
                        if !out4.status.success() {
                            eprintln!(
                                "{} 'ip' returned non-zero when inspecting interface {} for IPv4. Skipping IPv4 auto-assign.",
                                "[WARN]".yellow(),
                                iface_name
                            );
                        } else {
                            let stdout4 = String::from_utf8_lossy(&out4.stdout).to_string();
                            let mut found_v4_prefix: Option<(std::net::Ipv4Addr, usize)> = None;
                            for line in stdout4.lines() {
                                for token in line.split_whitespace() {
                                    if token.contains('.') && token.contains('/') {
                                        if let Some((addr_str, plen_str)) = token.split_once('/') {
                                            if let Ok(plen) = plen_str.parse::<usize>() {
                                                if let Ok(ipv4) =
                                                    addr_str.parse::<std::net::Ipv4Addr>()
                                                {
                                                    found_v4_prefix = Some((ipv4, plen));
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                                if found_v4_prefix.is_some() {
                                    break;
                                }
                            }
                            if let Some((base4, plen4)) = found_v4_prefix {
                                if plen4 >= 31 {
                                    eprintln!(
                                        "{} IPv4 prefix too small /{} on interface {}; skipping IPv4 auto-assign.",
                                        "[WARN]".yellow(),
                                        plen4,
                                        iface_name
                                    );
                                } else {
                                    let octs = base4.octets();
                                    let base_int = ((octs[0] as u32) << 24)
                                        | ((octs[1] as u32) << 16)
                                        | ((octs[2] as u32) << 8)
                                        | (octs[3] as u32);
                                    let host_bits = 32 - plen4;
                                    let mut seen4 = std::collections::HashSet::<u32>::new();
                                    for a in &addresses {
                                        if let Ok(ip) = a.parse::<std::net::Ipv4Addr>() {
                                            let o = ip.octets();
                                            let v = ((o[0] as u32) << 24)
                                                | ((o[1] as u32) << 16)
                                                | ((o[2] as u32) << 8)
                                                | (o[3] as u32);
                                            seen4.insert(v);
                                        }
                                    }
                                    let mut need4 = num - addresses.len();
                                    let mut attempts4 = 0usize;
                                    while need4 > 0 && attempts4 < (need4 * 8 + 32) {
                                        attempts4 += 1;
                                        let rand_host =
                                            (rand::random::<u32>() % (1u32 << host_bits)) as u32;
                                        // avoid network and broadcast host values
                                        if rand_host == 0 || rand_host == ((1u32 << host_bits) - 1)
                                        {
                                            continue;
                                        }
                                        let candidate_int =
                                            (base_int & (!0u32 << host_bits)) | rand_host;
                                        if seen4.contains(&candidate_int) {
                                            continue;
                                        }
                                        let cand_oct = [
                                            ((candidate_int >> 24) & 0xff) as u8,
                                            ((candidate_int >> 16) & 0xff) as u8,
                                            ((candidate_int >> 8) & 0xff) as u8,
                                            (candidate_int & 0xff) as u8,
                                        ];
                                        let cand_ip = std::net::Ipv4Addr::from(cand_oct);
                                        let assign_target = format!("{}/{}", cand_ip, plen4);
                                        let status_res = Command::new("ip")
                                            .args([
                                                "addr",
                                                "add",
                                                &assign_target,
                                                "dev",
                                                iface_name,
                                            ])
                                            .status();
                                        match status_res {
                                            Ok(status) if status.success() => {
                                                eprintln!(
                                                    "{} Assigned IPv4 {} on {}",
                                                    "[INFO]".green(),
                                                    cand_ip,
                                                    iface_name
                                                );
                                                addresses.push(cand_ip.to_string());
                                                seen4.insert(candidate_int);
                                                need4 -= 1;
                                            }
                                            Ok(_) => {
                                                eprintln!(
                                                    "{} 'ip addr add' returned non-zero for {} on {}. Continuing attempts.",
                                                    "[WARN]".yellow(),
                                                    assign_target,
                                                    iface_name
                                                );
                                            }
                                            Err(e) => {
                                                eprintln!(
                                                    "{} Failed to execute 'ip' for IPv4 assignment: {}. Continuing attempts.",
                                                    "[WARN]".yellow(),
                                                    e
                                                );
                                            }
                                        }
                                    }
                                    if need4 > 0 {
                                        eprintln!(
                                            "{} Could not assign sufficient IPv4 addresses to reach requested --num on interface {} (got {}).",
                                            "[WARN]".yellow(),
                                            iface_name,
                                            num - need4
                                        );
                                    }
                                }
                            } else {
                                eprintln!(
                                    "{} No IPv4 prefix found on interface {}; skipping IPv4 auto-assign.",
                                    "[WARN]".yellow(),
                                    iface_name
                                );
                            }
                        }
                    }
                }
            }
        } else {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(3))
                .build()?;

            // IPv4 public detection via api.ipify.org
            if detect_v4
                && let Ok(ip) = client.get("https://api.ipify.org").send().await
                && let Ok(text) = ip.text().await
            {
                addresses.push(text);
            }

            // IPv6 public detection via api6.ipify.org (and local fallback/augmentation up to `num`)
            if detect_v6 {
                // First try public detection
                let mut added = std::collections::HashSet::<String>::new();
                if let Ok(resp) = client.get("https://api6.ipify.org").send().await
                    && let Ok(text) = resp.text().await
                {
                    if !text.is_empty() {
                        addresses.push(text.clone());
                        added.insert(text);
                    }
                }

                // If we still need additional addresses, enumerate local interfaces and collect candidates
                if addresses.len() < num {
                    if let Ok(ifaces) = get_if_addrs() {
                        let ips_iter = ifaces.into_iter().map(|ifa| ifa.addr.ip());
                        let candidates = collect_ipv6_candidates(ips_iter, num);
                        for v6 in candidates {
                            let s = v6.to_string();
                            if !added.contains(&s) {
                                addresses.push(s.clone());
                                added.insert(s);
                            }
                            if addresses.len() >= num {
                                break;
                            }
                        }
                        if !addresses.is_empty() {
                            eprintln!(
                                "{} Auto-detected IPv6 candidate(s): {:?}",
                                "[WARN]".yellow(),
                                addresses
                            );
                        }
                    }
                }
            }
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

/// Collect VLESS links from various input formats (JSON array, newline separated, or single link)
fn collect_links_from_input(input: &str) -> Result<Vec<String>> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(vec![]);
    }

    // Try JSON first
    if let Ok(v) = serde_json::from_str::<Value>(trimmed) {
        if let Some(arr) = v.as_array() {
            let mut out = Vec::new();
            for item in arr {
                if let Some(s) = item.as_str() {
                    out.push(s.to_string());
                }
            }
            if !out.is_empty() {
                return Ok(out);
            }
        } else if let Some(s) = v.as_str() {
            return Ok(vec![s.to_string()]);
        }
    }

    let mut out = Vec::new();
    for line in trimmed.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        // try parse small JSON fragments like ["..."] or "..."
        if (l.starts_with('[') || l.starts_with('"')) {
            if let Ok(v2) = serde_json::from_str::<Value>(l) {
                if let Some(s) = v2.as_str() {
                    out.push(s.to_string());
                    continue;
                } else if let Some(arr) = v2.as_array() {
                    for item in arr {
                        if let Some(s) = item.as_str() {
                            out.push(s.to_string());
                        }
                    }
                    continue;
                }
            }
        }

        // tokenise whitespace, pick tokens that look like vless links
        for tok in l.split_whitespace() {
            if tok.starts_with("vless://") {
                out.push(tok.to_string());
            }
        }

        // fallback: if the whole line is a link
        if l.starts_with("vless://") && !out.contains(&l.to_string()) {
            out.push(l.to_string());
        }
    }

    Ok(out)
}

fn parse_link_to_outbound(
    link: &str,
    _idx: usize,
    packet_encoding: &str,
) -> Result<(String, Value)> {
    let url = Url::parse(link).map_err(|e| anyhow!("Failed to parse link '{}': {}", link, e))?;

    if url.scheme() != "vless" {
        return Err(anyhow!(
            "Invalid scheme '{}' in link '{}'",
            url.scheme(),
            link
        ));
    }

    let uuid = url.username().to_string();
    if uuid.is_empty() {
        return Err(anyhow!("Link is missing UUID"));
    }

    let host = {
        let h = url
            .host_str()
            .ok_or_else(|| anyhow!("Link missing host: {}", link))?
            .to_string();
        // Strip surrounding IPv6 brackets if present, e.g. "[2001:db8::1]" => "2001:db8::1"
        if let Some(stripped) = h.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            stripped.to_string()
        } else {
            h
        }
    };

    let port = url.port().unwrap_or(443);

    let query_pairs: std::collections::HashMap<_, _> = url.query_pairs().collect();

    let pbk = query_pairs
        .get("pbk")
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("Link missing 'pbk' parameter (Reality public key)"))?;

    let sni = query_pairs
        .get("sni")
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("Link missing 'sni' parameter"))?;

    let sid = query_pairs
        .get("sid")
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("Link missing 'sid' parameter"))?;

    let flow = query_pairs
        .get("flow")
        .map(|s| s.to_string())
        .unwrap_or_else(|| "xtls-rprx-vision".to_string());

    let fp = query_pairs
        .get("fp")
        .map(|s| s.to_string())
        .unwrap_or_else(|| "chrome".to_string());

    let tag = url
        .fragment()
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| sid_label(&sid));

    let tls = json!({
        "enabled": true,
        "server_name": sni,
        "utls": {
            "enabled": true,
            "fingerprint": fp
        },
        "reality": {
            "enabled": true,
            "public_key": pbk,
            "short_id": sid
        }
    });

    let outbound = json!({
        "type": "vless",
        "tag": tag,
        "server": host,
        "server_port": port,
        "uuid": uuid,
        "flow": flow,
        "tls": tls,
        "packet_encoding": packet_encoding
    });

    Ok((tag, outbound))
}

pub async fn from_link(
    _paths: &Paths,
    out: Option<PathBuf>,
    socks: bool,
    tun: bool,
    selector_tag: String,
) -> Result<()> {
    // Read stdin
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;

    let links = collect_links_from_input(&input)?;
    if links.is_empty() {
        return Err(anyhow!("No VLESS links found on stdin"));
    }

    let packet_encoding = "xudp";

    let mut outbounds: Vec<Value> = Vec::new();
    let mut tags: Vec<String> = Vec::new();

    for (i, link) in links.iter().enumerate() {
        let (tag, outbound) = parse_link_to_outbound(link, i, packet_encoding)?;
        tags.push(tag.clone());
        outbounds.push(outbound);
    }

    // Build base config
    let mut map = serde_json::Map::new();
    map.insert("log".to_string(), json!({"level":"info","timestamp": true}));
    map.insert(
        "dns".to_string(),
        json!({
            "servers": [{"tag":"dns","type":"udp","server":"1.1.1.1"}],
            "final": "dns",
            "strategy": "prefer_ipv4"
        }),
    );

    // inbounds: choose TUN or SOCKS
    if tun {
        map.insert(
            "inbounds".to_string(),
            json!([{
                "type": "tun",
                "tag": "tun-in",
                "mtu": 1400,
                "address": ["172.16.0.1/30", "fd00::1/126"],
                "auto_route": true,
                "strict_route": true,
                "stack": "mixed",
                "sniff": true,
                "sniff_override_destination": true
            }]),
        );
    } else {
        let socks_enabled = socks || !tun; // default to socks if neither specified
        if socks_enabled {
            map.insert(
                "inbounds".to_string(),
                json!([{
                    "type": "socks",
                    "tag": "socks-in",
                    "listen": "127.0.0.1",
                    "listen_port": 1080
                }]),
            );
        }
    }

    // outbounds: add basic direct/block then our vless entries
    let mut final_outbounds = vec![
        json!({"type":"direct","tag":"direct"}),
        json!({"type":"block","tag":"block"}),
    ];
    final_outbounds.extend(outbounds.into_iter());

    if tags.len() > 1 {
        final_outbounds.push(json!({
            "type": "selector",
            "tag": selector_tag,
            "outbounds": tags.clone()
        }));
        map.insert("outbounds".to_string(), json!(final_outbounds));
        map.insert("route".to_string(), json!({"final": selector_tag}));
    } else {
        let final_tag = tags.get(0).unwrap().clone();
        map.insert("outbounds".to_string(), json!(final_outbounds));
        map.insert("route".to_string(), json!({"final": final_tag}));
    }

    let content = serde_json::to_string_pretty(&map)?;
    if let Some(p) = out {
        std::fs::write(p, content)?;
    } else {
        println!("{}", content);
    }

    Ok(())
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
    fn test_collect_links_from_input_json_array() {
        let input = r#"["vless://1111@1.2.3.4:443?security=reality&pbk=PBK&sni=example.com&sid=SID#label"]"#;
        let links = collect_links_from_input(input).unwrap();
        assert_eq!(links.len(), 1);
        assert_eq!(
            links[0],
            "vless://1111@1.2.3.4:443?security=reality&pbk=PBK&sni=example.com&sid=SID#label"
        );
    }

    #[test]
    fn test_collect_links_from_input_newlines() {
        let input = "vless://a@1.2.3.4:443?security=reality&pbk=PBK1&sni=one.com&sid=S1#one\nvless://b@2.2.2.2:443?security=reality&pbk=PBK2&sni=two.com&sid=S2#two\n";
        let links = collect_links_from_input(input).unwrap();
        assert_eq!(links.len(), 2);
        assert!(links[0].starts_with("vless://a@1.2.3.4"));
        assert!(links[1].starts_with("vless://b@2.2.2.2"));
    }

    #[test]
    fn test_parse_link_to_outbound_basic() {
        let link = "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?security=reality&encryption=none&pbk=PBK123&fp=chrome&type=tcp&sni=learn.microsoft.com&sid=ABCD&flow=xtls-rprx-vision#abcd";
        let (tag, outbound) = parse_link_to_outbound(link, 0, "xudp").unwrap();
        assert_eq!(tag, "abcd");
        assert_eq!(outbound["type"].as_str().unwrap(), "vless");
        assert_eq!(outbound["server"].as_str().unwrap(), "1.2.3.4");
        assert_eq!(outbound["server_port"].as_i64().unwrap(), 443);
        assert_eq!(
            outbound["uuid"].as_str().unwrap(),
            "11111111-2222-3333-4444-555555555555"
        );
        assert_eq!(
            outbound["tls"]["reality"]["public_key"].as_str().unwrap(),
            "PBK123"
        );
        assert_eq!(
            outbound["tls"]["reality"]["short_id"].as_str().unwrap(),
            "ABCD"
        );
        assert_eq!(
            outbound["tls"]["server_name"].as_str().unwrap(),
            "learn.microsoft.com"
        );
        assert_eq!(outbound["packet_encoding"].as_str().unwrap(), "xudp");
    }

    #[test]
    fn test_parse_link_to_outbound_missing_pbk() {
        let link = "vless://uuid@1.2.3.4:443?security=reality&sni=example.com&sid=SID#lbl";
        let res = parse_link_to_outbound(link, 0, "xudp");
        assert!(res.is_err());
        let err = res.err().unwrap().to_string();
        assert!(err.contains("pbk"));
    }

    #[test]
    fn test_sid_label_shorter() {
        assert_eq!(sid_label("ab"), "ab");
    }

    #[test]
    fn test_parse_link_ipv6_bracketed() {
        let link = "vless://1111@[2001:db8::1]:443?security=reality&encryption=none&pbk=PBKIPv6&fp=chrome&type=tcp&sni=ipv6.example.com&sid=S6#ipv6";
        let (tag, outbound) = parse_link_to_outbound(link, 0, "xudp").unwrap();
        assert_eq!(tag, "ipv6");
        assert_eq!(outbound["server"].as_str().unwrap(), "2001:db8::1");
        assert_eq!(outbound["server_port"].as_i64().unwrap(), 443);
    }

    #[test]
    fn test_parse_links_mixed_ipv4_ipv6() {
        let input = "vless://u1@1.2.3.4:443?security=reality&pbk=PBK1&fp=chrome&type=tcp&sni=one.com&sid=S1#one\nvless://u2@[2001:db8::2]:443?security=reality&pbk=PBK2&fp=chrome&type=tcp&sni=two.com&sid=S2#two\n";
        let links = collect_links_from_input(input).unwrap();
        assert_eq!(links.len(), 2);
        let (_, o1) = parse_link_to_outbound(&links[0], 0, "xudp").unwrap();
        let (_, o2) = parse_link_to_outbound(&links[1], 1, "xudp").unwrap();
        assert_eq!(o1["server"].as_str().unwrap(), "1.2.3.4");
        assert_eq!(o2["server"].as_str().unwrap(), "2001:db8::2");
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
            None,
            1,
            false,
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
            None,
            1,
            false,
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

    #[test]
    fn test_choose_ipv6_candidate_prefers_global() {
        use std::net::IpAddr;
        let ips = vec![
            IpAddr::V6("fe80::1".parse::<std::net::Ipv6Addr>().unwrap()), // link-local (ignored)
            IpAddr::V6("fc00::1".parse::<std::net::Ipv6Addr>().unwrap()), // ULA (fallback)
            IpAddr::V6("2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap()), // global (preferred)
        ];
        let chosen = choose_ipv6_candidate(ips.into_iter());
        assert_eq!(
            chosen,
            Some("2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap())
        );
    }

    #[test]
    fn test_collect_ipv6_candidates_limits_and_order() {
        use std::net::IpAddr;
        let ips = vec![
            IpAddr::V6("2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap()),
            IpAddr::V6("fc00::1".parse::<std::net::Ipv6Addr>().unwrap()),
            IpAddr::V6("2001:db8::2".parse::<std::net::Ipv6Addr>().unwrap()),
            IpAddr::V6("fe80::1".parse::<std::net::Ipv6Addr>().unwrap()), // link-local (ignored)
        ];
        let chosen = collect_ipv6_candidates(ips.into_iter(), 2);
        assert_eq!(
            chosen,
            vec![
                "2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap(),
                "2001:db8::2".parse::<std::net::Ipv6Addr>().unwrap()
            ]
        );
    }
}
