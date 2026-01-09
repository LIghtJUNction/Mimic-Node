use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose};
use colored::*;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use url::Url;
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};

use crate::config::SingBoxConfig;
use crate::paths::Paths;
use crate::utils::load_config;

pub fn verify(
    paths: &Paths,
    verbose: bool,
    custom_config: Option<PathBuf>,
    link: Option<String>,
) -> Result<()> {
    // Determine which config to verify
    let (config_path, is_system_config) = if let Some(path) = custom_config {
        if !path.exists() {
            return Err(anyhow!("Custom config file not found: {:?}", path));
        }
        (path, false)
    } else {
        (paths.get_input_config_path().to_path_buf(), true)
    };

    if verbose {
        eprintln!("{} Target config: {:?}", "[INFO]".green(), config_path);
    }

    let config = load_config(&config_path)?;

    // If a link is provided, verify it exclusively against the loaded config
    if let Some(link_str) = link {
        return verify_link(&link_str, &config, verbose);
    }

    eprintln!("{} Verifying configuration integrity...", "[INFO]".green());

    let mut errors = 0;
    let mut warnings = 0;

    // 1. Verify Inbounds Structure
    let inbound = match config.inbounds.first() {
        Some(i) => i,
        None => {
            eprintln!("{} No inbounds defined in config.", "[ERROR]".red());
            return Err(anyhow!("Config must have at least one inbound."));
        }
    };

    if verbose {
        println!("  Inbound Type: {}", inbound.protocol_type);
        println!("  Listen Port: {}", inbound.listen_port);
    }

    // 2. Verify TLS & Reality Structure
    let tls = match &inbound.tls {
        Some(t) => t,
        None => {
            eprintln!("{} TLS configuration is missing.", "[ERROR]".red());
            return Err(anyhow!("Inbound must have TLS enabled."));
        }
    };

    let reality = match &tls.reality {
        Some(r) => r,
        None => {
            eprintln!("{} Reality configuration is missing.", "[ERROR]".red());
            return Err(anyhow!("TLS must have Reality enabled."));
        }
    };

    if verbose {
        println!("  SNI: {}", tls.server_name);
        println!(
            "  Reality Target: {}:{}",
            reality.handshake.server, reality.handshake.server_port
        );
    }

    // 3. Verify Private Key & Keypair Consistency
    let mut priv_key_bytes = Vec::new();

    if reality.private_key.is_empty() {
        eprintln!("{} Private key is empty.", "[ERROR]".red());
        errors += 1;
    } else {
        match general_purpose::URL_SAFE_NO_PAD.decode(&reality.private_key) {
            Ok(decoded) => {
                if decoded.len() != 32 {
                    eprintln!(
                        "{} Private key length invalid (expected 32 bytes, got {}).",
                        "[ERROR]".red(),
                        decoded.len()
                    );
                    errors += 1;
                } else {
                    priv_key_bytes = decoded;
                }
            }
            Err(_) => {
                // Try standard base64 if URL safe fails
                match general_purpose::STANDARD.decode(&reality.private_key) {
                    Ok(decoded) => {
                        if decoded.len() != 32 {
                            eprintln!(
                                "{} Private key length invalid (expected 32 bytes, got {}).",
                                "[ERROR]".red(),
                                decoded.len()
                            );
                            errors += 1;
                        } else {
                            priv_key_bytes = decoded;
                        }
                    }
                    Err(e) => {
                        eprintln!("{} Private key is not valid Base64: {}", "[ERROR]".red(), e);
                        errors += 1;
                    }
                }
            }
        }
    }

    // 3.5 Verify Keypair
    if !priv_key_bytes.is_empty() {
        match derive_x25519_pubkey(&priv_key_bytes) {
            Ok(derived_pubkey) => {
                let derived_pubkey_str = general_purpose::URL_SAFE_NO_PAD.encode(&derived_pubkey);
                if verbose {
                    println!("  Derived Public Key: {}", derived_pubkey_str);
                }

                // Only compare with stored PUBKEY file if we are checking the system/staged config
                if is_system_config {
                    // Read stored PUBKEY
                    let stored_pubkey = if paths.pubkey.exists() {
                        std::fs::read_to_string(&paths.pubkey)
                            .unwrap_or_default()
                            .trim()
                            .to_string()
                    } else {
                        String::new()
                    };

                    if stored_pubkey.is_empty() {
                        eprintln!("{} PUBKEY file is missing or empty.", "[WARN]".yellow());
                        warnings += 1;
                    } else {
                        // Validate stored pubkey format
                        match general_purpose::URL_SAFE_NO_PAD.decode(&stored_pubkey) {
                            Ok(pk) if pk.len() == 32 => {
                                if pk != derived_pubkey {
                                    eprintln!(
                                        "{} Private Key does NOT match stored Public Key!",
                                        "[ERROR]".red()
                                    );
                                    eprintln!(
                                        "  Config Private Key -> Derived Public: {}",
                                        derived_pubkey_str
                                    );
                                    eprintln!("  Stored PUBKEY file: {}", stored_pubkey);
                                    errors += 1;
                                } else if verbose {
                                    eprintln!(
                                        "{} Keypair verified (Private Key matches PUBKEY).",
                                        "[INFO]".green()
                                    );
                                }
                            }
                            _ => {
                                eprintln!(
                                    "{} Stored PUBKEY is invalid (not 32-byte Base64).",
                                    "[ERROR]".red()
                                );
                                errors += 1;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("{} Could not derive public key: {}", "[ERROR]".red(), e);
                errors += 1;
            }
        }
    }

    // 4. Verify Users, SIDs, and UUIDs
    let mut seen_uuids = HashMap::new();
    let mut seen_sids = HashMap::new();
    let mut user_sids = HashSet::new();

    let valid_short_ids: HashSet<String> = reality.short_id.iter().cloned().collect();

    if inbound.users.is_empty() {
        eprintln!("{} No users defined.", "[WARN]".yellow());
        warnings += 1;
    } else if verbose {
        println!("  Found {} users.", inbound.users.len());
    }

    for (index, user) in inbound.users.iter().enumerate() {
        // A. Validate UUID
        if let Err(e) = uuid::Uuid::parse_str(&user.uuid) {
            eprintln!(
                "{} User #{} ({}) has invalid UUID: {}",
                "[ERROR]".red(),
                index,
                user.name,
                e
            );
            errors += 1;
        } else {
            // Check Duplicate UUID
            if let Some(prev_user) = seen_uuids.insert(user.uuid.clone(), user.name.clone()) {
                eprintln!(
                    "{} Duplicate UUID detected: {} (shared by '{}' and '{}')",
                    "[ERROR]".red(),
                    user.uuid,
                    prev_user,
                    user.name
                );
                errors += 1;
            }
        }

        // B. Parse Name & Extract SID
        // Expected format: email:sid:level
        let parts: Vec<&str> = user.name.split(':').collect();
        if parts.len() < 3 {
            eprintln!(
                "{} User #{} name format invalid: '{}' (expected email:sid:level)",
                "[ERROR]".red(),
                index,
                user.name
            );
            errors += 1;
            continue;
        }

        let sid = parts[parts.len() - 2].to_string();
        user_sids.insert(sid.clone());

        // Check Duplicate SID in users
        if let Some(prev_user) = seen_sids.insert(sid.clone(), user.name.clone()) {
            eprintln!(
                "{} Duplicate SID usage: {} (shared by '{}' and '{}')",
                "[WARN]".yellow(),
                sid,
                prev_user,
                user.name
            );
            warnings += 1;
        }

        // C. Verify SID exists in reality.short_id
        if !valid_short_ids.contains(&sid) {
            eprintln!(
                "{} User '{}' uses SID '{}' which is MISSING from reality.short_id list.",
                "[ERROR]".red(),
                user.name,
                sid
            );
            errors += 1;
        }
    }

    // 5. Check for Orphaned SIDs (in reality.short_id but not used by any user)
    for sid in &reality.short_id {
        if !user_sids.contains(sid) {
            if verbose {
                eprintln!(
                    "{} Orphaned SID found in reality.short_id: '{}' (no user uses this)",
                    "[WARN]".yellow(),
                    sid
                );
            }
            warnings += 1;
        }
    }

    // Summary
    println!();
    if errors > 0 {
        eprintln!(
            "{} Verification FAILED with {} errors and {} warnings.",
            "[ERROR]".red(),
            errors,
            warnings
        );
        return Err(anyhow!("Configuration verification failed."));
    } else if warnings > 0 {
        eprintln!(
            "{} Verification PASSED with {} warnings.",
            "[WARN]".yellow(),
            warnings
        );
    } else {
        eprintln!(
            "{} Verification PASSED. Configuration looks healthy.",
            "[INFO]".green()
        );
    }

    Ok(())
}

fn derive_x25519_pubkey(priv_key: &[u8]) -> Result<Vec<u8>> {
    // Pure-Rust X25519 public key derivation using x25519-dalek's x25519 function
    if priv_key.len() != 32 {
        return Err(anyhow!("Private key length must be 32 bytes"));
    }
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(priv_key);

    // Compute public key: scalar * basepoint
    let pubkey = x25519(scalar, X25519_BASEPOINT_BYTES);

    Ok(pubkey.to_vec())
}

fn verify_link(link: &str, config: &SingBoxConfig, verbose: bool) -> Result<()> {
    eprintln!(
        "{} Verifying VLESS link against loaded config...",
        "[INFO]".green()
    );

    let url = Url::parse(link).context("Failed to parse URL")?;

    if url.scheme() != "vless" {
        return Err(anyhow!(
            "Invalid scheme: expected 'vless', got '{}'",
            url.scheme()
        ));
    }

    let inbound = config
        .inbounds
        .first()
        .ok_or_else(|| anyhow!("Config has no inbounds"))?;

    let tls = inbound
        .tls
        .as_ref()
        .ok_or_else(|| anyhow!("Config has no TLS"))?;
    let reality = tls
        .reality
        .as_ref()
        .ok_or_else(|| anyhow!("Config has no Reality"))?;

    let mut success = true;

    // 1. UUID Check
    let uuid_str = url.username();
    let mut found_user = false;
    for user in &inbound.users {
        if user.uuid == uuid_str {
            found_user = true;
            if verbose {
                println!("{} UUID matches user '{}'", "[PASS]".green(), user.name);
            }
            break;
        }
    }
    if !found_user {
        eprintln!(
            "{} UUID '{}' NOT found in configuration users.",
            "[FAIL]".red(),
            uuid_str
        );
        success = false;
    }

    let query_pairs: HashMap<_, _> = url.query_pairs().collect();

    // 2. SNI Check
    if let Some(sni) = query_pairs.get("sni") {
        if sni.as_ref() != tls.server_name {
            eprintln!(
                "{} SNI mismatch: Link has '{}', Config has '{}'",
                "[FAIL]".red(),
                sni,
                tls.server_name
            );
            success = false;
        } else if verbose {
            println!("{} SNI matches config '{}'", "[PASS]".green(), sni);
        }
    } else {
        eprintln!("{} Link missing SNI parameter.", "[FAIL]".red());
        success = false;
    }

    // 3. PBK Check
    if let Some(pbk) = query_pairs.get("pbk") {
        // Derive actual PBK from config private key
        let priv_key_bytes = match general_purpose::URL_SAFE_NO_PAD.decode(&reality.private_key) {
            Ok(b) => b,
            Err(_) => general_purpose::STANDARD
                .decode(&reality.private_key)
                .unwrap_or_default(),
        };

        if priv_key_bytes.len() == 32 {
            if let Ok(derived_pub) = derive_x25519_pubkey(&priv_key_bytes) {
                let config_pbk = general_purpose::URL_SAFE_NO_PAD.encode(&derived_pub);
                if pbk.as_ref() != config_pbk {
                    eprintln!(
                        "{} PBK mismatch: Link has '{}', Config derives '{}'",
                        "[FAIL]".red(),
                        pbk,
                        config_pbk
                    );
                    success = false;
                } else if verbose {
                    println!("{} PBK matches config derived key.", "[PASS]".green());
                }
            } else {
                eprintln!(
                    "{} Could not derive public key from config.",
                    "[ERROR]".red()
                );
            }
        } else {
            eprintln!("{} Config private key is invalid.", "[ERROR]".red());
        }
    } else {
        eprintln!("{} Link missing 'pbk' parameter.", "[FAIL]".red());
        success = false;
    }

    // 4. SID Check
    if let Some(sid) = query_pairs.get("sid") {
        if !reality.short_id.contains(&sid.to_string()) {
            eprintln!(
                "{} SID '{}' is NOT in config 'short_id' list.",
                "[FAIL]".red(),
                sid
            );
            success = false;
        } else if verbose {
            println!("{} SID found in config whitelist.", "[PASS]".green());
        }
    } else {
        eprintln!("{} Link missing 'sid' parameter.", "[FAIL]".red());
        success = false;
    }

    if success {
        eprintln!(
            "{} Link is VALID and matches configuration.",
            "[INFO]".green()
        );
        Ok(())
    } else {
        Err(anyhow!("Link verification failed against configuration."))
    }
}
