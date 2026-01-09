use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose};
use colored::*;
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::process::{Command, Stdio};

use crate::paths::Paths;
use crate::utils::load_config;

pub fn verify(paths: &Paths) -> Result<()> {
    eprintln!("{} Verifying configuration integrity...", "[INFO]".green());

    // Determine which config to verify (staged takes precedence if exists)
    let config_path = paths.get_input_config_path();
    eprintln!("{} Target config: {:?}", "[INFO]".green(), config_path);

    let config = load_config(config_path)?;
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

    // 3.5 Verify Keypair (using openssl if available)
    if !priv_key_bytes.is_empty() {
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
                    // Try to derive public key from private key to verify match
                    match derive_x25519_pubkey_openssl(&priv_key_bytes) {
                        Ok(derived_pubkey) => {
                            if pk != derived_pubkey {
                                eprintln!(
                                    "{} Private Key does NOT match stored Public Key!",
                                    "[ERROR]".red()
                                );
                                eprintln!(
                                    "  Config Private Key -> Derived Public: {}",
                                    general_purpose::URL_SAFE_NO_PAD.encode(&derived_pubkey)
                                );
                                eprintln!("  Stored PUBKEY file: {}", stored_pubkey);
                                errors += 1;
                            } else {
                                eprintln!(
                                    "{} Keypair verified (Private Key matches PUBKEY).",
                                    "[INFO]".green()
                                );
                            }
                        }
                        Err(e) => {
                            eprintln!("{} Could not verify keypair: {}", "[WARN]".yellow(), e);
                            warnings += 1;
                        }
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

    // 4. Verify Users, SIDs, and UUIDs
    let mut seen_uuids = HashMap::new();
    let mut seen_sids = HashMap::new();
    let mut user_sids = HashSet::new();

    let valid_short_ids: HashSet<String> = reality.short_id.iter().cloned().collect();

    if inbound.users.is_empty() {
        eprintln!("{} No users defined.", "[WARN]".yellow());
        warnings += 1;
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

        // Check Duplicate SID in users (technically allowable but suspicious for 1:1 user mapping)
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
            eprintln!(
                "{} Orphaned SID found in reality.short_id: '{}' (no user uses this)",
                "[WARN]".yellow(),
                sid
            );
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

fn derive_x25519_pubkey_openssl(priv_key: &[u8]) -> Result<Vec<u8>> {
    // Construct minimal ASN.1 DER for X25519 Private Key
    // 30 2E 02 01 00 30 05 06 03 2B 65 6E 04 22 04 20 <32-bytes-key>
    let mut der = vec![
        0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E, 0x04, 0x22, 0x04,
        0x20,
    ];
    der.extend_from_slice(priv_key);

    let mut child = Command::new("openssl")
        .args(["pkey", "-inform", "DER", "-text_pub", "-noout"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| anyhow!("openssl not found"))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(&der)?;
    }

    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(anyhow!("openssl failed"));
    }

    // Output format is like:
    // Public-Key: (253 bit)
    // pub:
    //     5e:c9:...
    //     ...
    let out_str = String::from_utf8(output.stdout)?;
    let mut hex_str = String::new();
    let mut capturing = false;

    for line in out_str.lines() {
        let line = line.trim();
        if line.starts_with("pub:") {
            capturing = true;
            continue;
        }
        if capturing {
            if line.contains(':') {
                hex_str.push_str(&line.replace(':', ""));
            } else {
                break;
            }
        }
    }

    let pub_key = hex::decode(&hex_str)?;
    if pub_key.len() != 32 {
        return Err(anyhow!("Derived key length mismatch"));
    }

    Ok(pub_key)
}
