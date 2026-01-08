use anyhow::{anyhow, Result};
use colored::*;
use regex::Regex;
use std::fs;

use crate::config;
use crate::paths::Paths;
use crate::utils::{generate_keypair, generate_sid, generate_uuid, load_config, save_config};

const FLOW_TYPE: &str = "xtls-rprx-vision";

pub fn add(paths: &Paths, emails: Vec<String>, level: u32) -> Result<()> {
    // Check for private key first
    let input_path = paths.get_input_config_path();
    let mut config = load_config(input_path)?;

    // Quick check if private key is present in loaded config
    let has_key = config
        .inbounds
        .first()
        .and_then(|i| i.tls.as_ref())
        .and_then(|t| t.reality.as_ref())
        .map(|r| !r.private_key.is_empty())
        .unwrap_or(false);

    if !has_key {
        eprintln!(
            "{}",
            "[WARN] No private key found; generating one now.".yellow()
        );
        // Generate keys in place into `config` object
        let (priv_key, pub_key) = generate_keypair()?;
        if let Some(inbound) = config.inbounds.first_mut() {
            if inbound.tls.is_none() {
                // Initialize structure if completely missing (unlikely given default)
                // Keeping it simple: assuming structure exists from default config
                return Err(anyhow!("Config structure invalid: missing tls"));
            }
            if let Some(tls) = inbound.tls.as_mut() {
                if tls.reality.is_none() {
                    // Init reality...
                    return Err(anyhow!("Config structure invalid: missing reality"));
                }
                if let Some(reality) = tls.reality.as_mut() {
                    reality.private_key = priv_key;
                }
            }
        }
        // Save pubkey immediately to staging path if we are generating it
        fs::write(&paths.staging_pubkey, &pub_key)?;
    }

    for email in emails {
        let uuid = generate_uuid();
        let sid = generate_sid();
        let name = format!("{}:{}:{}", email, sid, level);

        let user = config::User {
            name: name.clone(),
            uuid: uuid.clone(),
            flow: FLOW_TYPE.to_string(),
        };

        if let Some(inbound) = config.inbounds.first_mut() {
            inbound.users.push(user);
            if let Some(tls) = inbound.tls.as_mut() {
                if let Some(reality) = tls.reality.as_mut() {
                    reality.short_id.push(sid.clone());
                    // Deduplicate short_ids (simple approach)
                    reality.short_id.sort();
                    reality.short_id.dedup();
                }
            }
        }

        eprintln!(
            "{} Prepared user: {} (uuid: {})",
            "[INFO]".green(),
            name,
            uuid
        );
        println!("uuid: {}\nsid: {}", uuid, sid);
    }

    save_config(&paths.staging, &config)?;

    eprintln!(
        "{} Users staged. Run 'mimictl apply' to activate.",
        "[INFO]".green()
    );

    Ok(())
}

pub fn del(paths: &Paths, targets: Vec<String>) -> Result<()> {
    let input_path = paths.get_input_config_path();
    let mut config = load_config(input_path)?;

    for target in targets {
        // Handle wildcards: convert glob to regex
        let pattern = if target.contains('*') || target.contains('?') {
            regex::escape(&target)
                .replace("\\*", ".*")
                .replace("\\?", ".")
        } else {
            regex::escape(&target)
        };

        let regex_str = format!("^{}:", pattern);
        let re = Regex::new(&regex_str)?;

        if let Some(inbound) = config.inbounds.first_mut() {
            inbound.users.retain(|u| !re.is_match(&u.name));
        }

        eprintln!("{} Processed deletion for: {}", "[INFO]".green(), target);
    }

    save_config(&paths.staging, &config)?;

    eprintln!(
        "{} Deletion(s) staged. Run 'mimictl apply' to activate.",
        "[INFO]".green()
    );

    Ok(())
}

pub fn reset(paths: &Paths, email: String) -> Result<()> {
    let input_path = paths.get_input_config_path();
    let mut config = load_config(input_path)?;

    let mut found = false;
    let mut old_sid = String::new();
    let mut new_sid = String::new();
    let mut new_uuid = String::new();

    if let Some(inbound) = config.inbounds.first_mut() {
        if let Some(user) = inbound
            .users
            .iter_mut()
            .find(|u| u.name.starts_with(&format!("{}:", email)))
        {
            found = true;
            // Parse name: email:sid:level
            let parts: Vec<&str> = user.name.split(':').collect();
            let level = parts.last().unwrap_or(&"0");
            old_sid = parts.get(parts.len() - 2).unwrap_or(&"").to_string();

            new_sid = generate_sid();
            new_uuid = generate_uuid();
            let new_name = format!("{}:{}:{}", email, new_sid, level);

            eprintln!(
                "{} Resetting user {} (Level: {})",
                "[INFO]".green(),
                email,
                level
            );
            eprintln!(
                "{} Old SID: {} -> New SID: {}",
                "[INFO]".green(),
                old_sid,
                new_sid
            );

            user.name = new_name;
            user.uuid = new_uuid.clone();
        }

        if found {
            // Update short_id list
            if let Some(tls) = inbound.tls.as_mut() {
                if let Some(reality) = tls.reality.as_mut() {
                    if let Some(pos) = reality.short_id.iter().position(|x| x == &old_sid) {
                        reality.short_id.remove(pos);
                    }
                    reality.short_id.push(new_sid.clone());
                }
            }
        }
    }

    if !found {
        return Err(anyhow!("User not found: {}", email));
    }

    save_config(&paths.staging, &config)?;
    println!("uuid: {}\nsid: {}", new_uuid, new_sid);

    eprintln!(
        "{} Staged reset for: {}. Run 'mimictl apply' to activate.",
        "[INFO]".green(),
        email
    );

    Ok(())
}

pub fn list(paths: &Paths, filter: Option<String>) -> Result<()> {
    let input_path = paths.get_input_config_path();
    let config = load_config(input_path)?;

    if let Some(inbound) = config.inbounds.first() {
        for user in &inbound.users {
            if let Some(f) = &filter {
                if !user.name.contains(f) {
                    continue;
                }
            }
            println!("{}\t{}\t{}", user.name, user.uuid, user.flow);
        }
    }
    Ok(())
}

pub fn info(paths: &Paths, email: String) -> Result<()> {
    let input_path = paths.get_input_config_path();
    let config = load_config(input_path)?;

    if let Some(inbound) = config.inbounds.first() {
        if let Some(user) = inbound
            .users
            .iter()
            .find(|u| u.name.starts_with(&format!("{}:", email)))
        {
            println!("{}", serde_json::to_string_pretty(user)?);
            return Ok(());
        }
    }
    Err(anyhow!("User not found: {}", email))
}
