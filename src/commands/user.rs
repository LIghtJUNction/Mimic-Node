use anyhow::{Result, anyhow};
use colored::*;
use regex::Regex;
use std::fs;

use crate::config;
use crate::paths::Paths;
use crate::utils::{generate_keypair, generate_sid, generate_uuid, load_config, save_config};

const FLOW_TYPE: &str = "xtls-rprx-vision";

/// Helper to synchronize reality.short_id list with active users
fn sync_short_ids(config: &mut config::SingBoxConfig) {
    if let Some(inbound) = config.inbounds.first_mut() {
        let mut active_sids = Vec::new();

        // Extract SIDs from all users
        for user in &inbound.users {
            let parts: Vec<&str> = user.name.split(':').collect();
            // Format is email:sid:level. We need the SID (second to last)
            if parts.len() >= 3
                && let Some(sid) = parts.get(parts.len() - 2)
                    && !sid.is_empty() {
                        active_sids.push(sid.to_string());
                    }
        }

        // Sort and dedup
        active_sids.sort();
        active_sids.dedup();

        // Update config
        if let Some(tls) = inbound.tls.as_mut()
            && let Some(reality) = tls.reality.as_mut() {
                reality.short_id = active_sids;
            }
    }
}

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
                return Err(anyhow!("Config structure invalid: missing tls"));
            }
            if let Some(tls) = inbound.tls.as_mut() {
                if tls.reality.is_none() {
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
        }

        eprintln!(
            "{} Prepared user: {} (uuid: {})",
            "[INFO]".green(),
            name,
            uuid
        );
        println!("uuid: {}\nsid: {}", uuid, sid);
    }

    // Sync SIDs
    sync_short_ids(&mut config);

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

    // Track total deletions across all targets
    let mut total_deleted: usize = 0;

    for target in targets {
        let mut deleted_here: usize = 0;

        if let Some(inbound) = config.inbounds.first_mut() {
            // 1) If target is a UUID, try exact UUID match first
            if uuid::Uuid::parse_str(&target).is_ok() {
                let before = inbound.users.len();
                inbound.users.retain(|u| u.uuid != target);
                deleted_here = before - inbound.users.len();

                // If no exact UUID match, try substring fallback (name or uuid or local part of email)
                if deleted_here == 0 {
                    let before2 = inbound.users.len();
                    let local = target.split('@').next().unwrap_or(&target).to_string();
                    inbound.users.retain(|u| {
                        !(u.uuid.contains(&target)
                            || u.name.contains(&target)
                            || u.name.contains(&local))
                    });
                    deleted_here = before2 - inbound.users.len();
                }
            } else {
                // 2) Handle wildcard or anchored email/specific name match
                let pattern = if target.contains('*') || target.contains('?') {
                    regex::escape(&target)
                        .replace("\\*", ".*")
                        .replace("\\?", ".")
                } else {
                    regex::escape(&target)
                };

                // Try anchored-match (email:sid:level prefix)
                let regex_str = format!("^{}:", pattern);
                let re = Regex::new(&regex_str)?;
                let before = inbound.users.len();
                inbound.users.retain(|u| !re.is_match(&u.name));
                deleted_here = before - inbound.users.len();

                // 3) If nothing matched, do a substring fallback on name/uuid/local part
                if deleted_here == 0 {
                    let before2 = inbound.users.len();
                    let local = target.split('@').next().unwrap_or(&target).to_string();
                    inbound.users.retain(|u| {
                        !(u.name.contains(&target)
                            || u.name.contains(&local)
                            || u.uuid.contains(&target))
                    });
                    deleted_here = before2 - inbound.users.len();
                }
            }
        }

        if deleted_here > 0 {
            total_deleted += deleted_here;
            eprintln!(
                "{} Deleted {} user(s) for target: {}",
                "[INFO]".green(),
                deleted_here,
                target
            );
        } else {
            eprintln!(
                "{} No users matched for target: {}",
                "[WARN]".yellow(),
                target
            );
        }
    }

    if total_deleted == 0 {
        return Err(anyhow!("No users matched the provided target(s)."));
    }

    // Only sync and persist when we actually deleted something
    sync_short_ids(&mut config);
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
    let mut new_sid = String::new();
    let mut new_uuid = String::new();

    if let Some(inbound) = config.inbounds.first_mut()
        && let Some(user) = inbound
            .users
            .iter_mut()
            .find(|u| u.name.starts_with(&format!("{}:", email)))
        {
            found = true;
            // Parse name: email:sid:level
            let parts: Vec<&str> = user.name.split(':').collect();
            let level = parts.last().unwrap_or(&"0");
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
                parts.get(parts.len() - 2).unwrap_or(&""),
                new_sid
            );

            user.name = new_name;
            user.uuid = new_uuid.clone();
        }

    if !found {
        return Err(anyhow!("User not found: {}", email));
    }

    // Sync SIDs
    sync_short_ids(&mut config);

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
            if let Some(f) = &filter
                && !user.name.contains(f) {
                    continue;
                }
            println!("{}\t{}\t{}", user.name, user.uuid, user.flow);
        }
    }
    Ok(())
}

pub fn info(paths: &Paths, email: String) -> Result<()> {
    let input_path = paths.get_input_config_path();
    let config = load_config(input_path)?;

    if let Some(inbound) = config.inbounds.first()
        && let Some(user) = inbound
            .users
            .iter()
            .find(|u| u.name.starts_with(&format!("{}:", email)))
        {
            println!("{}", serde_json::to_string_pretty(user)?);
            return Ok(());
        }
    Err(anyhow!("User not found: {}", email))
}
