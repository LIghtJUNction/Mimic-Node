use anyhow::{anyhow, Result};
use colored::*;
use std::fs;
use std::process::Command;

use crate::paths::Paths;
use crate::utils::{apply_staging, load_config, save_config};

pub fn apply(paths: &Paths) -> Result<()> {
    apply_staging(paths)
}

pub fn reset(paths: &Paths, keep_users_emails: Vec<String>) -> Result<()> {
    eprintln!(
        "{} Resetting configuration to defaults...",
        "[INFO]".green()
    );

    // Load default config
    let default_config = load_config(&paths.default_config)?;
    let mut new_config = default_config.clone();

    // Preserve users
    if !keep_users_emails.is_empty() {
        let current_config = load_config(paths.get_input_config_path())?;

        for email in keep_users_emails {
            eprintln!("{} Preserving user: {}", "[INFO]".green(), email);

            // Find in current
            let user_opt = current_config.inbounds.first().and_then(|i| {
                i.users
                    .iter()
                    .find(|u| u.name.starts_with(&format!("{}:", email)))
            });

            if let Some(user) = user_opt {
                // Get SID
                let parts: Vec<&str> = user.name.split(':').collect();
                let sid = parts.get(parts.len() - 2).unwrap_or(&"").to_string();

                // Add to new config
                if let Some(inbound) = new_config.inbounds.first_mut() {
                    inbound.users.push(user.clone());
                    if let Some(tls) = inbound.tls.as_mut() {
                        if let Some(reality) = tls.reality.as_mut() {
                            reality.short_id.push(sid);
                            reality.short_id.sort();
                            reality.short_id.dedup();
                        }
                    }
                }
            } else {
                eprintln!(
                    "{} User '{}' not found in current config, skipping.",
                    "[WARN]".yellow(),
                    email
                );
            }
        }
    }

    save_config(&paths.staging, &new_config)?;

    eprintln!(
        "{} Staged global reset. Run 'mimictl apply' to activate.",
        "[INFO]".green()
    );

    Ok(())
}

pub fn show(paths: &Paths) -> Result<()> {
    eprintln!("Config ({:?}):", paths.config);
    if paths.config.exists() {
        let content = fs::read_to_string(&paths.config)?;
        println!("{}", content);
    }
    eprintln!("\nPUBKEY ({:?}):", paths.pubkey);
    if paths.pubkey.exists() {
        let content = fs::read_to_string(&paths.pubkey)?;
        println!("{}", content);
    }
    Ok(())
}

pub fn check(paths: &Paths) -> Result<()> {
    let input_path = paths.get_input_config_path();
    eprintln!(
        "{} Checking configuration at {:?}...",
        "[INFO]".green(),
        input_path
    );

    // 1. sing-box native check
    eprintln!("{} Running 'sing-box check'...", "[INFO]".green());
    let check_status = Command::new("sing-box")
        .args(["check", "-c", input_path.to_str().unwrap()])
        .status();

    match check_status {
        Ok(status) if status.success() => {
            eprintln!("{} 'sing-box check' passed.", "[INFO]".green());
        }
        _ => {
            return Err(anyhow!(
                "'sing-box check' failed. Invalid configuration syntax."
            ));
        }
    }

    // 2. Internal Consistency Checks
    eprintln!(
        "{} Running internal consistency checks...",
        "[INFO]".green()
    );
    let config = load_config(input_path)?;
    let mut warnings = 0;

    if let Some(inbound) = config.inbounds.first() {
        // Collect ShortIDs
        let mut valid_sids = Vec::new();
        if let Some(tls) = &inbound.tls {
            if let Some(reality) = &tls.reality {
                valid_sids = reality.short_id.clone();
            } else {
                eprintln!(
                    "{} Missing Reality configuration in first inbound.",
                    "[WARN]".yellow()
                );
                warnings += 1;
            }
        } else {
            eprintln!(
                "{} Missing TLS configuration in first inbound.",
                "[WARN]".yellow()
            );
            warnings += 1;
        }

        // Check Users
        for user in &inbound.users {
            let parts: Vec<&str> = user.name.split(':').collect();

            // Expected format: email:sid:level
            if parts.len() < 3 {
                eprintln!(
                    "{} User '{}' has invalid name format (expected email:sid:level).",
                    "[WARN]".yellow(),
                    user.name
                );
                warnings += 1;
                continue;
            }

            // Extract SID (second to last element)
            let sid = parts[parts.len() - 2];

            if !valid_sids.contains(&sid.to_string()) {
                eprintln!(
                    "{} User '{}' uses ShortID '{}' which is missing from reality.short_id list.",
                    "[WARN]".yellow(),
                    user.name,
                    sid
                );
                warnings += 1;
            }

            // Check UUID format
            if uuid::Uuid::parse_str(&user.uuid).is_err() {
                eprintln!(
                    "{} User '{}' has invalid UUID: {}",
                    "[WARN]".yellow(),
                    user.name,
                    user.uuid
                );
                warnings += 1;
            }
        }
    } else {
        eprintln!("{} No inbounds defined.", "[WARN]".yellow());
        warnings += 1;
    }

    if warnings == 0 {
        eprintln!("{} Internal consistency check passed.", "[INFO]".green());
    } else {
        eprintln!(
            "{} Consistency check finished with {} warning(s).",
            "[WARN]".yellow(),
            warnings
        );
    }

    Ok(())
}
