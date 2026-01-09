use anyhow::{Result, anyhow};
use colored::*;
use std::fs;
use std::process::Command;

use crate::paths::Paths;
use crate::utils::{apply_staging, load_config, save_config};

pub fn apply(paths: &Paths) -> Result<()> {
    apply_staging(paths)
}

/// Discard staged changes (staging files like `config.new` and `PUBKEY.new`).
///
/// Usage:
/// - `mimictl discard`                 : interactive prompt, removes both staging files if present
/// - `mimictl discard -i config`       : remove only `config.new`
/// - `mimictl discard -i pubkey`       : remove only `PUBKEY.new`
/// - `mimictl discard -i config -f`    : force remove without confirmation
///
/// Arguments:
/// - `items`: optional list of items to discard: "config" and/or "pubkey".
///   If empty, both staging files will be removed (if present).
/// - `force`: if true, skip interactive confirmation.
///
/// This operation deletes the staging files and cannot be undone.
pub fn discard(paths: &Paths, items: Vec<String>, force: bool) -> Result<()> {
    use std::collections::HashSet;

    // Resolve which staging files to operate on
    let mut targets: Vec<std::path::PathBuf> = Vec::new();

    if items.is_empty() {
        targets.push(paths.staging.clone());
        targets.push(paths.staging_pubkey.clone());
    } else {
        for it in items {
            match it.as_str() {
                "config" | "configuration" | "conf" | "c" => {
                    targets.push(paths.staging.clone());
                }
                "pubkey" | "key" | "pub" | "p" => {
                    targets.push(paths.staging_pubkey.clone());
                }
                other => {
                    return Err(anyhow!("Unknown discard item: {}", other));
                }
            }
        }
    }

    // Deduplicate targets and keep only existing files
    let mut seen = HashSet::new();
    let mut existing: Vec<std::path::PathBuf> = Vec::new();
    for p in targets.into_iter() {
        if !seen.insert(p.clone()) {
            continue;
        }
        if p.exists() {
            existing.push(p);
        }
    }

    if existing.is_empty() {
        eprintln!("{} No staged items found to discard.", "[INFO]".green());
        return Ok(());
    }

    eprintln!(
        "{} The following staged items will be removed:",
        "[WARN]".yellow()
    );
    for p in &existing {
        eprintln!("  - {:?}", p);
    }

    // Confirm unless forced
    if !force {
        use std::io::Write;
        eprint!("{} Confirm discard? [y/N] ", "[WARN]".yellow());
        std::io::stdout().flush().ok();

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let reply = input.trim().to_lowercase();
        if reply != "y" && reply != "yes" {
            eprintln!("{} Discard aborted.", "[INFO]".green());
            return Ok(());
        }
    }

    // Remove files (fail on first error)
    for p in &existing {
        match fs::remove_file(p) {
            Ok(_) => {
                eprintln!("{} Removed staged file: {:?}", "[INFO]".green(), p);
            }
            Err(e) => {
                return Err(anyhow!("Failed to remove staged file {:?}: {}", p, e));
            }
        }
    }

    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::Paths;
    use std::fs;
    use std::path::PathBuf;
    use uuid::Uuid;

    fn setup_tmp() -> PathBuf {
        let base = std::env::temp_dir();
        let dir = base.join(format!("mimic_node_test_{}", Uuid::new_v4()));
        let etc = dir.join("etc").join("sing-box");
        let usr = dir
            .join("usr")
            .join("share")
            .join("mimic-node")
            .join("default");
        fs::create_dir_all(&etc).expect("create tmp etc dir");
        fs::create_dir_all(&usr).expect("create tmp usr share default");
        dir
    }

    fn build_paths(root: PathBuf) -> Paths {
        let etc_singbox = root.join("etc/sing-box");
        let usr_share = root.join("usr/share/mimic-node");
        Paths {
            root: root.clone(),
            config: etc_singbox.join("config.json"),
            staging: etc_singbox.join("config.new"),
            pubkey: etc_singbox.join("PUBKEY"),
            staging_pubkey: etc_singbox.join("PUBKEY.new"),
            sni_list: usr_share.join("sni.txt"),
            default_config: usr_share.join("default/config.json"),
        }
    }

    #[test]
    fn test_discard_force_removes_files() {
        let tmp = setup_tmp();
        let paths = build_paths(tmp.clone());

        // create files
        fs::write(&paths.staging, "{}").expect("write staging");
        fs::write(&paths.staging_pubkey, "pubkey").expect("write pubkey");

        // ensure files exist
        assert!(paths.staging.exists());
        assert!(paths.staging_pubkey.exists());

        // call discard
        discard(&paths, Vec::new(), true).expect("discard should succeed");

        assert!(!paths.staging.exists(), "staging should be removed");
        assert!(
            !paths.staging_pubkey.exists(),
            "staging_pubkey should be removed"
        );

        fs::remove_dir_all(tmp).unwrap();
    }

    #[test]
    fn test_discard_unknown_item_returns_error() {
        let tmp = setup_tmp();
        let paths = build_paths(tmp.clone());

        let res = discard(&paths, vec!["unknown".to_string()], true);
        assert!(res.is_err());

        fs::remove_dir_all(tmp).unwrap();
    }

    #[test]
    fn test_discard_no_staged_items_ok() {
        let tmp = setup_tmp();
        let paths = build_paths(tmp.clone());

        let res = discard(&paths, Vec::new(), true);
        assert!(res.is_ok());

        fs::remove_dir_all(tmp).unwrap();
    }
}
