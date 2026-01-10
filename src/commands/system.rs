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
                    if let Some(tls) = inbound.tls.as_mut()
                        && let Some(reality) = tls.reality.as_mut()
                    {
                        reality.short_id.push(sid);
                        reality.short_id.sort();
                        reality.short_id.dedup();
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

    // Delegate entirely to sing-box's native check.
    // If sing-box accepts the configuration, we consider it valid.
    // Allow overriding which binary to use via the SING_BOX_BIN env var (useful for tests).
    let sing_box = std::env::var("SING_BOX_BIN").unwrap_or_else(|_| "sing-box".to_string());
    eprintln!("{} Running '{} check'...", "[INFO]".green(), sing_box);
    let status = Command::new(&sing_box)
        .args(["check", "-c", input_path.to_str().unwrap()])
        .status();

    match status {
        Ok(s) if s.success() => {
            eprintln!("{} 'sing-box check' passed.", "[INFO]".green());
            Ok(())
        }
        Ok(s) => Err(anyhow!(
            "'sing-box check' failed with exit code {}.",
            s.code().unwrap_or(-1)
        )),
        Err(e) => Err(anyhow!("Failed to execute 'sing-box': {}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::Paths;
    use std::env;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use uuid::Uuid;

    // Use the global test PATH lock defined in `utils` (under cfg(test)) to serialize tests
    // that modify PATH. This avoids having multiple per-module locks which don't prevent
    // races across test modules.

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

        if let Err(e) = fs::remove_dir_all(&tmp) {
            eprintln!("[WARN] Failed to remove test directory {:?}: {}", tmp, e);
        }
    }

    #[test]
    fn test_discard_unknown_item_returns_error() {
        let tmp = setup_tmp();
        let paths = build_paths(tmp.clone());

        let res = discard(&paths, vec!["unknown".to_string()], true);
        assert!(res.is_err());

        if let Err(e) = fs::remove_dir_all(&tmp) {
            eprintln!("[WARN] Failed to remove test directory {:?}: {}", tmp, e);
        }
    }

    #[test]
    fn test_discard_no_staged_items_ok() {
        let tmp = setup_tmp();
        let paths = build_paths(tmp.clone());

        let res = discard(&paths, Vec::new(), true);
        assert!(res.is_ok());

        if let Err(e) = fs::remove_dir_all(&tmp) {
            eprintln!("[WARN] Failed to remove test directory {:?}: {}", tmp, e);
        }
    }

    #[test]
    fn test_check_succeeds_when_singbox_returns_zero() {
        let tmp = setup_tmp();
        let paths = build_paths(tmp.clone());

        // create a config file so get_input_config_path() points to it
        fs::write(&paths.config, "{}").expect("write config");

        // create fake bin dir with sing-box script that exits 0
        let bin_dir = tmp.join("fakebin");
        fs::create_dir_all(&bin_dir).unwrap();
        let sing_box = bin_dir.join("sing-box");
        fs::write(&sing_box, "#!/bin/sh\nexit 0\n").unwrap();
        let mut perms = fs::metadata(&sing_box).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&sing_box, perms).unwrap();

        // Sanity check: ensure the fake sing-box script exists, is executable, and exits 0
        assert!(
            sing_box.exists(),
            "sing-box script not created: {:?}",
            sing_box
        );
        let status = std::process::Command::new(&sing_box)
            .status()
            .expect("failed to execute fake sing-box");
        assert!(
            status.success(),
            "fake sing-box did not exit 0 as expected: {:?}",
            status
        );

        // Use SING_BOX_BIN env (guarded to avoid races with other tests that also set it)
        let sing_box_path = sing_box.to_str().unwrap().to_string();
        // Acquire the global test PATH lock from utils to avoid races with other tests that also set PATH
        let _guard = crate::utils::TEST_PATH_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap();
        let old_sing = env::var("SING_BOX_BIN").ok();
        unsafe {
            std::env::set_var("SING_BOX_BIN", &sing_box_path);
        }

        // Call check
        let res = check(&paths);
        assert!(res.is_ok(), "check should succeed when sing-box returns 0");

        // Restore SING_BOX_BIN env and cleanup
        if let Some(v) = old_sing {
            unsafe {
                std::env::set_var("SING_BOX_BIN", v);
            }
        } else {
            unsafe {
                std::env::remove_var("SING_BOX_BIN");
            }
        }
        drop(_guard);
        if let Err(e) = fs::remove_dir_all(&tmp) {
            eprintln!("[WARN] Failed to remove test directory {:?}: {}", tmp, e);
        }
    }

    #[test]
    fn test_check_fails_when_singbox_returns_nonzero() {
        let tmp = setup_tmp();
        let paths = build_paths(tmp.clone());

        fs::write(&paths.config, "{}").expect("write config");

        let bin_dir = tmp.join("fakebin");
        fs::create_dir_all(&bin_dir).unwrap();
        let sing_box = bin_dir.join("sing-box");
        fs::write(&sing_box, "#!/bin/sh\nexit 2\n").unwrap();
        let mut perms = fs::metadata(&sing_box).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&sing_box, perms).unwrap();

        // Sanity check: ensure the fake sing-box script exists, is executable, and exits non-zero
        assert!(
            sing_box.exists(),
            "sing-box script not created: {:?}",
            sing_box
        );
        let status = std::process::Command::new(&sing_box)
            .status()
            .expect("failed to execute fake sing-box");
        assert!(
            !status.success(),
            "fake sing-box unexpectedly exited 0; status: {:?}",
            status
        );

        // Acquire the global test PATH lock from utils to avoid races with other tests that also set PATH
        let _guard = crate::utils::TEST_PATH_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap();
        let old_sing = std::env::var("SING_BOX_BIN").ok();
        unsafe {
            std::env::set_var("SING_BOX_BIN", sing_box.to_str().unwrap());
        }

        let res = check(&paths);
        assert!(
            res.is_err(),
            "check should fail when sing-box exits non-zero"
        );

        // Restore SING_BOX_BIN env and cleanup
        if let Some(v) = old_sing {
            unsafe {
                std::env::set_var("SING_BOX_BIN", v);
            }
        } else {
            unsafe {
                std::env::remove_var("SING_BOX_BIN");
            }
        }
        drop(_guard);
        if let Err(e) = fs::remove_dir_all(&tmp) {
            eprintln!("[WARN] Failed to remove test directory {:?}: {}", tmp, e);
        }
    }
}
