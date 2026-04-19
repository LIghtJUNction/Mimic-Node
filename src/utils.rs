use anyhow::{Context, Result, anyhow};
use colored::*;
use std::fs;
use std::path::Path;
use std::process::Command;

#[cfg(test)]
use std::sync::{Mutex, OnceLock};

#[cfg(test)]
pub static TEST_PATH_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

use crate::config::SingBoxConfig;
use crate::paths::Paths;

pub fn check_overlay(paths: &Paths) -> Result<()> {
    if paths.root == Path::new("/") {
        // We are operating on the system root
        let mount_target = "/etc/sing-box";

        // Check if mounted
        let is_mounted = check_mountpoint(mount_target);

        if !is_mounted {
            eprintln!("{}", "[WARN] OverlayFS is NOT mounted.".yellow());
            eprintln!("{}", "[INFO] Attempting to auto-mount...".green());

            // Try systemctl
            let _ = Command::new("systemctl")
                .args(["start", "mimic-node-mount.service"])
                .status();

            // Try direct script
            if !check_mountpoint(mount_target) {
                let _ = Command::new("/usr/bin/mimic-mount").arg("start").status();
            }

            if !check_mountpoint(mount_target) {
                return Err(anyhow!(
                    "CRITICAL: Failed to mount OverlayFS at {}. Please run 'sudo systemctl start mimic-node-mount'.",
                    mount_target
                ));
            }
            eprintln!("{}", "[INFO] OverlayFS mounted successfully.".green());
        }
    }
    Ok(())
}

pub fn check_mountpoint(path: &str) -> bool {
    Command::new("mountpoint")
        .arg("-q")
        .arg(path)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn load_config(path: &Path) -> Result<SingBoxConfig> {
    let content =
        fs::read_to_string(path).with_context(|| format!("Failed to read config: {:?}", path))?;
    let config: SingBoxConfig =
        serde_json::from_str(&content).context("Failed to parse config JSON")?;
    Ok(config)
}

pub fn save_config(path: &Path, config: &SingBoxConfig) -> Result<()> {
    let content = serde_json::to_string_pretty(config)?;
    fs::write(path, content)?;
    Ok(())
}

pub fn generate_keypair() -> Result<(String, String)> {
    // Try sing-box first (respect SING_BOX_BIN env override)
    let sing_box = std::env::var("SING_BOX_BIN").unwrap_or_else(|_| "sing-box".to_string());
    if let Ok(output) = Command::new(&sing_box)
        .args(["generate", "reality-keypair"])
        .output()
        && output.status.success()
    {
        let out_str = String::from_utf8(output.stdout)?;
        // Output format:
        // PrivateKey: ...
        // PublicKey: ...
        let mut priv_key = String::new();
        let mut pub_key = String::new();

        for line in out_str.lines() {
            if let Some(val) = line.strip_prefix("PrivateKey: ") {
                priv_key = val.trim().to_string();
            } else if let Some(val) = line.strip_prefix("PublicKey: ") {
                pub_key = val.trim().to_string();
            }
        }
        if !priv_key.is_empty() && !pub_key.is_empty() {
            return Ok((priv_key, pub_key));
        }
    }

    // Fallback: openssl (Warning)
    eprintln!(
        "{}",
        "[WARN] sing-box not available/failed; generating pseudo keypair with openssl.".yellow()
    );

    let gen_key = |bytes: usize| -> Result<String> {
        let output = Command::new("openssl")
            .args(["rand", "-base64", &bytes.to_string()])
            .output()?;
        let s = String::from_utf8(output.stdout)?;
        Ok(s.trim().to_string())
    };

    Ok((gen_key(32)?, gen_key(32)?))
}

pub fn generate_uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub fn generate_sid() -> String {
    let rand_bytes: [u8; 8] = rand::random();
    hex::encode(rand_bytes)
}

pub fn apply_staging(paths: &Paths) -> Result<()> {
    if paths.staging.exists() {
        // Validate JSON structure
        let _ = load_config(&paths.staging)?;

        // Validate using sing-box check (respect SING_BOX_BIN env override)
        eprintln!("{} Validating staged configuration...", "[INFO]".green());
        let sing_box = std::env::var("SING_BOX_BIN").unwrap_or_else(|_| "sing-box".to_string());
        let check_status = Command::new(&sing_box)
            .args(["check", "-c", paths.staging.to_str().unwrap()])
            .status();

        match check_status {
            Ok(status) if status.success() => {
                eprintln!("{} Configuration valid.", "[INFO]".green());
            }
            _ => {
                return Err(anyhow!(
                    "Staged configuration is invalid. 'sing-box check' failed. Aborting apply."
                ));
            }
        }

        // Remove immutable from old config before replacing
        let _ = remove_immutable(&paths.config);

        fs::rename(&paths.staging, &paths.config)?;
        eprintln!(
            "{} Applied staged config -> {:?}",
            "[INFO]".green(),
            paths.config
        );

        // Protect config with immutable attribute
        protect_file(&paths.config)?;
    }

    if paths.staging_pubkey.exists() {
        // Remove immutable from old pubkey before replacing
        let _ = remove_immutable(&paths.pubkey);

        fs::rename(&paths.staging_pubkey, &paths.pubkey)?;
        eprintln!(
            "{} Applied staged PUBKEY -> {:?}",
            "[INFO]".green(),
            paths.pubkey
        );

        // Protect pubkey with immutable attribute
        protect_file(&paths.pubkey)?;
    }

    // Reload sing-box
    let _ = Command::new("systemctl")
        .args(["try-reload-or-restart", "sing-box"])
        .status();

    Ok(())
}

/// Set immutable attribute on a file (chattr +i)
/// This prevents deletion, renaming, or modification even by root
pub fn protect_file(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    let output = Command::new("chattr")
        .args(["+i", path.to_str().unwrap()])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("{} Failed to set immutable on {:?}: {}", "[WARN]".yellow(), path, stderr);
        // Non-fatal - file might be on read-only filesystem
    } else {
        eprintln!("{} Protected {:?} with immutable attribute", "[INFO]".green(), path);
    }
    Ok(())
}

/// Remove immutable attribute from a file (chattr -i)
/// Alias for unprotect_file for semantic clarity in code
pub fn remove_immutable(path: &Path) -> Result<()> {
    unprotect_file(path)
}

/// Remove immutable attribute from a file (chattr -i)
pub fn unprotect_file(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    let output = Command::new("chattr")
        .args(["-i", path.to_str().unwrap()])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("{} Failed to remove immutable from {:?}: {}", "[WARN]".yellow(), path, stderr);
    }
    Ok(())
}

/// Protect all important mimic-node files with immutable attribute
pub fn protect_all(paths: &Paths) -> Result<()> {
    eprintln!("{}", "[INFO] Protecting important files with immutable attribute...".green());
    eprintln!("{}", "    This prevents accidental deletion or modification".dimmed());
    eprintln!("{}", "    To modify, use 'mimictl' commands or manually: sudo chattr -i <file>".dimmed());

    protect_file(&paths.config)?;
    protect_file(&paths.pubkey)?;

    Ok(())
}

/// Remove protection from all important files before modification
pub fn unprotect_all(paths: &Paths) -> Result<()> {
    unprotect_file(&paths.config)?;
    unprotect_file(&paths.pubkey)?;
    Ok(())
}
