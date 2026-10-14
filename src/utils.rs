use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use colored::*;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::Command;
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};

#[cfg(test)]
use std::sync::{Mutex, OnceLock};

#[cfg(test)]
pub static TEST_PATH_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

use crate::config::SingBoxConfig;
use crate::paths::Paths;

pub fn check_overlay(paths: &Paths) -> Result<()> {
    if paths.is_system_root() {
        require_root()?;
        let mount_target = paths
            .config
            .parent()
            .context("Config has no parent directory")?;
        if !check_overlay_mount(mount_target)? {
            eprintln!("{}", "[WARN] OverlayFS is NOT mounted.".yellow());
            eprintln!("{}", "[INFO] Attempting to auto-mount...".green());
            let _ = Command::new("systemctl")
                .args(["start", "mimic-node-mount.service"])
                .status();
            if !check_overlay_mount(mount_target)? {
                let _ = Command::new("/usr/bin/mimic-mount").arg("start").status();
            }
            if !check_overlay_mount(mount_target)? {
                return Err(anyhow!(
                    "Failed to mount OverlayFS at {}. Run 'sudo systemctl start mimic-node-mount'.",
                    mount_target.display()
                ));
            }
            eprintln!("{}", "[INFO] OverlayFS mounted successfully.".green());
        }
    }
    Ok(())
}

fn require_root() -> Result<()> {
    let status = fs::read_to_string("/proc/self/status")
        .context("Cannot determine effective UID for a system configuration change")?;
    if status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .and_then(|line| line.split_whitespace().nth(2))
        != Some("0")
    {
        return Err(anyhow!(
            "Changing the system configuration requires root; run this command with sudo"
        ));
    }
    Ok(())
}

#[derive(serde::Deserialize)]
struct MountTable {
    filesystems: Vec<MountInfo>,
}

#[derive(serde::Deserialize)]
struct MountInfo {
    target: String,
    fstype: String,
    source: String,
    options: String,
}

fn is_owned_overlay(mount: &MountInfo, target: &Path) -> bool {
    let options: Vec<_> = mount.options.split(',').collect();
    Path::new(&mount.target) == target
        && mount.fstype == "overlay"
        && matches!(mount.source.as_str(), "mimic-node" | "overlay")
        && options.contains(&"upperdir=/var/lib/mimic-node/upper")
        && options.contains(&"workdir=/var/lib/mimic-node/work")
}

fn check_overlay_mount(path: &Path) -> Result<bool> {
    let output = Command::new("findmnt")
        .args([
            "--json",
            "--output",
            "TARGET,FSTYPE,SOURCE,OPTIONS",
            "--mountpoint",
        ])
        .arg(path)
        .output()
        .context("Cannot inspect OverlayFS mount; install util-linux (findmnt)")?;
    if output.status.code() == Some(1) && output.stdout.is_empty() {
        return Ok(false);
    }
    if !output.status.success() {
        return Err(anyhow!(
            "Cannot inspect mount at {}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let mounts: MountTable = serde_json::from_slice(&output.stdout)
        .context("findmnt returned an invalid mount description")?;
    if mounts.filesystems.len() == 1 && is_owned_overlay(&mounts.filesystems[0], path) {
        return Ok(true);
    }
    Err(anyhow!(
        "Refusing to use an unrelated mount at {}; expected Mimic-Node OverlayFS with its own upper/work directories",
        path.display()
    ))
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
    write_private_file(path, content.as_bytes())
}

/// Replace a secret-bearing file atomically, without following a destination
/// symlink or briefly exposing its contents with permissive permissions.
pub fn write_private_file(path: &Path, content: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let temporary = parent.join(format!(".mimictl-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .with_context(|| format!("Cannot create temporary file in {}", parent.display()))?;
        file.write_all(content)?;
        file.sync_all()?;
        fs::rename(&temporary, path).with_context(|| {
            format!(
                "Cannot replace {}. If protected, run 'mimictl protect --unprotect' first",
                path.display()
            )
        })?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub fn generate_keypair() -> Result<(String, String)> {
    // Try sing-box first (respect SING_BOX_BIN env override)
    let sing_box = std::env::var("SING_BOX_BIN").unwrap_or_else(|_| "sing-box".to_string());
    if let Ok(output) = Command::new(&sing_box)
        .args(["generate", "reality-keypair"])
        .output()
        && output.status.success()
        && let Ok(out_str) = String::from_utf8(output.stdout)
    {
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
        if valid_keypair(&priv_key, &pub_key) {
            return Ok((priv_key, pub_key));
        }
    }

    // rand's thread RNG is cryptographically secure. Derive the public key from
    // the same X25519 scalar; two independently random strings are not a pair.
    Ok(native_keypair())
}

fn native_keypair() -> (String, String) {
    let mut private: [u8; 32] = rand::random();
    private[0] &= 248;
    private[31] &= 127;
    private[31] |= 64;
    let public = x25519(private, X25519_BASEPOINT_BYTES);
    (
        URL_SAFE_NO_PAD.encode(private),
        URL_SAFE_NO_PAD.encode(public),
    )
}

fn valid_keypair(private: &str, public: &str) -> bool {
    let Ok(private) = URL_SAFE_NO_PAD.decode(private) else {
        return false;
    };
    let Ok(private): Result<[u8; 32], _> = private.try_into() else {
        return false;
    };
    URL_SAFE_NO_PAD
        .decode(public)
        .is_ok_and(|public| public == x25519(private, X25519_BASEPOINT_BYTES))
}

fn validate_staged_pubkey(config: &SingBoxConfig, public: &str) -> Result<()> {
    let index = crate::commands::user::managed_vless_inbound_index(config)?;
    let valid = config.inbounds[index]
        .tls
        .as_ref()
        .and_then(|tls| tls.reality.as_ref())
        .is_some_and(|reality| valid_keypair(&reality.private_key, public.trim()));
    if !valid {
        return Err(anyhow!(
            "Staged PUBKEY does not match the VLESS Reality private key in config.new"
        ));
    }
    Ok(())
}

fn derive_managed_pubkey(config: &SingBoxConfig) -> Result<Option<String>> {
    let has_reality = config.inbounds.iter().any(|inbound| {
        inbound.protocol_type == "vless"
            && inbound.tls.as_ref().is_some_and(|tls| {
                tls.enabled && tls.reality.as_ref().is_some_and(|reality| reality.enabled)
            })
    });
    if !has_reality {
        return Ok(None);
    }
    let index = crate::commands::user::managed_vless_inbound_index(config)?;
    let private = &config.inbounds[index]
        .tls
        .as_ref()
        .and_then(|tls| tls.reality.as_ref())
        .context("Managed VLESS inbound has no Reality configuration")?
        .private_key;
    let private = URL_SAFE_NO_PAD
        .decode(private)
        .context("Cannot derive PUBKEY: Reality private key is not URL-safe Base64")?;
    let private: [u8; 32] = private
        .try_into()
        .map_err(|_| anyhow!("Cannot derive PUBKEY: Reality private key must contain 32 bytes"))?;
    Ok(Some(
        URL_SAFE_NO_PAD.encode(x25519(private, X25519_BASEPOINT_BYTES)),
    ))
}

pub fn generate_uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub fn generate_sid() -> String {
    let rand_bytes: [u8; 8] = rand::random();
    hex::encode(rand_bytes)
}

pub fn apply_staging(paths: &Paths) -> Result<()> {
    if !paths.staging.exists() {
        if paths.staging_pubkey.exists() {
            return Err(anyhow!(
                "PUBKEY.new exists without config.new; refusing to apply an unpaired key"
            ));
        }
        eprintln!("{} No staged changes.", "[INFO]".green());
        return Ok(());
    }
    if paths.is_system_root() {
        require_root()?;
    }
    let staged_content = fs::read(&paths.staging)?;
    let config: SingBoxConfig = serde_json::from_slice(&staged_content)
        .context("Failed to parse staged configuration JSON")?;
    let staged_pubkey = if paths.staging_pubkey.exists() {
        let public = fs::read_to_string(&paths.staging_pubkey)?;
        validate_staged_pubkey(&config, &public)?;
        Some(public)
    } else {
        None
    };
    // The private key in the staged configuration is authoritative. Discarding
    // PUBKEY.new must not leave an old active public key paired with a new
    // private key after a successful apply.
    let effective_pubkey = match &staged_pubkey {
        Some(public) => Some(public.trim().to_string()),
        None => derive_managed_pubkey(&config)?,
    };

    eprintln!("{} Validating staged configuration...", "[INFO]".green());
    let sing_box = std::env::var("SING_BOX_BIN").unwrap_or_else(|_| "sing-box".to_string());
    // Validate the exact bytes that will be installed, in the same directory so
    // relative paths in sing-box configuration keep their meaning.
    let validation_path = paths
        .staging
        .with_file_name(format!(".mimictl-check-{}.json", uuid::Uuid::new_v4()));
    write_private_file(&validation_path, &staged_content)?;
    let validation_result = Command::new(&sing_box)
        .args(["check", "-c"])
        .arg(&validation_path)
        .status()
        .with_context(|| format!("Cannot run {sing_box} check; staged files were preserved"));
    fs::remove_file(&validation_path)
        .context("Cannot remove temporary validation configuration")?;
    let status = validation_result?;
    if !status.success() {
        return Err(anyhow!(
            "'sing-box check' failed ({status}); staged files were preserved"
        ));
    }

    let old_pubkey = if effective_pubkey.is_some() {
        match fs::read(&paths.pubkey) {
            Ok(content) => Some(content),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        }
    } else {
        None
    };
    if let Some(public) = &effective_pubkey {
        write_private_file(&paths.pubkey, public.as_bytes())?;
    }
    // Keep staging until the installation and service action have succeeded so
    // a failed reload can be retried instead of being reported as a no-op.
    if let Err(error) = write_private_file(&paths.config, &staged_content) {
        if effective_pubkey.is_some() {
            let rollback = match old_pubkey {
                Some(content) => write_private_file(&paths.pubkey, &content),
                None => fs::remove_file(&paths.pubkey).map_err(Into::into),
            };
            rollback.context("Failed to restore PUBKEY after configuration installation failed")?;
        }
        return Err(error);
    }
    if paths.is_system_root() {
        let status = Command::new("systemctl")
            .args(["try-reload-or-restart", "sing-box.service"])
            .status()
            .context(
                "Configuration installed, but systemctl could not run; staging was preserved",
            )?;
        if !status.success() {
            return Err(anyhow!(
                "Configuration installed, but sing-box reload failed ({status}); staging was preserved for retry"
            ));
        }
    }
    // Preserve any new staging produced concurrently while validation/reload
    // ran, rather than silently discarding someone else's next update.
    if fs::read(&paths.staging)? == staged_content {
        fs::remove_file(&paths.staging)?;
    }
    if let Some(public) = staged_pubkey
        && fs::read_to_string(&paths.staging_pubkey)? == public
    {
        fs::remove_file(&paths.staging_pubkey)?;
    }
    eprintln!(
        "{} Applied staged configuration to {}",
        "[INFO]".green(),
        paths.config.display()
    );
    Ok(())
}

/// Set immutable attribute on a file (chattr +i)
/// This prevents deletion, renaming, or modification even by root
pub fn protect_file(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    let output = Command::new("chattr").arg("+i").arg(path).output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "Failed to set immutable on {}: {}",
            path.display(),
            stderr.trim()
        ));
    } else {
        eprintln!(
            "{} Protected {:?} with immutable attribute",
            "[INFO]".green(),
            path
        );
    }
    Ok(())
}

/// Remove immutable attribute from a file (chattr -i)
pub fn unprotect_file(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    let output = Command::new("chattr").arg("-i").arg(path).output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "Failed to remove immutable from {}: {}",
            path.display(),
            stderr.trim()
        ));
    }
    Ok(())
}

/// Protect all important mimic-node files with immutable attribute
pub fn protect_all(paths: &Paths) -> Result<()> {
    eprintln!(
        "{}",
        "[INFO] Protecting important files with immutable attribute...".green()
    );
    eprintln!(
        "{}",
        "    This prevents accidental deletion or modification".dimmed()
    );
    eprintln!(
        "{}",
        "    To modify, use 'mimictl' commands or manually: sudo chattr -i <file>".dimmed()
    );

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_identity_rejects_unrelated_mounts_and_ancestor_targets() {
        let target = Path::new("/etc/sing-box");
        let mut mount: MountInfo = serde_json::from_value(serde_json::json!({
            "target": "/etc/sing-box", "fstype": "overlay", "source": "mimic-node",
            "options": "rw,lowerdir=/run/mimic-node/lower:/usr/share/mimic-node/default,upperdir=/var/lib/mimic-node/upper,workdir=/var/lib/mimic-node/work"
        })).unwrap();
        assert!(is_owned_overlay(&mount, target));
        mount.source = "overlay".into();
        assert!(is_owned_overlay(&mount, target));
        mount.target = "/".into();
        assert!(!is_owned_overlay(&mount, target));
        mount.target = target.display().to_string();
        mount.source = "another-service".into();
        assert!(!is_owned_overlay(&mount, target));
        mount.source = "mimic-node".into();
        mount.options = "rw,upperdir=/var/lib/other/upper,workdir=/var/lib/mimic-node/work".into();
        assert!(!is_owned_overlay(&mount, target));
        mount.options = "rw,upperdir=/var/lib/mimic-node/upper,workdir=/var/lib/other/work".into();
        assert!(!is_owned_overlay(&mount, target));
        mount.options =
            "rw,upperdir=/var/lib/mimic-node/upper-extra,workdir=/var/lib/mimic-node/work".into();
        assert!(!is_owned_overlay(&mount, target));
        mount.fstype = "tmpfs".into();
        assert!(!is_owned_overlay(&mount, target));
    }

    #[test]
    fn staged_pubkey_validation_uses_the_unique_managed_reality_inbound() {
        let (private, public) = native_keypair();
        let managed = serde_json::json!({"type": "vless", "tls": {
            "enabled": true, "reality": {"enabled": true, "private_key": private}
        }});
        let mut config: SingBoxConfig = serde_json::from_value(serde_json::json!({
            "inbounds": [{"type": "vless"}, {"type": "hysteria2"}, managed]
        }))
        .unwrap();
        assert!(validate_staged_pubkey(&config, &public).is_ok());
        assert!(validate_staged_pubkey(&config, "unrelated-key").is_err());
        config.inbounds.push(config.inbounds[2].clone());
        assert!(
            validate_staged_pubkey(&config, &public)
                .unwrap_err()
                .to_string()
                .contains("ambiguous")
        );
        config.inbounds.truncate(2);
        assert!(
            validate_staged_pubkey(&config, &public)
                .unwrap_err()
                .to_string()
                .contains("No VLESS inbound")
        );
    }

    #[test]
    fn native_reality_keys_are_url_safe_and_cryptographically_paired() {
        let (private, public) = native_keypair();
        assert_eq!(private.len(), 43);
        assert_eq!(public.len(), 43);
        assert!(!private.contains(['=', '+', '/']));
        assert!(!public.contains(['=', '+', '/']));
        assert!(valid_keypair(&private, &public));

        // Exercise the actual X25519 agreement, independently of the string
        // validator: each participant must compute the same nonzero secret.
        let (peer_private, peer_public) = native_keypair();
        let decode =
            |key: &str| -> [u8; 32] { URL_SAFE_NO_PAD.decode(key).unwrap().try_into().unwrap() };
        let shared = x25519(decode(&private), decode(&peer_public));
        assert_eq!(shared, x25519(decode(&peer_private), decode(&public)));
        assert_ne!(shared, [0; 32]);
        assert!(!valid_keypair(&private, &peer_public));
        assert!(!valid_keypair("malformed", &public));
    }

    #[test]
    fn secret_writes_are_private_and_do_not_follow_destination_symlinks() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target/test-roots")
            .join(format!("private-write-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let outside = root.join("untouched");
        let destination = root.join("config.new");
        fs::write(&outside, "original").unwrap();
        std::os::unix::fs::symlink(&outside, &destination).unwrap();
        write_private_file(&destination, b"secret").unwrap();
        assert_eq!(fs::read_to_string(&outside).unwrap(), "original");
        assert_eq!(fs::read_to_string(&destination).unwrap(), "secret");
        assert!(
            !fs::symlink_metadata(&destination)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
            0o600
        );
        write_private_file(&destination, b"replacement").unwrap();
        assert_eq!(fs::read_to_string(&destination).unwrap(), "replacement");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 2);
        fs::remove_dir_all(&root).unwrap();
    }
}
