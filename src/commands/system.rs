use anyhow::{Context, Result, anyhow};
use colored::*;
use std::fs;
use std::io::{BufRead, Write};
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

    let mut new_config = load_config(&paths.default_config)?;

    // Preserve users
    if !keep_users_emails.is_empty() {
        let current_config = load_config(paths.get_input_config_path())?;
        let current_index = crate::commands::user::managed_vless_inbound_index(&current_config)
            .context("Cannot preserve users from current configuration")?;
        let default_index = crate::commands::user::managed_vless_inbound_index(&new_config)
            .context("Cannot preserve users in default configuration")?;
        let source = &current_config.inbounds[current_index];
        let mut kept_users = Vec::new();
        let mut kept_sids = Vec::new();
        for email in &keep_users_emails {
            let users: Vec<_> = source
                .users
                .iter()
                .filter(|user| {
                    user.get("name")
                        .and_then(|value| value.as_str())
                        .is_some_and(|name| name.starts_with(&format!("{}:", email)))
                })
                .collect();
            if users.is_empty() {
                eprintln!(
                    "{} User '{}' not found in current config, skipping.",
                    "[WARN]".yellow(),
                    email
                );
            }
            for user in users {
                if kept_users.contains(user) {
                    continue;
                }
                let name = user
                    .get("name")
                    .and_then(|value| value.as_str())
                    .unwrap_or("");
                let mut parts = name.rsplitn(3, ':');
                let level = parts.next().unwrap_or("");
                let sid = parts.next().unwrap_or("");
                if parts.next().is_none() || level.is_empty() || sid.is_empty() {
                    return Err(anyhow!("Cannot preserve user with invalid name: {}", name));
                }
                eprintln!("{} Preserving user: {}", "[INFO]".green(), email);
                kept_users.push(user.clone());
                kept_sids.push(sid.to_string());
            }
        }

        if kept_users.is_empty() {
            return Err(anyhow!(
                "None of the requested users were found; reset cancelled"
            ));
        }
        let target = &mut new_config.inbounds[default_index];
        target.users = kept_users;
        // Existing client links depend on the Reality key and TLS identity. Keep
        // them together instead of leaving an empty key from the default template.
        target.tls = source.tls.clone();
        if let Some(reality) = target.tls.as_mut().and_then(|tls| tls.reality.as_mut()) {
            kept_sids.sort();
            kept_sids.dedup();
            reality.short_id = kept_sids;
        }
    }

    save_config(&paths.staging, &new_config)?;

    eprintln!(
        "{} Staged global reset. Run 'mimictl apply' to activate.",
        "[INFO]".green()
    );

    Ok(())
}

/// Represents a single difference between two JSON values
#[derive(Debug, Clone)]
pub enum DiffEntry {
    Added {
        path: String,
        value: serde_json::Value,
    },
    Removed {
        path: String,
        value: serde_json::Value,
    },
    Modified {
        path: String,
        old_value: serde_json::Value,
        new_value: serde_json::Value,
    },
}

/// JSON Pointer paths also address keys containing dots, brackets, slashes or tildes.
fn child_pointer(path: &str, key: &str) -> String {
    format!("{}/{}", path, key.replace('~', "~0").replace('/', "~1"))
}

/// Recursively collect differences, with array removals in descending index order.
fn collect_diffs(
    path: &str,
    old_val: &serde_json::Value,
    new_val: &serde_json::Value,
    diffs: &mut Vec<DiffEntry>,
) {
    use serde_json::Value;
    match (old_val, new_val) {
        (Value::Object(old_map), Value::Object(new_map)) => {
            for (key, new_value) in new_map {
                let path = child_pointer(path, key);
                if let Some(old_value) = old_map.get(key) {
                    collect_diffs(&path, old_value, new_value, diffs);
                } else {
                    diffs.push(DiffEntry::Added {
                        path,
                        value: new_value.clone(),
                    });
                }
            }
            for (key, old_value) in old_map {
                if !new_map.contains_key(key) {
                    diffs.push(DiffEntry::Removed {
                        path: child_pointer(path, key),
                        value: old_value.clone(),
                    });
                }
            }
        }
        (Value::Array(old_arr), Value::Array(new_arr)) => {
            let min_len = old_arr.len().min(new_arr.len());
            for i in 0..min_len {
                collect_diffs(
                    &child_pointer(path, &i.to_string()),
                    &old_arr[i],
                    &new_arr[i],
                    diffs,
                );
            }
            for (i, item) in new_arr.iter().enumerate().skip(min_len) {
                diffs.push(DiffEntry::Added {
                    path: child_pointer(path, &i.to_string()),
                    value: item.clone(),
                });
            }
            for (i, item) in old_arr.iter().enumerate().skip(min_len).rev() {
                diffs.push(DiffEntry::Removed {
                    path: child_pointer(path, &i.to_string()),
                    value: item.clone(),
                });
            }
        }
        _ if old_val != new_val => diffs.push(DiffEntry::Modified {
            path: path.to_string(),
            old_value: old_val.clone(),
            new_value: new_val.clone(),
        }),
        _ => {}
    }
}

/// Apply one difference without inventing missing parents or silently ignoring errors.
fn apply_diff(value: &mut serde_json::Value, diff: &DiffEntry) -> Result<()> {
    use serde_json::Value;
    let path = match diff {
        DiffEntry::Added { path, .. }
        | DiffEntry::Removed { path, .. }
        | DiffEntry::Modified { path, .. } => path,
    };
    if path.is_empty() {
        return match diff {
            DiffEntry::Modified {
                old_value,
                new_value,
                ..
            } if value == old_value => {
                *value = new_value.clone();
                Ok(())
            }
            _ => Err(anyhow!(
                "Configuration root does not match the selected change"
            )),
        };
    }
    let (parent_path, token) = path
        .rsplit_once('/')
        .context("Invalid configuration change path")?;
    let key = token.replace("~1", "/").replace("~0", "~");
    let parent = value
        .pointer_mut(parent_path)
        .with_context(|| format!("Configuration change parent no longer exists: {}", path))?;
    match parent {
        Value::Object(object) => match diff {
            DiffEntry::Added { value, .. } if !object.contains_key(&key) => {
                object.insert(key, value.clone());
            }
            DiffEntry::Removed { value, .. } if object.get(&key) == Some(value) => {
                object.remove(&key);
            }
            DiffEntry::Modified {
                old_value,
                new_value,
                ..
            } if object.get(&key) == Some(old_value) => {
                object.insert(key, new_value.clone());
            }
            _ => {
                return Err(anyhow!(
                    "Configuration value no longer matches change: {}",
                    path
                ));
            }
        },
        Value::Array(array) => {
            let index: usize = key.parse().with_context(|| {
                format!("Invalid array index in configuration change: {}", path)
            })?;
            match diff {
                // Collected additions are tail items. Append only the selected items,
                // including when an earlier proposed addition was declined.
                DiffEntry::Added { value, .. } if index >= array.len() => array.push(value.clone()),
                DiffEntry::Removed { value, .. } if array.get(index) == Some(value) => {
                    array.remove(index);
                }
                DiffEntry::Modified {
                    old_value,
                    new_value,
                    ..
                } if array.get(index) == Some(old_value) => {
                    array[index] = new_value.clone();
                }
                _ => {
                    return Err(anyhow!(
                        "Configuration array no longer matches change: {}",
                        path
                    ));
                }
            }
        }
        _ => {
            return Err(anyhow!(
                "Configuration change parent is not a container: {}",
                path
            ));
        }
    }
    Ok(())
}

fn select_diffs(
    diffs: &[DiffEntry],
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<Option<Vec<DiffEntry>>> {
    let mut selected = Vec::new();
    for (i, diff) in diffs.iter().enumerate() {
        match diff {
            DiffEntry::Added { path, value } => {
                writeln!(output, "{}. [ADDED] {}", i + 1, path)?;
                writeln!(
                    output,
                    "    Value: {}",
                    serde_json::to_string_pretty(value)?
                )?;
            }
            DiffEntry::Removed { path, value } => {
                writeln!(output, "{}. [REMOVED] {}", i + 1, path)?;
                writeln!(
                    output,
                    "    Value: {}",
                    serde_json::to_string_pretty(value)?
                )?;
            }
            DiffEntry::Modified {
                path,
                old_value,
                new_value,
            } => {
                writeln!(output, "{}. [MODIFIED] {}", i + 1, path)?;
                writeln!(
                    output,
                    "    Old: {}",
                    serde_json::to_string_pretty(old_value)?
                )?;
                writeln!(
                    output,
                    "    New: {}",
                    serde_json::to_string_pretty(new_value)?
                )?;
            }
        }
        loop {
            write!(
                output,
                "Apply this change? [y/n/a/q] (y=yes, n=no, a=all, q=quit): "
            )?;
            output.flush()?;
            let mut reply = String::new();
            if input.read_line(&mut reply)? == 0 {
                writeln!(output, "\nInput ended. No changes applied.")?;
                return Ok(None);
            }
            match reply.trim().to_ascii_lowercase().as_str() {
                "y" | "yes" => {
                    selected.push(diff.clone());
                    break;
                }
                "n" | "no" => break,
                "a" | "all" => {
                    selected.extend_from_slice(&diffs[i..]);
                    writeln!(output, "Applying all remaining changes...")?;
                    return Ok(Some(selected));
                }
                "q" | "quit" => {
                    writeln!(output, "Quitting. No changes applied.")?;
                    return Ok(None);
                }
                _ => writeln!(output, "Invalid input. Please enter y, n, a, or q.")?,
            }
        }
    }
    Ok(Some(selected))
}

pub fn diff(paths: &Paths) -> Result<()> {
    use serde_json::Value;
    // Keep earlier staged edits when selecting additional changes.
    let input_path = paths.get_input_config_path();
    let current_json: Value = if input_path.exists() {
        serde_json::from_str(&fs::read_to_string(input_path)?)?
    } else {
        serde_json::json!({})
    };
    // A missing template is an error, not a request to delete the whole config.
    let default_json: Value =
        serde_json::from_str(&fs::read_to_string(&paths.default_config).with_context(|| {
            format!(
                "Cannot read default configuration {:?}",
                paths.default_config
            )
        })?)?;
    let mut diffs = Vec::new();
    collect_diffs("", &current_json, &default_json, &mut diffs);
    if diffs.is_empty() {
        eprintln!(
            "{} No differences found between current and default config.",
            "[INFO]".green()
        );
        return Ok(());
    }
    eprintln!(
        "{} Found {} difference(s) between current and default config:",
        "[INFO]".green(),
        diffs.len()
    );
    let Some(to_apply) = select_diffs(
        &diffs,
        &mut std::io::stdin().lock(),
        &mut std::io::stdout().lock(),
    )?
    else {
        return Ok(());
    };
    if to_apply.is_empty() {
        eprintln!("{} No changes selected to apply.", "[INFO]".green());
        return Ok(());
    }
    let mut new_config = current_json;
    for diff in &to_apply {
        apply_diff(&mut new_config, diff)?;
    }
    save_config(&paths.staging, &serde_json::from_value(new_config)?)?;
    eprintln!(
        "{} Applied {} change(s) to staging. Run 'mimictl apply' to activate.",
        "[INFO]".green(),
        to_apply.len()
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
        .args(["check", "-c"])
        .arg(input_path)
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
    fn test_diff_changes_only_selected_nested_array_field() {
        let mut current = serde_json::json!({
            "log": {"level": "warn"},
            "inbounds": [{"tls": {"server_name": "old.example", "reality": {"private_key": "keep"}}}]
        });
        let mut default = current.clone();
        default["inbounds"][0]["tls"]["server_name"] = serde_json::json!("new.example");
        default["log"]["level"] = serde_json::json!("info");
        let mut diffs = Vec::new();
        collect_diffs("", &current, &default, &mut diffs);
        let selected = diffs
            .iter()
            .find(|diff| {
                matches!(diff,
                    DiffEntry::Modified { path, .. } if path == "/inbounds/0/tls/server_name"
                )
            })
            .unwrap();
        apply_diff(&mut current, selected).unwrap();
        assert_eq!(current["inbounds"][0]["tls"]["server_name"], "new.example");
        assert_eq!(
            current["inbounds"][0]["tls"]["reality"]["private_key"],
            "keep"
        );
        assert_eq!(current["log"]["level"], "warn");
        assert!(current.get("server_name").is_none());
    }

    #[test]
    fn test_all_diffs_reproduce_nested_object_and_array_changes() {
        let mut current = serde_json::json!({
            "removed": true,
            "inbounds": [{"users": [{"name": "old"}, {"name": "remove"}, {"name": "remove2"}]}],
            "route": {"rules": []}
        });
        let default = serde_json::json!({
            "added": {"enabled": true},
            "inbounds": [{"users": [{"name": "new", "flow": "vision"}]}],
            "route": {"rules": [{"action": "sniff"}, {"action": "route"}]}
        });
        let mut diffs = Vec::new();
        collect_diffs("", &current, &default, &mut diffs);
        for diff in &diffs {
            apply_diff(&mut current, diff).unwrap();
        }
        assert_eq!(current, default);
    }

    #[test]
    fn test_diff_handles_keys_that_need_json_pointer_escaping() {
        let mut current = serde_json::json!({"a/b": {"~key.with[brackets]": [1, 2]}});
        let default = serde_json::json!({"a/b": {"~key.with[brackets]": [3]}});
        let mut diffs = Vec::new();
        collect_diffs("", &current, &default, &mut diffs);
        for diff in &diffs {
            apply_diff(&mut current, diff).unwrap();
        }
        assert_eq!(current, default);
    }

    #[test]
    fn test_selected_array_additions_do_not_require_declined_items() {
        let mut current = serde_json::json!({"rules": ["keep"]});
        let default = serde_json::json!({"rules": ["keep", "decline", "accept"]});
        let mut diffs = Vec::new();
        collect_diffs("", &current, &default, &mut diffs);
        apply_diff(&mut current, &diffs[1]).unwrap();
        assert_eq!(current, serde_json::json!({"rules": ["keep", "accept"]}));
    }

    #[test]
    fn test_diff_rejects_stale_values_without_modifying_config() {
        let mut current = serde_json::json!({"nested": {"value": "keep"}});
        let original = current.clone();
        let stale = DiffEntry::Modified {
            path: "/nested/value".into(),
            old_value: serde_json::json!("wrong"),
            new_value: serde_json::json!("replace"),
        };
        assert!(apply_diff(&mut current, &stale).is_err());
        assert_eq!(current, original);
        let missing = DiffEntry::Added {
            path: "/missing/key".into(),
            value: serde_json::json!(true),
        };
        assert!(apply_diff(&mut current, &missing).is_err());
        assert_eq!(current, original);
    }

    #[test]
    fn test_diff_all_stops_prompting_and_applies_each_change_once() {
        let current = serde_json::json!({"a": 1, "b": 2, "c": 3});
        let default = serde_json::json!({"a": 4, "b": 5, "c": 6});
        let mut diffs = Vec::new();
        collect_diffs("", &current, &default, &mut diffs);
        let mut output = Vec::new();
        let selected = select_diffs(&diffs, &mut &b"y\na\n"[..], &mut output)
            .unwrap()
            .unwrap();
        assert_eq!(selected.len(), diffs.len());
        assert_eq!(
            String::from_utf8(output)
                .unwrap()
                .matches("Apply this change?")
                .count(),
            2
        );
    }

    #[test]
    fn test_diff_eof_cancels_pending_selections() {
        let mut diffs = Vec::new();
        collect_diffs(
            "",
            &serde_json::json!({"a": 1, "b": 2}),
            &serde_json::json!({"a": 3, "b": 4}),
            &mut diffs,
        );
        let mut output = Vec::new();
        assert!(
            select_diffs(&diffs, &mut &b"y\n"[..], &mut output)
                .unwrap()
                .is_none()
        );
        assert!(String::from_utf8(output).unwrap().contains("Input ended"));
    }

    #[test]
    fn test_diff_missing_template_preserves_staging() {
        let tmp = setup_tmp();
        let paths = build_paths(tmp.clone());
        fs::write(&paths.config, "{}").unwrap();
        fs::write(&paths.staging, "{\"pending\": true}").unwrap();
        assert!(diff(&paths).is_err());
        assert_eq!(
            fs::read_to_string(&paths.staging).unwrap(),
            "{\"pending\": true}"
        );
        fs::remove_dir_all(tmp).unwrap();
    }

    #[test]
    fn test_reset_keeps_user_credentials_and_reality_identity() {
        let tmp = setup_tmp();
        let paths = build_paths(tmp.clone());
        let default = serde_json::json!({
            "log": {"level": "warn"},
            "inbounds": [{"type": "vless", "tag": "vless-in", "users": [],
                "tls": {"enabled": true, "reality": {"enabled": true, "private_key": "", "short_id": []}}}],
            "outbounds": [{"type": "direct"}]
        });
        let mut current = default.clone();
        current["log"]["level"] = serde_json::json!("debug");
        current["inbounds"][0]["users"] = serde_json::json!([
            {"name": "alice@example.com:aabb:1", "uuid": "keep-uuid", "flow": "xtls-rprx-vision"},
            {"name": "bob@example.com:ccdd:1", "uuid": "remove-uuid", "flow": "xtls-rprx-vision"}
        ]);
        current["inbounds"][0]["tls"] = serde_json::json!({
            "enabled": true, "server_name": "keep.example",
            "reality": {"enabled": true, "private_key": "keep-private-key", "short_id": ["aabb", "ccdd"],
                "handshake": {"server": "keep.example", "server_port": 8443}}
        });
        fs::write(&paths.default_config, default.to_string()).unwrap();
        fs::write(&paths.config, current.to_string()).unwrap();
        reset(
            &paths,
            vec!["alice@example.com".into(), "alice@example.com".into()],
        )
        .unwrap();
        let staged: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&paths.staging).unwrap()).unwrap();
        assert_eq!(staged["log"], default["log"]);
        assert_eq!(
            staged["inbounds"][0]["users"],
            serde_json::json!([current["inbounds"][0]["users"][0].clone()])
        );
        assert_eq!(
            staged["inbounds"][0]["tls"]["reality"]["private_key"],
            "keep-private-key"
        );
        assert_eq!(staged["inbounds"][0]["tls"]["server_name"], "keep.example");
        assert_eq!(
            staged["inbounds"][0]["tls"]["reality"]["handshake"],
            current["inbounds"][0]["tls"]["reality"]["handshake"]
        );
        assert_eq!(
            staged["inbounds"][0]["tls"]["reality"]["short_id"],
            serde_json::json!(["aabb"])
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&fs::read_to_string(&paths.config).unwrap())
                .unwrap(),
            current
        );
        fs::remove_dir_all(tmp).unwrap();
    }

    #[test]
    fn test_reset_unknown_kept_user_does_not_overwrite_staging() {
        let tmp = setup_tmp();
        let paths = build_paths(tmp.clone());
        let config = r#"{"inbounds": [{"type": "vless", "users": [], "tls": {"enabled": true, "reality": {"enabled": true}}}]}"#;
        fs::write(&paths.config, config).unwrap();
        fs::write(&paths.default_config, config).unwrap();
        fs::write(&paths.staging, config).unwrap();
        assert!(reset(&paths, vec!["missing@example.com".into()]).is_err());
        assert_eq!(fs::read_to_string(&paths.staging).unwrap(), config);
        fs::remove_dir_all(tmp).unwrap();
    }

    #[test]
    fn test_reset_preserves_managed_vless_with_reordered_hysteria_inbounds() {
        for current_vless_first in [false, true] {
            let tmp = setup_tmp();
            let paths = build_paths(tmp.clone());
            let current_vless = serde_json::json!({
                "type": "vless", "tag": "vless-in", "users": [
                    {"name": "alice@example.com:aabb:1", "uuid": "keep-vless-uuid", "flow": "xtls-rprx-vision"}
                ],
                "tls": {"enabled": true, "server_name": "keep.example", "reality": {
                    "enabled": true, "private_key": "keep-vless-key", "short_id": ["aabb"]
                }}
            });
            let current_hysteria = serde_json::json!({
                "type": "hysteria2", "tag": "hy2-in", "users": [
                    {"name": "alice@example.com:aabb:1", "password": "current-hy2-password"}
                ]
            });
            let default_vless = serde_json::json!({
                "type": "vless", "tag": "vless-in", "users": [],
                "tls": {"enabled": true, "reality": {"enabled": true, "private_key": "", "short_id": []}}
            });
            let default_hysteria = serde_json::json!({
                "type": "hysteria2", "tag": "hy2-in", "users": [
                    {"name": "default-hy2-user", "password": "default-hy2-password"}
                ]
            });
            let current_inbounds = if current_vless_first {
                vec![current_vless.clone(), current_hysteria]
            } else {
                vec![current_hysteria, current_vless.clone()]
            };
            let default_inbounds = if current_vless_first {
                vec![default_hysteria.clone(), default_vless]
            } else {
                vec![default_vless, default_hysteria.clone()]
            };
            fs::write(
                &paths.config,
                serde_json::json!({"inbounds": current_inbounds}).to_string(),
            )
            .unwrap();
            fs::write(
                &paths.default_config,
                serde_json::json!({"inbounds": default_inbounds}).to_string(),
            )
            .unwrap();
            reset(&paths, vec!["alice@example.com".into()]).unwrap();
            let staged = load_config(&paths.staging).unwrap();
            let vless_index = usize::from(current_vless_first);
            let hysteria_index = 1 - vless_index;
            assert_eq!(
                staged.inbounds[vless_index].users,
                current_vless["users"].as_array().unwrap().clone()
            );
            assert_eq!(
                staged.inbounds[vless_index]
                    .tls
                    .as_ref()
                    .unwrap()
                    .reality
                    .as_ref()
                    .unwrap()
                    .private_key,
                "keep-vless-key"
            );
            assert_eq!(
                staged.inbounds[hysteria_index].users,
                default_hysteria["users"].as_array().unwrap().clone()
            );
            fs::remove_dir_all(tmp).unwrap();
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
