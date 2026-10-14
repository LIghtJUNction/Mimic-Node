use anyhow::{Result, anyhow};
use colored::*;
use regex::Regex;
use std::collections::HashSet;

use crate::config;
use crate::paths::Paths;
use crate::utils::{
    generate_keypair, generate_sid, generate_uuid, load_config, save_config, write_private_file,
};

const FLOW_TYPE: &str = "xtls-rprx-vision";

/// Locate the one inbound managed by VLESS user and Reality commands.
/// Never infer the protocol from its position in the configuration.
pub(crate) fn managed_vless_inbound_index(config: &config::SingBoxConfig) -> Result<usize> {
    let mut matching = config.inbounds.iter().enumerate().filter(|(_, inbound)| {
        inbound.protocol_type == "vless"
            && inbound.tls.as_ref().is_some_and(|tls| {
                tls.enabled && tls.reality.as_ref().is_some_and(|reality| reality.enabled)
            })
    });
    let (index, _) = matching
        .next()
        .ok_or_else(|| anyhow!("No VLESS inbound with enabled TLS and Reality found."))?;
    if matching.next().is_some() {
        return Err(anyhow!(
            "Multiple VLESS Reality inbounds found; the managed inbound is ambiguous."
        ));
    }
    Ok(index)
}

/// Helper to synchronize reality.short_id list with active users
fn sync_short_ids(inbound: &mut config::Inbound) {
    let mut active_sids = Vec::new();

    // Extract SIDs from all users
    for user in &inbound.users {
        let name = user.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let parts: Vec<&str> = name.split(':').collect();
        // Format is email:sid:level. We need the SID (second to last)
        if parts.len() >= 3
            && let Some(sid) = parts.get(parts.len() - 2)
            && !sid.is_empty()
        {
            active_sids.push(sid.to_string());
        }
    }

    // Sort and dedup
    active_sids.sort();
    active_sids.dedup();

    // Update config
    if let Some(tls) = inbound.tls.as_mut()
        && let Some(reality) = tls.reality.as_mut()
    {
        reality.short_id = active_sids;
    }
}

/// Find matching user indices for a given target (uuid, anchored email, glob, or substring)
pub(crate) fn find_matching_indices(
    users: &[serde_json::Value],
    target: &str,
) -> Result<Vec<usize>> {
    // If target looks like a UUID, try exact uuid match first
    if uuid::Uuid::parse_str(target).is_ok() {
        let exact: Vec<usize> = users
            .iter()
            .enumerate()
            .filter(|(_i, u)| u.get("uuid").and_then(|v| v.as_str()) == Some(target))
            .map(|(i, _)| i)
            .collect();

        if !exact.is_empty() {
            return Ok(exact);
        }

        // Substring fallback (uuid, full name or local email part)
        let local = target.split('@').next().unwrap_or(target).to_string();
        let substr: Vec<usize> = users
            .iter()
            .enumerate()
            .filter(|(_i, u)| {
                let uuid = u.get("uuid").and_then(|v| v.as_str()).unwrap_or("");
                let name = u.get("name").and_then(|v| v.as_str()).unwrap_or("");
                uuid.contains(target) || name.contains(target) || name.contains(&local)
            })
            .map(|(i, _)| i)
            .collect();

        return Ok(substr);
    }

    // Build regex for anchored email prefix match if target contains glob chars or not
    let pattern = if target.contains('*') || target.contains('?') {
        regex::escape(target)
            .replace("\\*", ".*")
            .replace("\\?", ".")
    } else {
        regex::escape(target)
    };

    let regex_str = format!("^{}:", pattern);
    let re = Regex::new(&regex_str)?;
    let anchored: Vec<usize> = users
        .iter()
        .enumerate()
        .filter(|(_i, u)| {
            let name = u.get("name").and_then(|v| v.as_str()).unwrap_or("");
            re.is_match(name)
        })
        .map(|(i, _)| i)
        .collect();

    if !anchored.is_empty() {
        return Ok(anchored);
    }

    // Fallback to substring (name/uuid/local-part)
    let local = target.split('@').next().unwrap_or(target).to_string();
    let substr: Vec<usize> = users
        .iter()
        .enumerate()
        .filter(|(_i, u)| {
            let name = u.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let uuid = u.get("uuid").and_then(|v| v.as_str()).unwrap_or("");
            name.contains(target) || name.contains(&local) || uuid.contains(target)
        })
        .map(|(i, _)| i)
        .collect();

    Ok(substr)
}

pub fn add(paths: &Paths, emails: Vec<String>, level: u32) -> Result<()> {
    // Check for private key first
    let input_path = paths.get_input_config_path();
    let mut config = load_config(input_path)?;
    let inbound_index = managed_vless_inbound_index(&config)?;

    // Quick check if private key is present in loaded config
    let has_key = config
        .inbounds
        .get(inbound_index)
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
        if let Some(inbound) = config.inbounds.get_mut(inbound_index) {
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
        write_private_file(&paths.staging_pubkey, pub_key.as_bytes())?;
    }

    for email in emails {
        let uuid = generate_uuid();
        let sid = generate_sid();
        let name = format!("{}:{}:{}", email, sid, level);

        let user = serde_json::json!({
            "name": name,
            "uuid": uuid,
            "flow": FLOW_TYPE
        });

        if let Some(inbound) = config.inbounds.get_mut(inbound_index) {
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
    sync_short_ids(&mut config.inbounds[inbound_index]);

    save_config(&paths.staging, &config)?;

    eprintln!(
        "{} Users staged. Run 'mimictl apply' to activate.",
        "[INFO]".green()
    );

    Ok(())
}

pub fn del(paths: &Paths, targets: Vec<String>, dry_run: bool, apply: bool) -> Result<()> {
    let input_path = paths.get_input_config_path();
    let mut config = load_config(input_path)?;
    let inbound_index = managed_vless_inbound_index(&config)?;

    if let Some(inbound) = config.inbounds.get_mut(inbound_index) {
        // Collect matches per target and unique indices to delete
        let mut to_delete: HashSet<usize> = HashSet::new();
        let mut per_target_matches: Vec<(String, Vec<usize>)> = Vec::new();

        for target in targets {
            let indices = find_matching_indices(&inbound.users, &target)?;
            if indices.is_empty() {
                eprintln!(
                    "{} No users matched for target: {}",
                    "[WARN]".yellow(),
                    target
                );
                continue;
            }
            per_target_matches.push((target.clone(), indices.clone()));
            for idx in indices {
                to_delete.insert(idx);
            }
        }

        if to_delete.is_empty() {
            return Err(anyhow!("No users matched the provided target(s)."));
        }

        // Dry-run: just show which users would be deleted
        if dry_run {
            eprintln!(
                "{} Dry-run: the following users would be deleted:",
                "[INFO]".green()
            );
            let mut printed: HashSet<usize> = HashSet::new();
            for (target, indices) in &per_target_matches {
                let mut printed_here = 0usize;
                for idx in indices {
                    if printed.insert(*idx) {
                        let u = &inbound.users[*idx];
                        let name = u.get("name").and_then(|v| v.as_str()).unwrap_or("");
                        let uuid = u.get("uuid").and_then(|v| v.as_str()).unwrap_or("");
                        println!("{}\t{}", name, uuid);
                        printed_here += 1;
                    }
                }
                if printed_here > 0 {
                    eprintln!(
                        "{} Would delete {} user(s) for target: {}",
                        "[INFO]".green(),
                        printed_here,
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
            eprintln!(
                "{} Total unique users matched: {}",
                "[INFO]".green(),
                to_delete.len()
            );
            return Ok(());
        }

        // Report per-target deletions (deduped)
        let mut seen: HashSet<usize> = HashSet::new();
        for (target, indices) in &per_target_matches {
            let new_count = indices.iter().filter(|i| !seen.contains(i)).count();
            for idx in indices {
                seen.insert(*idx);
            }
            if new_count > 0 {
                eprintln!(
                    "{} Deleted {} user(s) for target: {}",
                    "[INFO]".green(),
                    new_count,
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

        // Perform deletion
        let before = inbound.users.len();
        let mut kept: Vec<serde_json::Value> = Vec::with_capacity(inbound.users.len());
        for (i, u) in inbound.users.iter().enumerate() {
            if !to_delete.contains(&i) {
                kept.push(u.clone());
            }
        }
        inbound.users = kept;
        let deleted_total = before - inbound.users.len();

        if deleted_total == 0 {
            return Err(anyhow!("No users matched the provided target(s)."));
        }

        // Persist changes
        sync_short_ids(&mut config.inbounds[inbound_index]);
        save_config(&paths.staging, &config)?;

        eprintln!(
            "{} Deletion(s) staged. Run 'mimictl apply' to activate.",
            "[INFO]".green()
        );

        // Optionally apply immediately
        if apply {
            eprintln!("{} Applying staged changes...", "[INFO]".green());
            crate::commands::system::apply(paths)?;
        }

        Ok(())
    } else {
        Err(anyhow!("No inbound configuration present."))
    }
}

/// Reset uuid and sid for matched user(s) - supports batch/patterns
pub fn reset(paths: &Paths, targets: Vec<String>, dry_run: bool, apply: bool) -> Result<()> {
    let input_path = paths.get_input_config_path();
    let mut config = load_config(input_path)?;
    let inbound_index = managed_vless_inbound_index(&config)?;

    // Plan resets first (to support dry-run and conflict-free application)
    // planned: (idx, old_name, old_uuid, new_name, new_sid)
    let mut planned: Vec<(usize, String, String, String, String)> = Vec::new();

    if let Some(inbound) = config.inbounds.get_mut(inbound_index) {
        let mut seen: HashSet<usize> = HashSet::new();

        for target in &targets {
            let indices = find_matching_indices(&inbound.users, target)?;

            if indices.is_empty() {
                eprintln!(
                    "{} No users matched for target: {}",
                    "[WARN]".yellow(),
                    target
                );
                continue;
            }

            for idx in indices {
                if seen.contains(&idx) {
                    // already planned via a previous target
                    continue;
                }

                let user = &inbound.users[idx];
                let old_name = user
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let old_uuid = user
                    .get("uuid")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let parts: Vec<&str> = old_name.split(':').collect();
                if parts.len() < 3 {
                    eprintln!(
                        "{} Skipping malformed user name: {}",
                        "[WARN]".yellow(),
                        old_name
                    );
                    continue;
                }

                let email = parts[..parts.len() - 2].join(":");
                let level = parts.last().unwrap_or(&"0");

                let new_sid = generate_sid();
                let new_name = format!("{}:{}:{}", email, new_sid, level);

                planned.push((idx, old_name, old_uuid, new_name, new_sid));
                seen.insert(idx);
            }
        }
    }

    if planned.is_empty() {
        return Err(anyhow!("No users matched the provided target(s)."));
    }

    // Dry-run: show planned changes and do not write staging
    if dry_run {
        eprintln!(
            "{} Dry-run: {} reset(s) planned.",
            "[INFO]".green(),
            planned.len()
        );
        for (_idx, old_name, old_uuid, new_name, new_sid) in &planned {
            eprintln!(
                "{} Would reset: {} -> {} (uuid: {} -> <new>, sid: {})",
                "[INFO]".green(),
                old_name,
                new_name,
                old_uuid,
                new_sid
            );
        }
        return Ok(());
    }

    // Apply resets
    if let Some(inbound) = config.inbounds.get_mut(inbound_index) {
        for (idx, old_name, old_uuid, new_name, new_sid) in planned {
            let user = &mut inbound.users[idx];
            let new_uuid = generate_uuid();

            if let Some(obj) = user.as_object_mut() {
                obj.insert("name".to_string(), serde_json::json!(new_name));
                obj.insert("uuid".to_string(), serde_json::json!(new_uuid));
            }

            eprintln!(
                "{} Reset user: {} -> {} (uuid: {} -> {})",
                "[INFO]".green(),
                old_name,
                new_name,
                old_uuid,
                new_uuid
            );

            println!("uuid: {}\nsid: {}", new_uuid, new_sid);
        }
    }

    // Persist changes to staging
    sync_short_ids(&mut config.inbounds[inbound_index]);
    save_config(&paths.staging, &config)?;

    eprintln!(
        "{} Reset(s) staged. Run 'mimictl apply' to activate.",
        "[INFO]".green()
    );

    if apply {
        eprintln!("{}", "[INFO] Applying staged changes...".green());
        crate::commands::system::apply(paths)?;
    }

    Ok(())
}

pub fn list(paths: &Paths, filter: Option<String>, json: bool) -> Result<()> {
    let input_path = paths.get_input_config_path();
    let config = load_config(input_path)?;
    let inbound_index = managed_vless_inbound_index(&config)?;

    if json {
        // Collect matching users and output as JSON array
        let mut out: Vec<serde_json::Value> = Vec::new();
        if let Some(inbound) = config.inbounds.get(inbound_index) {
            for user in &inbound.users {
                let name = user.get("name").and_then(|v| v.as_str()).unwrap_or("");
                if let Some(f) = &filter
                    && !name.contains(f)
                {
                    continue;
                }
                out.push(user.clone());
            }
        }
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    if let Some(inbound) = config.inbounds.get(inbound_index) {
        for user in &inbound.users {
            let name = user.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let uuid = user.get("uuid").and_then(|v| v.as_str()).unwrap_or("");
            let flow = user.get("flow").and_then(|v| v.as_str()).unwrap_or("");
            if let Some(f) = &filter
                && !name.contains(f)
            {
                continue;
            }
            println!("{}\t{}\t{}", name, uuid, flow);
        }
    }
    Ok(())
}

/// Show info for one or multiple targets (patterns supported)
/// When `json` is true, outputs a JSON array (compact) of matched users for scripts.
pub fn info(paths: &Paths, targets: Vec<String>, json: bool) -> Result<()> {
    let input_path = paths.get_input_config_path();
    let config = load_config(input_path)?;
    let inbound_index = managed_vless_inbound_index(&config)?;

    let mut any_matched = false;
    if let Some(inbound) = config.inbounds.get(inbound_index) {
        let mut seen: HashSet<usize> = HashSet::new();
        let mut result: Vec<serde_json::Value> = Vec::new();

        for target in targets {
            let indices = find_matching_indices(&inbound.users, &target)?;

            if indices.is_empty() {
                eprintln!(
                    "{} No users matched for target: {}",
                    "[WARN]".yellow(),
                    target
                );
                continue;
            }

            for idx in indices {
                if seen.insert(idx) {
                    if json {
                        result.push(inbound.users[idx].clone());
                    } else {
                        println!("{}", serde_json::to_string_pretty(&inbound.users[idx])?);
                    }
                    any_matched = true;
                }
            }
        }

        if json && any_matched {
            println!("{}", serde_json::to_string(&result)?);
            return Ok(());
        }

        if any_matched {
            return Ok(());
        }
    }

    Err(anyhow!("No users matched the provided target(s)."))
}

/// Update user properties in batch (supports --level, --email, --email-replace, --regex, --replace-first, --dry-run, --apply)
///
/// - `--level N` will set the level for all matched users.
/// - `--email foo@example.com` will set the email for a single matched user (only allowed when exactly one user matches).
/// - `--email-replace FROM TO` will replace substrings in the email part for all matched users; use `--regex` to treat FROM as a regex.
/// - `--replace-first` will perform only the first match replacement (default replaces all matches).
/// - `--dry-run` will show planned changes without writing staging.
/// - `--apply` will apply staged changes immediately after saving.
// Keep the existing CLI options together at the dispatch boundary.
#[allow(clippy::too_many_arguments)]
pub fn update(
    paths: &Paths,
    targets: Vec<String>,
    level: Option<u32>,
    email: Option<String>,
    email_replace: Option<Vec<String>>,
    regex: bool,
    replace_first: bool,
    dry_run: bool,
    apply: bool,
) -> Result<()> {
    // Basic validations
    if level.is_none() && email.is_none() && email_replace.is_none() {
        return Err(anyhow!(
            "No update action specified. Use --level and/or --email/--email-replace."
        ));
    }
    if email.is_some() && email_replace.is_some() {
        return Err(anyhow!(
            "--email and --email-replace are mutually exclusive."
        ));
    }
    if regex && email_replace.is_none() {
        return Err(anyhow!("--regex requires --email-replace to be provided."));
    }
    if let Some(ref repl) = email_replace
        && repl.len() != 2
    {
        return Err(anyhow!(
            "--email-replace requires two arguments: FROM and TO."
        ));
    }

    let input_path = paths.get_input_config_path();
    let mut config = load_config(input_path)?;
    let inbound_index = managed_vless_inbound_index(&config)?;

    // planned updates: (index, old_name, new_name)
    let mut planned: Vec<(usize, String, String)> = Vec::new();

    if let Some(inbound) = config.inbounds.get_mut(inbound_index) {
        for target in &targets {
            let indices = find_matching_indices(&inbound.users, target)?;

            if indices.is_empty() {
                eprintln!(
                    "{} No users matched for target: {}",
                    "[WARN]".yellow(),
                    target
                );
                continue;
            }

            // If --email is used it must be unambiguous per-target
            if email.is_some() && indices.len() > 1 {
                return Err(anyhow!(
                    "Email rename ambiguous for target '{}': {} users matched. Rename is only allowed when exactly one user is matched.",
                    target,
                    indices.len()
                ));
            }

            for idx in indices {
                // avoid double-planning for the same user across multiple targets
                if planned.iter().any(|(i, _old, _)| *i == idx) {
                    continue;
                }

                let user = &inbound.users[idx];
                let old_name = user
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let parts: Vec<&str> = old_name.split(':').collect();
                if parts.len() < 3 {
                    return Err(anyhow!(
                        "Invalid user name format encountered: {}",
                        old_name
                    ));
                }

                let cur_email = parts[..parts.len() - 2].join(":");
                let sid = parts.get(parts.len() - 2).unwrap_or(&"").to_string();
                let cur_level = parts.last().unwrap_or(&"0").to_string();
                let new_level = level.map(|l| l.to_string()).unwrap_or(cur_level);

                // Compute new email (support replace-first and regex backrefs)
                let new_email = if let Some(e) = &email {
                    e.clone()
                } else if let Some(repl) = &email_replace {
                    let from = &repl[0];
                    let to = &repl[1];
                    if regex {
                        let re = Regex::new(from)?;
                        if replace_first {
                            // replace first regex match
                            re.replace(&cur_email, to.as_str()).to_string()
                        } else {
                            // replace all
                            re.replace_all(&cur_email, to.as_str()).to_string()
                        }
                    } else if replace_first {
                        // replace first literal occurrence
                        cur_email.replacen(from, to, 1)
                    } else {
                        // replace all literal occurrences
                        cur_email.replace(from, to)
                    }
                } else {
                    cur_email
                };

                let new_name = format!("{}:{}:{}", new_email, sid, new_level);
                planned.push((idx, old_name, new_name));
            }
        }

        if planned.is_empty() {
            return Err(anyhow!("No users matched the provided target(s)."));
        }

        // If email rename (explicit) was requested, ensure exactly one user will be modified overall
        if email.is_some() {
            let uniq: HashSet<usize> = planned.iter().map(|(i, _, _)| *i).collect();
            if uniq.len() != 1 {
                return Err(anyhow!("Email rename requires exactly one matched user."));
            }
        }

        // Validate planned changes for conflicts
        let planned_idxs: HashSet<usize> = planned.iter().map(|(i, _, _)| *i).collect();
        let existing_names: HashSet<String> = inbound
            .users
            .iter()
            .enumerate()
            .filter(|(i, _)| !planned_idxs.contains(i))
            .map(|(_, u)| {
                u.get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string()
            })
            .collect();

        let mut seen_new: HashSet<String> = HashSet::new();
        for (_idx, _old, new_name) in &planned {
            if existing_names.contains(new_name) {
                return Err(anyhow!(
                    "Planned update would conflict with existing user: {}",
                    new_name
                ));
            }
            if !seen_new.insert(new_name.clone()) {
                return Err(anyhow!(
                    "Planned update would create duplicate user name: {}",
                    new_name
                ));
            }
        }

        // Dry run: print planned changes and return without writing staging
        if dry_run {
            eprintln!(
                "{} Dry-run: {} planned update(s)",
                "[INFO]".green(),
                planned.len()
            );
            for (_idx, old_name, new_name) in &planned {
                eprintln!("{} {} -> {}", "[INFO]".green(), old_name, new_name);
            }
            return Ok(());
        }

        // Apply planned changes
        let mut applied = 0usize;
        for (idx, old_name, new_name) in planned {
            if old_name == new_name {
                eprintln!("{} No change for user: {}", "[INFO]".green(), old_name);
                continue;
            }

            let user = &mut inbound.users[idx];
            if let Some(obj) = user.as_object_mut() {
                obj.insert("name".to_string(), serde_json::json!(new_name));
            }
            applied += 1;

            eprintln!(
                "{} Updated user: {} -> {}",
                "[INFO]".green(),
                old_name,
                new_name
            );
        }

        if applied == 0 {
            return Err(anyhow!("No changes were necessary."));
        }

        // Persist
        sync_short_ids(&mut config.inbounds[inbound_index]);
        save_config(&paths.staging, &config)?;

        eprintln!(
            "{} Update(s) staged. Run 'mimictl apply' to activate.",
            "[INFO]".green()
        );

        if apply {
            eprintln!("{} Applying staged changes...", "[INFO]".green());
            crate::commands::system::apply(paths)?;
        }

        Ok(())
    } else {
        Err(anyhow!("No inbound configuration present."))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use uuid::Uuid;
    // Use the global test PATH lock defined in `utils` (TEST_PATH_LOCK) to serialize tests
    // that modify PATH. This avoids races across test modules.

    fn make_user(name: &str, uuid: &str) -> serde_json::Value {
        serde_json::json!({"name": name, "uuid": uuid, "flow": FLOW_TYPE})
    }

    struct UserFixture {
        paths: Paths,
    }

    impl UserFixture {
        fn new(inbounds: serde_json::Value) -> Self {
            let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("target")
                .join(format!("user-test-{}", Uuid::new_v4()));
            let etc = root.join("etc/sing-box");
            fs::create_dir_all(&etc).unwrap();
            let paths = Paths {
                config: etc.join("config.json"),
                staging: etc.join("config.new"),
                pubkey: etc.join("PUBKEY"),
                staging_pubkey: etc.join("PUBKEY.new"),
                sni_list: root.join("sni.txt"),
                default_config: root.join("default/config.json"),
                root,
            };
            fs::write(
                &paths.config,
                serde_json::to_vec(&serde_json::json!({"inbounds": inbounds})).unwrap(),
            )
            .unwrap();
            Self { paths }
        }

        fn staged(&self) -> config::SingBoxConfig {
            load_config(&self.paths.staging).unwrap()
        }
    }

    impl Drop for UserFixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.paths.root).unwrap();
        }
    }

    fn reality_inbound() -> serde_json::Value {
        serde_json::json!({
            "type": "vless", "tag": "managed-vless",
            "tls": {"enabled": true, "reality": {
                "enabled": true, "private_key": "configured-key", "short_id": ["aabbccdd"]
            }},
            "users": [make_user(
                "alice@example.com:aabbccdd:0", "11111111-1111-1111-1111-111111111111"
            )]
        })
    }

    #[test]
    fn managed_inbound_is_selected_by_protocol_and_enabled_reality() {
        let fixture = UserFixture::new(serde_json::json!([
            {"type": "hysteria2", "users": [{"password": "secret"}]},
            {"type": "vless", "tls": {"enabled": true}},
            {"type": "vless", "tls": {"enabled": true, "reality": {"enabled": false}}},
            reality_inbound()
        ]));
        let config = load_config(&fixture.paths.config).unwrap();
        assert_eq!(managed_vless_inbound_index(&config).unwrap(), 3);
    }

    #[test]
    fn user_mutations_preserve_hysteria_when_inbounds_are_reordered() {
        let hy2_user = serde_json::json!({
            "name": "alice@example.com:aabbccdd:0", "password": "hy2-password"
        });
        let fixture = UserFixture::new(serde_json::json!([
            {"type": "hysteria2", "users": [hy2_user.clone()]},
            reality_inbound()
        ]));
        add(&fixture.paths, vec!["bob@example.com".to_string()], 2).unwrap();
        let staged = fixture.staged();
        assert_eq!(staged.inbounds[0].users, vec![hy2_user.clone()]);
        assert_eq!(staged.inbounds[1].users.len(), 2);
        assert_eq!(
            staged.inbounds[1]
                .tls
                .as_ref()
                .unwrap()
                .reality
                .as_ref()
                .unwrap()
                .short_id
                .len(),
            2
        );

        update(
            &fixture.paths,
            vec!["alice@example.com".to_string()],
            Some(3),
            None,
            None,
            false,
            false,
            false,
            false,
        )
        .unwrap();
        assert_eq!(
            fixture.staged().inbounds[1].users[0]["name"],
            "alice@example.com:aabbccdd:3"
        );

        reset(
            &fixture.paths,
            vec!["alice@example.com".to_string()],
            false,
            false,
        )
        .unwrap();
        let staged = fixture.staged();
        let new_name = staged.inbounds[1].users[0]["name"].as_str().unwrap();
        assert!(new_name.starts_with("alice@example.com:"));
        assert!(new_name.ends_with(":3"));
        assert_ne!(new_name, "alice@example.com:aabbccdd:3");
        let new_sid = new_name.split(':').nth(1).unwrap().to_string();
        let new_uuid = staged.inbounds[1].users[0]["uuid"].as_str().unwrap();
        assert_ne!(new_uuid, "11111111-1111-1111-1111-111111111111");
        Uuid::parse_str(new_uuid).unwrap();

        // Reads must use the same VLESS inbound, including users absent from Hysteria.
        list(&fixture.paths, None, true).unwrap();
        info(&fixture.paths, vec!["bob@example.com".to_string()], true).unwrap();

        del(
            &fixture.paths,
            vec!["bob@example.com".to_string()],
            false,
            false,
        )
        .unwrap();
        let staged = fixture.staged();
        assert_eq!(staged.inbounds[0].users, vec![hy2_user]);
        assert_eq!(staged.inbounds[1].users.len(), 1);
        assert_eq!(
            staged.inbounds[1]
                .tls
                .as_ref()
                .unwrap()
                .reality
                .as_ref()
                .unwrap()
                .short_id,
            vec![new_sid]
        );
        assert!(
            !fixture.paths.staging_pubkey.exists(),
            "the existing Reality key must be retained"
        );
    }

    #[test]
    fn all_user_commands_reject_missing_managed_inbound_without_staging() {
        let fixture = UserFixture::new(serde_json::json!([
            {"type": "hysteria2", "users": [{"name": "alice@example.com:aabbccdd:0", "password": "secret"}]}
        ]));
        let before = fs::read(&fixture.paths.config).unwrap();
        let results = [
            add(&fixture.paths, vec!["bob@example.com".to_string()], 0),
            del(
                &fixture.paths,
                vec!["alice@example.com".to_string()],
                false,
                false,
            ),
            reset(
                &fixture.paths,
                vec!["alice@example.com".to_string()],
                false,
                false,
            ),
            list(&fixture.paths, None, true),
            info(&fixture.paths, vec!["alice@example.com".to_string()], true),
            update(
                &fixture.paths,
                vec!["alice@example.com".to_string()],
                Some(1),
                None,
                None,
                false,
                false,
                false,
                false,
            ),
        ];
        for result in results {
            assert!(result.unwrap_err().to_string().contains("No VLESS inbound"));
        }
        assert_eq!(fs::read(&fixture.paths.config).unwrap(), before);
        assert!(!fixture.paths.staging.exists());
        assert!(!fixture.paths.staging_pubkey.exists());
    }

    #[test]
    fn ambiguous_reality_inbounds_are_rejected_without_staging() {
        let fixture = UserFixture::new(serde_json::json!([reality_inbound(), reality_inbound()]));
        let config = load_config(&fixture.paths.config).unwrap();
        assert!(
            managed_vless_inbound_index(&config)
                .unwrap_err()
                .to_string()
                .contains("ambiguous")
        );
        assert!(add(&fixture.paths, vec!["bob@example.com".to_string()], 0).is_err());
        assert!(!fixture.paths.staging.exists());
        assert!(!fixture.paths.staging_pubkey.exists());
    }

    #[test]
    fn test_find_matching_indices_uuid_exact() {
        let users = vec![
            make_user(
                "alice@example.com:SID1:0",
                "11111111-1111-1111-1111-111111111111",
            ),
            make_user(
                "bob@example.com:SID2:0",
                "22222222-2222-2222-2222-222222222222",
            ),
        ];
        let idxs = find_matching_indices(&users, "11111111-1111-1111-1111-111111111111").unwrap();
        assert_eq!(idxs, vec![0]);
    }

    #[test]
    fn test_find_matching_indices_uuid_substring() {
        let users = vec![
            make_user("alice@example.com:SID1:0", "abc-111"),
            make_user("bob@example.com:SID2:0", "abc-222"),
        ];
        let idxs = find_matching_indices(&users, "abc").unwrap();
        assert_eq!(idxs, vec![0, 1]);
    }

    #[test]
    fn test_find_matching_indices_anchored_email() {
        let users = vec![
            make_user("alice@example.com:SID1:0", "1"),
            make_user("bob@example.com:SID2:0", "2"),
        ];
        let idxs = find_matching_indices(&users, "alice@example.com").unwrap();
        assert_eq!(idxs, vec![0]);
    }

    #[test]
    fn test_find_matching_indices_glob() {
        let users = vec![
            make_user("alice@example.com:SID1:0", "1"),
            make_user("a.smith@example.com:SID2:0", "2"),
            make_user("bob@example.com:SID3:0", "3"),
        ];
        let idxs = find_matching_indices(&users, "a*example.com").unwrap();
        // anchored pattern '^a*example.com:' becomes '^a.*example\.com:'
        // Matches first two users (names starting with 'alice...' and 'a.smith...')
        assert_eq!(idxs, vec![0, 1]);
    }

    #[test]
    fn test_find_matching_indices_substring_local_part() {
        let users = vec![
            make_user("alice+tag@example.com:SID1:0", "1"),
            make_user("bob@example.com:SID2:0", "2"),
        ];
        let idxs = find_matching_indices(&users, "alice+tag").unwrap();
        assert_eq!(idxs, vec![0]);
    }

    #[test]
    fn test_update_email_replace_non_regex() {
        let mut inbound = reality_inbound();
        inbound["users"] = serde_json::json!([
            make_user("bob@old.com:SID2:0", "2222"),
            make_user("alice@example.com:SID1:0", "1111")
        ]);
        let fixture = UserFixture::new(serde_json::json!([inbound]));

        update(
            &fixture.paths,
            vec!["*@old.com".to_string()],
            None,
            None,
            Some(vec!["@old.com".to_string(), "@new.com".to_string()]),
            false,
            false,
            false,
            false,
        )
        .expect("update should succeed");

        assert_eq!(
            fixture.staged().inbounds[0].users[0]["name"],
            "bob@new.com:SID2:0"
        );
    }

    #[test]
    fn test_update_email_replace_dry_run() {
        let mut inbound = reality_inbound();
        inbound["users"] = serde_json::json!([make_user("bob@old.com:SID2:0", "2222")]);
        let fixture = UserFixture::new(serde_json::json!([inbound]));

        update(
            &fixture.paths,
            vec!["*@old.com".to_string()],
            None,
            None,
            Some(vec!["@old.com".to_string(), "@new.com".to_string()]),
            false,
            false,
            true,
            false,
        )
        .expect("dry-run update should succeed");

        assert!(
            !fixture.paths.staging.exists(),
            "staging should not be created in dry-run"
        );
    }

    // Test removed: this test invoked `apply()` which can trigger privileged systemctl calls.
    // Removed to avoid running privileged operations during package installation/tests.

    // Test removed: this test invoked `apply()` which can trigger privileged systemctl calls.
    // Removed to avoid running privileged operations during package installation/tests.
}
